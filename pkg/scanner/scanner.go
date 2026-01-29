package scanner

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/gocolly/colly/v2"
	"github.com/twmb/murmur3"
	"SMScan/pkg/extractor"
	"SMScan/pkg/fingerprint"
	"SMScan/pkg/honeypot"
	"SMScan/pkg/models"
	"SMScan/pkg/utils"
)

type Scanner struct {
	extractor       *extractor.Extractor
	fpMatcher       *fingerprint.Matcher
	hpDetector      *honeypot.Detector
	Results         []*models.ScanResult
	resultsMutex    sync.Mutex
	MaxDepth        int
	Concurrency     int
	Collector       *colly.Collector
	visitedPatterns sync.Map // pattern -> *int32
}

func NewScanner(fpConfigPath string, maxDepth int, concurrency int) (*Scanner, error) {
	fpMatcher, err := fingerprint.NewMatcher(fpConfigPath)
	if err != nil {
		return nil, err
	}

	return &Scanner{
		extractor:   extractor.NewExtractor(),
		fpMatcher:   fpMatcher,
		hpDetector:  honeypot.NewDetector(),
		MaxDepth:    maxDepth,
		Concurrency: concurrency,
		Results:     make([]*models.ScanResult, 0),
	}, nil
}

func (s *Scanner) Scan(startURL string) {
	c := colly.NewCollector(
		colly.MaxDepth(s.MaxDepth),
		colly.Async(true), // 开启异步
		// 忽略 robots.txt
		colly.IgnoreRobotsTxt(),
	)

	// 配置 TLS
	c.WithTransport(&http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}).DialContext,
		ResponseHeaderTimeout: 10 * time.Second, // 设置响应超时
	})
	
	// 设置全局请求超时
	c.SetRequestTimeout(15 * time.Second)

	// 设置并发限制
	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: s.Concurrency,
		RandomDelay: 200 * time.Millisecond,
	})

	// 调试日志 (可选)
	// c.SetDebugger(&debug.LogDebugger{})

	// 请求回调
	c.OnRequest(func(r *colly.Request) {
		// 再次检查 URL，防止漏网之鱼
		if !s.shouldVisit(r.URL.String()) {
			r.Abort()
			return
		}
		
		r.Headers.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
		fmt.Printf("[*] Scanning: %s\n", r.URL.String())
	})

	// 响应回调
	c.OnResponse(func(r *colly.Response) {
		// 限制响应大小，防止下载过大的文件 (例如 > 5MB)
		if len(r.Body) > 5*1024*1024 {
			return
		}
		s.processResponse(r)
	})

	// 错误回调
	c.OnError(func(r *colly.Response, err error) {
		// 忽略一些常见的非关键错误，避免刷屏
		if strings.Contains(err.Error(), "unsupported protocol scheme") {
			return
		}
		fmt.Printf("[-] Error fetching %s: %v\n", r.Request.URL, err)
	})

	// 链接提取与深挖
	// colly 自动处理 HTML 中的 href，这里我们需要处理更多类型的链接（如 API）
	// 并手动将其加入队列
	c.OnHTML("a[href], script[src], link[href], img[src]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		if link == "" {
			link = e.Attr("src")
		}
		if link != "" {
			// 只有同域或子域才继续爬取
			// colly 默认 Visit 会处理去重和深度
			// 这里简单判断一下是否应该继续爬取
			// 注意：colly 的 Visit 是针对页面的，对于 JS/CSS 等资源，我们可能只想分析不想“爬取”
			// 但为了简单，我们让 colly 决定，或者在这里做过滤
			// 为了深挖 API，我们需要解析 JS 文件，所以 JS 文件也应该 Visit
			if s.shouldVisit(link) {
				e.Request.Visit(link)
			}
		}
	})

	c.Visit(startURL)
	c.Wait()
}

func (s *Scanner) processResponse(r *colly.Response) {
	bodyStr := string(r.Body)
	targetURL := r.Request.URL.String()

	// 1. 提取资产
	assets := s.extractor.Extract(bodyStr, targetURL)

	// 2. 指纹识别
	headers := make(map[string]string)
	// colly 2.x r.Headers is *http.Header which is map[string][]string
	if r.Headers != nil {
		for k, v := range *r.Headers {
			headers[k] = strings.Join(v, ", ")
		}
	}
	
	// 尝试获取 Title 和 Favicon
	title := ""
	faviconHash := ""
	var doc *goquery.Document
	
	// 只对 HTML 内容进行 DOM 解析
	contentType := r.Headers.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		doc, _ = goquery.NewDocumentFromReader(strings.NewReader(bodyStr))
		if doc != nil {
			title = doc.Find("title").Text()

			// 提取 Favicon
			iconURL := ""
			doc.Find("link[rel*='icon']").Each(func(i int, s *goquery.Selection) {
				if iconURL == "" {
					href, exists := s.Attr("href")
					if exists {
						iconURL = href
					}
				}
			})
			
			// 如果没找到显式的 link icon，尝试默认的 favicon.ico
			// 注意：如果页面不是根目录，favicon 通常在根目录
			// 但这里我们尝试相对于当前 URL
			if iconURL == "" {
				iconURL = "/favicon.ico"
			}

			absIconURL := resolveURL(r.Request.URL, iconURL)
			if absIconURL != "" {
				content, err := s.fetchResource(absIconURL)
				if err == nil && len(content) > 0 {
					faviconHash = calculateFaviconHash(content)
				}
			}
		}
	}

	fingerprints := s.fpMatcher.Match(headers, bodyStr, title, faviconHash)

	// 3. 蜜罐检测
	honeypotInfo := s.hpDetector.Detect(headers, bodyStr, nil)

	// 4. 保存结果
	result := &models.ScanResult{
		URL:          targetURL,
		Status:       r.StatusCode,
		Title:        strings.TrimSpace(title),
		Server:       r.Headers.Get("Server"),
		Fingerprints: fingerprints,
		Assets:       assets,
		Honeypot:     honeypotInfo,
	}

	s.resultsMutex.Lock()
	s.Results = append(s.Results, result)
	s.resultsMutex.Unlock()
	
	// 手动将提取到的 API 路径加入深挖队列 (如果是绝对路径且看起来像 URL)
	// Colly 的 Visit 会自动处理相对路径，但对于正则提取到的 API，我们需要手动处理
	// 只有在深度允许的情况下才继续
	if r.Request.Depth < s.MaxDepth {
		baseURL := r.Request.URL
		
		// 限制每个页面提取并访问的 API 数量，防止队列爆炸
		maxApisToVisit := 50
		visitedCount := 0

		for _, api := range assets.AbsoluteApis {
			if visitedCount >= maxApisToVisit { break }
			absURL := resolveURL(baseURL, api)
			if absURL != "" && s.shouldVisit(absURL) {
				r.Request.Visit(absURL)
				visitedCount++
			}
		}
		for _, api := range assets.RelativeApis {
			if visitedCount >= maxApisToVisit { break }
			absURL := resolveURL(baseURL, api)
			if absURL != "" && s.shouldVisit(absURL) {
				r.Request.Visit(absURL)
				visitedCount++
			}
		}

		// Webpack Chunks (通常也是相对路径)
		for _, chunk := range assets.WebpackChunks {
			if visitedCount >= maxApisToVisit { break }
			absURL := resolveURL(baseURL, chunk)
			if absURL != "" && s.shouldVisit(absURL) {
				r.Request.Visit(absURL)
				visitedCount++
			}
		}
	}
}

func resolveURL(base *url.URL, ref string) string {
	refURL, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(refURL).String()
}

func (s *Scanner) shouldVisit(link string) bool {
	link = strings.ToLower(link)
	
	// 过滤非 HTTP 协议
	if strings.HasPrefix(link, "mailto:") || 
	   strings.HasPrefix(link, "tel:") || 
	   strings.HasPrefix(link, "javascript:") || 
	   strings.HasPrefix(link, "data:") ||
	   strings.HasPrefix(link, "#") {
		return false
	}

	// 过滤注销链接
	if strings.Contains(link, "logout") || strings.Contains(link, "signout") {
		return false
	}
	
	// 过滤第三方统计/广告
	if strings.Contains(link, "google-analytics.com") || 
	   strings.Contains(link, "googletagmanager.com") ||
	   strings.Contains(link, "hm.baidu.com") ||
	   strings.Contains(link, "cnzz.com") {
		return false
	}

	// 不爬取图片等二进制文件，除非为了元数据（这里为了效率跳过）
	if isBinary(link) {
		return false
	}
	
	// 基于 URL 模式的去重/限流
	// 如果同一模式的 URL 访问次数超过阈值，则不再访问
	// 例如: /category.php?id=1, /category.php?id=2 ...
	pattern := utils.GetURLPattern(link)
	val, _ := s.visitedPatterns.LoadOrStore(pattern, new(int32))
	count := atomic.AddInt32(val.(*int32), 1)
	if count > 10 { // 每个模式最多访问 10 次
		return false
	}

	return true
}

func isBinary(path string) bool {
	// 增加 css 作为"二进制"对待，意味着不深入爬取其内部链接（如背景图），但 processResponse 仍会处理它（进行指纹识别）
	// 用户反馈 css 扫描卡顿，可能是因为 css 文件很大，或者 colly 试图解析其中的链接
	// 我们可以在 OnHTML 中不监听 css 内容，或者在这里就过滤掉
	// 但如果指纹识别需要 css 内容（如 finger.json 中的 keyword），则必须下载
	// 所以这里不仅是是否爬取，而是是否"访问"
	// 考虑到效率，一般不递归爬取 css/js 内的链接（js 除外，因为要提取 API）
	// 这里 isBinary 主要用于 shouldVisit，控制的是 Visit 行为
	
	exts := []string{
		".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp", ".webp",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		".mp3", ".mp4", ".avi", ".mov", ".wav",
		".zip", ".tar", ".gz", ".rar", ".7z", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".iso", ".bin", ".exe", ".dll", ".so", ".dmg", ".apk",
	}
	// 注意：不建议过滤 .js，因为我们需要从中提取 API
	// .css 可以根据情况过滤，但如果指纹依赖 css，则不能过滤
	// 针对用户卡顿问题，主要是网络请求问题，通过超时和大小限制解决
	
	// 移除 query 参数进行判断
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}
	
	for _, ext := range exts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// fetchResource 简单的同步资源获取
func (s *Scanner) fetchResource(url string) ([]byte, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// calculateFaviconHash 计算 Favicon 的 MurmurHash3
// 算法参考 Shodan/Fofa: mmh3(base64_with_newlines(content))
func calculateFaviconHash(content []byte) string {
	b64 := base64.StdEncoding.EncodeToString(content)
	
	var buffer bytes.Buffer
	for i, r := range b64 {
		buffer.WriteRune(r)
		if (i+1)%76 == 0 {
			buffer.WriteRune('\n')
		}
	}
	buffer.WriteRune('\n')
	
	h32 := murmur3.New32()
	h32.Write(buffer.Bytes())
	return fmt.Sprintf("%d", int32(h32.Sum32()))
}
