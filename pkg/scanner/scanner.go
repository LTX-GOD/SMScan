package scanner

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
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
	techDetector    *extractor.TechDetector
	secAnalyzer     *extractor.SecurityAnalyzer
	Results         []*models.ScanResult
	resultsMutex    sync.Mutex
	MaxDepth        int
	Concurrency     int
	Timeout         int
	UserAgent       string
	Proxy           string
	Collector       *colly.Collector
	visitedPatterns sync.Map
	scannedCount    int32
	totalCount      int32
	errorCount      int32
	OnProgress      func(scanned, total int, currentURL string)
	startTime       time.Time
}

func NewScanner(fpConfigPath string, maxDepth int, concurrency int) (*Scanner, error) {
	fpMatcher, err := fingerprint.NewMatcher(fpConfigPath)
	if err != nil {
		return nil, err
	}

	return &Scanner{
		extractor:    extractor.NewExtractor(),
		fpMatcher:    fpMatcher,
		hpDetector:   honeypot.NewDetector(),
		techDetector: extractor.NewTechDetector(),
		secAnalyzer:  extractor.NewSecurityAnalyzer(),
		MaxDepth:     maxDepth,
		Concurrency:  concurrency,
		Timeout:      15,
		UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Results:      make([]*models.ScanResult, 0),
	}, nil
}

// SetProxy 设置代理
func (s *Scanner) SetProxy(proxy string) {
	s.Proxy = proxy
}

// SetUserAgent 设置 User-Agent
func (s *Scanner) SetUserAgent(ua string) {
	s.UserAgent = ua
}

// SetTimeout 设置超时
func (s *Scanner) SetTimeout(timeout int) {
	s.Timeout = timeout
}

// GetStats 获取扫描统计
func (s *Scanner) GetStats() models.ScanStats {
	stats := models.ScanStats{
		TotalURLs:   int(atomic.LoadInt32(&s.totalCount)),
		ScannedURLs: int(atomic.LoadInt32(&s.scannedCount)),
		Errors:      int(atomic.LoadInt32(&s.errorCount)),
	}

	// 统计指纹和敏感信息
	for _, r := range s.Results {
		stats.Fingerprints += len(r.Fingerprints)
		stats.SensitiveData += len(r.Assets.Keys) + len(r.Assets.Sensitive) + len(r.Assets.JWTs)
		stats.Vulnerabilities += len(r.NucleiFindings)
	}

	if !s.startTime.IsZero() {
		stats.Duration = time.Since(s.startTime).Round(time.Second).String()
		stats.StartTime = s.startTime.Format("2006-01-02 15:04:05")
	}

	return stats
}

func (s *Scanner) Scan(startURL string) {
	s.startTime = time.Now()

	// 创建 Transport
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		ResponseHeaderTimeout: time.Duration(s.Timeout) * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        s.Concurrency * 2,
		MaxIdleConnsPerHost: s.Concurrency,
		IdleConnTimeout:     30 * time.Second,
	}

	// 设置代理
	if s.Proxy != "" {
		proxyURL, err := url.Parse(s.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	c := colly.NewCollector(
		colly.MaxDepth(s.MaxDepth),
		colly.Async(true),
		colly.IgnoreRobotsTxt(),
	)

	c.WithTransport(transport)
	c.SetRequestTimeout(time.Duration(s.Timeout) * time.Second)

	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: s.Concurrency,
		RandomDelay: 100 * time.Millisecond,
	})

	c.OnRequest(func(r *colly.Request) {
		if !s.shouldVisit(r.URL.String()) {
			r.Abort()
			return
		}

		r.Headers.Set("User-Agent", s.UserAgent)
		r.Headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		r.Headers.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

		atomic.AddInt32(&s.totalCount, 1)

		if s.OnProgress != nil {
			s.OnProgress(int(atomic.LoadInt32(&s.scannedCount)), int(atomic.LoadInt32(&s.totalCount)), r.URL.String())
		}
	})

	c.OnResponse(func(r *colly.Response) {
		if len(r.Body) > 5*1024*1024 {
			return
		}
		s.processResponse(r)
		atomic.AddInt32(&s.scannedCount, 1)
	})

	c.OnError(func(r *colly.Response, err error) {
		atomic.AddInt32(&s.errorCount, 1)
		if strings.Contains(err.Error(), "unsupported protocol scheme") {
			return
		}
	})

	c.OnHTML("a[href], script[src], link[href], img[src], iframe[src], form[action]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		if link == "" {
			link = e.Attr("src")
		}
		if link == "" {
			link = e.Attr("action")
		}
		if link != "" && s.shouldVisit(link) {
			e.Request.Visit(link)
		}
	})

	c.Visit(startURL)
	c.Wait()
}

func (s *Scanner) processResponse(r *colly.Response) {
	startTime := time.Now()
	bodyStr := string(r.Body)
	targetURL := r.Request.URL.String()

	// 1. 提取资产
	assets := s.extractor.Extract(bodyStr, targetURL)

	// 2. 提取 Vue 信息
	vueInfo := s.extractor.ExtractVue(bodyStr)

	// 3. 指纹识别
	headers := make(map[string]string)
	if r.Headers != nil {
		for k, v := range *r.Headers {
			headers[k] = strings.Join(v, ", ")
		}
	}

	// 提取 Title 和 Favicon
	title := ""
	faviconHash := ""
	var doc *goquery.Document

	contentType := r.Headers.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		doc, _ = goquery.NewDocumentFromReader(strings.NewReader(bodyStr))
		if doc != nil {
			title = doc.Find("title").Text()

			iconURL := ""
			doc.Find("link[rel*='icon']").Each(func(i int, sel *goquery.Selection) {
				if iconURL == "" {
					href, exists := sel.Attr("href")
					if exists {
						iconURL = href
					}
				}
			})

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

	// 4. 蜜罐检测
	honeypotInfo := s.hpDetector.Detect(headers, bodyStr, nil)

	// 5. 技术栈检测
	techStack := s.techDetector.Detect(headers, bodyStr)

	// 6. 安全头分析
	responseInfo := s.secAnalyzer.AnalyzeResponse(headers, nil)
	responseInfo.ContentType = contentType
	responseInfo.ContentLength = int64(len(r.Body))

	// 解析 Cookies
	if setCookie := r.Headers.Get("Set-Cookie"); setCookie != "" {
		cookies := parseCookies(setCookie)
		responseInfo.Cookies = cookies
	}

	// 7. 计算风险评分
	riskLevel, riskScore := calculateRisk(assets, honeypotInfo, responseInfo.SecurityHeaders)

	// 计算响应时间
	responseTime := time.Since(startTime).Milliseconds()

	// 8. 保存结果
	result := &models.ScanResult{
		URL:          targetURL,
		Status:       r.StatusCode,
		Title:        strings.TrimSpace(title),
		Server:       r.Headers.Get("Server"),
		Fingerprints: fingerprints,
		Assets:       assets,
		Honeypot:     honeypotInfo,
		Vue:          vueInfo,
		TechStack:    techStack,
		ResponseInfo: responseInfo,
		RiskLevel:    riskLevel,
		RiskScore:    riskScore,
		ScanTime:     time.Now().Format("2006-01-02 15:04:05"),
		ResponseTime: responseTime,
	}

	s.resultsMutex.Lock()
	s.Results = append(s.Results, result)
	s.resultsMutex.Unlock()

	// 深挖 API
	if r.Request.Depth < s.MaxDepth {
		baseURL := r.Request.URL
		maxApisToVisit := 50
		visitedCount := 0

		for _, api := range assets.AbsoluteApis {
			if visitedCount >= maxApisToVisit {
				break
			}
			absURL := resolveURL(baseURL, api)
			if absURL != "" && s.shouldVisit(absURL) {
				r.Request.Visit(absURL)
				visitedCount++
			}
		}
		for _, api := range assets.RelativeApis {
			if visitedCount >= maxApisToVisit {
				break
			}
			absURL := resolveURL(baseURL, api)
			if absURL != "" && s.shouldVisit(absURL) {
				r.Request.Visit(absURL)
				visitedCount++
			}
		}

		for _, chunk := range assets.WebpackChunks {
			if visitedCount >= maxApisToVisit {
				break
			}
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

	if strings.HasPrefix(link, "mailto:") ||
		strings.HasPrefix(link, "tel:") ||
		strings.HasPrefix(link, "javascript:") ||
		strings.HasPrefix(link, "data:") ||
		strings.HasPrefix(link, "#") {
		return false
	}

	if strings.Contains(link, "logout") || strings.Contains(link, "signout") {
		return false
	}

	thirdParty := []string{
		"google-analytics.com", "googletagmanager.com", "hm.baidu.com",
		"cnzz.com", "51.la", "doubleclick.net", "facebook.com",
		"twitter.com", "linkedin.com", "youtube.com",
	}
	for _, domain := range thirdParty {
		if strings.Contains(link, domain) {
			return false
		}
	}

	if isBinary(link) {
		return false
	}

	pattern := utils.GetURLPattern(link)
	val, _ := s.visitedPatterns.LoadOrStore(pattern, new(int32))
	count := atomic.AddInt32(val.(*int32), 1)
	if count > 10 {
		return false
	}

	return true
}

func isBinary(path string) bool {
	exts := []string{
		".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp", ".webp",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		".mp3", ".mp4", ".avi", ".mov", ".wav", ".webm", ".flv",
		".zip", ".tar", ".gz", ".rar", ".7z", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".iso", ".bin", ".exe", ".dll", ".so", ".dmg", ".apk",
	}

	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}

	for _, ext := range exts {
		if strings.HasSuffix(strings.ToLower(path), ext) {
			return true
		}
	}
	return false
}

func (s *Scanner) fetchResource(resourceURL string) ([]byte, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest("GET", resourceURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

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

func parseCookies(setCookie string) []*models.Cookie {
	var cookies []*models.Cookie

	parts := strings.Split(setCookie, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		attrs := strings.Split(part, ";")
		if len(attrs) == 0 {
			continue
		}

		// 第一个是 name=value
		nameValue := strings.SplitN(attrs[0], "=", 2)
		if len(nameValue) != 2 {
			continue
		}

		cookie := &models.Cookie{
			Name:  strings.TrimSpace(nameValue[0]),
			Value: strings.TrimSpace(nameValue[1]),
		}

		for _, attr := range attrs[1:] {
			attr = strings.TrimSpace(attr)
			attrLower := strings.ToLower(attr)

			if attrLower == "secure" {
				cookie.Secure = true
			} else if attrLower == "httponly" {
				cookie.HttpOnly = true
			} else if strings.HasPrefix(attrLower, "samesite=") {
				cookie.SameSite = strings.TrimPrefix(attr, "SameSite=")
			} else if strings.HasPrefix(attrLower, "path=") {
				cookie.Path = strings.TrimPrefix(attr, "Path=")
			} else if strings.HasPrefix(attrLower, "domain=") {
				cookie.Domain = strings.TrimPrefix(attr, "Domain=")
			}
		}

		cookies = append(cookies, cookie)
	}

	return cookies
}

func calculateRisk(assets models.AssetResult, hp models.HoneypotInfo, sh *models.SecurityHeaders) (string, int) {
	score := 0

	// 敏感信息权重
	score += len(assets.Keys) * 15
	score += len(assets.Sensitive) * 10
	score += len(assets.JWTs) * 20
	score += len(assets.PrivateKeys) * 50
	score += len(assets.AWSKeys) * 40
	score += len(assets.GithubTokens) * 30
	score += len(assets.DatabaseConns) * 35
	score += len(assets.HardcodedCreds) * 25
	score += len(assets.IDCards) * 20
	score += len(assets.BankCards) * 25
	score += len(assets.InternalIPs) * 5

	// 安全头缺失
	if sh != nil {
		score += (100 - sh.Score) / 5
	}

	// 蜜罐警告
	if hp.IsHoneypot {
		score -= 50 // 降低风险分，因为可能是蜜罐
	}

	if score > 100 {
		score = 100
	}

	var level string
	switch {
	case score >= 80:
		level = "critical"
	case score >= 60:
		level = "high"
	case score >= 30:
		level = "medium"
	case score > 0:
		level = "low"
	default:
		level = "info"
	}

	return level, score
}
