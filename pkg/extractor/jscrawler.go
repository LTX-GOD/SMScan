package extractor

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// JSCrawler JS 文件深度爬取器
type JSCrawler struct {
	client       *http.Client
	visited      map[string]bool
	mu           sync.Mutex
	maxDepth     int
	downloadedJS map[string]string // URL -> 内容
}

func NewJSCrawler(timeout time.Duration, maxDepth int) *JSCrawler {
	return &JSCrawler{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		visited:      make(map[string]bool),
		downloadedJS: make(map[string]string),
		maxDepth:     maxDepth,
	}
}

// CrawlJS 深度爬取 JS 文件
func (c *JSCrawler) CrawlJS(startURL string) (map[string]string, error) {
	c.crawlRecursive(startURL, 0)
	return c.downloadedJS, nil
}

func (c *JSCrawler) crawlRecursive(pageURL string, depth int) {
	if depth > c.maxDepth {
		return
	}

	c.mu.Lock()
	if c.visited[pageURL] {
		c.mu.Unlock()
		return
	}
	c.visited[pageURL] = true
	c.mu.Unlock()

	// 下载页面
	resp, err := c.client.Get(pageURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	// 解析 HTML
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return
	}

	// 提取所有 JS 链接
	jsURLs := c.extractJSURLs(doc, pageURL)

	// 下载 JS 文件
	var wg sync.WaitGroup
	for _, jsURL := range jsURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			c.downloadJS(url)
		}(jsURL)
	}
	wg.Wait()
}

// extractJSURLs 从 HTML 中提取 JS URL
func (c *JSCrawler) extractJSURLs(n *html.Node, baseURL string) []string {
	var urls []string

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			for _, attr := range n.Attr {
				if attr.Key == "src" {
					fullURL := c.resolveURL(attr.Val, baseURL)
					if fullURL != "" && strings.HasSuffix(fullURL, ".js") {
						urls = append(urls, fullURL)
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			f(child)
		}
	}
	f(n)

	return urls
}

// downloadJS 下载 JS 文件
func (c *JSCrawler) downloadJS(jsURL string) {
	c.mu.Lock()
	if _, exists := c.downloadedJS[jsURL]; exists {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	resp, err := c.client.Get(jsURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	c.mu.Lock()
	c.downloadedJS[jsURL] = string(body)
	c.mu.Unlock()
}

// resolveURL 解析相对 URL
func (c *JSCrawler) resolveURL(href, base string) string {
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}

	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}

	relURL, err := url.Parse(href)
	if err != nil {
		return ""
	}

	return baseURL.ResolveReference(relURL).String()
}

// ExtractInlineJS 提取内联 JS
func (c *JSCrawler) ExtractInlineJS(htmlContent string) []string {
	var inlineScripts []string

	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return inlineScripts
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			// 检查是否有 src 属性
			hasSrc := false
			for _, attr := range n.Attr {
				if attr.Key == "src" {
					hasSrc = true
					break
				}
			}

			// 如果没有 src，则是内联脚本
			if !hasSrc && n.FirstChild != nil {
				inlineScripts = append(inlineScripts, n.FirstChild.Data)
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			f(child)
		}
	}
	f(doc)

	return inlineScripts
}

// CalculateHash 计算文件哈希
func (c *JSCrawler) CalculateHash(content string) string {
	hash := md5.Sum([]byte(content))
	return hex.EncodeToString(hash[:])
}

// DeduplicateJS 去重 JS 文件
func (c *JSCrawler) DeduplicateJS(jsFiles map[string]string) map[string]string {
	hashMap := make(map[string]string)
	deduplicated := make(map[string]string)

	for url, content := range jsFiles {
		hash := c.CalculateHash(content)
		if _, exists := hashMap[hash]; !exists {
			hashMap[hash] = url
			deduplicated[url] = content
		}
	}

	return deduplicated
}

// ExtractSourceMapURLs 提取 SourceMap URL
func (c *JSCrawler) ExtractSourceMapURLs(jsContent string) []string {
	var urls []string

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`//# sourceMappingURL=([^\s]+)`),
		regexp.MustCompile(`//@ sourceMappingURL=([^\s]+)`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(jsContent, -1)
		for _, match := range matches {
			if len(match) > 1 {
				urls = append(urls, match[1])
			}
		}
	}

	return urls
}
