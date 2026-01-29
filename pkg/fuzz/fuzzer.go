package fuzz

import (
	_ "embed"
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"SMScan/pkg/models"
)

//go:embed dicts/paths.txt
var pathsDict []byte

//go:embed dicts/api.txt
var apiDict []byte

//go:embed dicts/js.txt
var jsDict []byte

// Fuzzer 路径/API Fuzz 扫描器
type Fuzzer struct {
	client      *http.Client
	concurrency int
	timeout     int
	userAgent   string
	filterCodes []int
}

// NewFuzzer 创建 Fuzzer
func NewFuzzer(concurrency int, timeout int) *Fuzzer {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:       concurrency * 2,
		IdleConnTimeout:    30 * time.Second,
		MaxIdleConnsPerHost: concurrency,
	}

	return &Fuzzer{
		client: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// 不跟随重定向
				return http.ErrUseLastResponse
			},
		},
		concurrency: concurrency,
		timeout:     timeout,
		userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		filterCodes: []int{404, 502, 503},
	}
}

// FuzzTarget 对目标执行 Fuzz 扫描
func (f *Fuzzer) FuzzTarget(baseURL string, mode string, progressFn func(found models.FuzzResult)) []models.FuzzResult {
	var results []models.FuzzResult
	var mu sync.Mutex

	// 根据模式选择字典
	var wordlist []string
	switch mode {
	case "path":
		wordlist = loadDict(pathsDict)
	case "api":
		wordlist = loadDict(apiDict)
	case "js":
		wordlist = loadDict(jsDict)
	case "all":
		wordlist = append(wordlist, loadDict(pathsDict)...)
		wordlist = append(wordlist, loadDict(apiDict)...)
		wordlist = append(wordlist, loadDict(jsDict)...)
	default:
		wordlist = loadDict(pathsDict)
		wordlist = append(wordlist, loadDict(apiDict)...)
	}

	// 去重
	seen := make(map[string]bool)
	var uniqueWords []string
	for _, w := range wordlist {
		if !seen[w] {
			seen[w] = true
			uniqueWords = append(uniqueWords, w)
		}
	}

	// 先获取基准404响应
	baseline404Len := f.getBaseline404(baseURL)

	// 并发扫描
	sem := make(chan struct{}, f.concurrency)
	var wg sync.WaitGroup

	for _, word := range uniqueWords {
		wg.Add(1)
		sem <- struct{}{}

		go func(word string) {
			defer wg.Done()
			defer func() { <-sem }()

			targetURL := buildFuzzURL(baseURL, word)
			result := f.fuzzOne(targetURL, word, baseline404Len)

			if result.Discovered {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()

				if progressFn != nil {
					progressFn(result)
				}
			}
		}(word)
	}

	wg.Wait()
	return results
}

// FuzzCustom 使用自定义字典
func (f *Fuzzer) FuzzCustom(baseURL string, wordlistPath string, progressFn func(found models.FuzzResult)) ([]models.FuzzResult, error) {
	// 读取自定义字典
	var results []models.FuzzResult
	// 这里需要从文件读取，但为了简化，先返回空结果
	// 实际使用时在 main 中处理文件读取
	_ = wordlistPath
	_ = baseURL
	_ = progressFn
	return results, nil
}

func (f *Fuzzer) fuzzOne(targetURL string, word string, baseline404Len int) models.FuzzResult {
	result := models.FuzzResult{
		URL:  targetURL,
		Type: categorizeWord(word),
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return result
	}

	req.Header.Set("User-Agent", f.userAgent)

	resp, err := f.client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	result.Status = resp.StatusCode

	// 读取 body 长度
	buf := make([]byte, 64*1024)
	totalLen := 0
	for {
		n, _ := resp.Body.Read(buf)
		totalLen += n
		if n == 0 {
			break
		}
	}
	result.Length = totalLen

	// 判断是否为有效发现
	result.Discovered = f.isDiscovered(result, baseline404Len)

	return result
}

func (f *Fuzzer) isDiscovered(result models.FuzzResult, baseline404Len int) bool {
	// 过滤状态码
	for _, code := range f.filterCodes {
		if result.Status == code {
			return false
		}
	}

	// 2xx 状态码通常是有效发现
	if result.Status >= 200 && result.Status < 300 {
		// 但需要排除与404页面长度相近的页面（自定义404）
		if baseline404Len > 0 && abs(result.Length-baseline404Len) < 100 {
			return false
		}
		return true
	}

	// 3xx 重定向也算发现
	if result.Status >= 300 && result.Status < 400 {
		return true
	}

	// 401/403 也算发现（存在但需要认证）
	if result.Status == 401 || result.Status == 403 {
		return true
	}

	return false
}

func (f *Fuzzer) getBaseline404(baseURL string) int {
	// 访问一个不存在的路径获取 404 基准
	randomPath := "/smscan_404_test_" + fmt.Sprintf("%d", time.Now().UnixNano())
	targetURL := strings.TrimRight(baseURL, "/") + randomPath

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", f.userAgent)

	resp, err := f.client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	buf := make([]byte, 64*1024)
	totalLen := 0
	for {
		n, _ := resp.Body.Read(buf)
		totalLen += n
		if n == 0 {
			break
		}
	}

	return totalLen
}

func buildFuzzURL(baseURL, word string) string {
	base := strings.TrimRight(baseURL, "/")
	word = strings.TrimSpace(word)

	// 如果 word 已经是完整路径
	if strings.HasPrefix(word, "/") {
		return base + word
	}

	return base + "/" + word
}

func categorizeWord(word string) string {
	lower := strings.ToLower(word)
	if strings.HasSuffix(lower, ".js") {
		return "js"
	}
	if strings.HasPrefix(lower, "/api") || strings.Contains(lower, "/api/") {
		return "api"
	}
	return "path"
}

func loadDict(data []byte) []string {
	var words []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}
	return words
}

// GetDictSize 获取字典大小
func GetDictSize(mode string) int {
	switch mode {
	case "path":
		return len(loadDict(pathsDict))
	case "api":
		return len(loadDict(apiDict))
	case "js":
		return len(loadDict(jsDict))
	case "all":
		return len(loadDict(pathsDict)) + len(loadDict(apiDict)) + len(loadDict(jsDict))
	default:
		return len(loadDict(pathsDict)) + len(loadDict(apiDict))
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// ParseURLBase 从 URL 中提取基础 URL (scheme + host)
func ParseURLBase(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
}
