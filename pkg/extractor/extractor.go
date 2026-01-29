package extractor

import (
	"regexp"
	"strings"

	"github.com/dlclark/regexp2"
	"SMScan/pkg/models"
)

// Extractor 信息提取器
type Extractor struct {
	// 使用 regexp2 以支持更复杂的正则语法（如后行断言等，虽然 Go 标准库不支持，但这里为了兼容性更好）
	// 或者对于简单正则使用标准库 regexp
	ipRegex        *regexp.Regexp
	domainRegex    *regexp.Regexp
	urlRegex       *regexp.Regexp
	emailRegex     *regexp.Regexp
	phoneRegex     *regexp.Regexp
	jwtRegex       *regexp.Regexp
	keyRegex       *regexp2.Regexp // 使用 regexp2 处理复杂正则
	sensitiveRegex *regexp2.Regexp
	
	// API 相关
	apiRegex *regexp.Regexp
	// JS 文件中常见的敏感信息正则 (Phantom 风格)
	jsMapRegex     *regexp.Regexp // .js.map

	// 新增的高级提取器
	webpackExtractor   *WebpackExtractor
	sourceMapExtractor *SourceMapExtractor
	jsExtractor        *JSExtractor
}

func NewExtractor() *Extractor {
	return &Extractor{
		ipRegex:     regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b`),
		// 优化域名正则，避免匹配到文件名
		domainRegex: regexp.MustCompile(`\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+\.(?:com|cn|net|org|edu|gov|io|co)\b`),
		urlRegex:    regexp.MustCompile(`https?://[^\s"'<>]+`),
		emailRegex:  regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		phoneRegex:  regexp.MustCompile(`\b1[3-9]\d{9}\b`), // 简单的中国手机号正则
		jwtRegex:    regexp.MustCompile(`eyJ[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+`),
		
		// 复杂正则使用 regexp2
		keyRegex:       regexp2.MustCompile(`\b(?:api[_-]?key|access[_-]?key|secret|token)\b\s*[:=]\s*["']?([A-Za-z0-9-_]{16,})["']?`, regexp2.IgnoreCase),
		sensitiveRegex: regexp2.MustCompile(`\b(password|passwd|pwd|username|user_name|token|access_token|id_token|auth_token)\b\s*[:=]\s*["']?([A-Za-z0-9._-]{4,})["']?`, regexp2.IgnoreCase),
		
		// 简单的 API 路径匹配 (Phantom 风格)
		// 匹配以 / 或 ./ 或 ../ 开头的字符串，且不包含非法字符
		apiRegex: regexp.MustCompile(`["']((?:/|\.\.?/)[A-Za-z0-9/_\-\.]+(?:\?[^\s"'<>]*)?)["']`),
		
		// JS Map
		jsMapRegex: regexp.MustCompile(`\b[a-zA-Z0-9_\-\.]+\.js\.map\b`),

		// 初始化高级提取器
		webpackExtractor:   NewWebpackExtractor(),
		sourceMapExtractor: NewSourceMapExtractor(),
		jsExtractor:        NewJSExtractor(),
	}
}

func (e *Extractor) Extract(body string, baseURL string) models.AssetResult {
	// Limit matches to avoid performance issues on large files
	limit := 500

	result := models.AssetResult{
		IPs:          unique(e.ipRegex.FindAllString(body, limit)),
		Domains:      unique(e.domainRegex.FindAllString(body, limit)),
		URLs:         unique(e.urlRegex.FindAllString(body, limit)),
		Emails:       unique(e.emailRegex.FindAllString(body, limit)),
		Phones:       unique(e.phoneRegex.FindAllString(body, limit)),
		JWTs:         unique(e.jwtRegex.FindAllString(body, limit)),
		AbsoluteApis: []string{},
		RelativeApis: []string{},
		WebpackChunks: []string{},
		SourceMaps:    []string{},
	}

	// 1. 基础正则提取
	// 提取 Keys
	if m, err := e.keyRegex.FindStringMatch(body); err == nil && m != nil {
		cur := m
		count := 0
		for cur != nil && count < limit {
			if len(cur.Groups()) > 1 {
				result.Keys = append(result.Keys, cur.Groups()[1].String())
			}
			cur, _ = e.keyRegex.FindNextMatch(cur)
			count++
		}
	}
	result.Keys = unique(result.Keys)

	// 提取 Sensitive
	if m, err := e.sensitiveRegex.FindStringMatch(body); err == nil && m != nil {
		cur := m
		count := 0
		for cur != nil && count < limit {
			// 捕获整个匹配
			result.Sensitive = append(result.Sensitive, cur.String())
			cur, _ = e.sensitiveRegex.FindNextMatch(cur)
			count++
		}
	}
	result.Sensitive = unique(result.Sensitive)

	// 提取 API 路径 (基础正则)
	apiMatches := e.apiRegex.FindAllStringSubmatch(body, limit)
	for _, m := range apiMatches {
		if len(m) > 1 {
			path := m[1]
			// 简单的过滤
			if isStaticFile(path) {
				continue
			}
			if strings.HasPrefix(path, "/") {
				result.AbsoluteApis = append(result.AbsoluteApis, path)
			} else if strings.HasPrefix(path, ".") {
				result.RelativeApis = append(result.RelativeApis, path)
			}
		}
	}

	// 2. 高级提取 (Phantom 增强)
	
	// Webpack Chunks
	result.WebpackChunks = e.webpackExtractor.ExtractChunks(body)

	// Source Maps
	if mapURL := e.sourceMapExtractor.ExtractSourceMapURL(body); mapURL != "" {
		result.SourceMaps = append(result.SourceMaps, mapURL)
	}

	// Advanced JS APIs (simulating AST)
	jsAPIs := e.jsExtractor.ExtractAPIs(body)
	for _, api := range jsAPIs {
		// 简单的过滤
		if isStaticFile(api) {
			continue
		}
		
		if strings.HasPrefix(api, "http") {
			result.URLs = append(result.URLs, api)
		} else if strings.HasPrefix(api, "/") {
			result.AbsoluteApis = append(result.AbsoluteApis, api)
		} else if strings.HasPrefix(api, ".") {
			result.RelativeApis = append(result.RelativeApis, api)
		} else if strings.Contains(api, "/") {
			// 可能是相对路径，也可能是无关字符串
			// 暂时作为相对 API 处理，但在 Scanner 中 resolve 时会验证
			result.RelativeApis = append(result.RelativeApis, api)
		}
	}

	// 去重
	result.AbsoluteApis = unique(result.AbsoluteApis)
	result.RelativeApis = unique(result.RelativeApis)
	result.URLs = unique(result.URLs)

	return result
}

func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func isStaticFile(path string) bool {
	exts := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"}
	lowerPath := strings.ToLower(path)
	for _, ext := range exts {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	// 排除一些常见的库路径
	if strings.Contains(lowerPath, "node_modules") || strings.Contains(lowerPath, "jquery") {
		return true
	}
	return false
}
