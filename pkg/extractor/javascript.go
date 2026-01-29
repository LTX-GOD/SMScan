package extractor

import (
	"github.com/dlclark/regexp2"
)

// JSExtractor 负责高级 JS 语义提取
type JSExtractor struct {
	// API 调用模式
	// 匹配 axios.get('...'), fetch('...'), $.ajax('...') 等
	apiPatterns []*regexp2.Regexp
}

func NewJSExtractor() *JSExtractor {
	return &JSExtractor{
		apiPatterns: []*regexp2.Regexp{
			// axios/http client: .get("/api/v1/...")
			regexp2.MustCompile(`\.(?:get|post|put|delete|patch|head|options)\s*\(\s*["']([^"']+)["']`, regexp2.IgnoreCase),
			// fetch("/api/...")
			regexp2.MustCompile(`\bfetch\s*\(\s*["']([^"']+)["']`, regexp2.IgnoreCase),
			// xhr.open("GET", "/api/...")
			regexp2.MustCompile(`\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']`, regexp2.IgnoreCase),
			// common variable assignment: const API_URL = "..."
			regexp2.MustCompile(`\b(?:API|URL|HOST|DOMAIN|ENDPOINT)_?(?:URL|PATH|PREFIX)?\s*[:=]\s*["']([^"']+)["']`, regexp2.IgnoreCase),
		},
	}
}

// ExtractAPIs 从 JS 代码中提取 API 端点
func (j *JSExtractor) ExtractAPIs(body string) []string {
	var apis []string
	
	// 限制匹配长度以防卡顿
	limit := 1000 // 每个正则最多匹配 1000 次
	
	for _, pattern := range j.apiPatterns {
		if m, err := pattern.FindStringMatch(body); err == nil && m != nil {
			cur := m
			count := 0
			for cur != nil && count < limit {
				if len(cur.Groups()) > 1 {
					apis = append(apis, cur.Groups()[1].String())
				}
				cur, _ = pattern.FindNextMatch(cur)
				count++
			}
		}
	}
	
	return unique(apis)
}
