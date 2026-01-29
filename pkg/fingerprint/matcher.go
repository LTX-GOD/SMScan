package fingerprint

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"SMScan/pkg/models"
)

//go:embed finger.json
var defaultFingerprintData []byte

// Matcher 指纹匹配器
type Matcher struct {
	Rules []models.FingerprintRule
}

// NewMatcher 创建新的匹配器
// 如果 configPath 为空，或文件不存在且为默认路径，则使用内置指纹库
func NewMatcher(configPath string) (*Matcher, error) {
	var byteValue []byte
	var err error

	// 尝试读取外部文件
	if configPath != "" {
		jsonFile, err := os.Open(configPath)
		if err == nil {
			defer jsonFile.Close()
			byteValue, _ = io.ReadAll(jsonFile)
		} else {
			// 如果文件不存在，且是默认路径 "config/finger.json"，则忽略错误使用内置库
			// 如果用户指定了其他路径但不存在，则返回错误
			if !os.IsNotExist(err) || configPath != "config/finger.json" {
				// 如果用户明确指定了非默认路径，报错
				return nil, err
			}
		}
	}

	// 如果没有读取到外部文件，使用内置数据
	if len(byteValue) == 0 {
		if len(defaultFingerprintData) == 0 {
			return nil, fmt.Errorf("内置指纹库为空且未指定有效配置文件")
		}
		byteValue = defaultFingerprintData
	}

	var config models.FingerprintConfig
	err = json.Unmarshal(byteValue, &config)
	if err != nil {
		return nil, fmt.Errorf("解析指纹配置失败: %v", err)
	}

	return &Matcher{
		Rules: config.Fingerprint,
	}, nil
}

// Match 执行指纹匹配
func (m *Matcher) Match(headers map[string]string, body string, title string, faviconHash string) []models.FingerprintInfo {
	var results []models.FingerprintInfo
	
	// 转换 headers 为字符串方便匹配
	var headerStrBuilder strings.Builder
	for k, v := range headers {
		headerStrBuilder.WriteString(fmt.Sprintf("%s: %s\n", k, v))
	}
	headerStr := strings.ToLower(headerStrBuilder.String())
	bodyLower := strings.ToLower(body)
	titleLower := strings.ToLower(title)

	seen := make(map[string]bool)

	for _, rule := range m.Rules {
		matched := false
		keywords := getKeywords(rule.Keyword)

		if rule.Method == "faviconhash" {
			if faviconHash != "" {
				matched = matchFavicon(faviconHash, keywords)
			}
		} else if rule.Method == "keyword" {
			switch rule.Location {
			case "header":
				matched = matchKeywords(headerStr, keywords)
			case "body":
				matched = matchKeywords(bodyLower, keywords)
			case "title":
				matched = matchKeywords(titleLower, keywords)
			}
		}

		if matched {
			key := rule.Cms
			if !seen[key] {
				results = append(results, models.FingerprintInfo{
					Name:   rule.Cms,
					Source: rule.Location,
				})
				seen[key] = true
			}
		}
	}

	// 补充检查常见的 Server 头
	if server, ok := headers["Server"]; ok {
		if !seen["Server"] {
			results = append(results, models.FingerprintInfo{Name: "Server: " + server, Source: "header"})
			seen["Server"] = true
		}
	}

	return results
}

func getKeywords(k interface{}) []string {
	var keywords []string
	switch v := k.(type) {
	case string:
		keywords = append(keywords, strings.ToLower(v))
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				keywords = append(keywords, strings.ToLower(s))
			}
		}
	}
	return keywords
}

func matchKeywords(text string, keywords []string) bool {
	if len(keywords) == 0 {
		return false
	}
	// 默认为 AND 逻辑，所有关键词都必须存在
	for _, k := range keywords {
		if !strings.Contains(text, k) {
			return false
		}
	}
	return true
}

func matchFavicon(hash string, keywords []string) bool {
	for _, k := range keywords {
		if hash == k {
			return true
		}
	}
	return false
}
