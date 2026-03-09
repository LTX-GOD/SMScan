package extractor

import (
	"regexp"
	"strings"

	"github.com/dlclark/regexp2"
)

// MatchResult 匹配结果（带上下文）
type MatchResult struct {
	Type     string `json:"type"`      // 敏感信息类型
	Value    string `json:"value"`     // 匹配值
	Source   string `json:"source"`    // 来源文件
	Line     int    `json:"line"`      // 行号
	Context  string `json:"context"`   // 上下文（前后各150字符）
	Severity string `json:"severity"`  // 严重程度: critical, high, medium, low
}

// AdvancedScanner 高级扫描器
type AdvancedScanner struct {
	regexPatterns  map[string]*ScanPattern
	regex2Patterns map[string]*ScanPattern2
}

type ScanPattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
}

type ScanPattern2 struct {
	Name     string
	Pattern  *regexp2.Regexp
	Severity string
}

func NewAdvancedScanner() *AdvancedScanner {
	scanner := &AdvancedScanner{
		regexPatterns:  make(map[string]*ScanPattern),
		regex2Patterns: make(map[string]*ScanPattern2),
	}
	scanner.initPatterns()
	return scanner
}

func (s *AdvancedScanner) initPatterns() {
	// Critical 级别
	s.regexPatterns["AWS_AccessKey"] = &ScanPattern{
		Name:     "AWS AccessKey",
		Pattern:  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity: "critical",
	}
	s.regexPatterns["私钥"] = &ScanPattern{
		Name:     "私钥",
		Pattern:  regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		Severity: "critical",
	}
	s.regexPatterns["GitHub_Token"] = &ScanPattern{
		Name:     "GitHub Token",
		Pattern:  regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}`),
		Severity: "critical",
	}

	// High 级别
	s.regexPatterns["JWT"] = &ScanPattern{
		Name:     "JWT Token",
		Pattern:  regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}`),
		Severity: "high",
	}
	s.regexPatterns["数据库连接"] = &ScanPattern{
		Name:     "数据库连接",
		Pattern:  regexp.MustCompile(`(?i)(?:mysql|postgres|mongodb|redis)://[^\s"'<>]+`),
		Severity: "high",
	}

	// Medium 级别
	s.regexPatterns["内网IP"] = &ScanPattern{
		Name:     "内网IP",
		Pattern:  regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
		Severity: "medium",
	}
	s.regexPatterns["身份证"] = &ScanPattern{
		Name:     "身份证号",
		Pattern:  regexp.MustCompile(`\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`),
		Severity: "medium",
	}

	// 使用 regexp2
	s.regex2Patterns["API密钥"] = &ScanPattern2{
		Name:     "API密钥",
		Pattern:  regexp2.MustCompile(`(?i)(?:api[_-]?key|access[_-]?key|secret[_-]?key)['":\s]*[=:]\s*['"]?([A-Za-z0-9\-_]{16,})['"]?`, 0),
		Severity: "high",
	}
	s.regex2Patterns["密码"] = &ScanPattern2{
		Name:     "密码",
		Pattern:  regexp2.MustCompile(`(?i)(?:password|passwd|pwd)['":\s]*[=:]\s*['"]?([^\s"']{4,32})['"]?`, 0),
		Severity: "high",
	}
}

// ScanWithContext 扫描并返回带上下文的结果
func (s *AdvancedScanner) ScanWithContext(content, source string) []MatchResult {
	var results []MatchResult

	// 使用 regexp 扫描
	for _, pattern := range s.regexPatterns {
		matches := pattern.Pattern.FindAllStringIndex(content, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				value := content[match[0]:match[1]]
				line := s.getLineNumber(content, match[0])
				ctx := s.extractContext(content, match[0], match[1])

				results = append(results, MatchResult{
					Type:     pattern.Name,
					Value:    value,
					Source:   source,
					Line:     line,
					Context:  ctx,
					Severity: pattern.Severity,
				})
			}
		}
	}

	// 使用 regexp2 扫描
	for _, pattern := range s.regex2Patterns {
		m, _ := pattern.Pattern.FindStringMatch(content)
		for m != nil {
			value := m.String()
			if len(m.Groups()) > 1 {
				value = m.Groups()[1].String()
			}
			line := s.getLineNumber(content, m.Index)
			ctx := s.extractContext(content, m.Index, m.Index+m.Length)

			results = append(results, MatchResult{
				Type:     pattern.Name,
				Value:    value,
				Source:   source,
				Line:     line,
				Context:  ctx,
				Severity: pattern.Severity,
			})
			m, _ = pattern.Pattern.FindNextMatch(m)
		}
	}

	return results
}

// getLineNumber 获取行号
func (s *AdvancedScanner) getLineNumber(content string, pos int) int {
	return strings.Count(content[:pos], "\n") + 1
}

// extractContext 提取上下文
func (s *AdvancedScanner) extractContext(content string, start, end int) string {
	contextSize := 150
	ctxStart := start - contextSize
	if ctxStart < 0 {
		ctxStart = 0
	}
	ctxEnd := end + contextSize
	if ctxEnd > len(content) {
		ctxEnd = len(content)
	}

	ctx := content[ctxStart:ctxEnd]
	ctx = strings.ReplaceAll(ctx, "\n", " ")
	ctx = strings.ReplaceAll(ctx, "\r", " ")
	return strings.TrimSpace(ctx)
}

// GroupByType 按类型分组
func (s *AdvancedScanner) GroupByType(results []MatchResult) map[string][]MatchResult {
	grouped := make(map[string][]MatchResult)
	for _, result := range results {
		grouped[result.Type] = append(grouped[result.Type], result)
	}
	return grouped
}

// GroupBySeverity 按严重程度分组
func (s *AdvancedScanner) GroupBySeverity(results []MatchResult) map[string][]MatchResult {
	grouped := make(map[string][]MatchResult)
	for _, result := range results {
		grouped[result.Severity] = append(grouped[result.Severity], result)
	}
	return grouped
}
