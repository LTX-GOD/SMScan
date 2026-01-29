package extractor

import (
	"regexp"
	"strings"
)

// SourceMapExtractor 负责提取 SourceMap 链接
type SourceMapExtractor struct {
	mapRegex *regexp.Regexp
}

func NewSourceMapExtractor() *SourceMapExtractor {
	return &SourceMapExtractor{
		// 匹配 sourceMappingURL 注释
		mapRegex: regexp.MustCompile(`(?m)^//[#@]\s*sourceMappingURL=(.*)$`),
	}
}

// ExtractSourceMapURL 提取 SourceMap 的 URL
func (s *SourceMapExtractor) ExtractSourceMapURL(body string) string {
	match := s.mapRegex.FindStringSubmatch(body)
	if len(match) > 1 {
		return strings.TrimSpace(match[1])
	}
	return ""
}
