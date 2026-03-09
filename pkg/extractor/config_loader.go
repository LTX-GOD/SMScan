package extractor

import (
	"encoding/json"
	"os"
	"regexp"
)

// PatternConfig 规则配置
type PatternConfig struct {
	RegexPatterns map[string]string `json:"regex_patterns"`
}

// LoadPatterns 加载敏感信息检测规则
func LoadPatterns(configPath string) (map[string]*regexp.Regexp, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config PatternConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	patterns := make(map[string]*regexp.Regexp)
	for name, pattern := range config.RegexPatterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			patterns[name] = re
		}
	}

	return patterns, nil
}
