package extractor

import (
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/dlclark/regexp2"
)

// SensitiveDetector 敏感信息检测器
type SensitiveDetector struct {
	patterns map[string]*regexp.Regexp
	patterns2 map[string]*regexp2.Regexp
}

func NewSensitiveDetector() *SensitiveDetector {
	return &SensitiveDetector{
		patterns: map[string]*regexp.Regexp{
			// 云服务密钥
			"阿里云OSS": regexp.MustCompile(`(?i)[a-zA-Z0-9-]+\.oss[-\w]*\.aliyuncs\.com`),
			"腾讯云COS": regexp.MustCompile(`(?i)[a-zA-Z0-9-]+\.cos\.[a-z-]+\.myqcloud\.com`),
			"AWS S3": regexp.MustCompile(`(?i)[a-zA-Z0-9-]+\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com`),

			// Token 类型
			"JWT": regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.?[A-Za-z0-9-_.+/=]*`),
			"GitHub Token": regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}`),
			"GitLab Token": regexp.MustCompile(`glpat-[0-9A-Za-z_-]{20,}`),
			"Google API Key": regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
			"Slack Token": regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z-]{10,}`),
			"Stripe Key": regexp.MustCompile(`(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{20,}`),
			"Mailgun Key": regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
			"Twilio Key": regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
			"SendGrid Key": regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`),

			// 微信/支付宝
			"微信AppID": regexp.MustCompile(`\bwx[a-f0-9]{16}\b`),

			// 私钥
			"私钥": regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),

			// 个人信息
			"身份证": regexp.MustCompile(`\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`),
			"手机号": regexp.MustCompile(`(?<!\d)(?:\+86|0086)?1[3-9]\d{9}(?!\d)`),
			"邮箱": regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),

			// 内网IP
			"内网IP": regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`),
		},
		patterns2: map[string]*regexp2.Regexp{
			// AWS 密钥
			"AWS AccessKey": regexp2.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`, 0),
			"AWS SecretKey": regexp2.MustCompile(`(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key['":\s]*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`, 0),

			// 阿里云/支付宝
			"阿里云AccessKey": regexp2.MustCompile(`(?i)(?:aliyun|ali)[_-]?(?:access[_-]?key|app[_-]?id)['":\s]*[=:]\s*['"]?([A-Za-z0-9]{16,})['"]?`, 0),
			"支付宝密钥": regexp2.MustCompile(`(?i)alipay[_-]?(?:app[_-]?id|private[_-]?key)['":\s]*[=:]\s*['"]?([A-Za-z0-9]{16,})['"]?`, 0),

			// 数据库连接
			"数据库连接": regexp2.MustCompile(`(?i)(?:mysql|postgres|mongodb|redis|oracle|sqlserver|jdbc)://[^\s"'<>]+`, 0),

			// 通用密钥
			"API密钥": regexp2.MustCompile(`(?i)\b(?:api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?key|app[_-]?key)['":\s]*[=:]\s*['"]?([A-Za-z0-9\-_]{16,})['"]?`, 0),

			// 密码
			"密码": regexp2.MustCompile(`(?i)(?:password|passwd|pwd)['":\s]*[=:]\s*['"]?([A-Za-z0-9._\-!@#$%^&*]{4,32})['"]?`, 0),

			// 硬编码凭证
			"硬编码凭证": regexp2.MustCompile(`(?i)(?:admin|root|test|demo)[_-]?(?:password|passwd|pwd)['":\s]*[=:]\s*['"]?([^\s"']{4,32})['"]?`, 0),

			// 敏感配置
			"敏感配置": regexp2.MustCompile(`(?i)(?:secret|token|auth|credential|private)['":\s]*[=:]\s*['"]?([A-Za-z0-9\-_]{8,})['"]?`, 0),
		},
	}
}

// DetectSensitive 检测敏感信息
func (s *SensitiveDetector) DetectSensitive(content string) map[string][]string {
	results := make(map[string][]string)

	// 使用 regexp 检测
	for name, pattern := range s.patterns {
		matches := pattern.FindAllString(content, -1)
		if len(matches) > 0 {
			results[name] = uniqueStrings(matches)
		}
	}

	// 使用 regexp2 检测
	for name, pattern := range s.patterns2 {
		var matches []string
		m, _ := pattern.FindStringMatch(content)
		for m != nil {
			if len(m.Groups()) > 1 {
				matches = append(matches, m.Groups()[1].String())
			} else {
				matches = append(matches, m.String())
			}
			m, _ = pattern.FindNextMatch(m)
		}
		if len(matches) > 0 {
			results[name] = uniqueStrings(matches)
		}
	}

	return results
}

// DetectBase64Secrets 检测 Base64 编码的敏感信息
func (s *SensitiveDetector) DetectBase64Secrets(content string) []string {
	var secrets []string

	// 匹配可能的 Base64 字符串
	re := regexp.MustCompile(`['"]([A-Za-z0-9+/]{40,}={0,2})['"]`)
	matches := re.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			encoded := match[1]
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err == nil {
				decodedStr := string(decoded)
				// 检查解码后是否包含敏感关键词
				if containsSensitiveKeywords(decodedStr) {
					secrets = append(secrets, encoded+" -> "+decodedStr)
				}
			}
		}
	}

	return secrets
}

// containsSensitiveKeywords 检查是否包含敏感关键词
func containsSensitiveKeywords(s string) bool {
	keywords := []string{
		"password", "passwd", "pwd", "secret", "token", "key",
		"api", "auth", "credential", "private", "admin", "root",
	}

	lower := strings.ToLower(s)
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// uniqueStrings 去重
func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}
