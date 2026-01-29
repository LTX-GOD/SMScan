package extractor

import (
	"regexp"
	"strings"

	"github.com/dlclark/regexp2"
	"SMScan/pkg/models"
)

// Extractor 信息提取器
type Extractor struct {
	ipRegex        *regexp.Regexp
	domainRegex    *regexp.Regexp
	urlRegex       *regexp.Regexp
	emailRegex     *regexp.Regexp
	phoneRegex     *regexp.Regexp
	jwtRegex       *regexp.Regexp
	keyRegex       *regexp2.Regexp
	sensitiveRegex *regexp2.Regexp
	apiRegex       *regexp.Regexp
	jsMapRegex     *regexp.Regexp

	// 新增正则
	idCardRegex       *regexp.Regexp        // 身份证
	bankCardRegex     *regexp.Regexp        // 银行卡
	awsKeyRegex       *regexp2.Regexp       // AWS Key
	privateKeyRegex   *regexp.Regexp        // 私钥
	githubTokenRegex  *regexp.Regexp        // GitHub Token
	wechatAppIDRegex  *regexp.Regexp        // 微信 AppID
	alipayKeyRegex    *regexp2.Regexp       // 支付宝
	dbConnRegex       *regexp2.Regexp       // 数据库连接
	internalIPRegex   *regexp.Regexp        // 内网 IP
	commentRegex      *regexp.Regexp        // 注释
	hardcodedCredRegex *regexp2.Regexp      // 硬编码凭证

	// 高级提取器
	webpackExtractor   *WebpackExtractor
	sourceMapExtractor *SourceMapExtractor
	jsExtractor        *JSExtractor
	vueExtractor       *VueExtractor
}

func NewExtractor() *Extractor {
	return &Extractor{
		ipRegex:     regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b`),
		domainRegex: regexp.MustCompile(`\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+\.(?:com|cn|net|org|edu|gov|io|co|xyz|top|vip|club|site|online|app|dev)\b`),
		urlRegex:    regexp.MustCompile(`https?://[^\s"'<>\]\)]+`),
		emailRegex:  regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		phoneRegex:  regexp.MustCompile(`\b1[3-9]\d{9}\b`),
		jwtRegex:    regexp.MustCompile(`eyJ[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+`),

		keyRegex:       regexp2.MustCompile(`(?i)\b(?:api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?key|app[_-]?key|private[_-]?key)\b\s*[:=]\s*["']?([A-Za-z0-9\-_]{16,})["']?`, 0),
		sensitiveRegex: regexp2.MustCompile(`(?i)\b(password|passwd|pwd|username|user_name|token|access_token|id_token|auth_token|refresh_token|bearer)\b\s*[:=]\s*["']?([A-Za-z0-9._\-!@#$%^&*]{4,64})["']?`, 0),

		apiRegex:   regexp.MustCompile(`["']((?:/|\.\.?/)[A-Za-z0-9/_\-\.]+(?:\?[^\s"'<>]*)?)["']`),
		jsMapRegex: regexp.MustCompile(`\b[a-zA-Z0-9_\-\.]+\.js\.map\b`),

		// 新增正则
		idCardRegex:     regexp.MustCompile(`\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`),
		bankCardRegex:   regexp.MustCompile(`\b(?:62|4\d|5[1-5])\d{14,17}\b`),
		awsKeyRegex:     regexp2.MustCompile(`(?i)(AKIA[0-9A-Z]{16})|(?:aws[_-]?(?:access[_-]?key|secret)[_-]?(?:id|key)?)\s*[:=]\s*["']?([A-Za-z0-9/+=]{20,})["']?`, 0),
		privateKeyRegex: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		githubTokenRegex: regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}`),
		wechatAppIDRegex: regexp.MustCompile(`\bwx[a-f0-9]{16}\b`),
		alipayKeyRegex:   regexp2.MustCompile(`(?i)(?:alipay|ali)[_-]?(?:app[_-]?id|private[_-]?key|public[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{16,})["']?`, 0),
		dbConnRegex:      regexp2.MustCompile(`(?i)(?:mysql|postgres|mongodb|redis|oracle|sqlserver|jdbc)://[^\s"'<>]+|(?:host|server)\s*[:=]\s*["']?[^\s"']+["']?\s*[;,]\s*(?:port|database|user|password)`, 0),
		internalIPRegex:  regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`),
		commentRegex:     regexp.MustCompile(`(?://|#|/\*|\*)\s*(TODO|FIXME|HACK|XXX|BUG|NOTE|WARNING|DEBUG|TEMP|PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL|ADMIN|ROOT|BACKDOOR)[:\s]+[^\n\r*/]{5,100}`),
		hardcodedCredRegex: regexp2.MustCompile(`(?i)(?:admin|root|test|demo|guest|default)[_-]?(?:password|passwd|pwd|pass)\s*[:=]\s*["']?([^\s"']{4,32})["']?`, 0),

		// 高级提取器
		webpackExtractor:   NewWebpackExtractor(),
		sourceMapExtractor: NewSourceMapExtractor(),
		jsExtractor:        NewJSExtractor(),
		vueExtractor:       NewVueExtractor(),
	}
}

func (e *Extractor) Extract(body string, baseURL string) models.AssetResult {
	limit := 500

	result := models.AssetResult{
		IPs:           unique(e.ipRegex.FindAllString(body, limit)),
		Domains:       unique(e.domainRegex.FindAllString(body, limit)),
		URLs:          unique(e.cleanURLs(e.urlRegex.FindAllString(body, limit))),
		Emails:        unique(e.emailRegex.FindAllString(body, limit)),
		Phones:        unique(e.phoneRegex.FindAllString(body, limit)),
		JWTs:          unique(e.jwtRegex.FindAllString(body, limit)),
		AbsoluteApis:  []string{},
		RelativeApis:  []string{},
		WebpackChunks: []string{},
		SourceMaps:    []string{},
	}

	// 提取 Keys
	result.Keys = e.extractRegexp2Matches(e.keyRegex, body, limit, 1)

	// 提取 Sensitive
	result.Sensitive = e.extractRegexp2Matches(e.sensitiveRegex, body, limit, 0)

	// 提取 API 路径
	apiMatches := e.apiRegex.FindAllStringSubmatch(body, limit)
	for _, m := range apiMatches {
		if len(m) > 1 {
			path := m[1]
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

	// 新增提取
	result.IDCards = unique(e.idCardRegex.FindAllString(body, limit))
	result.BankCards = unique(e.bankCardRegex.FindAllString(body, limit))
	result.AWSKeys = e.extractRegexp2Matches(e.awsKeyRegex, body, limit, 0)
	result.PrivateKeys = unique(e.privateKeyRegex.FindAllString(body, 10))
	result.GithubTokens = unique(e.githubTokenRegex.FindAllString(body, limit))
	result.WechatAppIDs = unique(e.wechatAppIDRegex.FindAllString(body, limit))
	result.AlipayKeys = e.extractRegexp2Matches(e.alipayKeyRegex, body, limit, 1)
	result.DatabaseConns = e.extractRegexp2Matches(e.dbConnRegex, body, limit, 0)
	result.InternalIPs = unique(e.internalIPRegex.FindAllString(body, limit))
	result.Comments = unique(e.commentRegex.FindAllString(body, limit))
	result.HardcodedCreds = e.extractRegexp2Matches(e.hardcodedCredRegex, body, limit, 0)

	// Webpack Chunks
	result.WebpackChunks = e.webpackExtractor.ExtractChunks(body)

	// Source Maps
	if mapURL := e.sourceMapExtractor.ExtractSourceMapURL(body); mapURL != "" {
		result.SourceMaps = append(result.SourceMaps, mapURL)
	}

	// Advanced JS APIs
	jsAPIs := e.jsExtractor.ExtractAPIs(body)
	for _, api := range jsAPIs {
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
			result.RelativeApis = append(result.RelativeApis, api)
		}
	}

	// 去重
	result.AbsoluteApis = unique(result.AbsoluteApis)
	result.RelativeApis = unique(result.RelativeApis)
	result.URLs = unique(result.URLs)

	return result
}

// ExtractVue 提取 Vue 信息
func (e *Extractor) ExtractVue(body string) *models.VueInfo {
	return e.vueExtractor.Detect(body)
}

// extractRegexp2Matches 辅助函数：提取 regexp2 匹配
func (e *Extractor) extractRegexp2Matches(re *regexp2.Regexp, body string, limit int, groupIdx int) []string {
	var results []string
	if m, err := re.FindStringMatch(body); err == nil && m != nil {
		cur := m
		count := 0
		for cur != nil && count < limit {
			if groupIdx > 0 && len(cur.Groups()) > groupIdx {
				results = append(results, cur.Groups()[groupIdx].String())
			} else {
				results = append(results, cur.String())
			}
			cur, _ = re.FindNextMatch(cur)
			count++
		}
	}
	return unique(results)
}

// cleanURLs 清理 URL 列表，移除尾部无效字符
func (e *Extractor) cleanURLs(urls []string) []string {
	var cleaned []string
	for _, u := range urls {
		// 移除尾部的标点符号
		u = strings.TrimRight(u, ".,;:!?")
		if len(u) > 10 {
			cleaned = append(cleaned, u)
		}
	}
	return cleaned
}

func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func isStaticFile(path string) bool {
	exts := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map"}
	lowerPath := strings.ToLower(path)
	for _, ext := range exts {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	if strings.Contains(lowerPath, "node_modules") ||
	   strings.Contains(lowerPath, "jquery") ||
	   strings.Contains(lowerPath, "bootstrap") ||
	   strings.Contains(lowerPath, "font-awesome") {
		return true
	}
	return false
}
