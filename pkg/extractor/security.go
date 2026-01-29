package extractor

import (
	"strings"

	"SMScan/pkg/models"
)

// SecurityAnalyzer 安全头分析器
type SecurityAnalyzer struct{}

func NewSecurityAnalyzer() *SecurityAnalyzer {
	return &SecurityAnalyzer{}
}

// AnalyzeHeaders 分析响应头安全性
func (sa *SecurityAnalyzer) AnalyzeHeaders(headers map[string]string) *models.SecurityHeaders {
	sh := &models.SecurityHeaders{
		Score: 100,
	}

	// 获取安全头
	sh.XFrameOptions = getHeaderCaseInsensitive(headers, "X-Frame-Options")
	sh.XContentTypeOptions = getHeaderCaseInsensitive(headers, "X-Content-Type-Options")
	sh.XSSProtection = getHeaderCaseInsensitive(headers, "X-XSS-Protection")
	sh.StrictTransportSecurity = getHeaderCaseInsensitive(headers, "Strict-Transport-Security")
	sh.ContentSecurityPolicy = getHeaderCaseInsensitive(headers, "Content-Security-Policy")
	sh.ReferrerPolicy = getHeaderCaseInsensitive(headers, "Referrer-Policy")
	sh.PermissionsPolicy = getHeaderCaseInsensitive(headers, "Permissions-Policy")

	// 评分
	if sh.XFrameOptions == "" {
		sh.Missing = append(sh.Missing, "X-Frame-Options")
		sh.Score -= 15
	}

	if sh.XContentTypeOptions == "" {
		sh.Missing = append(sh.Missing, "X-Content-Type-Options")
		sh.Score -= 10
	} else if !strings.EqualFold(sh.XContentTypeOptions, "nosniff") {
		sh.Warnings = append(sh.Warnings, "X-Content-Type-Options 应设为 nosniff")
		sh.Score -= 5
	}

	if sh.XSSProtection == "" {
		sh.Missing = append(sh.Missing, "X-XSS-Protection")
		sh.Score -= 10
	}

	if sh.StrictTransportSecurity == "" {
		sh.Missing = append(sh.Missing, "Strict-Transport-Security")
		sh.Score -= 20
	}

	if sh.ContentSecurityPolicy == "" {
		sh.Missing = append(sh.Missing, "Content-Security-Policy")
		sh.Score -= 20
	}

	if sh.ReferrerPolicy == "" {
		sh.Missing = append(sh.Missing, "Referrer-Policy")
		sh.Score -= 10
	}

	if sh.PermissionsPolicy == "" {
		sh.Missing = append(sh.Missing, "Permissions-Policy")
		sh.Score -= 5
	}

	// 额外检查
	server := getHeaderCaseInsensitive(headers, "Server")
	if server != "" {
		sh.Warnings = append(sh.Warnings, "Server 头泄露了服务器信息: "+server)
		sh.Score -= 5
	}

	xPoweredBy := getHeaderCaseInsensitive(headers, "X-Powered-By")
	if xPoweredBy != "" {
		sh.Warnings = append(sh.Warnings, "X-Powered-By 泄露了后端技术: "+xPoweredBy)
		sh.Score -= 5
	}

	if sh.Score < 0 {
		sh.Score = 0
	}

	return sh
}

// ParseCSP 解析 CSP 策略
func (sa *SecurityAnalyzer) ParseCSP(cspHeader string) *models.CSPInfo {
	if cspHeader == "" {
		return nil
	}

	info := &models.CSPInfo{
		Raw: cspHeader,
	}

	directives := strings.Split(cspHeader, ";")
	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}

		parts := strings.Fields(directive)
		if len(parts) < 2 {
			continue
		}

		name := strings.ToLower(parts[0])
		values := parts[1:]

		switch name {
		case "default-src":
			info.DefaultSrc = values
		case "script-src":
			info.ScriptSrc = values
		case "style-src":
			info.StyleSrc = values
		case "img-src":
			info.ImgSrc = values
		case "connect-src":
			info.ConnectSrc = values
		case "font-src":
			info.FontSrc = values
		case "frame-src":
			info.FrameSrc = values
		case "report-uri":
			info.ReportUri = strings.Join(values, " ")
		}

		// 检查危险指令
		for _, v := range values {
			v = strings.ToLower(strings.Trim(v, "'\""))
			if v == "unsafe-inline" {
				info.UnsafeInline = true
			}
			if v == "unsafe-eval" {
				info.UnsafeEval = true
			}
		}
	}

	// 生成警告
	if info.UnsafeInline {
		info.Warnings = append(info.Warnings, "CSP 允许 unsafe-inline，可能导致 XSS")
	}
	if info.UnsafeEval {
		info.Warnings = append(info.Warnings, "CSP 允许 unsafe-eval，可能导致代码注入")
	}
	if containsWildcard(info.ScriptSrc) {
		info.Warnings = append(info.Warnings, "script-src 包含通配符 *，CSP 保护无效")
	}
	if containsWildcard(info.DefaultSrc) && len(info.ScriptSrc) == 0 {
		info.Warnings = append(info.Warnings, "default-src 包含通配符且无 script-src，CSP 保护无效")
	}

	return info
}

// AnalyzeResponse 综合分析响应
func (sa *SecurityAnalyzer) AnalyzeResponse(headers map[string]string, cookies []*models.Cookie) *models.ResponseInfo {
	info := &models.ResponseInfo{
		ContentType: getHeaderCaseInsensitive(headers, "Content-Type"),
		Headers:     headers,
	}

	// 安全头分析
	info.SecurityHeaders = sa.AnalyzeHeaders(headers)

	// CSP 分析
	csp := getHeaderCaseInsensitive(headers, "Content-Security-Policy")
	info.CSPInfo = sa.ParseCSP(csp)

	// Cookies
	info.Cookies = cookies

	return info
}

func getHeaderCaseInsensitive(headers map[string]string, key string) string {
	// 直接查找
	if v, ok := headers[key]; ok {
		return v
	}
	// 大小写不敏感查找
	keyLower := strings.ToLower(key)
	for k, v := range headers {
		if strings.ToLower(k) == keyLower {
			return v
		}
	}
	return ""
}

func containsWildcard(sources []string) bool {
	for _, s := range sources {
		if s == "*" {
			return true
		}
	}
	return false
}
