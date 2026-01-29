package models

// FingerprintRule 指纹识别规则
type FingerprintRule struct {
	Cms      string      `json:"cms"`
	Method   string      `json:"method"`
	Location string      `json:"location"`
	Keyword  interface{} `json:"keyword"` // 可能是 string 或 []string
}

// FingerprintConfig 指纹配置
type FingerprintConfig struct {
	Fingerprint []FingerprintRule `json:"fingerprint"`
}

// AssetResult 资产提取结果
type AssetResult struct {
	IPs           []string `json:"ips"`
	Domains       []string `json:"domains"`
	URLs          []string `json:"urls"`
	AbsoluteApis  []string `json:"absolute_apis"`
	RelativeApis  []string `json:"relative_apis"`
	Emails        []string `json:"emails"`
	Phones        []string `json:"phones"`
	JWTs          []string `json:"jwts"`
	Keys          []string `json:"keys"`
	Crypto        []string `json:"crypto"`
	Sensitive     []string `json:"sensitive"`
	SourceMaps    []string `json:"source_maps"`
	WebpackChunks []string `json:"webpack_chunks"`

	// 新增：更丰富的资产类型
	IDCards       []string `json:"id_cards,omitempty"`        // 身份证号
	BankCards     []string `json:"bank_cards,omitempty"`      // 银行卡号
	AWSKeys       []string `json:"aws_keys,omitempty"`        // AWS 密钥
	PrivateKeys   []string `json:"private_keys,omitempty"`    // 私钥
	GithubTokens  []string `json:"github_tokens,omitempty"`   // GitHub Token
	WechatAppIDs  []string `json:"wechat_appids,omitempty"`   // 微信 AppID
	AlipayKeys    []string `json:"alipay_keys,omitempty"`     // 支付宝密钥
	DatabaseConns []string `json:"database_conns,omitempty"`  // 数据库连接串
	InternalIPs   []string `json:"internal_ips,omitempty"`    // 内网 IP
	Comments      []string `json:"comments,omitempty"`        // 代码注释
	HardcodedCreds []string `json:"hardcoded_creds,omitempty"` // 硬编码凭证
}

// VueInfo Vue 框架信息
type VueInfo struct {
	Detected   bool     `json:"detected"`
	Version    string   `json:"version,omitempty"`
	Routes     []string `json:"routes,omitempty"`
	Components []string `json:"components,omitempty"`
}

// TechStack 技术栈信息
type TechStack struct {
	Frontend    []string `json:"frontend,omitempty"`
	Backend     []string `json:"backend,omitempty"`
	Server      []string `json:"server,omitempty"`
	Framework   []string `json:"framework,omitempty"`
	CMS         []string `json:"cms,omitempty"`
	CDN         []string `json:"cdn,omitempty"`
	Analytics   []string `json:"analytics,omitempty"`
	JavaScript  []string `json:"javascript,omitempty"`
	CSS         []string `json:"css,omitempty"`
}

// ResponseInfo HTTP 响应详细信息
type ResponseInfo struct {
	ContentType     string            `json:"content_type"`
	ContentLength   int64             `json:"content_length"`
	Headers         map[string]string `json:"headers"`
	Cookies         []*Cookie         `json:"cookies,omitempty"`
	SecurityHeaders *SecurityHeaders  `json:"security_headers,omitempty"`
	CSPInfo         *CSPInfo          `json:"csp_info,omitempty"`
}

// SecurityHeaders 安全响应头
type SecurityHeaders struct {
	XFrameOptions          string `json:"x_frame_options,omitempty"`
	XContentTypeOptions    string `json:"x_content_type_options,omitempty"`
	XSSProtection          string `json:"xss_protection,omitempty"`
	StrictTransportSecurity string `json:"strict_transport_security,omitempty"`
	ContentSecurityPolicy  string `json:"content_security_policy,omitempty"`
	ReferrerPolicy         string `json:"referrer_policy,omitempty"`
	PermissionsPolicy      string `json:"permissions_policy,omitempty"`
	// 安全评分
	Score    int      `json:"score"`
	Missing  []string `json:"missing,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// CSPInfo CSP 策略详情
type CSPInfo struct {
	Raw          string   `json:"raw"`
	DefaultSrc   []string `json:"default_src,omitempty"`
	ScriptSrc    []string `json:"script_src,omitempty"`
	StyleSrc     []string `json:"style_src,omitempty"`
	ImgSrc       []string `json:"img_src,omitempty"`
	ConnectSrc   []string `json:"connect_src,omitempty"`
	FontSrc      []string `json:"font_src,omitempty"`
	FrameSrc     []string `json:"frame_src,omitempty"`
	ReportUri    string   `json:"report_uri,omitempty"`
	UnsafeInline bool     `json:"unsafe_inline"`
	UnsafeEval   bool     `json:"unsafe_eval"`
	Warnings     []string `json:"warnings,omitempty"`
}

// ScanResult 完整的扫描结果
type ScanResult struct {
	URL            string            `json:"url"`
	Status         int               `json:"status"`
	Title          string            `json:"title"`
	Server         string            `json:"server"`
	Fingerprints   []FingerprintInfo `json:"fingerprints"`
	Assets         AssetResult       `json:"assets"`
	Honeypot       HoneypotInfo      `json:"honeypot"`
	NucleiFindings []NucleiResult    `json:"nuclei_findings,omitempty"`

	// 新增字段
	Vue           *VueInfo         `json:"vue,omitempty"`
	TechStack     *TechStack       `json:"tech_stack,omitempty"`
	ResponseInfo  *ResponseInfo    `json:"response_info,omitempty"`
	FuzzResults   []FuzzResult     `json:"fuzz_results,omitempty"`
	RiskLevel     string           `json:"risk_level,omitempty"` // low, medium, high, critical
	RiskScore     int              `json:"risk_score,omitempty"` // 0-100
	ScanTime      string           `json:"scan_time,omitempty"`
	ResponseTime  int64            `json:"response_time_ms,omitempty"`
}

// FingerprintInfo 识别到的指纹信息
type FingerprintInfo struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Source   string `json:"source"`
	Category string `json:"category,omitempty"`
}

// HoneypotInfo 蜜罐识别信息
type HoneypotInfo struct {
	IsHoneypot bool     `json:"is_honeypot"`
	Findings   []string `json:"findings"`
	Confidence int      `json:"confidence,omitempty"` // 0-100
}

// NucleiResult Nuclei 扫描结果摘要
type NucleiResult struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	MatchedAt  string `json:"matched_at"`
}

// FuzzResult Fuzz 扫描结果
type FuzzResult struct {
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Length     int    `json:"length"`
	Words      int    `json:"words,omitempty"`
	Lines      int    `json:"lines,omitempty"`
	Type       string `json:"type"` // path, api, js, param
	Discovered bool   `json:"discovered"`
}

// Cookie 简单的 Cookie 结构
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Expires  string `json:"expires,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HttpOnly bool   `json:"http_only,omitempty"`
	SameSite string `json:"same_site,omitempty"`
}

// ScanConfig 扫描配置
type ScanConfig struct {
	MaxDepth      int      `json:"max_depth"`
	Concurrency   int      `json:"concurrency"`
	Timeout       int      `json:"timeout"`
	UserAgent     string   `json:"user_agent"`
	Proxy         string   `json:"proxy,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Cookies       string   `json:"cookies,omitempty"`
	FollowRedirect bool    `json:"follow_redirect"`
	EnableFuzz    bool     `json:"enable_fuzz"`
	FuzzWordlist  string   `json:"fuzz_wordlist,omitempty"`
	EnableNuclei  bool     `json:"enable_nuclei"`
	NucleiTags    []string `json:"nuclei_tags,omitempty"`
	ExcludeExts   []string `json:"exclude_exts,omitempty"`
}

// ScanStats 扫描统计
type ScanStats struct {
	TotalURLs      int           `json:"total_urls"`
	ScannedURLs    int           `json:"scanned_urls"`
	Fingerprints   int           `json:"fingerprints"`
	Vulnerabilities int          `json:"vulnerabilities"`
	SensitiveData  int           `json:"sensitive_data"`
	Duration       string        `json:"duration"`
	StartTime      string        `json:"start_time"`
	EndTime        string        `json:"end_time"`
	Errors         int           `json:"errors"`
}
