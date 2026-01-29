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
	IPs          []string `json:"ips"`
	Domains      []string `json:"domains"`
	URLs         []string `json:"urls"`
	AbsoluteApis []string `json:"absolute_apis"`
	RelativeApis []string `json:"relative_apis"`
	Emails       []string `json:"emails"`
	Phones       []string `json:"phones"`
	JWTs         []string `json:"jwts"`
	Keys         []string `json:"keys"`
	Crypto       []string `json:"crypto"`
	Sensitive    []string `json:"sensitive"`
	SourceMaps   []string `json:"source_maps"`
	WebpackChunks []string `json:"webpack_chunks"`
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
}

// FingerprintInfo 识别到的指纹信息
type FingerprintInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"`
}

// HoneypotInfo 蜜罐识别信息
type HoneypotInfo struct {
	IsHoneypot bool     `json:"is_honeypot"`
	Findings   []string `json:"findings"`
}

// NucleiResult Nuclei 扫描结果摘要
type NucleiResult struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	MatchedAt  string `json:"matched_at"`
}

// Cookie 简单的 Cookie 结构
type Cookie struct {
	Name  string
	Value string
}
