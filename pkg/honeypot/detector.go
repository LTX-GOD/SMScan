package honeypot

import (
	"strings"

	"SMScan/pkg/models"
)

// Detector 蜜罐检测器
type Detector struct{}

// NewDetector 创建新的蜜罐检测器
func NewDetector() *Detector {
	return &Detector{}
}

// Detect 检测蜜罐
func (d *Detector) Detect(headers map[string]string, body string, cookies []*models.Cookie) models.HoneypotInfo {
	var findings []string
	
	// 1. 检查 Headers
	if server, ok := headers["Server"]; ok {
		serverLower := strings.ToLower(server)
		if strings.Contains(serverLower, "hfish") || 
		   strings.Contains(serverLower, "honeypot") || 
		   strings.Contains(serverLower, "opencanary") {
			findings = append(findings, "Server 头异常: "+server)
		}
	}

	// 2. 检查 Cookies (通过 Set-Cookie 头或传入的 cookies)
	// 这里简化处理，检查 headers 中的 Set-Cookie
	if setCookie, ok := headers["Set-Cookie"]; ok {
		setCookieLower := strings.ToLower(setCookie)
		if strings.Contains(setCookieLower, "hfish") || strings.Contains(setCookieLower, "honeypot") {
			findings = append(findings, "Set-Cookie 包含蜜罐特征")
		}
	}

	// 3. 检查 Body 内容 (模拟 XMCVE 的 JS 变量检测)
	// 注意：这里是静态检测，无法检测动态生成的全局变量，只能检测源码中出现的特征字符串
	susVars := []string{
		"HFish", "HoneyPot", "Miao", "sec_headers", "x_client_data",
		"AntSword", "Beebeeto", "Honeyd", "Labrea", "FakeNet",
	}

	for _, v := range susVars {
		// 简单的字符串匹配，模拟 content script 查找 window[v] 或源码特征
		if strings.Contains(body, v) {
			findings = append(findings, "发现疑似蜜罐关键词: "+v)
		}
	}

	if strings.Contains(body, "canvas_fingerprint") {
		findings = append(findings, "发现 Canvas 指纹脚本 (可能为蜜罐)")
	}
	
	if strings.Contains(body, "/scripts/jquery.landray.common.js") {
		// 来自 finger.json 的规则，但这里也可以作为特征
	}

	return models.HoneypotInfo{
		IsHoneypot: len(findings) > 0,
		Findings:   findings,
	}
}
