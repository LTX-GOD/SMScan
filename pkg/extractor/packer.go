package extractor

import (
	"regexp"
	"strings"
)

// PackerDetector 打包器检测器
type PackerDetector struct {
	htmlPatterns map[string]*regexp.Regexp
	jsPatterns   map[string]*regexp.Regexp
}

// PackerInfo 打包器信息
type PackerInfo struct {
	Detected bool     `json:"detected"`
	Type     string   `json:"type,omitempty"`     // webpack, vite, rollup, parcel, etc.
	Features []string `json:"features,omitempty"` // 检测到的特征
}

func NewPackerDetector() *PackerDetector {
	return &PackerDetector{
		htmlPatterns: map[string]*regexp.Regexp{
			"webpack":    regexp.MustCompile(`(?i)webpack|__webpack_require__|webpackJsonp`),
			"next.js":    regexp.MustCompile(`<script id="__NEXT_DATA__"`),
			"gatsby":     regexp.MustCompile(`(?i)<meta name="generator" content="Gatsby|<div id="___gatsby|<style id="gatsby-inlined-css"`),
			"vite":       regexp.MustCompile(`(?i)type="module".*?vite|/@vite/`),
			"nuxt":       regexp.MustCompile(`(?i)__NUXT__|window\.__NUXT__`),
			"parcel":     regexp.MustCompile(`(?i)parcel-bundler`),
			"rollup":     regexp.MustCompile(`(?i)rollup`),
			"phoenix":    regexp.MustCompile(`<meta name="generator" content="phoenix"`),
			"docusaurus": regexp.MustCompile(`<meta name="generator" content="Docusaurus"`),
		},
		jsPatterns: map[string]*regexp.Regexp{
			"webpack":    regexp.MustCompile(`(?i)webpackJsonp|__webpack_require__|webpack_modules`),
			"vite":       regexp.MustCompile(`(?i)import\.meta\.hot|/@vite/client`),
			"rollup":     regexp.MustCompile(`(?i)rollup`),
			"parcel":     regexp.MustCompile(`(?i)parcelRequire`),
			"esbuild":    regexp.MustCompile(`(?i)__toESM|__commonJS`),
			"gulp":       regexp.MustCompile(`(?i)gulp`),
			"grunt":      regexp.MustCompile(`(?i)grunt`),
		},
	}
}

// DetectFromHTML 从 HTML 检测打包器
func (p *PackerDetector) DetectFromHTML(html string) PackerInfo {
	info := PackerInfo{Detected: false}

	for name, pattern := range p.htmlPatterns {
		if pattern.MatchString(html) {
			info.Detected = true
			info.Type = name
			info.Features = append(info.Features, "HTML:"+name)
		}
	}

	return info
}

// DetectFromJS 从 JS 代码检测打包器
func (p *PackerDetector) DetectFromJS(jsCode string) PackerInfo {
	info := PackerInfo{Detected: false}

	for name, pattern := range p.jsPatterns {
		if pattern.MatchString(jsCode) {
			info.Detected = true
			if info.Type == "" {
				info.Type = name
			}
			info.Features = append(info.Features, "JS:"+name)
		}
	}

	return info
}

// Detect 综合检测
func (p *PackerDetector) Detect(html, jsCode string) PackerInfo {
	htmlInfo := p.DetectFromHTML(html)
	jsInfo := p.DetectFromJS(jsCode)

	if !htmlInfo.Detected && !jsInfo.Detected {
		return PackerInfo{Detected: false}
	}

	// 合并结果
	result := PackerInfo{Detected: true}

	if htmlInfo.Type != "" {
		result.Type = htmlInfo.Type
	} else if jsInfo.Type != "" {
		result.Type = jsInfo.Type
	}

	result.Features = append(result.Features, htmlInfo.Features...)
	result.Features = append(result.Features, jsInfo.Features...)

	return result
}

// ExtractWebpackChunkIDs 提取 Webpack chunk ID 映射
func (p *PackerDetector) ExtractWebpackChunkIDs(jsCode string) map[string]string {
	chunkMap := make(map[string]string)

	// 匹配 chunk 映射表: {0:"abc",1:"def"}
	re := regexp.MustCompile(`\{(?:\s*(?:\d+|"[^"]+")\s*:\s*"[0-9a-fA-F]+"\s*,?\s*)+\}`)
	matches := re.FindAllString(jsCode, -1)

	for _, match := range matches {
		// 提取 key:value 对
		pairRe := regexp.MustCompile(`(\d+|"[^"]+"):\s*"([0-9a-fA-F]+)"`)
		pairs := pairRe.FindAllStringSubmatch(match, -1)

		for _, pair := range pairs {
			if len(pair) >= 3 {
				key := strings.Trim(pair[1], `"`)
				value := pair[2]
				chunkMap[key] = value
			}
		}
	}

	return chunkMap
}
