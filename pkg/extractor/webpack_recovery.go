package extractor

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// WebpackRecovery Webpack 代码拆分还原
type WebpackRecovery struct {
	chunkIDRegex    *regexp.Regexp
	importRegex     *regexp.Regexp
	publicPathRegex *regexp.Regexp
}

func NewWebpackRecovery() *WebpackRecovery {
	return &WebpackRecovery{
		// 匹配 chunk ID 映射: {0:"abc",1:"def"}
		chunkIDRegex: regexp.MustCompile(`\{(?:\s*(?:\d+|"[^"]+")\s*:\s*"[0-9a-fA-F]+"\s*,?\s*)+\}`),
		// 匹配动态 import: import("./chunk")
		importRegex: regexp.MustCompile(`import\s*\(\s*['"]([^'"]+)['"]\s*\)`),
		// 匹配 publicPath
		publicPathRegex: regexp.MustCompile(`(?:__webpack_require__\.p|publicPath)\s*=\s*['"]([^'"]*)['"]`),
	}
}

// RecoverAsyncChunks 还原异步加载的 chunk 文件
func (w *WebpackRecovery) RecoverAsyncChunks(jsCode, baseURL string) []string {
	var chunks []string

	// 1. 提取 publicPath
	publicPath := w.extractPublicPath(jsCode)

	// 2. 提取 chunk ID 映射
	chunkMap := w.extractChunkMap(jsCode)

	// 3. 生成 chunk URL
	for id, hash := range chunkMap {
		chunkURLs := w.buildChunkURLs(id, hash, publicPath, baseURL)
		chunks = append(chunks, chunkURLs...)
	}

	// 4. 提取动态 import 路径
	importPaths := w.extractDynamicImports(jsCode)
	for _, path := range importPaths {
		fullURL := w.buildFullURL(path, baseURL)
		if fullURL != "" {
			chunks = append(chunks, fullURL)
		}
	}

	return uniqueStrings(chunks)
}

// extractPublicPath 提取 publicPath
func (w *WebpackRecovery) extractPublicPath(jsCode string) string {
	matches := w.publicPathRegex.FindStringSubmatch(jsCode)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractChunkMap 提取 chunk ID 到 hash 的映射
func (w *WebpackRecovery) extractChunkMap(jsCode string) map[string]string {
	chunkMap := make(map[string]string)

	matches := w.chunkIDRegex.FindAllString(jsCode, -1)
	for _, match := range matches {
		// 解析 {id:"hash"} 格式
		pairRe := regexp.MustCompile(`(\d+|"[^"]+"):\s*"([0-9a-fA-F]+)"`)
		pairs := pairRe.FindAllStringSubmatch(match, -1)

		for _, pair := range pairs {
			if len(pair) >= 3 {
				id := strings.Trim(pair[1], `"`)
				hash := pair[2]
				chunkMap[id] = hash
			}
		}
	}

	return chunkMap
}

// extractDynamicImports 提取动态 import 路径
func (w *WebpackRecovery) extractDynamicImports(jsCode string) []string {
	var paths []string

	matches := w.importRegex.FindAllStringSubmatch(jsCode, -1)
	for _, match := range matches {
		if len(match) > 1 {
			paths = append(paths, match[1])
		}
	}

	return paths
}

// buildChunkURLs 构建 chunk 文件的可能 URL
func (w *WebpackRecovery) buildChunkURLs(id, hash, publicPath, baseURL string) []string {
	var urls []string

	// 常见的 chunk 文件名格式
	patterns := []string{
		fmt.Sprintf("%s.%s.js", id, hash),
		fmt.Sprintf("%s.js", hash),
		fmt.Sprintf("chunk.%s.js", hash),
		fmt.Sprintf("%s.chunk.js", id),
	}

	for _, pattern := range patterns {
		// 使用 publicPath
		if publicPath != "" {
			fullPath := publicPath
			if !strings.HasSuffix(fullPath, "/") {
				fullPath += "/"
			}
			fullPath += pattern
			urls = append(urls, w.buildFullURL(fullPath, baseURL))
		}

		// 尝试常见路径
		commonPaths := []string{
			pattern,
			"js/" + pattern,
			"static/js/" + pattern,
			"assets/js/" + pattern,
			"dist/js/" + pattern,
		}

		for _, path := range commonPaths {
			fullURL := w.buildFullURL(path, baseURL)
			if fullURL != "" {
				urls = append(urls, fullURL)
			}
		}
	}

	return urls
}

// buildFullURL 构建完整 URL
func (w *WebpackRecovery) buildFullURL(path, baseURL string) string {
	// 如果已经是完整 URL
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	// 绝对路径
	if strings.HasPrefix(path, "/") {
		return fmt.Sprintf("%s://%s%s", base.Scheme, base.Host, path)
	}

	// 相对路径 - 处理路径重叠
	basePath := base.Path
	if !strings.HasSuffix(basePath, "/") {
		// 移除文件名，保留目录
		lastSlash := strings.LastIndex(basePath, "/")
		if lastSlash >= 0 {
			basePath = basePath[:lastSlash+1]
		}
	}

	// 检测路径重叠
	pathSegments := strings.Split(strings.Trim(path, "/"), "/")
	baseSegments := strings.Split(strings.Trim(basePath, "/"), "/")

	// 从后向前查找最大重叠
	overlapLen := 0
	for i := 1; i <= len(baseSegments) && i <= len(pathSegments); i++ {
		if strings.Join(baseSegments[len(baseSegments)-i:], "/") == strings.Join(pathSegments[:i], "/") {
			overlapLen = i
		}
	}

	// 构建最终路径
	finalSegments := append(baseSegments, pathSegments[overlapLen:]...)
	finalPath := "/" + strings.Join(finalSegments, "/")

	return fmt.Sprintf("%s://%s%s", base.Scheme, base.Host, finalPath)
}

// ExtractWebpackInfo 提取 Webpack 相关信息
func (w *WebpackRecovery) ExtractWebpackInfo(jsCode string) map[string]interface{} {
	info := make(map[string]interface{})

	// 检测 Webpack 版本
	versionRe := regexp.MustCompile(`webpack[/\s]+v?(\d+\.\d+\.\d+)`)
	if match := versionRe.FindStringSubmatch(jsCode); len(match) > 1 {
		info["version"] = match[1]
	}

	// 检测模块数量
	moduleRe := regexp.MustCompile(`\bmodules\s*:\s*\{`)
	if moduleRe.MatchString(jsCode) {
		info["has_modules"] = true
	}

	// 检测代码拆分
	if strings.Contains(jsCode, "__webpack_require__.e") || strings.Contains(jsCode, "import(") {
		info["code_splitting"] = true
	}

	// 提取 publicPath
	publicPath := w.extractPublicPath(jsCode)
	if publicPath != "" {
		info["public_path"] = publicPath
	}

	// 统计 chunk 数量
	chunkMap := w.extractChunkMap(jsCode)
	if len(chunkMap) > 0 {
		info["chunk_count"] = len(chunkMap)
	}

	return info
}
