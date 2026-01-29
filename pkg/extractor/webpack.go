package extractor

import (
	"regexp"
	"strings"
)

// WebpackExtractor 负责提取 Webpack 打包的 Chunk 信息
type WebpackExtractor struct {
	// 匹配 chunk 映射表，例如: {0:"e12a",1:"f34b"}
	// 这是一个比较宽泛的正则，需要在代码中进一步验证
	chunkMapRegex *regexp.Regexp
	// 匹配 publicPath，例如: __webpack_require__.p = "/"
	publicPathRegex *regexp.Regexp
}

func NewWebpackExtractor() *WebpackExtractor {
	return &WebpackExtractor{
		// 匹配类似: {0:"abcd",1:"efgh"} 或者 {"app":"abcd"}
		// 注意：这只是一个启发式正则，可能会有误报，需要后续过滤
		chunkMapRegex: regexp.MustCompile(`\{(?:\s*(?:\d+|"[^"]+")\s*:\s*"[0-9a-fA-F]{4,}"\s*,?)+\}`),
		
		// 匹配 publicPath 赋值
		publicPathRegex: regexp.MustCompile(`(?:__webpack_require__\.p|p)\s*=\s*["']([^"']*)["']`),
	}
}

// ExtractChunks 从 JS 代码中提取潜在的 Chunk 文件名
func (w *WebpackExtractor) ExtractChunks(body string) []string {
	var chunks []string
	
	// 0. 尝试提取 publicPath
	publicPath := ""
	if match := w.publicPathRegex.FindStringSubmatch(body); len(match) > 1 {
		publicPath = match[1]
	}

	// 1. 尝试查找 chunk 映射表
	matches := w.chunkMapRegex.FindAllString(body, 5) // 限制匹配数量，通常只有一个主要的映射表
	
	for _, match := range matches {
		// 简单的清理
		cleanMatch := strings.ReplaceAll(match, " ", "")
		cleanMatch = strings.ReplaceAll(cleanMatch, "\n", "")
		
		// 解析 key:value
		// 假设格式为 {key:"value",...}
		// 我们主要关心 value (hash) 和 key (id)
		
		// 提取所有的 value (hash)
		// 格式: :"value"
		re := regexp.MustCompile(`:"([0-9a-fA-F]+)"`)
		hashMatches := re.FindAllStringSubmatch(cleanMatch, -1)
		
		// 提取所有的 key (id)
		// 格式: {key: or ,key:
		keyRe := regexp.MustCompile(`(?:\{|,)(\d+|"[^"]+"):`)
		keyMatches := keyRe.FindAllStringSubmatch(cleanMatch, -1)

		if len(hashMatches) > 0 && len(keyMatches) == len(hashMatches) {
			for i, hashM := range hashMatches {
				if i < len(keyMatches) {
					id := strings.Trim(keyMatches[i][1], `"`)
					hash := hashM[1]
					
					// 构造可能的 chunk 文件名
					// 常见格式: id.hash.js, hash.js, id.js
					// 如果有 publicPath，则加上前缀
					
					filename := id + "." + hash + ".js"
					
					if publicPath != "" {
						// 简单的路径拼接
						if strings.HasSuffix(publicPath, "/") {
							chunks = append(chunks, publicPath+filename)
						} else {
							chunks = append(chunks, publicPath+"/"+filename)
						}
					} else {
						// 如果没有 publicPath，我们生成相对路径
						chunks = append(chunks, filename)
						// 也可以尝试加一个 js/ 前缀的变体，因为很多项目都在 static/js/ 下
						chunks = append(chunks, "js/"+filename)
						chunks = append(chunks, "static/js/"+filename)
					}
				}
			}
		}
	}
	
	return unique(chunks)
}
