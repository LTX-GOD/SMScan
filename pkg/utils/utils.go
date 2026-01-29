package utils

import (
	"net/url"
	"regexp"
)

// GetURLPattern 获取 URL 模式 (将数字 query value 替换为 ~)
func GetURLPattern(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	
	q := u.Query()
	if len(q) == 0 {
		return rawURL
	}

	// 替换数字值为 ~
	numericRegex := regexp.MustCompile(`^\d+$`)
	for k, v := range q {
		if len(v) > 0 && numericRegex.MatchString(v[0]) {
			q.Set(k, "~")
		}
	}
	
	// 重建 URL
	u.RawQuery = q.Encode()
	// 为了保持顺序一致性 (Encode 默认会排序 keys)，我们直接使用 encoded query
	// 但我们需要解码 ~ 回来，因为 encode 会把 ~ 转义
	decoded, _ := url.QueryUnescape(u.String())
	return decoded
}
