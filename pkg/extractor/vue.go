package extractor

import (
	"regexp"
	"strings"

	"SMScan/pkg/models"
)

// VueExtractor Vue 框架检测器
type VueExtractor struct {
	// Vue 特征检测
	vueGlobalRegex   *regexp.Regexp
	vueVersionRegex  *regexp.Regexp
	vueRouterRegex   *regexp.Regexp
	vueComponentRegex *regexp.Regexp

	// Vue 路由提取
	routePathRegex   *regexp.Regexp
	routeNameRegex   *regexp.Regexp
}

func NewVueExtractor() *VueExtractor {
	return &VueExtractor{
		// Vue 存在检测
		vueGlobalRegex:   regexp.MustCompile(`(?i)(?:Vue\.(?:use|component|mixin|directive)|new\s+Vue\s*\(|createApp\s*\(|__vue__|__VUE__|vue-devtools)`),
		vueVersionRegex:  regexp.MustCompile(`(?i)vue[/@]?(\d+\.\d+(?:\.\d+)?)|"vue":\s*"[~^]?(\d+\.\d+(?:\.\d+)?)`),
		vueRouterRegex:   regexp.MustCompile(`(?i)VueRouter|vue-router|createRouter|useRouter`),
		vueComponentRegex: regexp.MustCompile(`(?i)Vue\.component\s*\(\s*["']([^"']+)["']|components:\s*\{([^}]+)\}`),

		// 路由提取
		routePathRegex:   regexp.MustCompile(`(?i)path\s*:\s*["']([^"']+)["']`),
		routeNameRegex:   regexp.MustCompile(`(?i)name\s*:\s*["']([^"']+)["']`),
	}
}

// Detect 检测 Vue 框架
func (v *VueExtractor) Detect(body string) *models.VueInfo {
	info := &models.VueInfo{
		Detected: false,
	}

	// 检测 Vue 存在
	if !v.vueGlobalRegex.MatchString(body) {
		// 额外检查常见 Vue 特征
		vueSignatures := []string{
			"v-model", "v-if", "v-for", "v-show", "v-bind", "v-on",
			"$mount", "$emit", "$refs", "$store", "$router",
			"data-v-", "__NUXT__", "vue-router", "vuex",
		}
		found := false
		for _, sig := range vueSignatures {
			if strings.Contains(body, sig) {
				found = true
				break
			}
		}
		if !found {
			return info
		}
	}

	info.Detected = true

	// 提取版本
	if matches := v.vueVersionRegex.FindStringSubmatch(body); len(matches) > 1 {
		for _, m := range matches[1:] {
			if m != "" {
				info.Version = m
				break
			}
		}
	}

	// 如果没找到版本，尝试推断
	if info.Version == "" {
		if strings.Contains(body, "createApp") || strings.Contains(body, "createRouter") {
			info.Version = "3.x"
		} else if strings.Contains(body, "new Vue") || strings.Contains(body, "Vue.use") {
			info.Version = "2.x"
		}
	}

	// 提取路由
	routes := make(map[string]bool)
	pathMatches := v.routePathRegex.FindAllStringSubmatch(body, 100)
	for _, m := range pathMatches {
		if len(m) > 1 {
			path := m[1]
			// 过滤掉动态参数标记但保留路径结构
			if strings.Contains(path, ":") || strings.Contains(path, "*") {
				// 保留带参数的路由，但做标记
				path = strings.TrimPrefix(path, "/")
				if path != "" && !routes[path] {
					routes[path] = true
				}
			} else if path != "" && path != "/" {
				routes[path] = true
			}
		}
	}

	for route := range routes {
		info.Routes = append(info.Routes, route)
	}

	// 提取组件
	components := make(map[string]bool)
	compMatches := v.vueComponentRegex.FindAllStringSubmatch(body, 100)
	for _, m := range compMatches {
		if len(m) > 1 && m[1] != "" {
			components[m[1]] = true
		}
		if len(m) > 2 && m[2] != "" {
			// 解析 components: { ... } 中的组件名
			parts := strings.Split(m[2], ",")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if idx := strings.Index(p, ":"); idx > 0 {
					p = strings.TrimSpace(p[:idx])
				}
				if p != "" && !strings.HasPrefix(p, "//") {
					components[p] = true
				}
			}
		}
	}

	for comp := range components {
		info.Components = append(info.Components, comp)
	}

	return info
}

// ExtractVueRoutes 从 JS 代码中提取 Vue 路由配置
func (v *VueExtractor) ExtractVueRoutes(body string) []string {
	var routes []string
	seen := make(map[string]bool)

	// 匹配常见的路由配置模式
	patterns := []*regexp.Regexp{
		// routes: [{ path: '...' }]
		regexp.MustCompile(`(?i)routes\s*:\s*\[\s*\{[^}]*path\s*:\s*["']([^"']+)["']`),
		// { path: '/xxx', component: ... }
		regexp.MustCompile(`(?i)\{\s*path\s*:\s*["']([^"']+)["'][^}]*component`),
		// router.addRoute({ path: '...' })
		regexp.MustCompile(`(?i)(?:addRoute|addRoutes)\s*\(\s*\{[^}]*path\s*:\s*["']([^"']+)["']`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(body, 50)
		for _, m := range matches {
			if len(m) > 1 {
				path := m[1]
				if !seen[path] {
					seen[path] = true
					routes = append(routes, path)
				}
			}
		}
	}

	return routes
}
