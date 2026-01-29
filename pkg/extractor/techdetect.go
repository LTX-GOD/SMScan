package extractor

import (
	"regexp"
	"strings"

	"SMScan/pkg/models"
)

// TechDetector 技术栈检测器
type TechDetector struct {
	patterns map[string]*techPattern
}

type techPattern struct {
	Category string
	Name     string
	Patterns []*regexp.Regexp
	Headers  map[string]string // header key -> value pattern
}

// NewTechDetector 创建技术栈检测器
func NewTechDetector() *TechDetector {
	td := &TechDetector{
		patterns: make(map[string]*techPattern),
	}
	td.init()
	return td
}

func (td *TechDetector) init() {
	// 前端框架
	td.addBodyPattern("frontend", "Vue.js", `(?i)__vue__|vue\.(?:use|component)|v-(?:model|if|for|show|bind|on)|createApp|__NUXT__`)
	td.addBodyPattern("frontend", "React", `(?i)react\.(?:createElement|Component)|__REACT|_reactRootContainer|__next|data-reactroot|data-reactid`)
	td.addBodyPattern("frontend", "Angular", `(?i)ng-(?:app|controller|model|repeat|if|show|class)|angular\.(?:module|element)|__ng_|ng-version`)
	td.addBodyPattern("frontend", "Svelte", `(?i)__svelte|svelte-\w+`)
	td.addBodyPattern("frontend", "Next.js", `(?i)__NEXT_DATA__|_next/static|next/dist`)
	td.addBodyPattern("frontend", "Nuxt.js", `(?i)__NUXT__|_nuxt/|window\.__NUXT__`)

	// UI 框架
	td.addBodyPattern("css", "Element UI", `(?i)el-(?:button|input|table|form|dialog|select|menu)|element-ui|element-plus`)
	td.addBodyPattern("css", "Ant Design", `(?i)ant-(?:btn|input|table|form|modal|select|menu)|antd`)
	td.addBodyPattern("css", "Bootstrap", `(?i)bootstrap\.(?:min\.)?(?:css|js)|class="(?:container|row|col-|btn-|navbar)`)
	td.addBodyPattern("css", "Tailwind CSS", `(?i)tailwindcss|class="(?:flex|grid|p-|m-|text-|bg-|w-|h-)`)
	td.addBodyPattern("css", "LayUI", `(?i)layui\.(?:css|js)|layui-`)
	td.addBodyPattern("css", "iView", `(?i)iview|view-design`)

	// JavaScript 库
	td.addBodyPattern("javascript", "jQuery", `(?i)jquery[.-]?\d|jQuery\.fn\.jquery|jquery\.min\.js`)
	td.addBodyPattern("javascript", "Axios", `(?i)axios\.(?:get|post|put|delete|create)|__AXIOS__`)
	td.addBodyPattern("javascript", "Lodash", `(?i)lodash|_\.(?:map|filter|reduce|each|forEach)`)
	td.addBodyPattern("javascript", "Moment.js", `(?i)moment\.(?:js|min\.js)|moment\(\)\.format`)
	td.addBodyPattern("javascript", "ECharts", `(?i)echarts\.(?:init|min\.js)|echartsInstance`)
	td.addBodyPattern("javascript", "D3.js", `(?i)d3\.(?:select|scale|axis|svg)`)
	td.addBodyPattern("javascript", "Three.js", `(?i)THREE\.(?:Scene|Camera|Renderer|Mesh)`)

	// 后端框架 (通过响应特征推断)
	td.addHeaderPattern("backend", "Express.js", "X-Powered-By", `Express`)
	td.addHeaderPattern("backend", "PHP", "X-Powered-By", `(?i)PHP`)
	td.addHeaderPattern("backend", "ASP.NET", "X-Powered-By", `(?i)ASP\.NET`)
	td.addHeaderPattern("backend", "Django", "X-Frame-Options", `DENY`) // 加上 body 检测
	td.addBodyPattern("backend", "Django", `(?i)csrfmiddlewaretoken|__admin__|django`)
	td.addBodyPattern("backend", "Spring", `(?i)spring-security|JSESSIONID|spring\.`)
	td.addBodyPattern("backend", "Laravel", `(?i)laravel_session|XSRF-TOKEN.*laravel`)
	td.addBodyPattern("backend", "Flask", `(?i)flask|werkzeug`)
	td.addBodyPattern("backend", "Gin", `(?i)gin-gonic`)
	td.addBodyPattern("backend", "ThinkPHP", `(?i)thinkphp|think_template`)

	// 服务器
	td.addHeaderPattern("server", "Nginx", "Server", `(?i)nginx`)
	td.addHeaderPattern("server", "Apache", "Server", `(?i)Apache`)
	td.addHeaderPattern("server", "IIS", "Server", `(?i)Microsoft-IIS`)
	td.addHeaderPattern("server", "Tomcat", "Server", `(?i)Apache-Coyote|Tomcat`)
	td.addHeaderPattern("server", "Caddy", "Server", `(?i)Caddy`)
	td.addHeaderPattern("server", "OpenResty", "Server", `(?i)openresty`)
	td.addHeaderPattern("server", "Tengine", "Server", `(?i)Tengine`)

	// CDN
	td.addHeaderPattern("cdn", "Cloudflare", "Server", `(?i)cloudflare`)
	td.addHeaderPattern("cdn", "Cloudflare", "CF-RAY", `.+`)
	td.addHeaderPattern("cdn", "Akamai", "Server", `(?i)AkamaiGHost`)
	td.addHeaderPattern("cdn", "Fastly", "X-Served-By", `(?i)cache-`)
	td.addHeaderPattern("cdn", "CloudFront", "Via", `(?i)cloudfront`)
	td.addHeaderPattern("cdn", "阿里云CDN", "Via", `(?i)Ali/`)
	td.addHeaderPattern("cdn", "腾讯云CDN", "X-NWS-LOG-UUID", `.+`)
	td.addHeaderPattern("cdn", "百度云加速", "Server", `(?i)yunjiasu`)

	// 分析/追踪
	td.addBodyPattern("analytics", "Google Analytics", `(?i)google-analytics\.com|gtag|GoogleAnalyticsObject|_gaq`)
	td.addBodyPattern("analytics", "百度统计", `(?i)hm\.baidu\.com|_hmt\.push`)
	td.addBodyPattern("analytics", "CNZZ", `(?i)cnzz\.com|_czc\.push`)
	td.addBodyPattern("analytics", "51.la", `(?i)51\.la`)
	td.addBodyPattern("analytics", "Hotjar", `(?i)hotjar\.com|hj\('`)
	td.addBodyPattern("analytics", "友盟", `(?i)umeng\.com`)

	// 构建工具
	td.addBodyPattern("frontend", "Webpack", `(?i)__webpack_require__|webpackJsonp|webpack_modules`)
	td.addBodyPattern("frontend", "Vite", `(?i)/@vite/client|__vite_|import\.meta\.hot`)
	td.addBodyPattern("frontend", "Parcel", `(?i)parcelRequire`)
}

func (td *TechDetector) addBodyPattern(category, name, pattern string) {
	key := category + ":" + name
	if existing, ok := td.patterns[key]; ok {
		existing.Patterns = append(existing.Patterns, regexp.MustCompile(pattern))
	} else {
		td.patterns[key] = &techPattern{
			Category: category,
			Name:     name,
			Patterns: []*regexp.Regexp{regexp.MustCompile(pattern)},
			Headers:  make(map[string]string),
		}
	}
}

func (td *TechDetector) addHeaderPattern(category, name, headerKey, valuePattern string) {
	key := category + ":" + name
	if existing, ok := td.patterns[key]; ok {
		existing.Headers[headerKey] = valuePattern
	} else {
		td.patterns[key] = &techPattern{
			Category: category,
			Name:     name,
			Patterns: []*regexp.Regexp{},
			Headers:  map[string]string{headerKey: valuePattern},
		}
	}
}

// Detect 检测技术栈
func (td *TechDetector) Detect(headers map[string]string, body string) *models.TechStack {
	ts := &models.TechStack{}
	detected := make(map[string]bool)

	for key, pattern := range td.patterns {
		if detected[key] {
			continue
		}

		found := false

		// 检查 body 模式
		for _, p := range pattern.Patterns {
			if p.MatchString(body) {
				found = true
				break
			}
		}

		// 检查 header 模式
		if !found {
			for hKey, hPattern := range pattern.Headers {
				for headerName, headerValue := range headers {
					if strings.EqualFold(headerName, hKey) {
						if matched, _ := regexp.MatchString(hPattern, headerValue); matched {
							found = true
							break
						}
					}
				}
				if found {
					break
				}
			}
		}

		if found {
			detected[key] = true
			switch pattern.Category {
			case "frontend":
				ts.Frontend = append(ts.Frontend, pattern.Name)
			case "backend":
				ts.Backend = append(ts.Backend, pattern.Name)
			case "server":
				ts.Server = append(ts.Server, pattern.Name)
			case "framework":
				ts.Framework = append(ts.Framework, pattern.Name)
			case "cms":
				ts.CMS = append(ts.CMS, pattern.Name)
			case "cdn":
				ts.CDN = append(ts.CDN, pattern.Name)
			case "analytics":
				ts.Analytics = append(ts.Analytics, pattern.Name)
			case "javascript":
				ts.JavaScript = append(ts.JavaScript, pattern.Name)
			case "css":
				ts.CSS = append(ts.CSS, pattern.Name)
			}
		}
	}

	// 如果没检测到任何内容，返回 nil
	if len(ts.Frontend) == 0 && len(ts.Backend) == 0 && len(ts.Server) == 0 &&
		len(ts.Framework) == 0 && len(ts.CMS) == 0 && len(ts.CDN) == 0 &&
		len(ts.Analytics) == 0 && len(ts.JavaScript) == 0 && len(ts.CSS) == 0 {
		return nil
	}

	return ts
}
