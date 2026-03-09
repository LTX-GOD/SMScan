package extractor

import (
	"fmt"
	"html"
	"strings"
	"time"
)

// ReportGenerator 报告生成器
type ReportGenerator struct{}

func NewReportGenerator() *ReportGenerator {
	return &ReportGenerator{}
}

// GenerateHTMLReport 生成交互式 HTML 报告
func (r *ReportGenerator) GenerateHTMLReport(data map[string]interface{}) string {
	var sb strings.Builder

	// HTML 头部
	sb.WriteString(r.getHTMLHeader())

	// 报告标题
	sb.WriteString(fmt.Sprintf(`
	<div class="header">
		<h1>🔍 SMScan 扫描报告</h1>
		<p class="timestamp">生成时间: %s</p>
	</div>
`, time.Now().Format("2006-01-02 15:04:05")))

	// 摘要统计
	sb.WriteString(r.generateSummary(data))

	// 详细结果
	sb.WriteString(r.generateDetails(data))

	// HTML 尾部
	sb.WriteString(r.getHTMLFooter())

	return sb.String()
}

// getHTMLHeader 获取 HTML 头部
func (r *ReportGenerator) getHTMLHeader() string {
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>SMScan 扫描报告</title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif;
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			padding: 20px;
			color: #333;
		}
		.container {
			max-width: 1400px;
			margin: 0 auto;
			background: #fff;
			border-radius: 12px;
			box-shadow: 0 10px 40px rgba(0,0,0,0.2);
			overflow: hidden;
		}
		.header {
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			color: white;
			padding: 30px;
			text-align: center;
		}
		.header h1 { font-size: 2.5em; margin-bottom: 10px; }
		.timestamp { opacity: 0.9; font-size: 0.9em; }
		.summary {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
			gap: 20px;
			padding: 30px;
			background: #f8f9fa;
		}
		.stat-card {
			background: white;
			padding: 20px;
			border-radius: 8px;
			box-shadow: 0 2px 8px rgba(0,0,0,0.1);
			text-align: center;
			transition: transform 0.2s;
		}
		.stat-card:hover { transform: translateY(-5px); }
		.stat-number {
			font-size: 2.5em;
			font-weight: bold;
			color: #667eea;
			margin: 10px 0;
		}
		.stat-label { color: #666; font-size: 0.9em; }
		.content { padding: 30px; }
		.section {
			margin-bottom: 30px;
			border: 1px solid #e0e0e0;
			border-radius: 8px;
			overflow: hidden;
		}
		.section-header {
			background: #667eea;
			color: white;
			padding: 15px 20px;
			cursor: pointer;
			display: flex;
			justify-content: space-between;
			align-items: center;
			user-select: none;
		}
		.section-header:hover { background: #5568d3; }
		.section-title { font-size: 1.2em; font-weight: bold; }
		.section-count {
			background: rgba(255,255,255,0.2);
			padding: 5px 15px;
			border-radius: 20px;
			font-size: 0.9em;
		}
		.section-body {
			padding: 20px;
			display: none;
		}
		.section-body.active { display: block; }
		.item-list { list-style: none; }
		.item {
			padding: 12px;
			margin: 8px 0;
			background: #f8f9fa;
			border-left: 4px solid #667eea;
			border-radius: 4px;
			font-family: 'Courier New', monospace;
			word-break: break-all;
		}
		.item.critical { border-left-color: #dc3545; background: #fff5f5; }
		.item.warning { border-left-color: #ffc107; background: #fffbf0; }
		.item.info { border-left-color: #17a2b8; background: #f0f9ff; }
		.tabs {
			display: flex;
			border-bottom: 2px solid #e0e0e0;
			margin-bottom: 20px;
		}
		.tab {
			padding: 12px 24px;
			cursor: pointer;
			border: none;
			background: none;
			font-size: 1em;
			color: #666;
			transition: all 0.3s;
		}
		.tab:hover { color: #667eea; }
		.tab.active {
			color: #667eea;
			border-bottom: 3px solid #667eea;
			font-weight: bold;
		}
		.tab-content { display: none; }
		.tab-content.active { display: block; }
		.search-box {
			width: 100%;
			padding: 12px;
			margin-bottom: 20px;
			border: 2px solid #e0e0e0;
			border-radius: 6px;
			font-size: 1em;
		}
		.search-box:focus {
			outline: none;
			border-color: #667eea;
		}
		.highlight { background: #ffeb3b; padding: 2px 4px; border-radius: 2px; }
		.footer {
			text-align: center;
			padding: 20px;
			color: #666;
			font-size: 0.9em;
			border-top: 1px solid #e0e0e0;
		}
	</style>
</head>
<body>
<div class="container">
`
}

// generateSummary 生成摘要统计
func (r *ReportGenerator) generateSummary(data map[string]interface{}) string {
	var sb strings.Builder
	sb.WriteString(`<div class="summary">`)

	stats := []struct {
		label string
		key   string
	}{
		{"扫描URL", "url_count"},
		{"发现指纹", "fingerprint_count"},
		{"敏感信息", "sensitive_count"},
		{"API端点", "api_count"},
		{"漏洞风险", "vuln_count"},
	}

	for _, stat := range stats {
		count := 0
		if v, ok := data[stat.key]; ok {
			if num, ok := v.(int); ok {
				count = num
			}
		}
		sb.WriteString(fmt.Sprintf(`
		<div class="stat-card">
			<div class="stat-label">%s</div>
			<div class="stat-number">%d</div>
		</div>`, stat.label, count))
	}

	sb.WriteString(`</div>`)
	return sb.String()
}

// generateDetails 生成详细结果
func (r *ReportGenerator) generateDetails(data map[string]interface{}) string {
	var sb strings.Builder
	sb.WriteString(`<div class="content">`)

	// 搜索框
	sb.WriteString(`<input type="text" class="search-box" id="searchBox" placeholder="🔍 搜索关键词...">`)

	// 敏感信息部分
	if sensitive, ok := data["sensitive"].(map[string][]string); ok && len(sensitive) > 0 {
		sb.WriteString(r.generateSection("敏感信息", sensitive, "critical"))
	}

	// API 端点部分
	if apis, ok := data["apis"].([]string); ok && len(apis) > 0 {
		sb.WriteString(r.generateListSection("API端点", apis, "info"))
	}

	// 指纹识别部分
	if fingerprints, ok := data["fingerprints"].([]string); ok && len(fingerprints) > 0 {
		sb.WriteString(r.generateListSection("指纹识别", fingerprints, "info"))
	}

	sb.WriteString(`</div>`)
	return sb.String()
}

// generateSection 生成分类部分
func (r *ReportGenerator) generateSection(title string, items map[string][]string, level string) string {
	var sb strings.Builder
	totalCount := 0
	for _, v := range items {
		totalCount += len(v)
	}

	sb.WriteString(fmt.Sprintf(`
	<div class="section">
		<div class="section-header" onclick="toggleSection(this)">
			<span class="section-title">%s</span>
			<span class="section-count">%d 项</span>
		</div>
		<div class="section-body">`, title, totalCount))

	for category, values := range items {
		if len(values) > 0 {
			sb.WriteString(fmt.Sprintf(`<h3>%s (%d)</h3><ul class="item-list">`, html.EscapeString(category), len(values)))
			for _, v := range values {
				sb.WriteString(fmt.Sprintf(`<li class="item %s">%s</li>`, level, html.EscapeString(v)))
			}
			sb.WriteString(`</ul>`)
		}
	}

	sb.WriteString(`</div></div>`)
	return sb.String()
}

// generateListSection 生成列表部分
func (r *ReportGenerator) generateListSection(title string, items []string, level string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`
	<div class="section">
		<div class="section-header" onclick="toggleSection(this)">
			<span class="section-title">%s</span>
			<span class="section-count">%d 项</span>
		</div>
		<div class="section-body">
			<ul class="item-list">`, title, len(items)))

	for _, item := range items {
		sb.WriteString(fmt.Sprintf(`<li class="item %s">%s</li>`, level, html.EscapeString(item)))
	}

	sb.WriteString(`</ul></div></div>`)
	return sb.String()
}

// getHTMLFooter 获取 HTML 尾部
func (r *ReportGenerator) getHTMLFooter() string {
	return `
	<div class="footer">
		<p>Powered by SMScan | 生成时间: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
	</div>
</div>

<script>
	// 切换区块展开/收起
	function toggleSection(header) {
		const body = header.nextElementSibling;
		body.classList.toggle('active');
	}

	// 搜索功能
	const searchBox = document.getElementById('searchBox');
	if (searchBox) {
		searchBox.addEventListener('input', function(e) {
			const keyword = e.target.value.toLowerCase();
			const items = document.querySelectorAll('.item');

			items.forEach(item => {
				const text = item.textContent.toLowerCase();
				if (text.includes(keyword)) {
					item.style.display = 'block';
					// 高亮关键词
					if (keyword) {
						const regex = new RegExp('(' + keyword + ')', 'gi');
						item.innerHTML = item.textContent.replace(regex, '<span class="highlight">$1</span>');
					}
				} else {
					item.style.display = 'none';
				}
			});
		});
	}

	// 默认展开第一个区块
	const firstSection = document.querySelector('.section-body');
	if (firstSection) {
		firstSection.classList.add('active');
	}
</script>
</body>
</html>
`
}

