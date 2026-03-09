package extractor

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// BatchScanner 批量扫描器
type BatchScanner struct {
	scanner  *AdvancedScanner
	crawler  *JSCrawler
	results  map[string]*ScanResult
	mu       sync.Mutex
}

// ScanResult 单个目标的扫描结果
type ScanResult struct {
	URL           string         `json:"url"`
	Status        string         `json:"status"` // success, failed
	Matches       []MatchResult  `json:"matches"`
	JSFiles       int            `json:"js_files"`
	TotalFindings int            `json:"total_findings"`
	Critical      int            `json:"critical"`
	High          int            `json:"high"`
	Medium        int            `json:"medium"`
	ScanTime      time.Duration  `json:"scan_time"`
}

func NewBatchScanner() *BatchScanner {
	return &BatchScanner{
		scanner: NewAdvancedScanner(),
		crawler: NewJSCrawler(30*time.Second, 2),
		results: make(map[string]*ScanResult),
	}
}

// ScanMultiple 批量扫描多个目标
func (b *BatchScanner) ScanMultiple(urls []string, concurrency int) map[string]*ScanResult {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)

	for _, url := range urls {
		wg.Add(1)
		go func(targetURL string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			b.scanSingle(targetURL)
		}(url)
	}

	wg.Wait()
	return b.results
}

// scanSingle 扫描单个目标
func (b *BatchScanner) scanSingle(url string) {
	startTime := time.Now()
	result := &ScanResult{
		URL:    url,
		Status: "success",
	}

	// 爬取 JS 文件
	jsFiles, err := b.crawler.CrawlJS(url)
	if err != nil {
		result.Status = "failed"
		b.mu.Lock()
		b.results[url] = result
		b.mu.Unlock()
		return
	}

	result.JSFiles = len(jsFiles)

	// 扫描每个 JS 文件
	var allMatches []MatchResult
	for jsURL, content := range jsFiles {
		matches := b.scanner.ScanWithContext(content, jsURL)
		allMatches = append(allMatches, matches...)
	}

	result.Matches = allMatches
	result.TotalFindings = len(allMatches)

	// 统计严重程度
	for _, match := range allMatches {
		switch match.Severity {
		case "critical":
			result.Critical++
		case "high":
			result.High++
		case "medium":
			result.Medium++
		}
	}

	result.ScanTime = time.Since(startTime)

	b.mu.Lock()
	b.results[url] = result
	b.mu.Unlock()
}

// GenerateAggregateReport 生成聚合报告
func (b *BatchScanner) GenerateAggregateReport() string {
	var sb strings.Builder

	sb.WriteString(b.getAggregateHeader())
	sb.WriteString(b.generateOverviewTable())
	sb.WriteString(b.generateDetailedSections())
	sb.WriteString(b.getAggregateFooter())

	return sb.String()
}

// getAggregateHeader 聚合报告头部
func (b *BatchScanner) getAggregateHeader() string {
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
	<meta charset="UTF-8">
	<title>SMScan 批量扫描总览报告</title>
	<style>
		body { font-family: "Microsoft YaHei", sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
		.container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
		.header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
		.header h1 { margin: 0; font-size: 2em; }
		table { width: 100%; border-collapse: collapse; margin: 20px 0; }
		th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
		th { background: #f8f9fa; font-weight: bold; }
		tr:hover { background: #f8f9fa; cursor: pointer; }
		.critical { color: #dc3545; font-weight: bold; }
		.high { color: #fd7e14; font-weight: bold; }
		.medium { color: #ffc107; }
		.detail { display: none; padding: 20px; background: #f8f9fa; }
		.detail.active { display: block; }
	</style>
</head>
<body>
<div class="container">
	<div class="header">
		<h1>🔍 SMScan 批量扫描总览报告</h1>
		<p>生成时间: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
	</div>
`
}

// generateOverviewTable 生成总览表格
func (b *BatchScanner) generateOverviewTable() string {
	var sb strings.Builder
	sb.WriteString(`<table><thead><tr>
		<th>目标URL</th><th>状态</th><th>JS文件</th><th>发现数</th>
		<th>Critical</th><th>High</th><th>Medium</th><th>耗时</th>
	</tr></thead><tbody>`)

	for url, result := range b.results {
		criticalClass := ""
		if result.Critical > 0 {
			criticalClass = "critical"
		}
		sb.WriteString(fmt.Sprintf(`<tr onclick="toggleDetail('%s')" class="%s">
			<td>%s</td><td>%s</td><td>%d</td><td>%d</td>
			<td class="critical">%d</td><td class="high">%d</td><td class="medium">%d</td>
			<td>%.2fs</td>
		</tr>`, url, criticalClass, url, result.Status, result.JSFiles, result.TotalFindings,
			result.Critical, result.High, result.Medium, result.ScanTime.Seconds()))
	}

	sb.WriteString(`</tbody></table>`)
	return sb.String()
}

// generateDetailedSections 生成详细区块
func (b *BatchScanner) generateDetailedSections() string {
	var sb strings.Builder
	for url, result := range b.results {
		sb.WriteString(fmt.Sprintf(`<div id="detail-%s" class="detail">`, url))
		sb.WriteString(fmt.Sprintf(`<h2>%s 详细结果</h2>`, url))

		grouped := b.scanner.GroupByType(result.Matches)
		for typ, matches := range grouped {
			sb.WriteString(fmt.Sprintf(`<h3>%s (%d)</h3><ul>`, typ, len(matches)))
			for _, match := range matches {
				sb.WriteString(fmt.Sprintf(`<li><strong>%s</strong> (行%d)<br><code>%s</code></li>`,
					match.Value, match.Line, match.Context))
			}
			sb.WriteString(`</ul>`)
		}
		sb.WriteString(`</div>`)
	}
	return sb.String()
}

// getAggregateFooter 聚合报告尾部
func (b *BatchScanner) getAggregateFooter() string {
	return `</div>
<script>
function toggleDetail(url) {
	const detail = document.getElementById('detail-' + url);
	detail.classList.toggle('active');
}
</script>
</body>
</html>`
}
