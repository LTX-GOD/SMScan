package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"SMScan/pkg/fuzz"
	"SMScan/pkg/models"
	"SMScan/pkg/scanner"
	"SMScan/pkg/ui"
)

var (
	targetURL    string
	urlFile      string
	maxDepth     int
	concurrency  int
	outputFile   string
	saveFile     string
	fpConfig     string
	enableNuclei bool
	enableFuzz   bool
	fuzzMode     string
	proxyURL     string
	timeout      int
	userAgent    string
	quiet        bool
	verbose      bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "smscan",
		Short: "SMScan - Web 资产扫描与指纹识别工具",
		Long: `SMScan 集成了资产提取、指纹识别、技术栈检测、安全评估等功能。
支持深度爬取、Fuzz 扫描、Nuclei 集成等多种扫描模式。`,
		Run: runScan,
	}

	// 目标
	rootCmd.Flags().StringVarP(&targetURL, "url", "u", "", "目标 URL")
	rootCmd.Flags().StringVarP(&urlFile, "list", "l", "", "URL 列表文件 (每行一个)")

	// 扫描配置
	rootCmd.Flags().IntVarP(&maxDepth, "depth", "d", 2, "爬取深度")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 10, "并发数")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 15, "请求超时 (秒)")
	rootCmd.Flags().StringVar(&userAgent, "ua", "", "自定义 User-Agent")
	rootCmd.Flags().StringVar(&proxyURL, "proxy", "", "代理地址 (http://host:port)")

	// 功能开关
	rootCmd.Flags().BoolVarP(&enableNuclei, "nuclei", "n", false, "启用 Nuclei PoC 扫描")
	rootCmd.Flags().BoolVar(&enableFuzz, "fuzz", false, "启用 Fuzz 路径扫描")
	rootCmd.Flags().StringVar(&fuzzMode, "fuzz-mode", "default", "Fuzz 模式: path, api, js, all, default")

	// 输出
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "输出文件 (json/csv) - 覆盖模式")
	rootCmd.Flags().StringVarP(&saveFile, "save", "s", "", "保存文件 (json/csv) - 追加模式")
	rootCmd.Flags().StringVarP(&fpConfig, "fingerprint", "f", "config/finger.json", "指纹配置文件路径")

	// 显示控制
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "静默模式 (只输出结果)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "详细模式 (输出所有信息)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) {
	if targetURL == "" && urlFile == "" {
		ui.PrintError("请指定目标: -u <URL> 或 -l <文件>")
		os.Exit(1)
	}

	if !quiet {
		ui.PrintBanner()
	}

	// 收集所有目标 URL
	var targets []string
	if targetURL != "" {
		targets = append(targets, targetURL)
	}
	if urlFile != "" {
		fileTargets, err := loadURLFile(urlFile)
		if err != nil {
			ui.PrintError("读取 URL 文件失败: %v", err)
			os.Exit(1)
		}
		targets = append(targets, fileTargets...)
	}

	ui.PrintInfo("目标数: %d | 深度: %d | 并发: %d | 超时: %ds", len(targets), maxDepth, concurrency, timeout)
	if proxyURL != "" {
		ui.PrintInfo("代理: %s", proxyURL)
	}
	if enableFuzz {
		ui.PrintInfo("Fuzz: %s (字典: %d 条)", fuzzMode, fuzz.GetDictSize(fuzzMode))
	}
	fmt.Println()

	// 初始化扫描器
	s, err := scanner.NewScanner(fpConfig, maxDepth, concurrency)
	if err != nil {
		ui.PrintError("初始化扫描器失败: %v", err)
		os.Exit(1)
	}

	if proxyURL != "" {
		s.SetProxy(proxyURL)
	}
	if userAgent != "" {
		s.SetUserAgent(userAgent)
	}
	s.SetTimeout(timeout)

	// 进度回调
	var progress *ui.Progress
	if !quiet {
		progress = ui.NewProgress(len(targets) * 10)
		s.OnProgress = func(scanned, total int, currentURL string) {
			progress.SetTotal(total)
			progress.Update(scanned, truncateURL(currentURL, 60))
		}
	}

	// 扫描所有目标
	start := time.Now()
	for _, target := range targets {
		s.Scan(target)
	}

	if progress != nil {
		progress.Stop()
	}

	duration := time.Since(start)

	// Fuzz 扫描
	if enableFuzz {
		runFuzzScan(targets, s)
	}

	// Nuclei 扫描
	if enableNuclei {
		for _, target := range targets {
			runNuclei(target, s)
		}
	}

	// 输出结果
	if !quiet {
		printSummary(s, duration)
	}

	printResults(s)

	// 导出
	if outputFile != "" {
		exportResults(s, outputFile, false)
	}
	if saveFile != "" {
		exportResults(s, saveFile, true)
	}
}

func loadURLFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if !strings.HasPrefix(line, "http") {
				line = "http://" + line
			}
			urls = append(urls, line)
		}
	}
	return urls, scanner.Err()
}

func runFuzzScan(targets []string, s *scanner.Scanner) {
	ui.PrintSection("Fuzz 扫描")

	fuzzer := fuzz.NewFuzzer(concurrency, timeout)

	for _, target := range targets {
		baseURL := fuzz.ParseURLBase(target)
		ui.PrintInfo("Fuzz 目标: %s (模式: %s)", baseURL, fuzzMode)

		results := fuzzer.FuzzTarget(baseURL, fuzzMode, func(found models.FuzzResult) {
			statusColor := color.New(color.FgGreen)
			if found.Status == 403 || found.Status == 401 {
				statusColor = color.New(color.FgYellow)
			} else if found.Status >= 300 {
				statusColor = color.New(color.FgCyan)
			}
			statusColor.Printf("  [%d] %s (%d bytes)\n", found.Status, found.URL, found.Length)
		})

		// 将 fuzz 结果添加到扫描结果
		if len(s.Results) > 0 {
			s.Results[0].FuzzResults = append(s.Results[0].FuzzResults, results...)
		}

		ui.PrintSuccess("Fuzz 发现 %d 个有效路径", len(results))
	}
}

func printSummary(s *scanner.Scanner, duration time.Duration) {
	stats := s.GetStats()

	ui.PrintSection("扫描摘要")

	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	fmt.Printf("  %s %s  %s %s  %s %s  %s %s  %s %s\n",
		cyan("扫描:"), green(fmt.Sprintf("%d", stats.ScannedURLs)),
		cyan("指纹:"), green(fmt.Sprintf("%d", stats.Fingerprints)),
		cyan("敏感:"), yellow(fmt.Sprintf("%d", stats.SensitiveData)),
		cyan("漏洞:"), red(fmt.Sprintf("%d", stats.Vulnerabilities)),
		cyan("耗时:"), duration.Round(time.Millisecond).String(),
	)

	// 统计更多信息
	totalAPIs := 0
	totalKeys := 0
	totalVue := 0
	totalHoneypot := 0
	totalFuzz := 0
	for _, r := range s.Results {
		totalAPIs += len(r.Assets.AbsoluteApis) + len(r.Assets.RelativeApis)
		totalKeys += len(r.Assets.Keys) + len(r.Assets.AWSKeys) + len(r.Assets.GithubTokens) + len(r.Assets.PrivateKeys)
		if r.Vue != nil && r.Vue.Detected {
			totalVue++
		}
		if r.Honeypot.IsHoneypot {
			totalHoneypot++
		}
		totalFuzz += len(r.FuzzResults)
	}

	if totalAPIs > 0 || totalKeys > 0 || totalVue > 0 || totalHoneypot > 0 {
		fmt.Printf("  %s %s  %s %s",
			cyan("APIs:"), green(fmt.Sprintf("%d", totalAPIs)),
			cyan("密钥:"), yellow(fmt.Sprintf("%d", totalKeys)),
		)
		if totalVue > 0 {
			fmt.Printf("  %s %s", cyan("Vue:"), green(fmt.Sprintf("%d", totalVue)))
		}
		if totalHoneypot > 0 {
			fmt.Printf("  %s %s", cyan("蜜罐:"), red(fmt.Sprintf("%d", totalHoneypot)))
		}
		if totalFuzz > 0 {
			fmt.Printf("  %s %s", cyan("Fuzz:"), green(fmt.Sprintf("%d", totalFuzz)))
		}
		fmt.Println()
	}
}

func printResults(s *scanner.Scanner) {
	if len(s.Results) == 0 {
		ui.PrintWarning("未发现任何结果")
		return
	}

	// 按风险评分排序
	sort.Slice(s.Results, func(i, j int) bool {
		return s.Results[i].RiskScore > s.Results[j].RiskScore
	})

	// 聚合结果
	type aggResult struct {
		Count   int
		Pattern string
		Example *models.ScanResult
	}

	aggMap := make(map[string]*aggResult)
	var order []string

	for _, r := range s.Results {
		pattern := truncateURL(r.URL, 50)
		key := fmt.Sprintf("%s|%d", pattern, r.Status)

		if _, exists := aggMap[key]; !exists {
			aggMap[key] = &aggResult{
				Count:   0,
				Pattern: pattern,
				Example: r,
			}
			order = append(order, key)
		}
		aggMap[key].Count++
	}

	// ===== 主表 =====
	ui.PrintSection("扫描结果")

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"URL", "状态", "标题", "指纹/技术栈", "风险", "资产"})
	table.SetAutoWrapText(true)
	table.SetRowLine(true)
	table.SetColWidth(35)
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
	)

	for _, key := range order {
		agg := aggMap[key]
		r := agg.Example

		displayURL := agg.Pattern
		if agg.Count > 1 {
			displayURL = fmt.Sprintf("%s\n(x%d)", agg.Pattern, agg.Count)
		}

		// 指纹 + 技术栈
		fpStr := formatFingerprints(r)

		// 风险
		riskStr := formatRisk(r)

		// 资产统计
		assetStr := formatAssets(r)

		// 标题
		title := r.Title
		if len(title) > 30 {
			title = title[:27] + "..."
		}

		table.Append([]string{
			displayURL,
			fmt.Sprintf("%d", r.Status),
			title,
			fpStr,
			riskStr,
			assetStr,
		})
	}
	table.Render()

	// ===== 敏感信息详情 =====
	printSensitiveDetails(s)

	// ===== Fuzz 结果 =====
	printFuzzResults(s)

	// ===== Vue 信息 =====
	printVueInfo(s)

	// ===== 安全评估 =====
	printSecurityAssessment(s)
}

func formatFingerprints(r *models.ScanResult) string {
	var parts []string

	// 指纹
	for _, fp := range r.Fingerprints {
		parts = append(parts, fp.Name)
	}

	// 技术栈
	if r.TechStack != nil {
		if len(r.TechStack.Frontend) > 0 {
			parts = append(parts, color.CyanString("前端: ")+strings.Join(r.TechStack.Frontend, ", "))
		}
		if len(r.TechStack.Backend) > 0 {
			parts = append(parts, color.MagentaString("后端: ")+strings.Join(r.TechStack.Backend, ", "))
		}
		if len(r.TechStack.JavaScript) > 0 {
			parts = append(parts, color.YellowString("JS: ")+strings.Join(r.TechStack.JavaScript, ", "))
		}
		if len(r.TechStack.CSS) > 0 {
			parts = append(parts, color.BlueString("UI: ")+strings.Join(r.TechStack.CSS, ", "))
		}
		if len(r.TechStack.CDN) > 0 {
			parts = append(parts, color.GreenString("CDN: ")+strings.Join(r.TechStack.CDN, ", "))
		}
	}

	// Vue
	if r.Vue != nil && r.Vue.Detected {
		vueStr := "Vue"
		if r.Vue.Version != "" {
			vueStr += " " + r.Vue.Version
		}
		if len(r.Vue.Routes) > 0 {
			vueStr += fmt.Sprintf(" (%d routes)", len(r.Vue.Routes))
		}
		parts = append(parts, color.GreenString(vueStr))
	}

	// 蜜罐
	if r.Honeypot.IsHoneypot {
		parts = append(parts, color.RedString("⚠ HONEYPOT"))
	}

	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "\n")
}

func formatRisk(r *models.ScanResult) string {
	if r.RiskScore == 0 {
		return color.GreenString("安全")
	}

	var c *color.Color
	switch r.RiskLevel {
	case "critical":
		c = color.New(color.FgRed, color.Bold)
	case "high":
		c = color.New(color.FgRed)
	case "medium":
		c = color.New(color.FgYellow)
	case "low":
		c = color.New(color.FgBlue)
	default:
		c = color.New(color.FgCyan)
	}

	return c.Sprintf("%s\n(%d/100)", strings.ToUpper(r.RiskLevel), r.RiskScore)
}

func formatAssets(r *models.ScanResult) string {
	var parts []string

	apis := len(r.Assets.AbsoluteApis) + len(r.Assets.RelativeApis)
	if apis > 0 {
		parts = append(parts, fmt.Sprintf("API: %d", apis))
	}
	if len(r.Assets.Keys) > 0 {
		parts = append(parts, color.YellowString("Key: %d", len(r.Assets.Keys)))
	}
	if len(r.Assets.Sensitive) > 0 {
		parts = append(parts, color.YellowString("敏感: %d", len(r.Assets.Sensitive)))
	}
	if len(r.Assets.JWTs) > 0 {
		parts = append(parts, color.RedString("JWT: %d", len(r.Assets.JWTs)))
	}
	if len(r.Assets.Emails) > 0 {
		parts = append(parts, fmt.Sprintf("邮箱: %d", len(r.Assets.Emails)))
	}
	if len(r.Assets.InternalIPs) > 0 {
		parts = append(parts, color.YellowString("内网IP: %d", len(r.Assets.InternalIPs)))
	}
	if len(r.Assets.SourceMaps) > 0 {
		parts = append(parts, color.RedString("SourceMap: %d", len(r.Assets.SourceMaps)))
	}
	if len(r.Assets.WebpackChunks) > 0 {
		parts = append(parts, fmt.Sprintf("Chunks: %d", len(r.Assets.WebpackChunks)))
	}
	if len(r.Assets.DatabaseConns) > 0 {
		parts = append(parts, color.RedString("DB: %d", len(r.Assets.DatabaseConns)))
	}
	if len(r.Assets.PrivateKeys) > 0 {
		parts = append(parts, color.RedString("私钥: %d", len(r.Assets.PrivateKeys)))
	}
	if len(r.Assets.AWSKeys) > 0 {
		parts = append(parts, color.RedString("AWS: %d", len(r.Assets.AWSKeys)))
	}
	if len(r.Assets.GithubTokens) > 0 {
		parts = append(parts, color.RedString("GitHub: %d", len(r.Assets.GithubTokens)))
	}
	if len(r.Assets.HardcodedCreds) > 0 {
		parts = append(parts, color.RedString("硬编码: %d", len(r.Assets.HardcodedCreds)))
	}

	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "\n")
}

func printSensitiveDetails(s *scanner.Scanner) {
	// 收集所有敏感数据
	var allKeys, allSensitive, allJWTs, allCreds, allDBConns []string
	var allAWS, allGithub, allPrivate, allComments []string
	seen := make(map[string]bool)

	for _, r := range s.Results {
		for _, v := range r.Assets.Keys {
			if !seen[v] { seen[v] = true; allKeys = append(allKeys, fmt.Sprintf("[%s] %s", truncateURL(r.URL, 30), v)) }
		}
		for _, v := range r.Assets.Sensitive {
			if !seen[v] { seen[v] = true; allSensitive = append(allSensitive, fmt.Sprintf("[%s] %s", truncateURL(r.URL, 30), v)) }
		}
		for _, v := range r.Assets.JWTs {
			if !seen[v] { seen[v] = true; allJWTs = append(allJWTs, fmt.Sprintf("[%s] %s", truncateURL(r.URL, 30), truncate(v, 60))) }
		}
		for _, v := range r.Assets.HardcodedCreds {
			if !seen[v] { seen[v] = true; allCreds = append(allCreds, fmt.Sprintf("[%s] %s", truncateURL(r.URL, 30), v)) }
		}
		for _, v := range r.Assets.DatabaseConns {
			if !seen[v] { seen[v] = true; allDBConns = append(allDBConns, fmt.Sprintf("[%s] %s", truncateURL(r.URL, 30), v)) }
		}
		for _, v := range r.Assets.AWSKeys {
			if !seen[v] { seen[v] = true; allAWS = append(allAWS, fmt.Sprintf("[%s] %s", truncateURL(r.URL, 30), v)) }
		}
		for _, v := range r.Assets.GithubTokens {
			if !seen[v] { seen[v] = true; allGithub = append(allGithub, fmt.Sprintf("[%s] %s", truncateURL(r.URL, 30), truncate(v, 50))) }
		}
		for _, v := range r.Assets.PrivateKeys {
			if !seen[v] { seen[v] = true; allPrivate = append(allPrivate, fmt.Sprintf("[%s] %s", truncateURL(r.URL, 30), v)) }
		}
		if verbose {
			for _, v := range r.Assets.Comments {
				if !seen[v] { seen[v] = true; allComments = append(allComments, fmt.Sprintf("[%s] %s", truncateURL(r.URL, 30), v)) }
			}
		}
	}

	hasSensitive := len(allKeys) > 0 || len(allSensitive) > 0 || len(allJWTs) > 0 || len(allCreds) > 0 ||
		len(allDBConns) > 0 || len(allAWS) > 0 || len(allGithub) > 0 || len(allPrivate) > 0

	if !hasSensitive {
		return
	}

	ui.PrintSection("敏感信息详情")
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)

	printItems := func(title string, items []string, c *color.Color) {
		if len(items) == 0 { return }
		c.Printf("  [%s] (%d)\n", title, len(items))
		limit := 10
		if verbose { limit = len(items) }
		for i, item := range items {
			if i >= limit {
				fmt.Printf("    ... 还有 %d 项\n", len(items)-limit)
				break
			}
			fmt.Printf("    %s\n", item)
		}
	}

	printItems("私钥", allPrivate, red)
	printItems("AWS 密钥", allAWS, red)
	printItems("GitHub Token", allGithub, red)
	printItems("数据库连接", allDBConns, red)
	printItems("硬编码凭证", allCreds, red)
	printItems("JWT Token", allJWTs, yellow)
	printItems("API 密钥", allKeys, yellow)
	printItems("敏感配置", allSensitive, yellow)
	if verbose {
		printItems("代码注释", allComments, color.New(color.FgWhite))
	}
}

func printFuzzResults(s *scanner.Scanner) {
	var allFuzz []models.FuzzResult
	for _, r := range s.Results {
		allFuzz = append(allFuzz, r.FuzzResults...)
	}

	if len(allFuzz) == 0 {
		return
	}

	ui.PrintSection("Fuzz 发现")

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"URL", "状态码", "大小", "类型"})
	table.SetAutoWrapText(false)
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
	)

	for _, f := range allFuzz {
		statusStr := fmt.Sprintf("%d", f.Status)
		if f.Status == 200 {
			statusStr = color.GreenString(statusStr)
		} else if f.Status == 403 || f.Status == 401 {
			statusStr = color.YellowString(statusStr)
		} else if f.Status >= 300 && f.Status < 400 {
			statusStr = color.CyanString(statusStr)
		}

		table.Append([]string{
			f.URL,
			statusStr,
			fmt.Sprintf("%d", f.Length),
			f.Type,
		})
	}
	table.Render()
}

func printVueInfo(s *scanner.Scanner) {
	var vueResults []*models.ScanResult
	for _, r := range s.Results {
		if r.Vue != nil && r.Vue.Detected {
			vueResults = append(vueResults, r)
		}
	}

	if len(vueResults) == 0 {
		return
	}

	ui.PrintSection("Vue 框架信息")

	for _, r := range vueResults {
		green := color.New(color.FgGreen)
		green.Printf("  [%s] Vue %s\n", truncateURL(r.URL, 40), r.Vue.Version)

		if len(r.Vue.Routes) > 0 {
			fmt.Printf("    路由 (%d):\n", len(r.Vue.Routes))
			limit := 20
			if verbose { limit = len(r.Vue.Routes) }
			for i, route := range r.Vue.Routes {
				if i >= limit {
					fmt.Printf("      ... 还有 %d 条\n", len(r.Vue.Routes)-limit)
					break
				}
				fmt.Printf("      /%s\n", route)
			}
		}

		if len(r.Vue.Components) > 0 {
			fmt.Printf("    组件 (%d): %s\n", len(r.Vue.Components), strings.Join(r.Vue.Components, ", "))
		}
	}
}

func printSecurityAssessment(s *scanner.Scanner) {
	if !verbose {
		return
	}

	ui.PrintSection("安全头评估")

	for _, r := range s.Results {
		if r.ResponseInfo == nil || r.ResponseInfo.SecurityHeaders == nil {
			continue
		}

		sh := r.ResponseInfo.SecurityHeaders

		// 根据评分着色
		var scoreColor *color.Color
		switch {
		case sh.Score >= 80:
			scoreColor = color.New(color.FgGreen)
		case sh.Score >= 50:
			scoreColor = color.New(color.FgYellow)
		default:
			scoreColor = color.New(color.FgRed)
		}

		scoreColor.Printf("  [%s] 安全评分: %d/100\n", truncateURL(r.URL, 40), sh.Score)

		if len(sh.Missing) > 0 {
			fmt.Printf("    缺失: %s\n", color.YellowString(strings.Join(sh.Missing, ", ")))
		}
		if len(sh.Warnings) > 0 {
			for _, w := range sh.Warnings {
				fmt.Printf("    %s %s\n", color.YellowString("!"), w)
			}
		}

		// CSP 详情
		if r.ResponseInfo.CSPInfo != nil {
			csp := r.ResponseInfo.CSPInfo
			if len(csp.Warnings) > 0 {
				for _, w := range csp.Warnings {
					fmt.Printf("    %s %s\n", color.RedString("!"), w)
				}
			}
		}
	}
}

// ===== Nuclei 集成 =====

func runNuclei(target string, s *scanner.Scanner) {
	ui.PrintSection("Nuclei 扫描")

	path, err := findExecutable("nuclei")
	if err != nil {
		ui.PrintError("未找到 nuclei 命令: https://github.com/projectdiscovery/nuclei")
		return
	}

	ui.PrintInfo("启动 Nuclei 扫描: %s", target)

	cmd := createCommand(path, "-u", target, "-jsonl", "-silent")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		ui.PrintError("无法获取 Nuclei 输出管道: %v", err)
		return
	}

	if err := cmd.Start(); err != nil {
		ui.PrintError("启动 Nuclei 失败: %v", err)
		return
	}

	sc := bufio.NewScanner(stdout)
	var findings []models.NucleiResult

	for sc.Scan() {
		line := sc.Text()
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			info, ok := result["info"].(map[string]interface{})
			if ok {
				finding := models.NucleiResult{
					TemplateID: getString(result["template-id"]),
					MatchedAt:  getString(result["matched-at"]),
					Name:       getString(info["name"]),
					Severity:   getString(info["severity"]),
				}
				findings = append(findings, finding)
				ui.PrintVuln(finding.Severity, finding.Name, finding.TemplateID)
			}
		}
	}

	if err := cmd.Wait(); err != nil {
		ui.PrintWarning("Nuclei 运行异常: %v", err)
	}

	if len(s.Results) > 0 {
		s.Results[0].NucleiFindings = findings
	}

	ui.PrintSuccess("Nuclei 完成，发现 %d 个结果", len(findings))
}

func getString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// ===== 导出 =====

func exportResults(s *scanner.Scanner, filename string, appendMode bool) {
	if strings.HasSuffix(filename, ".csv") {
		saveCSV(s, filename, appendMode)
	} else {
		saveJSON(s, filename, appendMode)
	}
}

func saveJSON(s *scanner.Scanner, filename string, appendMode bool) {
	var results []*models.ScanResult

	if appendMode {
		if _, err := os.Stat(filename); err == nil {
			data, err := os.ReadFile(filename)
			if err == nil && len(data) > 0 {
				var existing []*models.ScanResult
				if err := json.Unmarshal(data, &existing); err != nil {
					ui.PrintWarning("无法解析现有文件 %s，将覆盖", filename)
				} else {
					results = append(results, existing...)
				}
			}
		}
	}

	results = append(results, s.Results...)

	file, err := os.Create(filename)
	if err != nil {
		ui.PrintError("创建输出文件失败: %v", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		ui.PrintError("写入 JSON 失败: %v", err)
	} else {
		ui.PrintSuccess("结果已%s: %s", map[bool]string{true: "追加至", false: "保存至"}[appendMode], filename)
	}
}

func saveCSV(s *scanner.Scanner, filename string, appendMode bool) {
	fileExists := false
	if _, err := os.Stat(filename); err == nil {
		fileExists = true
	}

	flags := os.O_RDWR | os.O_CREATE | os.O_TRUNC
	if appendMode {
		flags = os.O_RDWR | os.O_CREATE | os.O_APPEND
	}

	file, err := os.OpenFile(filename, flags, 0644)
	if err != nil {
		ui.PrintError("打开 CSV 文件失败: %v", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if !appendMode || !fileExists {
		header := []string{"URL", "Status", "Title", "Server", "Fingerprints", "TechStack", "Risk", "RiskScore",
			"Honeypot", "Keys", "Sensitive", "JWTs", "APIs", "Emails", "InternalIPs",
			"SourceMaps", "WebpackChunks", "Vue", "SecurityScore", "Nuclei"}
		writer.Write(header)
	}

	for _, r := range s.Results {
		var fps []string
		for _, fp := range r.Fingerprints {
			fps = append(fps, fp.Name)
		}

		// 技术栈
		var techs []string
		if r.TechStack != nil {
			techs = append(techs, r.TechStack.Frontend...)
			techs = append(techs, r.TechStack.Backend...)
			techs = append(techs, r.TechStack.JavaScript...)
		}

		hpStr := "No"
		if r.Honeypot.IsHoneypot {
			hpStr = "Yes"
		}

		vueStr := "No"
		if r.Vue != nil && r.Vue.Detected {
			vueStr = fmt.Sprintf("Vue %s (%d routes)", r.Vue.Version, len(r.Vue.Routes))
		}

		secScore := ""
		if r.ResponseInfo != nil && r.ResponseInfo.SecurityHeaders != nil {
			secScore = fmt.Sprintf("%d/100", r.ResponseInfo.SecurityHeaders.Score)
		}

		var apis []string
		apis = append(apis, r.Assets.AbsoluteApis...)
		apis = append(apis, r.Assets.RelativeApis...)

		var nucleiStr string
		if len(r.NucleiFindings) > 0 {
			var findings []string
			for _, f := range r.NucleiFindings {
				findings = append(findings, fmt.Sprintf("[%s]%s", f.Severity, f.Name))
			}
			nucleiStr = strings.Join(findings, "|")
		}

		record := []string{
			r.URL,
			fmt.Sprintf("%d", r.Status),
			r.Title,
			r.Server,
			strings.Join(fps, "|"),
			strings.Join(techs, "|"),
			r.RiskLevel,
			fmt.Sprintf("%d", r.RiskScore),
			hpStr,
			strings.Join(r.Assets.Keys, "|"),
			strings.Join(r.Assets.Sensitive, "|"),
			strings.Join(r.Assets.JWTs, "|"),
			strings.Join(apis, "|"),
			strings.Join(r.Assets.Emails, "|"),
			strings.Join(r.Assets.InternalIPs, "|"),
			strings.Join(r.Assets.SourceMaps, "|"),
			strings.Join(r.Assets.WebpackChunks, "|"),
			vueStr,
			secScore,
			nucleiStr,
		}
		writer.Write(record)
	}

	ui.PrintSuccess("结果已%s CSV: %s", map[bool]string{true: "追加至", false: "保存至"}[appendMode], filename)
}

// ===== 辅助函数 =====

func truncateURL(u string, maxLen int) string {
	if len(u) <= maxLen {
		return u
	}
	return u[:maxLen-3] + "..."
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
