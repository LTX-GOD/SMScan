package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"SMScan/pkg/models"
	"SMScan/pkg/scanner"
	"SMScan/pkg/utils"
)

var (
	targetURL   string
	maxDepth    int
	concurrency int
	outputFile  string
	saveFile    string
	fpConfig    string
	enableNuclei bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "smscan",
		Short: "SMScan - 高效的资产提取与指纹识别工具",
		Long: `SMScan 是一款集成 Phantom 的资产提取能力与 XMCVE 的指纹识别能力的命令行工具。
支持深度扫描、敏感信息提取、蜜罐识别等功能。`,
		Run:   runScan,
	}

	rootCmd.Flags().StringVarP(&targetURL, "url", "u", "", "目标 URL")
	rootCmd.Flags().IntVarP(&maxDepth, "depth", "d", 1, "爬取深度 (默认: 1)")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 10, "并发数 (默认: 10)")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "输出文件 (支持 json, csv) - 覆盖模式")
	rootCmd.Flags().StringVarP(&saveFile, "save", "s", "", "保存文件 (支持 json, csv) - 追加模式")
	rootCmd.Flags().StringVarP(&fpConfig, "fingerprint", "f", "config/finger.json", "指纹配置文件路径 (默认使用内置指纹库)")
	rootCmd.Flags().BoolVarP(&enableNuclei, "nuclei", "n", false, "调用 Nuclei 进行 PoC 扫描")

	rootCmd.MarkFlagRequired("url")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) {
	color.Green("[+] 开始扫描: %s", targetURL)
	color.Cyan("[*] 配置: 深度=%d, 并发=%d", maxDepth, concurrency)
	
	// 指纹库加载逻辑已在 scanner.NewScanner 中优化：
	// 优先使用指定文件，如果未指定或文件不存在（且为默认路径），则自动回退到内置指纹库
	s, err := scanner.NewScanner(fpConfig, maxDepth, concurrency)
	if err != nil {
		color.Red("[-] 初始化扫描器失败: %v", err)
		os.Exit(1)
	}

	start := time.Now()
	s.Scan(targetURL)
	duration := time.Since(start)

	color.Green("[+] 扫描完成，耗时: %s", duration)
	color.Green("[+] 共发现 %d 个结果", len(s.Results))

	// 执行 Nuclei 扫描
	if enableNuclei {
		runNuclei(targetURL, s)
	}

	// 输出表格
	printTable(s)

	// 导出结果
	if outputFile != "" {
		exportResults(s, outputFile, false)
	}
	if saveFile != "" {
		exportResults(s, saveFile, true)
	}
}

func runNuclei(target string, s *scanner.Scanner) {
	// 检查 nuclei 是否存在
	path, err := exec.LookPath("nuclei")
	if err != nil {
		color.Red("[-] 未找到 nuclei 命令，请确保已安装并在 PATH 中: https://github.com/projectdiscovery/nuclei")
		return
	}

	color.Cyan("[*] 正在启动 Nuclei 扫描...")
	
	// 构建命令：nuclei -u target -jsonl -silent
	cmd := exec.Command(path, "-u", target, "-jsonl", "-silent")
	
	// 获取 stdout 管道
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		color.Red("[-] 无法获取 Nuclei 输出管道: %v", err)
		return
	}

	if err := cmd.Start(); err != nil {
		color.Red("[-] 启动 Nuclei 失败: %v", err)
		return
	}

	// 实时解析输出
	scanner := bufio.NewScanner(stdout)
	var findings []models.NucleiResult
	
	for scanner.Scan() {
		line := scanner.Text()
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			// 解析基本信息
			info, ok := result["info"].(map[string]interface{})
			if ok {
				finding := models.NucleiResult{
					TemplateID: getString(result["template-id"]),
					MatchedAt:  getString(result["matched-at"]),
					Name:       getString(info["name"]),
					Severity:   getString(info["severity"]),
				}
				findings = append(findings, finding)
				
				// 实时打印发现
				sevColor := color.New(color.FgWhite)
				switch strings.ToLower(finding.Severity) {
				case "critical":
					sevColor = color.New(color.FgRed, color.Bold)
				case "high":
					sevColor = color.New(color.FgRed)
				case "medium":
					sevColor = color.New(color.FgYellow)
				case "low":
					sevColor = color.New(color.FgBlue)
				case "info":
					sevColor = color.New(color.FgCyan)
				}
				sevColor.Printf("[Nuclei] [%s] %s (%s)\n", finding.Severity, finding.Name, finding.TemplateID)
			}
		}
	}

	if err := cmd.Wait(); err != nil {
		color.Red("[-] Nuclei 运行异常: %v", err)
	}

	// 将结果关联到 ScanResult (假设第一个结果对应目标 URL)
	if len(s.Results) > 0 {
		s.Results[0].NucleiFindings = findings
	} else {
		// 如果没有扫描结果（比如爬虫失败），创建一个只有 Nuclei 结果的条目？
		// 这里暂不处理，假设 SMScan 总会有结果
	}
	
	color.Green("[+] Nuclei 扫描完成，发现 %d 个漏洞/信息", len(findings))
}

func getString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// 辅助结构用于聚合
type aggregatedResult struct {
	Count   int
	Pattern string
	Example *models.ScanResult
}

func printTable(s *scanner.Scanner) {
	// 1. 聚合结果
	// Map key: Method + Pattern + Status + Title (简化)
	// 这里简单按 Pattern + Status 聚合
	aggMap := make(map[string]*aggregatedResult)
	var order []string // 保持顺序

	for _, r := range s.Results {
		pattern := utils.GetURLPattern(r.URL)
		key := fmt.Sprintf("%s|%d", pattern, r.Status)
		
		if _, exists := aggMap[key]; !exists {
			aggMap[key] = &aggregatedResult{
				Count:   0,
				Pattern: pattern,
				Example: r,
			}
			order = append(order, key)
		}
		aggMap[key].Count++
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"URL", "状态", "标题", "指纹", "敏感信息", "Nuclei"})
	table.SetAutoWrapText(true) // 开启自动换行
	table.SetRowLine(true)

	// 设置列宽，避免表格过宽
	table.SetColWidth(30) 

	for _, key := range order {
		agg := aggMap[key]
		r := agg.Example
		
		// 构造显示的 URL
		displayURL := agg.Pattern
		if agg.Count > 1 {
			displayURL = fmt.Sprintf("%s\n(Aggregated %d URLs)", agg.Pattern, agg.Count)
		}

		fpStr := formatFingerprints(r.Fingerprints)
		if fpStr == "" {
			fpStr = "-"
		}
		
		// 合并蜜罐到指纹列，减少列数
		if r.Honeypot.IsHoneypot {
			hpMsg := color.RedString("HONEYPOT: %v", strings.Join(r.Honeypot.Findings, ", "))
			if fpStr == "-" {
				fpStr = hpMsg
			} else {
				fpStr += "\n" + hpMsg
			}
		}

		// 统计敏感信息
		keysCount := len(r.Assets.Keys)
		sensitiveCount := len(r.Assets.Sensitive)
		apiCount := len(r.Assets.AbsoluteApis) + len(r.Assets.RelativeApis)
		chunkCount := len(r.Assets.WebpackChunks)
		mapCount := len(r.Assets.SourceMaps)
		
		sensitiveStr := fmt.Sprintf("Keys: %d\nConf: %d\nAPIs: %d", keysCount, sensitiveCount, apiCount)
		if chunkCount > 0 || mapCount > 0 {
			sensitiveStr += fmt.Sprintf("\nChunks: %d\nMaps: %d", chunkCount, mapCount)
		}
		
		// 提取 API 路径列表，显示前 5 个
		if apiCount > 0 {
			var apiPaths []string
			count := 0
			for _, api := range r.Assets.AbsoluteApis {
				if count >= 5 { break }
				apiPaths = append(apiPaths, api)
				count++
			}
			for _, api := range r.Assets.RelativeApis {
				if count >= 5 { break }
				apiPaths = append(apiPaths, api)
				count++
			}
			sensitiveStr += "\n---\n" + strings.Join(apiPaths, "\n")
			if apiCount > 5 {
				sensitiveStr += fmt.Sprintf("\n... (+%d more)", apiCount-5)
			}
		}

		if keysCount > 0 || sensitiveCount > 0 {
			sensitiveStr = color.YellowString(sensitiveStr)
		}

		// Nuclei 统计
		nucleiStr := "-"
		if len(r.NucleiFindings) > 0 {
			critical := 0
			high := 0
			medium := 0
			low := 0
			for _, f := range r.NucleiFindings {
				switch strings.ToLower(f.Severity) {
				case "critical":
					critical++
				case "high":
					high++
				case "medium":
					medium++
				case "low":
					low++
				}
			}
			nucleiStr = fmt.Sprintf("C:%d H:%d\nM:%d L:%d", critical, high, medium, low)
			if critical > 0 || high > 0 {
				nucleiStr = color.RedString(nucleiStr)
			} else if medium > 0 {
				nucleiStr = color.YellowString(nucleiStr)
			}
		}

		// 截断过长的 Title
		title := r.Title
		if len(title) > 30 {
			title = title[:27] + "..."
		}

		table.Append([]string{
			displayURL,
			fmt.Sprintf("%d", r.Status),
			title,
			fpStr,
			sensitiveStr,
			nucleiStr,
		})
	}
	table.Render()
}

func formatFingerprints(fps []models.FingerprintInfo) string {
	if len(fps) == 0 {
		return ""
	}
	var list []string
	for _, fp := range fps {
		list = append(list, fmt.Sprintf("%s (%s)", fp.Name, fp.Source))
	}
	return strings.Join(list, "\n")
}

func exportResults(s *scanner.Scanner, filename string, appendMode bool) {
	if strings.HasSuffix(filename, ".csv") {
		saveCSV(s, filename, appendMode)
	} else {
		// 默认为 JSON
		saveJSON(s, filename, appendMode)
	}
}

func saveJSON(s *scanner.Scanner, filename string, appendMode bool) {
	var results []*models.ScanResult

	// 如果是追加模式，先读取现有文件
	if appendMode {
		if _, err := os.Stat(filename); err == nil {
			data, err := os.ReadFile(filename)
			if err == nil && len(data) > 0 {
				var existing []*models.ScanResult
				if err := json.Unmarshal(data, &existing); err != nil {
					color.Yellow("[!] 警告: 无法解析现有文件 %s (可能不是有效的 JSON 数组)，将覆盖文件", filename)
				} else {
					results = append(results, existing...)
				}
			}
		}
	}

	// 添加新结果
	results = append(results, s.Results...)

	// 写入文件
	file, err := os.Create(filename)
	if err != nil {
		color.Red("[-] 创建输出文件失败: %v", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		color.Red("[-] 写入 JSON 失败: %v", err)
	} else {
		if appendMode {
			color.Green("[+] 结果已追加至: %s", filename)
		} else {
			color.Green("[+] 结果已保存至: %s", filename)
		}
	}
}

func saveCSV(s *scanner.Scanner, filename string, appendMode bool) {
	fileExists := false
	if _, err := os.Stat(filename); err == nil {
		fileExists = true
	}

	// 打开模式
	flags := os.O_RDWR | os.O_CREATE | os.O_TRUNC
	if appendMode {
		flags = os.O_RDWR | os.O_CREATE | os.O_APPEND
	}

	file, err := os.OpenFile(filename, flags, 0644)
	if err != nil {
		color.Red("[-] 打开 CSV 文件失败: %v", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头 (如果文件不存在或不是追加模式)
	if !appendMode || !fileExists {
		header := []string{"URL", "Status", "Title", "Server", "Fingerprints", "Honeypot", "Findings", "IPs", "Domains", "Emails", "Sensitive", "APIs", "Chunks", "SourceMaps", "Nuclei"}
		writer.Write(header)
	}

	for _, r := range s.Results {
		// 格式化指纹
		var fps []string
		for _, fp := range r.Fingerprints {
			fps = append(fps, fp.Name)
		}
		fpStr := strings.Join(fps, "|")

		// 格式化蜜罐
		hpStr := "No"
		hpDetails := ""
		if r.Honeypot.IsHoneypot {
			hpStr = "Yes"
			hpDetails = strings.Join(r.Honeypot.Findings, "|")
		}

		// 格式化资产
		ips := strings.Join(r.Assets.IPs, "|")
		domains := strings.Join(r.Assets.Domains, "|")
		emails := strings.Join(r.Assets.Emails, "|")
		
		sensitive := fmt.Sprintf("Keys:%d|Conf:%d|APIs:%d", len(r.Assets.Keys), len(r.Assets.Sensitive), len(r.Assets.AbsoluteApis)+len(r.Assets.RelativeApis))

		// 格式化 APIs
		var apis []string
		apis = append(apis, r.Assets.AbsoluteApis...)
		apis = append(apis, r.Assets.RelativeApis...)
		apisStr := strings.Join(apis, "|")

		// 格式化 Chunks 和 Maps
		chunksStr := strings.Join(r.Assets.WebpackChunks, "|")
		mapsStr := strings.Join(r.Assets.SourceMaps, "|")

		// 格式化 Nuclei
		var nucleiStr string
		if len(r.NucleiFindings) > 0 {
			var findings []string
			for _, f := range r.NucleiFindings {
				findings = append(findings, fmt.Sprintf("[%s]%s", f.Severity, f.Name))
			}
			nucleiStr = strings.Join(findings, "|")
		} else {
			nucleiStr = "-"
		}

		record := []string{
			r.URL,
			fmt.Sprintf("%d", r.Status),
			r.Title,
			r.Server,
			fpStr,
			hpStr,
			hpDetails,
			ips,
			domains,
			emails,
			sensitive,
			apisStr,
			chunksStr,
			mapsStr,
			nucleiStr,
		}
		writer.Write(record)
	}
	
	if appendMode {
		color.Green("[+] 结果已追加至 CSV: %s", filename)
	} else {
		color.Green("[+] 结果已保存至 CSV: %s", filename)
	}
}
