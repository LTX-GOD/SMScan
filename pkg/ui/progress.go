package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Progress 进度显示器
type Progress struct {
	total     int
	current   int
	mu        sync.Mutex
	startTime time.Time
	message   string
	spinner   int
	done      bool
	doneChan  chan struct{}
}

var spinnerChars = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// NewProgress 创建新的进度显示器
func NewProgress(total int) *Progress {
	p := &Progress{
		total:     total,
		startTime: time.Now(),
		doneChan:  make(chan struct{}),
	}
	go p.run()
	return p
}

func (p *Progress) run() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.mu.Lock()
			if !p.done {
				p.render()
			}
			p.mu.Unlock()
		case <-p.doneChan:
			return
		}
	}
}

func (p *Progress) render() {
	p.spinner = (p.spinner + 1) % len(spinnerChars)
	elapsed := time.Since(p.startTime)

	// 清除当前行
	fmt.Print("\r\033[K")

	// 进度条
	width := 30
	filled := 0
	if p.total > 0 {
		filled = int(float64(p.current) / float64(p.total) * float64(width))
	}
	if filled > width {
		filled = width
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	percent := 0
	if p.total > 0 {
		percent = int(float64(p.current) / float64(p.total) * 100)
	}

	// 速率计算
	rate := float64(0)
	if elapsed.Seconds() > 0 {
		rate = float64(p.current) / elapsed.Seconds()
	}

	// 显示
	cyan := color.New(color.FgCyan).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	fmt.Printf("%s %s [%s] %s/%s (%d%%) %.1f/s %s",
		cyan(spinnerChars[p.spinner]),
		yellow("扫描中"),
		bar,
		fmt.Sprintf("%d", p.current),
		fmt.Sprintf("%d", p.total),
		percent,
		rate,
		p.message,
	)
}

// Update 更新进度
func (p *Progress) Update(current int, message string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = current
	p.message = message
}

// Increment 增加进度
func (p *Progress) Increment(message string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current++
	p.message = message
}

// SetTotal 设置总数
func (p *Progress) SetTotal(total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.total = total
}

// Stop 停止进度显示
func (p *Progress) Stop() {
	p.mu.Lock()
	p.done = true
	p.mu.Unlock()
	close(p.doneChan)
	fmt.Print("\r\033[K") // 清除当前行
}

// Banner 打印启动 Banner
func PrintBanner() {
	banner := `
   _____ __  __  _____
  / ____|  \/  |/ ____|
 | (___ | \  / | (___   ___ __ _ _ __
  \___ \| |\/| |\___ \ / __/ _` + "`" + ` | '_ \
  ____) | |  | |____) | (_| (_| | | | |
 |_____/|_|  |_|_____/ \___\__,_|_| |_|

`
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Println(banner)

	info := color.New(color.FgWhite)
	info.Println("  Web Asset Scanner & Fingerprint Identifier")
	info.Println("  https://github.com/example/smscan")
	fmt.Println()
}

// PrintSection 打印分隔区域
func PrintSection(title string) {
	cyan := color.New(color.FgCyan, color.Bold)
	fmt.Println()
	cyan.Printf("━━━ %s ━━━\n", title)
}

// PrintSuccess 打印成功信息
func PrintSuccess(format string, a ...interface{}) {
	green := color.New(color.FgGreen)
	green.Printf("[+] "+format+"\n", a...)
}

// PrintInfo 打印信息
func PrintInfo(format string, a ...interface{}) {
	cyan := color.New(color.FgCyan)
	cyan.Printf("[*] "+format+"\n", a...)
}

// PrintWarning 打印警告
func PrintWarning(format string, a ...interface{}) {
	yellow := color.New(color.FgYellow)
	yellow.Printf("[!] "+format+"\n", a...)
}

// PrintError 打印错误
func PrintError(format string, a ...interface{}) {
	red := color.New(color.FgRed)
	red.Printf("[-] "+format+"\n", a...)
}

// PrintVuln 打印漏洞信息
func PrintVuln(severity, name, detail string) {
	var c *color.Color
	switch strings.ToLower(severity) {
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
	c.Printf("[%s] %s - %s\n", strings.ToUpper(severity), name, detail)
}

// SeverityColor 根据严重性返回颜色函数
func SeverityColor(severity string) func(a ...interface{}) string {
	switch strings.ToLower(severity) {
	case "critical":
		return color.New(color.FgRed, color.Bold).SprintFunc()
	case "high":
		return color.New(color.FgRed).SprintFunc()
	case "medium":
		return color.New(color.FgYellow).SprintFunc()
	case "low":
		return color.New(color.FgBlue).SprintFunc()
	default:
		return color.New(color.FgCyan).SprintFunc()
	}
}
