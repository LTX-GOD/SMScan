# SMScan

高效的 Web 资产扫描与指纹识别工具，集成资产提取、技术栈检测、安全评估等功能。

## ✨ 核心特性

### 🔍 智能检测

- **打包器识别**: 自动检测 Webpack、Vite、Next.js、Gatsby、Nuxt 等 10+ 种现代前端打包器
- **Webpack 模块还原**: 智能还原异步加载的 JS chunk，发现隐藏代码
- **指纹识别**: 1000+ 指纹规则 + FaviconHash
- **技术栈检测**: 前端框架、后端框架、JS库、UI组件、CDN 等
- **Vue 框架分析**: 版本检测、路由提取、组件识别

### 🛡️ 敏感信息检测 (30+ 规则)

- **云服务密钥**: AWS、阿里云 OSS、腾讯云 COS
- **API Token**: GitHub、GitLab、Slack、Stripe、Google API、SendGrid 等
- **凭证信息**: JWT Token、私钥、数据库连接串、硬编码密码
- **个人信息**: 身份证、银行卡、手机号、邮箱
- **内部信息**: 内网 IP、敏感配置、代码注释
- **编码检测**: Base64 编码的敏感数据

### 🚀 高级功能

- **JS 深度爬取**: 递归下载所有 JS 文件（外链 + 内联），自动去重
- **批量扫描**: 并发扫描多个目标，生成聚合报告
- **上下文展示**: 每个匹配项显示行号和代码上下文
- **交互式报告**: 可折叠、可搜索、按严重程度分类的输出
- **安全评估**: 响应头分析、CSP 解析、安全评分
- **蜜罐检测**: 多特征识别
- **Fuzz 扫描**: 内置 300+ 路径/API/JS 字典
- **Nuclei 集成**: PoC 漏洞检测

## 安装

```bash
git clone https://github.com/LTX-GOD/SMScan.git
cd SMScan
go build -o smscan ./cmd/smscan/
```

## 使用方法

```bash
# 基础扫描
./smscan -u https://example.com

# 深度扫描 + 打包器检测
./smscan -u https://example.com -d 3 --enable-packer

# Webpack 模块还原
./smscan -u https://example.com --webpack-recovery

# 高级敏感信息扫描（带上下文）
./smscan -u https://example.com --advanced-scan

# JS 深度爬取
./smscan -u https://example.com --deep-crawl

# 批量扫描 + 聚合报告
./smscan -l urls.txt --batch-mode --aggregate-report

# 完整扫描（所有功能）
./smscan -u https://example.com -d 3 --enable-packer --webpack-recovery --advanced-scan --deep-crawl --fuzz --nuclei -o report.json
```

## 参数说明

| 参数                 | 说明                         | 默认值  |
| -------------------- | ---------------------------- | ------- |
| `-u, --url`          | 目标 URL                     | -       |
| `-l, --list`         | URL 列表文件                 | -       |
| `-d, --depth`        | 爬取深度                     | 2       |
| `-c, --concurrency`  | 并发数                       | 10      |
| `-t, --timeout`      | 超时 (秒)                    | 15      |
| `-f, --fingerprint`  | 指纹配置文件路径             | config/finger.json |
| `--proxy`            | 代理地址                     | -       |
| `--ua`               | 自定义 User-Agent            | -       |
| `--enable-packer`    | 启用打包器检测               | false   |
| `--webpack-recovery` | 启用 Webpack 模块还原        | false   |
| `--deep-crawl`       | 深度爬取 JS 文件             | false   |
| `--advanced-scan`    | 高级敏感信息扫描（带上下文） | false   |
| `--batch-mode`       | 批量扫描模式                 | false   |
| `--aggregate-report` | 生成聚合报告                 | false   |
| `--fuzz`             | 启用 Fuzz 扫描               | false   |
| `--fuzz-mode`        | Fuzz 模式 (path/api/js/all/default) | default |
| `-n, --nuclei`       | 启用 Nuclei 扫描             | false   |
| `-o, --output`       | 输出文件 (json/csv) - 覆盖模式 | -     |
| `-s, --save`         | 保存文件 (json/csv) - 追加模式 | -     |
| `-q, --quiet`        | 静默模式                     | false   |
| `-v, --verbose`      | 详细模式                     | false   |

## 输出示例

```
━━━ 扫描摘要 ━━━
  扫描: 15  指纹: 3  敏感: 5  漏洞: 1  耗时: 12.5s
  APIs: 45  密钥: 2  Vue: 1  打包器: Webpack

━━━ 扫描结果 ━━━
+------------------+------+----------+------------------+----------+------------+
|       URL        | 状态 |   标题   |   指纹/技术栈    |   风险   |    资产    |
+------------------+------+----------+------------------+----------+------------+
| https://xxx.com/ | 200  | Example  | Server: nginx    | HIGH     | API: 45    |
|                  |      |          | 前端: Vue.js     | (65/100) | JWT: 1     |
|                  |      |          | 后端: Spring     |          | 内网IP: 3  |
|                  |      |          | 打包器: Webpack  |          | AWS密钥: 1 |
+------------------+------+----------+------------------+----------+------------+

━━━ 敏感信息详情 ━━━
[CRITICAL] AWS AccessKey
  值: AKIA****************
  位置: app.js:1234
  上下文: const config = { accessKey: "AKIA...", region: "us-east-1" }

[HIGH] JWT Token
  值: eyJ***
  位置: main.js:567
  上下文: localStorage.setItem("token", "eyJ...")

━━━ Webpack 模块还原 ━━━
✓ 发现 15 个异步 chunk:
  - /static/js/2.a3f4b2c1.chunk.js
  - /static/js/3.d5e6f7a8.chunk.js
  ...
```

## 项目结构

```
SMScan/
├── cmd/smscan/          # 主程序
├── pkg/
│   ├── scanner/         # 核心扫描器
│   ├── extractor/       # 资产提取模块
│   │   ├── extractor.go         # 基础提取
│   │   ├── packer.go            # 打包器检测 ⭐
│   │   ├── sensitive.go         # 增强敏感检测 ⭐
│   │   ├── webpack_recovery.go  # Webpack 还原 ⭐
│   │   ├── jscrawler.go         # JS 深度爬取 ⭐
│   │   ├── advanced_scanner.go  # 高级扫描器 ⭐
│   │   ├── batch_scanner.go     # 批量扫描 ⭐
│   │   ├── report.go            # 报告生成 ⭐
│   │   ├── config_loader.go     # 配置加载 ⭐
│   │   ├── vue.go               # Vue 检测
│   │   ├── techdetect.go        # 技术栈检测
│   │   ├── security.go          # 安全分析
│   │   ├── webpack.go           # Webpack 分析
│   │   ├── sourcemap.go         # SourceMap 提取
│   │   └── javascript.go        # JS 分析
│   ├── fingerprint/     # 指纹识别
│   ├── honeypot/        # 蜜罐检测
│   ├── fuzz/            # Fuzz 扫描
│   │   └── dicts/       # 内置字典
│   ├── models/          # 数据模型
│   ├── ui/              # UI 组件
│   └── utils/           # 工具函数
└── config/              # 配置文件
    └── sensitive_patterns.json  # 敏感信息规则库 ⭐
```

⭐ 标记为新增核心模块

## 🚀 快速开始

### 基础扫描

```bash
./smscan -u https://example.com
```

### 完整扫描（推荐）

```bash
./smscan -u https://example.com \
  --enable-packer \
  --webpack-recovery \
  --advanced-scan \
  --deep-crawl \
  -o report.html
```

### 批量扫描

```bash
# 创建目标列表
cat > targets.txt << EOF
https://example1.com
https://example2.com
https://example3.com
EOF

# 批量扫描并生成聚合报告
./smscan -l targets.txt --batch-mode --aggregate-report -o aggregate.html
```

## 🎯 核心优势

1. **智能打包器识别** - 自动检测 10+ 种现代前端打包器
2. **Webpack 模块还原** - 发现隐藏的异步加载代码
3. **30+ 敏感信息规则** - 覆盖云服务、API Token、个人信息
4. **深度 JS 爬取** - 递归下载 + 自动去重
5. **批量扫描** - 并发处理多目标
6. **交互式报告** - 可折叠、可搜索、带上下文

## 致谢

- [Packer-InfoFinder](https://github.com/TFour123/Packer-InfoFinder) - Webpack 模块还原灵感来源
- [Phantom (无影)](https://github.com/Team-intN18-SoybeanSeclab/Phantom)
- [XMCVE-WebRecon](https://github.com/duckpigdog/XMCVE-WebRecon)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Colly](https://github.com/gocolly/colly)

## 许可证

MIT License
