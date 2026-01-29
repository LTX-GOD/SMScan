# SMScan

高效的 Web 资产扫描与指纹识别工具，集成资产提取、技术栈检测、安全评估等功能。

## 特性

- **资产提取**: IP、域名、邮箱、手机号、API 端点等
- **敏感信息检测**:
  - API 密钥 (AWS, GitHub, 支付宝, 微信等)
  - JWT Token, 私钥, 数据库连接串
  - 身份证、银行卡、硬编码凭证
  - 内网 IP、代码注释等
- **指纹识别**: 1000+ 指纹规则 + FaviconHash
- **技术栈检测**: 前端框架、后端框架、JS库、UI组件、CDN 等
- **Vue 框架分析**: 版本检测、路由提取、组件识别
- **安全评估**: 响应头分析、CSP 解析、安全评分
- **蜜罐检测**: 多特征识别
- **Fuzz 扫描**: 内置 300+ 路径/API/JS 字典
- **Nuclei 集成**: PoC 漏洞检测
- **深度爬取**: 支持多层级 URL 发现

## 安装

```bash
git clone https://github.com/xxx/SMScan.git
cd SMScan
go build -o smscan ./cmd/smscan/
```

## 使用方法

```bash
# 基础扫描
./smscan -u https://example.com

# 深度扫描 + Fuzz
./smscan -u https://example.com -d 3 --fuzz

# 批量扫描 + 导出
./smscan -l urls.txt -o results.json

# 完整扫描
./smscan -u https://example.com -d 2 -c 20 --fuzz --nuclei -v -o out.json
```

## 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-u, --url` | 目标 URL | - |
| `-l, --list` | URL 列表文件 | - |
| `-d, --depth` | 爬取深度 | 2 |
| `-c, --concurrency` | 并发数 | 10 |
| `-t, --timeout` | 超时 (秒) | 15 |
| `--proxy` | 代理地址 | - |
| `--ua` | 自定义 User-Agent | - |
| `--fuzz` | 启用 Fuzz 扫描 | false |
| `--fuzz-mode` | Fuzz 模式 (path/api/js/all) | default |
| `-n, --nuclei` | 启用 Nuclei 扫描 | false |
| `-o, --output` | 输出文件 (json/csv) | - |
| `-s, --save` | 追加保存文件 | - |
| `-q, --quiet` | 静默模式 | false |
| `-v, --verbose` | 详细模式 | false |

## 输出示例

```
━━━ 扫描摘要 ━━━
  扫描: 15  指纹: 3  敏感: 5  漏洞: 1  耗时: 12.5s
  APIs: 45  密钥: 2  Vue: 1

━━━ 扫描结果 ━━━
+------------------+------+----------+------------------+----------+------------+
|       URL        | 状态 |   标题   |   指纹/技术栈    |   风险   |    资产    |
+------------------+------+----------+------------------+----------+------------+
| https://xxx.com/ | 200  | Example  | Server: nginx    | HIGH     | API: 45    |
|                  |      |          | 前端: Vue.js     | (65/100) | JWT: 1     |
|                  |      |          | 后端: Spring     |          | 内网IP: 3  |
+------------------+------+----------+------------------+----------+------------+
```

## 项目结构

```
SMScan/
├── cmd/smscan/          # 主程序
├── pkg/
│   ├── scanner/         # 核心扫描器
│   ├── extractor/       # 资产提取模块
│   │   ├── extractor.go     # 基础提取
│   │   ├── vue.go           # Vue 检测
│   │   ├── techdetect.go    # 技术栈检测
│   │   ├── security.go      # 安全分析
│   │   ├── webpack.go       # Webpack 分析
│   │   └── sourcemap.go     # SourceMap 提取
│   ├── fingerprint/     # 指纹识别
│   ├── honeypot/        # 蜜罐检测
│   ├── fuzz/            # Fuzz 扫描
│   │   └── dicts/       # 内置字典
│   ├── models/          # 数据模型
│   ├── ui/              # UI 组件
│   └── utils/           # 工具函数
└── config/              # 配置文件
```

## 致谢

- [Phantom (无影)](https://github.com/Team-intN18-SoybeanSeclab/Phantom)
- [XMCVE-WebRecon](https://github.com/user/XMCVE-WebRecon)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Colly](https://github.com/gocolly/colly)
