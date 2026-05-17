<div align="center">

# 🔍 ProcTrace

### 进程追踪与安全分析工具
### Process Tracing & Security Analysis Tool

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

[English](#english) | [简体中文](#简体中文) | [繁體中文](#繁體中文)

</div>

---

<a name="简体中文"></a>
# 🇨🇳 简体中文

## 🎉 项目介绍

**ProcTrace** 是一款专注于系统安全分析的进程追踪工具，帮助用户快速识别系统中的可疑进程和潜在威胁。

### 灵感来源

本项目灵感来源于 [witr](https://github.com/pranshuparmar/witr)（"Why is this running?"），但我们进行了**完全独立自研开发**，专注于**安全分析维度**的差异化创新：

- 🔴 **威胁评分系统** - 基于多维度指标计算进程威胁分数
- 🌐 **Web可视化界面** - 实时展示进程风险分布与资源使用
- 🛡️ **可疑行为检测** - 内置多种安全检测规则
- 📊 **进程树分析** - 可视化展示进程血缘关系

### ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 🔍 **进程扫描** | 全系统进程信息获取与分析 |
| 🎯 **威胁评分** | 0-100分智能威胁评估系统 |
| ⚠️ **风险分级** | 高/中/低/安全 四级风险分类 |
| 🌐 **Web可视化** | 现代化仪表盘实时展示 |
| 📈 **资源监控** | CPU/内存使用率Top排行 |
| 🔗 **网络连接** | 进程网络连接状态分析 |
| 📄 **报告导出** | JSON/Text格式报告生成 |
| 🖥️ **跨平台** | 支持Windows/Linux/macOS |

## 🚀 快速开始

### 环境要求

- Python 3.8 或更高版本
- 支持平台：Windows / Linux / macOS

### 安装步骤

#### 方式一：通过 pip 安装

```bash
pip install proctrace
```

#### 方式二：从源码安装

```bash
git clone https://github.com/gitstq/proctrace.git
cd proctrace
pip install -r requirements.txt
pip install -e .
```

#### 方式三：使用独立可执行文件

从 [Releases](https://github.com/gitstq/proctrace/releases) 页面下载对应平台的可执行文件。

### 基本使用

```bash
# 扫描所有进程
proctrace scan

# 仅显示可疑进程
proctrace scan --suspicious

# 仅显示高风险进程
proctrace scan --high-risk

# 查看指定进程详情
proctrace scan --pid 1234

# 生成JSON报告
proctrace report --output json

# 启动Web可视化界面
proctrace web

# 指定端口启动
proctrace web --port 8080
```

## 📖 详细使用指南

### 命令行工具

#### 1. 进程扫描 (scan)

```bash
# 基础扫描
proctrace scan

# 仅显示可疑进程
proctrace scan -s

# 仅显示高风险进程
proctrace scan -r

# JSON格式输出
proctrace scan --json

# 查看指定PID
proctrace scan -p 1234
```

#### 2. Web服务 (web)

```bash
# 默认启动 (127.0.0.1:5000)
proctrace web

# 指定地址和端口
proctrace web --host 0.0.0.0 --port 8080

# 调试模式
proctrace web --debug
```

启动后访问 http://127.0.0.1:5000 查看可视化仪表盘。

#### 3. 报告生成 (report)

```bash
# 文本格式报告
proctrace report

# JSON格式报告
proctrace report --output json

# 保存到文件
proctrace report -o json --file report.json
```

### Web界面功能

- 📊 **仪表盘概览** - 总进程数、可疑进程、高风险进程统计
- 🥧 **风险分布图** - 饼图展示各级别风险进程占比
- 📈 **资源使用排行** - CPU/内存使用率Top10进程
- 📋 **可疑进程列表** - 详细的威胁指标展示
- 🔄 **自动刷新** - 每30秒自动更新数据

## 💡 设计思路与迭代规划

### 技术选型原因

| 技术 | 选择原因 |
|------|----------|
| **Python** | 跨平台支持好，psutil库功能强大 |
| **Flask** | 轻量级Web框架，适合嵌入式部署 |
| **ECharts** | 开源可视化库，图表效果丰富 |
| **psutil** | 跨平台进程和系统监控库 |

### 威胁评分算法

威胁评分基于以下维度计算：

1. **进程名称检测** (+30分) - 匹配已知恶意软件模式
2. **执行路径分析** (+20分) - 检测可疑临时目录执行
3. **父进程检查** (+15分) - 识别孤儿进程
4. **网络连接分析** (+10分) - 大量外部连接检测
5. **资源使用监控** (+10分) - 异常CPU/内存占用
6. **命令行参数** (+25分) - 检测可疑PowerShell/编码命令

### 后续迭代计划

- [ ] YARA规则集成 - 恶意软件签名检测
- [ ] 行为监控模块 - 实时监控进程行为
- [ ] 云端威胁情报 - 哈希值云端查询
- [ ] 邮件告警功能 - 发现高风险进程时通知
- [ ] 历史数据存储 - SQLite数据持久化

## 📦 打包与部署

### 构建独立可执行文件

```bash
# 安装打包依赖
pip install pyinstaller

# 执行构建
python build.py

# 仅清理构建目录
python build.py --clean
```

构建完成后，`dist/`目录将包含：
- `proctrace` (Linux/macOS) 或 `proctrace.exe` (Windows)
- 分发压缩包 `proctrace-v1.0.0-{platform}-{arch}.zip`

### 跨平台兼容性

| 平台 | 支持状态 | 测试版本 |
|------|----------|----------|
| Windows 10/11 | ✅ 完全支持 | 测试通过 |
| Ubuntu 20.04+ | ✅ 完全支持 | 测试通过 |
| macOS 12+ | ✅ 完全支持 | 测试通过 |

## 🤝 贡献指南

欢迎提交Issue和Pull Request！

### 提交规范

- 使用 [Conventional Commits](https://conventionalcommits.org/) 规范
- 类型：`feat:` 新功能 / `fix:` 修复 / `docs:` 文档 / `refactor:` 重构

### 开发环境搭建

```bash
git clone https://github.com/gitstq/proctrace.git
cd proctrace
pip install -r requirements.txt
pip install -e ".[dev]"
```

## 📄 开源协议

本项目采用 [MIT License](LICENSE) 开源协议。

---

<a name="english"></a>
# 🇬🇧 English

## 🎉 Introduction

**ProcTrace** is a process tracing tool focused on system security analysis, helping users quickly identify suspicious processes and potential threats in the system.

### Inspiration

This project is inspired by [witr](https://github.com/pranshuparmar/witr) ("Why is this running?"), but we have developed it **completely independently**, focusing on **security analysis dimensions** for differentiated innovation:

- 🔴 **Threat Scoring System** - Calculate process threat scores based on multi-dimensional indicators
- 🌐 **Web Visualization Interface** - Real-time display of process risk distribution and resource usage
- 🛡️ **Suspicious Behavior Detection** - Built-in multiple security detection rules
- 📊 **Process Tree Analysis** - Visual display of process blood relationships

### ✨ Core Features

| Feature | Description |
|---------|-------------|
| 🔍 **Process Scan** | Full system process information acquisition and analysis |
| 🎯 **Threat Scoring** | 0-100 intelligent threat assessment system |
| ⚠️ **Risk Classification** | High/Medium/Low/Safe four-level risk classification |
| 🌐 **Web Visualization** | Modern dashboard real-time display |
| 📈 **Resource Monitoring** | CPU/Memory usage Top ranking |
| 🔗 **Network Connection** | Process network connection status analysis |
| 📄 **Report Export** | JSON/Text format report generation |
| 🖥️ **Cross-platform** | Support Windows/Linux/macOS |

## 🚀 Quick Start

### Requirements

- Python 3.8 or higher
- Supported platforms: Windows / Linux / macOS

### Installation

#### Method 1: Install via pip

```bash
pip install proctrace
```

#### Method 2: Install from source

```bash
git clone https://github.com/gitstq/proctrace.git
cd proctrace
pip install -r requirements.txt
pip install -e .
```

#### Method 3: Use standalone executable

Download the executable for your platform from the [Releases](https://github.com/gitstq/proctrace/releases) page.

### Basic Usage

```bash
# Scan all processes
proctrace scan

# Show only suspicious processes
proctrace scan --suspicious

# Show only high-risk processes
proctrace scan --high-risk

# View specific process details
proctrace scan --pid 1234

# Generate JSON report
proctrace report --output json

# Start Web visualization interface
proctrace web

# Start with specified port
proctrace web --port 8080
```

## 📖 Detailed Usage Guide

### Command Line Tool

#### 1. Process Scan (scan)

```bash
# Basic scan
proctrace scan

# Show only suspicious processes
proctrace scan -s

# Show only high-risk processes
proctrace scan -r

# JSON format output
proctrace scan --json

# View specific PID
proctrace scan -p 1234
```

#### 2. Web Service (web)

```bash
# Default startup (127.0.0.1:5000)
proctrace web

# Specify address and port
proctrace web --host 0.0.0.0 --port 8080

# Debug mode
proctrace web --debug
```

After startup, visit http://127.0.0.1:5000 to view the visualization dashboard.

#### 3. Report Generation (report)

```bash
# Text format report
proctrace report

# JSON format report
proctrace report --output json

# Save to file
proctrace report -o json --file report.json
```

### Web Interface Features

- 📊 **Dashboard Overview** - Total processes, suspicious processes, high-risk process statistics
- 🥧 **Risk Distribution Chart** - Pie chart showing proportion of risk levels
- 📈 **Resource Usage Ranking** - CPU/Memory usage Top10 processes
- 📋 **Suspicious Process List** - Detailed threat indicator display
- 🔄 **Auto Refresh** - Automatic data update every 30 seconds

## 💡 Design Philosophy & Iteration Plan

### Technology Selection

| Technology | Reason for Selection |
|------------|---------------------|
| **Python** | Good cross-platform support, powerful psutil library |
| **Flask** | Lightweight web framework, suitable for embedded deployment |
| **ECharts** | Open source visualization library, rich chart effects |
| **psutil** | Cross-platform process and system monitoring library |

### Threat Scoring Algorithm

Threat scoring is calculated based on the following dimensions:

1. **Process Name Detection** (+30 points) - Match known malware patterns
2. **Execution Path Analysis** (+20 points) - Detect suspicious temporary directory execution
3. **Parent Process Check** (+15 points) - Identify orphan processes
4. **Network Connection Analysis** (+10 points) - High volume external connection detection
5. **Resource Usage Monitoring** (+10 points) - Abnormal CPU/Memory usage
6. **Command Line Parameters** (+25 points) - Detect suspicious PowerShell/encoded commands

### Future Iteration Plans

- [ ] YARA rule integration - Malware signature detection
- [ ] Behavior monitoring module - Real-time process behavior monitoring
- [ ] Cloud threat intelligence - Hash value cloud query
- [ ] Email alert function - Notification when high-risk processes are found
- [ ] Historical data storage - SQLite data persistence

## 📦 Packaging & Deployment

### Build Standalone Executable

```bash
# Install packaging dependencies
pip install pyinstaller

# Execute build
python build.py

# Clean build directory only
python build.py --clean
```

After build completion, the `dist/` directory will contain:
- `proctrace` (Linux/macOS) or `proctrace.exe` (Windows)
- Distribution package `proctrace-v1.0.0-{platform}-{arch}.zip`

### Cross-platform Compatibility

| Platform | Support Status | Test Version |
|----------|---------------|--------------|
| Windows 10/11 | ✅ Fully Supported | Tested |
| Ubuntu 20.04+ | ✅ Fully Supported | Tested |
| macOS 12+ | ✅ Fully Supported | Tested |

## 🤝 Contribution Guide

Issues and Pull Requests are welcome!

### Commit Convention

- Use [Conventional Commits](https://conventionalcommits.org/) specification
- Types: `feat:` New feature / `fix:` Fix / `docs:` Documentation / `refactor:` Refactoring

### Development Environment Setup

```bash
git clone https://github.com/gitstq/proctrace.git
cd proctrace
pip install -r requirements.txt
pip install -e ".[dev]"
```

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<a name="繁體中文"></a>
# 🇹