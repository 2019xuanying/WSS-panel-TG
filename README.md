# **WSS 隧道管理面板 (Axiom V11)**

**WSS (WebSocket Secure) 面板** 是一个企业级的高性能 SSH 隧道管理系统。它采用 **控制平面与数据平面分离** 的先进架构，专为流量转发、用户管理和网络穿透设计。

系统集成了 **WSS (80/443)**、**Stunnel (444)**、**UDP Custom (7400)** 和 **BadVPN UDPGW (7300)** 等多种协议，并提供了一个现代化的 Web 管理界面和功能强大的 Telegram 机器人。

## **📋 目录**

* [✨ 功能特性](https://www.google.com/search?q=%23-%E5%8A%9F%E8%83%BD%E7%89%B9%E6%80%A7)  
* [🚀 快速开始](https://www.google.com/search?q=%23-%E5%BF%AB%E9%80%9F%E5%BC%80%E5%A7%8B)  
* [🖥️ 使用方法](https://www.google.com/search?q=%23%EF%B8%8F-%E4%BD%BF%E7%94%A8%E6%96%B9%E6%B3%95)  
* [⚙️ 配置说明](https://www.google.com/search?q=%23%EF%B8%8F-%E9%85%8D%E7%BD%AE%E8%AF%B4%E6%98%8E)  
* [📱 客户端连接指南](https://www.google.com/search?q=%23-%E5%AE%A2%E6%88%B7%E7%AB%AF%E8%BF%9E%E6%8E%A5%E6%8C%87%E5%8D%97)  
* [🤖 Telegram 机器人](https://www.google.com/search?q=%23-telegram-%E6%9C%BA%E5%99%A8%E4%BA%BA)  
* [🔧 故障排查 (Troubleshooting)](https://www.google.com/search?q=%23-%E6%95%85%E9%9A%9C%E6%8E%92%E6%9F%A5-troubleshooting)  
* [⚠️ 免责声明](https://www.google.com/search?q=%23%EF%B8%8F-%E5%85%8D%E8%B4%A3%E5%A3%B0%E6%98%8E)

## **✨ 功能特性**

|

| 模块 | 描述 |  
| 多协议支持 | 原生支持 WSS (WebSocket \+ TLS)、HTTP Proxy、Stunnel (SSL)、UDP Custom 及 BadVPN UDPGW。 |  
| 实时仪表盘 | 基于 WebSocket 的毫秒级实时监控，展示 CPU/内存负载、实时带宽速率及活跃连接数。 |  
| 用户管理 | 完善的用户生命周期管理：流量配额、到期日、限速 (令牌桶算法)、最大并发限制。 |  
| 安全加固 | 控制平面与数据平面分离，Web 面板以非 Root 权限运行；集成 全局 IP 封禁 和 自动熔断机制。 |  
| Telegram 机器人 | 支持用户自助申请试用、账号绑定/解绑、卡密兑换、流量查询及管理员广播通知。 |  
| 卡密系统 | 内置 CDK/卡密生成与兑换系统，支持自动续期和流量充值。 |  
| 智能负载 | 内置 Payload Eater 技术，兼容各种 HTTP Injector 载荷；支持 Host 白名单 过滤。 |

## **🚀 快速开始**

### **1\. 系统要求**

* OS: Ubuntu 20.04+, Debian 10+ (推荐 Debian 11/12)  
* 架构: AMD64 (x86\_64)  
* 内存: ≥ 512MB

### **2\. 一键部署**

使用 root 用户执行以下命令即可完成安装。脚本会自动处理依赖、编译 BadVPN 并配置 Systemd 服务。

\# 下载并运行部署脚本  
wget \-O deploy.sh \[https://raw.githubusercontent.com/2019xuanying/WSS-panel-TGtest/main/deploy.sh\](https://raw.githubusercontent.com/2019xuanying/WSS-panel-TGtest/main/deploy.sh) && chmod \+x deploy.sh && ./deploy.sh

**安装过程中您需要配置：**

1. **服务端口**（WSS, Stunnel, Panel, UDP Custom 等，默认回车即可）。  
2. **管理员密码**（用于 Web 面板登录）。  
3. **Telegram Bot Token**（可选，用于启用机器人功能）。

### **3\. 更新/维护**

如果代码有更新，只需重新运行上述部署脚本即可（配置会被保留）。

### **4\. 卸载**

\# 下载并运行卸载脚本  
wget \-O NOinstall.sh \[https://raw.githubusercontent.com/2019xuanying/WSS-panel-TGtest/main/NOinstall.sh\](https://raw.githubusercontent.com/2019xuanying/WSS-panel-TGtest/main/NOinstall.sh) && chmod \+x NOinstall.sh && ./NOinstall.sh

## **🖥️ 使用方法**

### **访问管理面板**

安装完成后，通过浏览器访问： http://\<服务器IP\>:\<面板端口\> (默认端口: **54321**)

* **默认用户**: root  
* **密码**: 安装时设置的密码

### **核心操作**

1. **创建用户**: 点击“用户管理” \-\> “新增用户”。设置用户名、密码、流量限制、有效期等。  
2. **实时监控**: 在“仪表盘”查看当前的上传/下载速率和活跃连接 IP。  
3. **载荷生成**: 使用“载荷生成器”快速生成 HTTP Injector 的配置 Payload。  
4. **端口管理**: 在“端口配置”中修改 WSS 或 UDP 服务端口（修改后服务会自动重启）。

## **⚙️ 配置说明**

核心配置文件位于 /etc/wss-panel/config.json。通常建议通过 Web 面板的 **“系统配置”** 页面进行修改，而不是直接编辑文件。

### **关键端口定义**

| 服务名称 | 默认端口 | 说明 |  
| Panel | 54321 | Web 管理面板 (HTTP) |  
| WSS (HTTP) | 80 | WebSocket 隧道 (非加密) |  
| WSS (TLS) | 443 | WebSocket Secure 隧道 (加密) |  
| Stunnel | 444 | SSH over SSL |  
| UDP Custom | 7400 | HTTP Custom 专用 UDP 端口 |  
| BadVPN UDPGW | 7300 | 本地 UDP 转发网关 (仅 127.0.0.1) |

## **📱 客户端连接指南**

### **1\. HTTP Injector (安卓)**

* **Payload (WSS 模式):**  
  GET wss://\<你的域名\>/ HTTP/1.1\[crlf\]Host: \<你的域名\>\[crlf\]Upgrade: websocket\[crlf\]Connection: Upgrade\[crlf\]User-Agent: \[ua\]\[crlf\]Proxy-Authorization: Basic \<Base64令牌\>\[crlf\]\[crlf\]

* **远程代理**: \<服务器IP\>:80  
* **SSH 设置**: 主机 127.0.0.1，端口 22 (通过隧道转发)。

### **2\. UDP Custom (安卓)**

* **IP/Host**: \<服务器IP\>  
* **端口**: 7400 (或您配置的 UDP Custom 端口)  
* **格式**: username:password

## **🤖 Telegram 机器人**

如果配置了 Bot Token，您可以与机器人交互进行自助服务。

| 角色 | 指令 | 描述 |  
| 用户 | /apply | 申请试用账号 |  
| 用户 | /my\_status | 查询当前账号状态（流量/到期日） |  
| 用户 | /bind \<user\> \<pass\> | 将 WSS 账号绑定到 Telegram ID |  
| 用户 | /redeem \<code \> | 兑换卡密进行续期或充值 |  
| 管理员 | /pending | 查看并审批试用申请 |  
| 管理员 | /create\_voucher | 创建新的充值卡密 |  
| 管理员 | /status | 查看服务器系统负载 |

## **🔧 故障排查 (Troubleshooting)**

### **🔴 常见问题：组件启动失败 (BadVPN / UDPGW)**

如果在日志中看到 bind failed 或服务不断重启，通常是因为 **端口 (7300) 被旧进程占用**。

解决方法：  
使用以下自动修复脚本清理僵尸进程并重启服务。

1. 创建修复脚本 fix\_udpgw.sh：  
   nano fix\_udpgw.sh

2. 粘贴以下内容：  
   \#\!/bin/bash  
   \# UDPGW 端口占用自动修复工具  
   PORT=7300  
   echo "正在清理端口 $PORT..."  
   fuser \-k \-n tcp $PORT  
   echo "重启服务..."  
   systemctl stop udpgw  
   systemctl reset-failed udpgw  
   systemctl start udpgw  
   systemctl status udpgw \--no-pager  
   echo "修复完成。"

3. 运行修复：  
   chmod \+x fix\_udpgw.sh && sudo ./fix\_udpgw.sh

### **🟠 常见问题：Web 面板无法访问**

1. 检查服务状态：  
   systemctl status wss\_panel

2. 检查端口是否开放（防火墙）：  
   iptables \-L \-n | grep 54321

### **🟡 常见问题：无法连接 WSS (403/401 错误)**

1. **Host 白名单拦截**：检查面板中的“Host 白名单”设置，确保客户端请求的 Host 头在列表中（或者列表为空以允许所有）。  
2. **时间同步**：确保服务器时间与客户端时间同步。  
3. **日志排查**：  
   \# 查看实时代理日志  
   journalctl \-u wss \-f

### **🔵 高级：释放特定 UDP 端口 (不转发到 7400\)**

如果您需要让某个端口（如 9856）不走 UDP Custom 转发，请运行以下命令：

iptables \-t nat \-I WSS\_UDP\_REDIR 1 \-p udp \--dport 9856 \-j RETURN  
netfilter-persistent save

## **⚠️ 免责声明**

本项目仅供网络技术研究、学习及企业内部管理使用。

1. 严禁将本项目用于任何违反当地法律法规的用途。  
2. 开发者不对使用本项目产生的任何后果负责。  
3. 请勿在生产环境中使用弱密码。