# 🔍 Secure WordPress Recon & Assessment Script

**Author:** Kasau  
**Version:** 2.3  
**Last Modified:** *(Automatically updated)*  
**License:** MIT  
**Language:** Bash  

## 🛡️ Purpose

This script performs a comprehensive and secure assessment of WordPress installations using tools like WPScan, Gobuster, Nikto, WhatWeb, and custom checks. It includes safety features like:

- **Target domain validation**
- **Rate-limiting**
- **Timeout enforcement**
- **Scoped scanning only on permitted domains**

## 📦 Features

- Automatic dependency check and secure output directory creation
- Scans for:
  - WordPress version, plugins, users, and themes
  - Hidden directories and files (via Gobuster)
  - Basic vulnerabilities (via Nikto)
  - HTTP headers, XML-RPC, WP-JSON, SSL checks
- Summarized results and structured logs
- Automatically generates a detailed report

## 🧰 Tools Used

- [WPScan](https://github.com/wpscanteam/wpscan)
- [Gobuster](https://github.com/OJ/gobuster)
- [Nikto](https://github.com/sullo/nikto)
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
- `jq`, `curl`, and core Unix tools

## 📋 Usage

```bash
chmod +x wpsecure_recon.sh
./wpsecure_recon.sh <http://target-wordpress-site.com>
