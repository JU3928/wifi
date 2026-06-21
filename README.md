# WiFi 密码破解工具 (Web GUI)

移动端友好的 WiFi 密码穷举破解工具——通过遍历密码字典、自动尝试连接目标热点来破解密码。提供 Web 图形界面，支持手机浏览器访问。

## 功能特性

- 🔍 输入目标 WiFi 名称 (SSID)，一键启动破解
- 📊 实时进度显示（进度条 + 当前尝试密码）
- 📱 移动端优先设计，手机浏览器操作友好
- 🌐 Flask Web 后端 + SSE 推送实时状态
- 🎨 深色现代 UI（Tailwind CSS）
- ⏹ 支持随时停止

## 技术栈

| 层 | 技术 |
|-----|------|
| 后端 | Python 3 + Flask |
| 前端 | HTML5 + Tailwind CSS (CDN) + vanilla JavaScript |
| 通信 | REST API（启动/停止）+ SSE（实时进度推送）|
| 破解方式 | `netsh wlan` 自动连接验证 |

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

仅需 Flask 一个依赖。

### 2. 启动服务

```bash
python server.py
```

### 3. 打开界面

- **本机访问**: http://127.0.0.1:5000
- **手机访问**: http://\<本机IP\>:5000（手机需与电脑在同一网络）

### 4. 使用

1. 在输入框填写目标 WiFi 名称（默认 `2lou`）
2. 点击"开始破解"
3. 等待密码出现，或手动停止

## 项目结构

```
wifi/
├── server.py              # Flask 后端（核心破解逻辑）
├── templates/
│   └── index.html         # 前端界面
├── brute_connect.py       # 原始命令行脚本（独立版）
├── crack_wifi.py          # WPA 握手包离线破解脚本（需抓包文件）
├── common_passwords.txt   # 常见密码字典
├── requirements.txt       # Python 依赖
└── README.md
```

## 工作原理

```
用户输入 SSID
     ↓
后端遍历密码字典
     ↓
netsh wlan add profile  →  写入 WiFi 配置
     ↓
netsh wlan connect      →  尝试连接
     ↓
netsh wlan show interfaces → 检查是否连上
     ↓
连上 → 密码正确 🎉  /  未连上 → 尝试下一个
```

## 注意事项

1. **仅支持 Windows**（依赖 `netsh wlan` 命令）
2. 破解过程中电脑会**断开当前 WiFi**，影响上网
3. 每个密码尝试约需 **5-7 秒**（配置 + 连接 + 验证）
4. 部分杀毒软件可能误报，请添加信任

## ⚠️ 法律免责声明

**本工具仅供安全研究和授权测试使用。**

- 仅可用于破解您**自己拥有**或**已获得书面授权**的 WiFi 网络
- 未经授权破解他人 WiFi 属于**违法行为**，可能面临法律责任
- 使用者需自行承担一切法律后果
- 作者不对任何滥用行为负责

> 《中华人民共和国刑法》第二百八十五条 —— 非法侵入计算机信息系统罪

## License

MIT — 仅供教育及合法授权用途