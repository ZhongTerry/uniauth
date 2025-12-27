# 🛡️ UniAuth - 轻量级企业级 OAuth2 认证中心

UniAuth 是一个基于 Flask 构建的现代化、安全且功能完备的 OAuth2 身份认证提供商 (Identity Provider)。它旨在为您的应用生态系统提供统一的单点登录 (SSO) 服务。

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Python](https://img.shields.io/badge/python-3.8%2B-green.svg) ![Flask](https://img.shields.io/badge/framework-Flask-lightgrey.svg)

## ✨ 核心特性

*   **标准的 OAuth2 流程**：支持授权码模式 (Authorization Code)，配备 Refresh Token 自动续期机制。
*   **企业级安全防护**：
    *   🛡️ **全站 CSRF 防护**：防止跨站请求伪造。
    *   🚦 **API 速率限制 (Rate Limiting)**：防止暴力破解和接口滥用。
    *   🔒 **安全注册**：本地图片验证码 + SMTP 邮箱验证码（支持国内主流邮箱白名单）。
*   **完善的用户体系**：
    *   支持头像上传（本地存储/绝对路径返回）。
    *   支持扩展资料（手机号、简介、生日）。
    *   找回密码流程（邮件重置）。
*   **可视化仪表盘**：
    *   **开发者后台**：应用管理、密钥重置、回调地址修改。
    *   **数据统计**：全站流量大屏、单应用 API 调用趋势图 (Chart.js)。
*   **权限控制 (Scopes)**：支持 `profile`, `email`, `phone` 等细粒度权限申请。

---

## 🚀 快速开始

### 1. 环境准备

确保您的环境中已安装 Python 3.8+。

```bash
# 1. 克隆项目
git clone https://github.com/your-repo/uniauth.git
cd uniauth

# 2. 创建并激活虚拟环境 (可选但推荐)
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 3. 安装依赖
pip install -r requirements.txt
```

> **注意**：如果没有 `requirements.txt`，请先安装核心库：
> `pip install Flask Flask-SQLAlchemy Flask-Migrate Flask-WTF Flask-Limiter Flask-Mail captcha email-validator chart.js`

### 2. 初始化配置

打开 `app.py`，找到配置区域，**务必修改以下配置**以使其正常工作：

```python
# app.py

# 1. 修改密钥 (生产环境务必修改)
app.secret_key = '请修改为一个复杂的随机字符串'

# 2. 配置 SMTP 邮件服务 (用于发送验证码)
app.config['MAIL_SERVER'] = 'smtp.qq.com'      # 例如使用 QQ 邮箱
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'your_email@qq.com'
app.config['MAIL_PASSWORD'] = 'your_smtp_auth_code' # 邮箱授权码
app.config['MAIL_DEFAULT_SENDER'] = 'UniAuth <your_email@qq.com>'
```

### 3. 初始化数据库

UniAuth 使用 Flask-Migrate 管理数据库，无需手动删库。

```bash
# 初始化迁移仓库
flask db init

# 生成迁移脚本
flask db migrate -m "Initial migration"

# 应用到数据库
flask db upgrade
```

### 4. 启动服务

```bash
python app.py
```

*   **访问地址**: `http://127.0.0.1:5124`
*   **管理员账号**: 系统会自动将**第一个注册的用户**设置为超级管理员。

---

## 🔌 OAuth2 接入指南 (给第三方开发者)

您的应用（Client）可以通过以下步骤接入 UniAuth：

### 1. 注册应用
登录 UniAuth 仪表盘，创建一个新应用，获取：
*   **Client ID**: `your_client_id`
*   **Client Secret**: `your_client_secret`
*   **Redirect URI**: `http://your-app.com/callback` (必须完全匹配)

### 2. 发起授权请求 (GET)

引导用户访问以下地址：

```http
http://127.0.0.1:5124/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=profile email phone
```

*   **scope 参数 (可选)**: `profile` (默认), `email`, `phone`, `bio`, `birthday`。多个权限用空格分隔。

### 3. 获取 Access Token (POST)

用户同意授权后，UniAuth 会重定向回您的 `redirect_uri` 并附带 `code`。使用该 `code` 换取 Token：

**请求:**
`POST http://127.0.0.1:5124/oauth/token`

**Payload (JSON):**
```json
{
  "grant_type": "authorization_code",
  "client_id": "your_client_id",
  "client_secret": "your_client_secret",
  "code": "received_auth_code"
}
```

**响应:**
```json
{
  "access_token": "at_MzJm...",
  "refresh_token": "rt_Kls9...",
  "expires_in": 3600,
  "scope": "profile email",
  "token_type": "Bearer"
}
```

### 4. 获取用户信息 (GET)

使用 Access Token 获取用户资料。

**请求:**
`GET http://127.0.0.1:5124/api/user`

**Header:**
`Authorization: Bearer <your_access_token>`

**响应 (根据 Scope 不同而变化):**
```json
{
  "id": 1,
  "username": "zhangsan",
  "avatar": "http://127.0.0.1:5124/static/uploads/avatar.jpg",
  "email": "zhangsan@qq.com",
  "phone": "13800138000"
}
```

### 5. 刷新令牌 (POST)

当 Access Token 过期时，使用 Refresh Token 获取新的 Token，无需用户重新登录。

**请求:**
`POST http://127.0.0.1:5124/oauth/token`

**Payload (JSON):**
```json
{
  "grant_type": "refresh_token",
  "client_id": "your_client_id",
  "client_secret": "your_client_secret",
  "refresh_token": "your_refresh_token"
}
```

---

## 📂 项目结构

```text
UniAuth/
├── app.py               # 核心入口与业务逻辑
├── uniauth.db           # SQLite 数据库文件
├── migrations/          # 数据库迁移脚本目录
├── static/
│   └── uploads/         # 用户上传的头像文件
├── templates/
│   ├── base.html        # 基础模板 (含 CSRF 注入, Toast 提示)
│   ├── login.html       # 登录/注册页 (Tab切换, 验证码逻辑)
│   ├── dashboard.html   # 开发者仪表盘
│   ├── profile.html     # 用户个人中心
│   ├── app_details.html # 应用详情页
│   ├── app_stats.html   # 应用专属统计 (Chart.js)
│   ├── admin_stats.html # 管理员全局统计
│   ├── authorize.html   # OAuth 授权确认页
│   └── ... (其他页面)
└── client_demo.py       # (可选) 用于测试接入的 Demo 客户端
```

---

## ⚙️ 常见问题 (FAQ)

**Q: 为什么提示 "Redirect URI mismatched"?**
A: 请确保代码中请求的 `redirect_uri` 与 UniAuth 仪表盘中填写的地址**完全一致**（包括 `http/https`、端口号和末尾斜杠）。

**Q: 头像为什么不显示？**
A: 确保 `static/uploads` 文件夹存在。如果你使用的是相对路径，UniAuth 已经优化了 API，会自动返回带域名的绝对路径。

**Q: 如何成为管理员？**
A: 初始化数据库后，**第一个注册**的用户会自动获得管理员权限。

---

## 📝 依赖列表 (requirements.txt)

为了方便其他开发者，你可以直接提供以下依赖内容：

```text
Flask==2.3.2
Flask-SQLAlchemy==3.0.3
Flask-Migrate==4.0.4
Flask-WTF==1.1.1
Flask-Limiter==3.3.1
Flask-Mail==0.9.1
captcha==0.4
email-validator==2.0.0
Werkzeug==2.3.6
itsdangerous==2.1.2
requests==2.31.0
```