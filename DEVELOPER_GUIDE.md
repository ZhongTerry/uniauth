# 🔌 UniAuth 开发者接入指南

欢迎使用 **UniAuth**！本文档将指导您如何将您的应用接入 UniAuth 生态系统，实现 **OAuth2 单点登录 (SSO)**、获取用户资料以及管理授权状态。

---

## 1. 准备工作

在开始编码之前，您需要在 UniAuth 管理后台注册您的应用。

1.  登录 **UniAuth 仪表盘** (`http://127.0.0.1:5124/dashboard`)。
2.  点击 **"🚀 创建新应用"**。
3.  填写应用名称和 **回调地址 (Redirect URI)**。
    *   *注意：回调地址必须与您代码中的接收地址完全一致（包括 http/https 和端口）。*
4.  创建成功后，您将获得：
    *   **Client ID**: 应用的唯一标识（公开）。
    *   **Client Secret**: 应用密钥（**绝密**，请勿在前端代码中暴露）。

---

## 2. OAuth2 授权流程

UniAuth 遵循标准的 **OAuth 2.0 授权码模式 (Authorization Code Grant)**。

### 步骤 1: 引导用户登录

将用户重定向到 UniAuth 的授权页面。

*   **Endpoint**: `GET /oauth/authorize`
*   **URL 示例**:
    ```http
    http://127.0.0.1:5124/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=profile email
    ```

| 参数 | 必填 | 描述 |
| :--- | :---: | :--- |
| `client_id` | 是 | 您在仪表盘获取的 Client ID |
| `redirect_uri` | 是 | 必须与后台配置的完全一致 |
| `response_type` | 否 | 默认为 `code` |
| `scope` | 否 | 请求的权限范围，多个用空格分隔 (见下文 Scope 列表) |

### 步骤 2: 接收授权码 (Code)

用户同意授权后，浏览器将跳回您的 `redirect_uri`，并附带一个临时 `code`。

*   **回调示例**:
    ```http
    http://your-app.com/callback?code=AuthCode_xyz123...
    ```

### 步骤 3: 换取访问令牌 (Access Token)

使用后台获得的 `code` 向 UniAuth 服务器换取 `access_token`。

*   **Endpoint**: `POST /oauth/token`
*   **Content-Type**: `application/json` 或 `application/x-www-form-urlencoded`

**请求参数:**

```json
{
  "grant_type": "authorization_code",
  "client_id": "您的_CLIENT_ID",
  "client_secret": "您的_CLIENT_SECRET",
  "code": "步骤2收到的code"
}
```

**成功响应 (200 OK):**

```json
{
  "access_token": "at_MzJm...",       // 用于调用 API
  "refresh_token": "rt_Kls9...",      // 用于过期后续期 (有效期30天)
  "token_type": "Bearer",
  "expires_in": 3600,                 // Access Token 有效期 (秒)
  "scope": "profile email"            // 最终授予的权限
}
```

---

## 3. 获取用户资源

拿到 `access_token` 后，您可以调用 API 获取用户信息。

### 获取当前用户信息

*   **Endpoint**: `GET /api/user`
*   **Headers**:
    ```http
    Authorization: Bearer <您的_ACCESS_TOKEN>
    ```

**成功响应示例:**

```json
{
  "id": 101,
  "username": "developer_x",
  "avatar": "http://127.0.0.1:5124/static/uploads/avatar.jpg",
  "email": "dev@example.com",  // 需申请 email 权限
  "phone": "13800138000",      // 需申请 phone 权限
  "bio": "Full Stack Dev",     // 需申请 bio 权限
  "birthday": "1995-01-01"     // 需申请 birthday 权限
}
```

---

## 4. 刷新令牌 (保持登录状态)

`access_token` 的有效期较短（默认 1 小时）。过期后，使用 `refresh_token` 获取新的令牌，无需用户重新登录。

*   **Endpoint**: `POST /oauth/token`

**请求参数:**

```json
{
  "grant_type": "refresh_token",
  "client_id": "您的_CLIENT_ID",
  "client_secret": "您的_CLIENT_SECRET",
  "refresh_token": "您的_REFRESH_TOKEN"
}
```

**成功响应:**
返回新的 `access_token` (结构同步骤 3)。

---

## 5. 权限范围 (Scopes)

您可以在步骤 1 中请求以下 Scope，用户将在授权页看到相应的提示。

| Scope | 描述 | 包含字段 |
| :--- | :--- | :--- |
| `profile` | **(默认)** 基础公开资料 | `id`, `username`, `avatar` |
| `email` | 邮箱地址 | `email` |
| `phone` | 手机号码 | `phone` |
| `bio` | 个人简介 | `bio` |
| `birthday` | 生日信息 | `birthday` |

**示例**: `scope=profile email phone`

---

## 6. 注意事项

注意每个应用应当有一个独一无二的 session 名字，具体实现需要见代码。

## 6. Python 接入示例 (Flask)

```python
import requests
from flask import Flask, redirect, request, session

app = Flask(__name__)
app.secret_key = 'your_client_app_secret'
app.config['SESSION_COOKIE_NAME'] = 'unique_app_session' #独一无二的 session 名字

CLIENT_ID = '填入您的ID'
CLIENT_SECRET = '填入您的Secret'
AUTH_SERVER = 'http://127.0.0.1:5124'
REDIRECT_URI = 'http://127.0.0.1:5000/callback'

@app.route('/login')
def login():
    # 1. 跳转授权
    return redirect(f"{AUTH_SERVER}/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=profile email")

@app.route('/callback')
def callback():
    code = request.args.get('code')
    # 2. 换取 Token
    token_resp = requests.post(f"{AUTH_SERVER}/oauth/token", json={
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code': code
    }).json()
    
    # 3.以此 Token 获取用户
    user_resp = requests.get(f"{AUTH_SERVER}/api/user", headers={
        'Authorization': f"Bearer {token_resp['access_token']}"
    }).json()
    
    return f"欢迎您，{user_resp.get('username')}!"

if __name__ == '__main__':
    app.run(port=5000)
```

---

## ❓ 常见错误排查

*   **HTTP 400: Redirect URI mismatched**
    *   **原因**: 代码中发送的 `redirect_uri` 与后台配置的不一致。
    *   **解决**: 检查端口号、尾部斜杠 `/` 是否完全匹配。

*   **HTTP 401: Invalid Client**
    *   **原因**: `client_id` 或 `client_secret` 错误。
    *   **解决**: 在 UniAuth 仪表盘重置 Secret 并更新代码。

*   **HTTP 401: Token expired**
    *   **原因**: Access Token 已过期。
    *   **解决**: 使用 Refresh Token 流程获取新令牌。