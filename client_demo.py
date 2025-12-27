from flask import Flask, redirect, request, session, url_for, jsonify
import requests

app = Flask(__name__)
app.secret_key = 'client_secret_demo'

# === 配置 ===
# 请务必替换为你刚才在 Dashboard 创建的 App 信息
CLIENT_ID = '1cf9062d9cd64dc0fb0e' 
CLIENT_SECRET = '493676326dc3f8c2b70b81489326aef24d1dcb29'

AUTH_SERVER = 'http://127.0.0.1:5124'
REDIRECT_URI = 'http://127.0.0.1:8000/callback'

@app.route('/')
def home():
    user = session.get('user')
    tokens = session.get('tokens', {})
    
    if user:
        return f'''
        <div style="font-family: sans-serif; padding: 20px; text-align: center;">
            <img src="{user['avatar']}" width="80" style="border-radius: 50%"><br>
            <h2>Hello, {user['username']}!</h2>
            <p style="color: green;">✅ 状态: 已登录</p>
            
            <div style="background: #f0f0f0; padding: 15px; text-align: left; margin: 20px auto; max-width: 600px; word-break: break-all; border-radius: 8px;">
                <strong>Access Token:</strong><br> {tokens.get('access_token')}<br><br>
                <strong>Refresh Token:</strong><br> {tokens.get('refresh_token')}
            </div>

            <div style="display: flex; gap: 10px; justify-content: center;">
                <a href="/refresh_token"><button style="padding: 10px 20px; cursor: pointer;">🔄 刷新 Token</button></a>
                <a href="/clear_token"><button style="padding: 10px 20px; cursor: pointer;">⚠️ 模拟 Token 过期</button></a>
                <a href="/logout"><button style="padding: 10px 20px; cursor: pointer;">🚪 登出</button></a>
            </div>
        </div>
        '''
    return f'''
    <div style="font-family: sans-serif; padding: 50px; text-align: center;">
        <h1>My Awesome Blog</h1>
        <p>This is a demo client app.</p>
        <a href="/login"><button style="padding: 15px 30px; font-size: 18px; background: #007bff; color: white; border: none; border-radius: 6px; cursor: pointer;">Login with UniAuth</button></a>
    </div>
    '''

@app.route('/login')
def login():
    auth_url = f"{AUTH_SERVER}/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}"
    return redirect(auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    
    # 1. 用 Code 换 Token (Grant Type: authorization_code)
    try:
        token_resp = requests.post(f"{AUTH_SERVER}/oauth/token", json={
            'grant_type': 'authorization_code',
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'code': code
        })
        token_data = token_resp.json()
        
        if 'error' in token_data:
            return f"Error getting token: {token_data}", 400

        # 保存 Tokens
        session['tokens'] = token_data
        
        # 2. 获取用户信息
        access_token = token_data.get('access_token')
        user_resp = requests.get(f"{AUTH_SERVER}/api/user", headers={
            'Authorization': f'Bearer {access_token}'
        })
        
        session['user'] = user_resp.json()
        return redirect('/')
        
    except Exception as e:
        return f"Connection Error: {e}"

@app.route('/refresh_token')
def do_refresh():
    tokens = session.get('tokens', {})
    refresh_token = tokens.get('refresh_token')
    
    if not refresh_token:
        return "No refresh token found! Please login first."
        
    # 3. 用 Refresh Token 换新 Access Token (Grant Type: refresh_token)
    try:
        resp = requests.post(f"{AUTH_SERVER}/oauth/token", json={
            'grant_type': 'refresh_token',
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'refresh_token': refresh_token
        })
        new_data = resp.json()
        
        if 'error' in new_data:
            return f"Refresh failed: {new_data}"
            
        # 更新 Session 中的 Access Token
        # 注意：Refresh Token 本身可能不变，也可能更新，取决于服务器策略。这里我们更新全部。
        tokens.update(new_data)
        session['tokens'] = tokens
        
        return redirect('/')
        
    except Exception as e:
        return f"Error: {e}"

@app.route('/clear_token')
def clear_token():
    # 模拟 Access Token 丢失或过期
    if 'tokens' in session:
        session['tokens']['access_token'] = 'EXPIRED_TOKEN_Simulated'
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    print(f"Client App running at http://127.0.0.1:8000")
    app.run(port=8000)