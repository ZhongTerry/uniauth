import os
import secrets
import time
import datetime
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort, Response
from flask_sqlalchemy import SQLAlchemy
# import urllib
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from itsdangerous import URLSafeTimedSerializer
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from captcha.image import ImageCaptcha
# [新增] 引入迁移库
from flask_migrate import Migrate
import uuid # 用于生成唯一文件名
from werkzeug.utils import secure_filename
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv  # [新增]
load_dotenv()
from werkzeug.middleware.proxy_fix import ProxyFix # 确保导入了
import random
import string
import dns.resolver

# [新增] 安全跳转校验函数
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    # 要求：协议必须是 http/https，且域名必须是当前站点
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc
           


# === 基础配置 ===
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'uniauth.db')

app = Flask(__name__)
# app.secret_key = 'your-secret-key-here-change-in-production111'
app.config['SESSION_COOKIE_NAME'] = 'uniauth_session' 
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
if os.getenv('FLASK_ENV') == 'production':
    # 只有在生产环境，才信任 Nginx 传来的 Header
    # x_for=1, x_proto=1, x_host=1 分别对应 X-Forwarded-For, Proto, Host
    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
    )
    print("🚀 生产环境模式：已启用 ProxyFix 信任 Nginx 代理")
else:
    print("🏠 开发环境模式：直接访问本地端口")

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 限制最大 2MB

# 确保上传目录存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 邮件配置 (保持你之前的配置)
app.secret_key = os.getenv('SECRET_KEY', 'dev-key-please-change')

# [修改] 邮件配置
app.config['MAIL_SERVER'] = 'smtp.163.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
if os.getenv('FLASK_ENV') == 'production':
    # 1. 关闭 Debug 模式 (致命隐患修复)
    app.config['DEBUG'] = False
        
    # 2. Cookie 安全设置
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # 禁止 JS 读取 Cookie (防 XSS)
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # 防 CSRF
    app.config['SESSION_COOKIE_SECURE'] = True    # [注意] 仅允许 HTTPS 发送 Cookie

ALLOWED_DOMAINS = ['qq.com', '163.com', '126.com', 'sina.com', 'aliyun.com', 'gmail.com', 'outlook.com']

csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["3000 per day", "1000 per hour"], storage_uri="memory://")
db = SQLAlchemy(app)
mail = Mail(app)

# [新增] 初始化迁移工具
migrate = Migrate(app, db)

# [修改] 定义更丰富的权限范围
SUPPORTED_SCOPES = {
    'profile': '👤 基础资料 (头像、用户名)',
    'email': '📧 邮箱地址',
    'phone': '📱 手机号码',
    'bio': '📝 个人简介',
    'birthday': '🎂 生日信息',
    'admin': '⚙️ 管理权限'
}

# === 模型定义 ===

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    avatar = db.Column(db.String(200), default="https://api.dicebear.com/7.x/avataaars/svg?seed=Felix")
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    # [新增] 扩展资料字段 (nullable=True 表示选填)
    phone = db.Column(db.String(20), nullable=True)
    bio = db.Column(db.String(500), nullable=True) # 简介
    birthday = db.Column(db.Date, nullable=True)   # 生日
    
    apps = db.relationship('OAuthApp', backref='owner', lazy=True)

class OAuthApp(db.Model):
    __tablename__ = 'oauth_apps'
    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    redirect_uri = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class AuthCode(db.Model):
    __tablename__ = 'auth_codes'
    code = db.Column(db.String(100), primary_key=True)
    client_id = db.Column(db.String(40), db.ForeignKey('oauth_apps.client_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    redirect_uri = db.Column(db.String(200), nullable=False)
    expires_at = db.Column(db.Float, nullable=False)
    scope = db.Column(db.String(200), default='profile')

class AccessToken(db.Model):
    __tablename__ = 'access_tokens'
    token = db.Column(db.String(100), primary_key=True)
    client_id = db.Column(db.String(40), db.ForeignKey('oauth_apps.client_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    expires_at = db.Column(db.Float, nullable=False)
    scope = db.Column(db.String(200), default='profile')

class RefreshToken(db.Model):
    __tablename__ = 'refresh_tokens'
    token = db.Column(db.String(100), primary_key=True)
    client_id = db.Column(db.String(40), db.ForeignKey('oauth_apps.client_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    expires_at = db.Column(db.Float, nullable=False)
    scope = db.Column(db.String(200), default='profile')

class UsageLog(db.Model):
    __tablename__ = 'usage_logs'
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(40), db.ForeignKey('oauth_apps.client_id'), nullable=False)
    endpoint = db.Column(db.String(20), nullable=False) 
    timestamp = db.Column(db.Float, default=time.time)
class InviteLink(db.Model):
    __tablename__ = 'invite_links'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False) # 随机邀请码
    max_uses = db.Column(db.Integer, default=1)                  # 最大使用次数
    current_uses = db.Column(db.Integer, default=0)              # 已使用次数
    expires_at = db.Column(db.DateTime, nullable=False)          # 过期时间
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    @property
    def is_valid(self):
        # 检查是否过期以及次数是否用完
        return self.current_uses < self.max_uses and self.expires_at > datetime.datetime.utcnow()
# === 辅助函数 ===
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login', redirect_uri=request.url))
        user = db.session.get(User, session['user_id'])
        if not user:
            session.clear()
            return redirect(url_for('login', redirect_uri=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login', redirect_uri=request.url))
        user = db.session.get(User, session['user_id'])
        if not user or not user.is_admin:
            flash('🚫 访问拒绝：需要管理员权限', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    if 'user_id' in session: return db.session.get(User, session['user_id'])
    return None

def record_usage(client_id, endpoint):
    try:
        log = UsageLog(client_id=client_id, endpoint=endpoint, timestamp=time.time())
        db.session.add(log)
        db.session.commit()
    except: pass

def get_app_stats(client_id):
    now = time.time()
    periods = { '1h': 3600, '24h': 86400, '7d': 604800, '30d': 2592000 }
    stats = {}
    for label, seconds in periods.items():
        count = UsageLog.query.filter(UsageLog.client_id == client_id, UsageLog.timestamp >= now - seconds).count()
        stats[label] = count
    return stats

# === [新增] 验证码与邮件逻辑 ===

@app.route('/captcha')
def get_captcha():
    """生成图片验证码"""
    image = ImageCaptcha(width=120, height=40)
    # 生成4位随机字符 (大写字母+数字，排除易混淆的 0,O,1,I)
    characters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    captcha_text = ''.join(random.choice(characters) for _ in range(4))
    
    # 存入 Session (注意：这是图片验证码，用于保护邮件接口)
    session['img_captcha'] = captcha_text.lower()
    
    data = image.generate(captcha_text)
    return Response(data, mimetype='image/png')
# 增强版白名单
ALLOWED_EMAIL_DOMAINS = {
    'qq.com', 'vip.qq.com', 'foxmail.com',
    '163.com', 'vip.163.com', '126.com', 'yeah.net',
    'sina.com', 'sina.cn', 'sohu.com',
    'aliyun.com', '139.com', '189.cn', 'wo.cn'
}
@app.route('/send-code', methods=['POST'])
@limiter.limit("5 per minute") 
def send_email_code():
    """发送邮件验证码 (增强安全版)"""
    email = request.form.get('email', '').strip().lower()
    img_code = request.form.get('img_code')
    
    # 1. 校验图片验证码
    if not img_code or img_code.lower() != session.get('img_captcha', ''):
        return jsonify({'status': 'error', 'message': '图片验证码错误'}), 400
    
    # 2. 基础格式校验
    if not email or '@' not in email:
        return jsonify({'status': 'error', 'message': '邮箱格式错误'}), 400
    
    # 3. [核心修复] 白名单域名校验
    username, domain = email.split('@')
    if domain not in ALLOWED_EMAIL_DOMAINS:
        return jsonify({'status': 'error', 'message': '仅支持国内常用邮箱 (QQ/网易/新浪等)，不支持国外或临时邮箱'}), 400
        
    # 4. [核心修复] DNS MX 记录校验 (防止乱填域名)
    try:
        # 查询该域名的邮件服务器记录
        records = dns.resolver.resolve(domain, 'MX')
        if not records:
            raise Exception("No MX record")
    except Exception:
        return jsonify({'status': 'error', 'message': '该邮箱域名无法接收邮件，请检查拼写'}), 400

    # 5. 检查是否已注册
    if User.query.filter_by(email=email).first():
        return jsonify({'status': 'error', 'message': '该邮箱已被注册'}), 400

    # 6. 生成并发送
    email_code = ''.join(random.choices(string.digits, k=6))
    session['email_code'] = email_code
    session['email_code_time'] = time.time()
    session['email_target'] = email 
    
    try:
        msg = Message('UniAuth 注册验证码', recipients=[email])
        msg.body = f"您的验证码是：{email_code}\n有效期10分钟。"
        mail.send(msg)
        return jsonify({'status': 'success', 'message': '验证码已发送'})
    except Exception as e:
        print(f"Mail Error: {e}")
        return jsonify({'status': 'error', 'message': '邮件发送失败，请稍后重试'}), 500
# === 路由：用户认证 ===

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    target_url = request.args.get('redirect_uri') or request.args.get('next')
    if request.method == 'POST':
        target_url = request.form.get('redirect_uri') or target_url
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session.permanent = True 
            session['user_id'] = user.id
            
            # [修复] 安全跳转逻辑
            if target_url and target_url != 'None':
                # 1. 如果是站内跳转 (如 /dashboard)，检查 is_safe_url
                if is_safe_url(target_url):
                    return redirect(target_url)
                
                # 2. 如果是 OAuth 授权流程 (带域名的完整 URL)，检查是否属于合法的 redirect_uri
                # 这是一个简单的检查，严谨的做法是查询 OAuthApp 表
                # 这里简单放行包含 oauth/authorize 的链接，或者你自己写逻辑校验域名
                if '/oauth/authorize' in target_url:
                    return redirect(target_url)
                    
            return redirect(url_for('dashboard'))
        flash('用户名或密码错误', 'error')
    return render_template('login.html', mode='login', redirect_uri=target_url)
@app.route('/register/invite/<code>', methods=['GET', 'POST'])
def register_by_invite(code):
    invite = InviteLink.query.filter_by(code=code).first()
    
    # 验证邀请链接有效性
    if not invite or not invite.is_valid:
        flash('邀请链接无效或已过期', 'error')
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('请填写完整信息', 'error')
        elif User.query.filter_by(username=username).first():
            flash('用户名已存在', 'error')
        else:
            # 自动生成一个占位邮箱，因为 User 模型中 email 是必填且唯一的
            dummy_email = f"invited_{username}_{secrets.token_hex(3)}@invited.local"
            
            new_user = User(
                username=username,
                password_hash=generate_password_hash(password),
                email=dummy_email,
                is_admin=False
            )
            # 更新邀请链接使用次数
            invite.current_uses += 1
            db.session.add(new_user)
            db.session.commit()
            
            flash('注册成功，请登录', 'success')
            return redirect(url_for('login'))
            
    return render_template('register_invite.html', code=code, invite=invite)
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def register():
    target_url = request.args.get('redirect_uri')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        code = request.form['code'] # 邮件验证码
        
        # 1. 基础校验
        if not all([username, password, email, code]):
            flash('请填写完整信息', 'error')
            return render_template('login.html', mode='register', redirect_uri=target_url)
            
        # 2. 校验验证码 (逻辑：存在 + 未过期 + 匹配 + 邮箱一致)
        correct_code = session.get('email_code')
        code_time = session.get('email_code_time', 0)
        target_email = session.get('email_target')
        
        if not correct_code or time.time() - code_time > 600: # 10分钟有效期
            flash('验证码已过期或未发送', 'error')
        elif code != correct_code:
            flash('验证码错误', 'error')
        elif email != target_email:
            flash('提交的邮箱与验证码接收邮箱不一致', 'error')
        elif User.query.filter_by(username=username).first():
            flash('用户名已存在', 'error')
        elif User.query.filter_by(email=email).first():
            flash('邮箱已存在', 'error')
        else:
            # 3. 创建用户
            is_first_user = (User.query.count() == 0)
            new_user = User(
                username=username, 
                password_hash=generate_password_hash(password), 
                email=email,
                is_admin=is_first_user
            )
            db.session.add(new_user)
            db.session.commit()
            
            # 清理 Session 中的验证码
            session.pop('email_code', None)
            
            flash('注册成功，请登录', 'success')
            return redirect(url_for('login', redirect_uri=target_url))
            
    return render_template('login.html', mode='register', redirect_uri=target_url)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user:
            s = URLSafeTimedSerializer(app.secret_key)
            token = s.dumps(user.username, salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True)
            
            # 这里也建议改为发真实邮件，为了简单先保持控制台输出
            print(f"\n📧 [找回密码] To {user.email}: {reset_link}\n")
            flash('重置链接已发送！(请查看服务器控制台)', 'success')
        else:
            flash('如果账号存在，重置链接已发送！', 'success')
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    s = URLSafeTimedSerializer(app.secret_key)
    try:
        username = s.loads(token, salt='password-reset-salt', max_age=900)
    except:
        flash('链接已失效或不合法', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_pwd = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            user.password_hash = generate_password_hash(new_pwd)
            db.session.commit()
            flash('密码修改成功，请登录', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = get_current_user()
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_info':
            # 1. 处理文件上传 (优先级高于 URL)
            file = request.files.get('avatar_file')
            if file and file.filename != '':
                if allowed_file(file.filename):
                    # 生成安全且唯一的文件名
                    ext = file.filename.rsplit('.', 1)[1].lower()
                    filename = f"{user.id}_{uuid.uuid4().hex[:8]}.{ext}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    
                    file.save(filepath)
                    
                    # 更新用户头像路径
                    user.avatar = f"/static/uploads/{filename}"
                else:
                    flash('不支持的文件格式 (仅限 png, jpg, gif)', 'error')
            
            # 2. 处理 URL 输入 (如果没上传文件，且用户手动改了 URL)
            elif request.form.get('avatar_url'):
                # 只有当没有上传文件时，才采用输入框的 URL
                user.avatar = request.form.get('avatar_url')

            # 3. 更新其他字段
            user.phone = request.form.get('phone')
            user.bio = request.form.get('bio')
            
            birthday_str = request.form.get('birthday')
            if birthday_str:
                try:
                    user.birthday = datetime.datetime.strptime(birthday_str, '%Y-%m-%d').date()
                except ValueError:
                    pass
            else:
                user.birthday = None
                
            db.session.commit()
            flash('个人资料已更新', 'success')
            
        elif action == 'update_password':
            # ... (保持原有的密码修改逻辑不变) ...
            old_pwd = request.form.get('old_password')
            new_pwd = request.form.get('new_password')
            confirm_pwd = request.form.get('confirm_password')
            if not check_password_hash(user.password_hash, old_pwd):
                flash('旧密码错误', 'error')
            elif new_pwd != confirm_pwd:
                flash('两次新密码输入不一致', 'error')
            else:
                user.password_hash = generate_password_hash(new_pwd)
                db.session.commit()
                flash('密码修改成功，请重新登录', 'success')
                return redirect(url_for('logout'))
            
    return render_template('profile.html', user=user)

# === 管理面板 & 其他路由 (保持不变，省略以节省篇幅，请复制上一版的内容) ===
# 请将上一版 app.py 中的 admin_stats, dashboard, app_details, oauth/* 等路由原样粘贴在此处
# 务必保证代码完整性
@app.route('/admin/invites', methods=['GET', 'POST'])
@admin_required
def admin_invites():
    if request.method == 'POST':
        max_uses = int(request.form.get('max_uses', 1))
        days = int(request.form.get('days', 7))
        
        # 生成随机 12 位邀请码
        code = secrets.token_hex(6)
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=days)
        
        new_link = InviteLink(code=code, max_uses=max_uses, expires_at=expires_at)
        db.session.add(new_link)
        db.session.commit()
        flash('邀请链接已生成', 'success')
        return redirect(url_for('admin_invites'))

    invites = InviteLink.query.order_by(InviteLink.id.desc()).all()
    return render_template('admin_invites.html', invites=invites, now=datetime.datetime.utcnow())

@app.route('/admin/invites/<int:id>/delete', methods=['POST'])
@admin_required
def delete_invite(id):
    invite = db.session.get(InviteLink, id)
    if invite:
        db.session.delete(invite)
        db.session.commit()
        flash('邀请链接已删除', 'success')
    return redirect(url_for('admin_invites'))
@app.route('/admin/stats')
@admin_required
def admin_stats():
    user = get_current_user()
    total_users = User.query.count()
    total_apps = OAuthApp.query.count()
    total_calls = UsageLog.query.count()
    
    now = time.time()
    today_start = now - 86400
    today_calls = UsageLog.query.filter(UsageLog.timestamp >= today_start).count()
    
    recent_users = User.query.order_by(User.id.desc()).limit(5).all()
    
    chart_labels = []
    chart_data = []
    for i in range(6, -1, -1):
        day_end = now - (i * 86400)
        day_start = day_end - 86400
        date_str = datetime.datetime.fromtimestamp(day_end).strftime('%m-%d')
        chart_labels.append(date_str)
        cnt = UsageLog.query.filter(UsageLog.timestamp >= day_start, UsageLog.timestamp < day_end).count()
        chart_data.append(cnt)

    return render_template('admin_stats.html', user=user, total_users=total_users, total_apps=total_apps, total_calls=total_calls, today_calls=today_calls, recent_users=recent_users, chart_labels=chart_labels, chart_data=chart_data)

@app.route('/stats')
@login_required
def global_stats():
    user = get_current_user()
    total_users = User.query.count()
    total_apps = OAuthApp.query.count()
    total_calls = UsageLog.query.count()
    
    now = time.time()
    chart_labels = []
    chart_data = []
    
    for i in range(6, -1, -1):
        day_end = now - (i * 86400)
        day_start = day_end - 86400
        date_str = datetime.datetime.fromtimestamp(day_end).strftime('%m-%d')
        chart_labels.append(date_str)
        cnt = UsageLog.query.filter(UsageLog.timestamp >= day_start, UsageLog.timestamp < day_end).count()
        chart_data.append(cnt)

    return render_template('global_stats.html', user=user, total_users=total_users, total_apps=total_apps, total_calls=total_calls, chart_labels=chart_labels, chart_data=chart_data)

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    my_apps = OAuthApp.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', user=user, apps=my_apps)

@app.route('/apps/new', methods=['POST'])
@login_required
def new_app():
    user = get_current_user()
    name = request.form['name']
    redirect_uri = request.form['redirect_uri']
    if not name or not redirect_uri:
        flash('请填写完整信息', 'error')
        return redirect(url_for('dashboard'))
    client_id = secrets.token_hex(10)
    client_secret = secrets.token_hex(20)
    app = OAuthApp(name=name, redirect_uri=redirect_uri, user_id=user.id, 
                   client_id=client_id, client_secret=client_secret)
    db.session.add(app)
    db.session.commit()
    flash(f'应用 {name} 创建成功！', 'success')
    return redirect(url_for('dashboard'))

@app.route('/apps/<client_id>')
@login_required
def app_details(client_id):
    user = get_current_user()
    app = db.session.get(OAuthApp, client_id)
    if not app or app.user_id != user.id: return abort(404)
    stats = get_app_stats(client_id)
    return render_template('app_details.html', user=user, app=app, stats=stats)

@app.route('/apps/<client_id>/regenerate_secret', methods=['POST'])
@login_required
def regenerate_secret(client_id):
    user = get_current_user()
    app = db.session.get(OAuthApp, client_id)
    if app and app.user_id == user.id:
        app.client_secret = secrets.token_hex(20)
        db.session.commit()
        flash('Client Secret 已重置', 'success')
    return redirect(url_for('app_details', client_id=client_id))

@app.route('/apps/<client_id>/update', methods=['POST'])
@login_required
def update_app(client_id):
    user = get_current_user()
    app = db.session.get(OAuthApp, client_id)
    if not app or app.user_id != user.id:
        flash('无权操作', 'error')
        return redirect(url_for('dashboard'))
    new_name = request.form.get('name')
    new_redirect_uri = request.form.get('redirect_uri')
    if new_name and new_redirect_uri:
        app.name = new_name
        app.redirect_uri = new_redirect_uri
        db.session.commit()
        flash('应用信息已更新', 'success')
    else:
        flash('信息不能为空', 'error')
    if request.referrer and 'apps/' in request.referrer:
        return redirect(url_for('app_details', client_id=client_id))
    return redirect(url_for('dashboard'))

@app.route('/apps/<client_id>/delete', methods=['POST'])
@login_required
def delete_app(client_id):
    user = get_current_user()
    app = db.session.get(OAuthApp, client_id)
    if not app or app.user_id != user.id:
        flash('无权操作', 'error')
        return redirect(url_for('dashboard'))
    AuthCode.query.filter_by(client_id=client_id).delete()
    AccessToken.query.filter_by(client_id=client_id).delete()
    RefreshToken.query.filter_by(client_id=client_id).delete()
    UsageLog.query.filter_by(client_id=client_id).delete()
    db.session.delete(app)
    db.session.commit()
    flash(f'应用 {app.name} 已删除', 'success')
    return redirect(url_for('dashboard'))

@app.route('/apps/<client_id>/stats')
@login_required
def app_analytics(client_id):
    user = get_current_user()
    oauth_app = db.session.get(OAuthApp, client_id)
    if not oauth_app or oauth_app.user_id != user.id:
        return abort(404)
    now = time.time()
    thirty_days_ago = now - (86400 * 30)
    logs = UsageLog.query.filter(UsageLog.client_id == client_id, UsageLog.timestamp >= thirty_days_ago).all()
    daily_counts = {} 
    dates_list = []
    for i in range(29, -1, -1):
        d = datetime.datetime.now() - datetime.timedelta(days=i)
        date_str = d.strftime('%m-%d')
        daily_counts[date_str] = 0
        dates_list.append(date_str)
    endpoint_counts = {'Login (Token)': 0, 'API (User Info)': 0, 'Refresh': 0}
    for log in logs:
        log_date = datetime.datetime.fromtimestamp(log.timestamp).strftime('%m-%d')
        if log_date in daily_counts: daily_counts[log_date] += 1
        if 'token' in log.endpoint:
            if 'refresh' in log.endpoint: endpoint_counts['Refresh'] += 1
            else: endpoint_counts['Login (Token)'] += 1
        elif 'user_info' in log.endpoint: endpoint_counts['API (User Info)'] += 1
    trend_data = [daily_counts[d] for d in dates_list]
    pie_data = list(endpoint_counts.values())
    pie_labels = list(endpoint_counts.keys())
    return render_template('app_stats.html', user=user, app=oauth_app, dates=dates_list, trend_data=trend_data, pie_labels=pie_labels, pie_data=pie_data)

@app.route('/oauth/authorize', methods=['GET', 'POST'])
@login_required
def authorize():
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    if not client_id or not redirect_uri: return "Missing client_id or redirect_uri", 400
    oauth_app = db.session.get(OAuthApp, client_id)
    if not oauth_app: return "Invalid Client ID", 400
    if redirect_uri != oauth_app.redirect_uri: return "Redirect URI mismatched", 400
    raw_scope = request.args.get('scope', 'profile')
    requested_scopes = raw_scope.split(' ')
    valid_scopes = {k: v for k, v in SUPPORTED_SCOPES.items() if k in requested_scopes}
    if not valid_scopes: valid_scopes = {'profile': SUPPORTED_SCOPES['profile']}
    if request.method == 'POST':
        code = secrets.token_urlsafe(16)
        final_scope_str = " ".join(valid_scopes.keys())
        auth_code = AuthCode(code=code, client_id=client_id, user_id=session['user_id'], redirect_uri=redirect_uri, expires_at=time.time() + 600, scope=final_scope_str)
        db.session.add(auth_code)
        db.session.commit()
        return redirect(f"{redirect_uri}?code={code}")
    return render_template('authorize.html', app=oauth_app, user=get_current_user(), scopes=valid_scopes)

@app.route('/oauth/token', methods=['POST'])
@csrf.exempt
def token():
    try:
        data = request.json or request.form
        grant_type = data.get('grant_type', 'authorization_code')
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        oauth_app = db.session.get(OAuthApp, client_id)
        if not oauth_app or oauth_app.client_secret != client_secret: return jsonify({'error': 'invalid_client'}), 401
        final_scope = 'profile'
        if grant_type == 'authorization_code':
            code = data.get('code')
            auth_code = db.session.get(AuthCode, code)
            if not auth_code or auth_code.expires_at < time.time(): return jsonify({'error': 'invalid_grant'}), 400
            if auth_code.client_id != client_id: return jsonify({'error': 'invalid_request'}), 400
            user_id = auth_code.user_id
            final_scope = auth_code.scope
            db.session.delete(auth_code)
        elif grant_type == 'refresh_token':
            refresh_token = data.get('refresh_token')
            rt_entry = db.session.get(RefreshToken, refresh_token)
            if not rt_entry or rt_entry.expires_at < time.time(): return jsonify({'error': 'invalid_grant'}), 400
            if rt_entry.client_id != client_id: return jsonify({'error': 'invalid_request'}), 400
            user_id = rt_entry.user_id
            final_scope = rt_entry.scope
        else: return jsonify({'error': 'unsupported_grant_type'}), 400
        access_token = secrets.token_urlsafe(20)
        at_entry = AccessToken(token=access_token, client_id=client_id, user_id=user_id, expires_at=time.time() + 3600, scope=final_scope)
        db.session.add(at_entry)
        refresh_token_str = None
        if grant_type == 'authorization_code':
            refresh_token_str = secrets.token_urlsafe(24)
            rt_entry = RefreshToken(token=refresh_token_str, client_id=client_id, user_id=user_id, expires_at=time.time() + 86400 * 30, scope=final_scope)
            db.session.add(rt_entry)
        elif grant_type == 'refresh_token':
            refresh_token_str = data.get('refresh_token')
        record_usage(client_id, f'token_{grant_type}')
        db.session.commit()
        return jsonify({'access_token': access_token, 'token_type': 'Bearer', 'expires_in': 3600, 'refresh_token': refresh_token_str, 'scope': final_scope})
    except Exception as e: return jsonify({'error': 'server_error', 'message': str(e)}), 500

# 修改 app.py 中的 api_user 函数

@app.route('/api/user')
@csrf.exempt
def api_user():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'unauthorized'}), 401
    
    token_str = auth_header.split(' ')[1]
    token = db.session.get(AccessToken, token_str)
    
    if not token or token.expires_at < time.time():
        return jsonify({'error': 'invalid_token'}), 401
    
    record_usage(token.client_id, 'user_info')
    user = db.session.get(User, token.user_id)
    
    granted_scopes = token.scope.split(' ')
    response = {'id': user.id}
    
    if 'profile' in granted_scopes:
        response['username'] = user.username
        
        # === [关键修复] 处理头像路径 ===
        avatar_url = user.avatar
        # 如果是本地路径 (以 /static 开头)，加上当前服务器的域名
        if avatar_url and avatar_url.startswith('/'):
            # request.host_url 会获取当前运行的域名端口，如 http://127.0.0.1:5124/
            avatar_url = request.host_url.rstrip('/') + avatar_url
            
        response['avatar'] = avatar_url
        # ============================

    if 'email' in granted_scopes:
        response['email'] = user.email
    if 'phone' in granted_scopes:
        response['phone'] = user.phone
    if 'bio' in granted_scopes:
        response['bio'] = user.bio
    if 'birthday' in granted_scopes:
        response['birthday'] = user.birthday.isoformat() if user.birthday else None
        
    return jsonify(response)

@app.route('/settings/authorized')
@login_required
def authorized_apps():
    user = get_current_user()
    
    # 1. 查询当前用户拥有的所有 Refresh Token
    # 这里我们假设拥有 Refresh Token 就代表是一种长期的授权关系
    tokens = db.session.query(RefreshToken).filter_by(user_id=user.id).all()
    
    # 2. 提取唯一的 App 信息
    # 一个用户在同一个 App 可能有多个设备登录，会有多个 Token，我们需要去重
    authorized_apps_map = {}
    
    for token in tokens:
        if token.client_id not in authorized_apps_map:
            app_info = db.session.get(OAuthApp, token.client_id)
            if app_info:
                authorized_apps_map[token.client_id] = {
                    'app': app_info,
                    'last_authorized': datetime.datetime.fromtimestamp(token.timestamp if hasattr(token, 'timestamp') else time.time()), # 简单起见，这里如果有时间戳最好，没有就算了
                    'scopes': token.scope
                }
    
    return render_template('authorized_apps.html', user=user, apps=authorized_apps_map.values())

@app.route('/settings/authorized/<client_id>/revoke', methods=['POST'])
@login_required
def revoke_authorization(client_id):
    user = get_current_user()
    
    # 1. 查找应用名称（仅为了提示友好）
    app_info = db.session.get(OAuthApp, client_id)
    app_name = app_info.name if app_info else "应用"
    
    # 2. 删除该用户在该 App 下的所有令牌 (Access + Refresh + AuthCode)
    # 这相当于“踢出登录”
    AccessToken.query.filter_by(user_id=user.id, client_id=client_id).delete()
    RefreshToken.query.filter_by(user_id=user.id, client_id=client_id).delete()
    AuthCode.query.filter_by(user_id=user.id, client_id=client_id).delete()
    
    db.session.commit()
    
    flash(f'已撤销对 {app_name} 的授权，该应用将无法再访问您的账户。', 'success')
    return redirect(url_for('authorized_apps'))
# [新增] 命令行创建管理员
@app.cli.command("create-admin")
def create_admin():
    """手动创建一个管理员账号"""
    import click
    username = click.prompt("请输入管理员用户名")
    email = click.prompt("请输入邮箱")
    password = click.prompt("请输入密码", hide_input=True)
    
    if User.query.filter((User.username==username) | (User.email==email)).first():
        print("❌ 用户已存在")
        return

    user = User(
        username=username, 
        email=email, 
        password_hash=generate_password_hash(password), 
        is_admin=True
    )
    db.session.add(user)
    db.session.commit()
    print(f"✅ 管理员 {username} 创建成功！")
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print(f"✅ 数据库连接成功: {DB_PATH}")
    app.run(debug=True, port=5124)