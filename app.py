from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
import os
import json
import secrets
import re
import hashlib
import time
from datetime import datetime, timedelta
from functools import wraps
import threading
import sys
import traceback
import requests
import random

app = Flask(__name__, static_folder='public', static_url_path='')

# ====== 設定 ======
if not os.environ.get("SECRET_KEY"):
    os.environ["SECRET_KEY"] = secrets.token_hex(32)

app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
CORS(app, supports_credentials=True, origins=["http://localhost:3000", "http://127.0.0.1:3000"])

# ====== 管理者設定 ======
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = None

if os.environ.get("ADMIN_PASSWORD_HASH"):
    ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")
    print(f"環境変数から管理者パスワードハッシュを読み込みました")
else:
    try:
        if os.path.exists("admin_password.txt"):
            with open("admin_password.txt", "r") as f:
                file_hash = f.read().strip()
                if len(file_hash) == 64:
                    ADMIN_PASSWORD_HASH = file_hash
                    print(f"ファイルから管理者パスワードハッシュを読み込みました")
    except:
        pass

if not ADMIN_PASSWORD_HASH:
    ADMIN_PASSWORD_HASH = "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"  # admin123
    print("デフォルトの管理者パスワードハッシュを使用します（admin123）")

FIXED_MODEL = "gemini-2.5-flash-lite"

# ====== データストア ======
class JSONStore:
    def __init__(self, filename):
        self.filename = filename
        self.lock = threading.Lock()
    
    def load(self):
        with self.lock:
            if os.path.exists(self.filename):
                try:
                    with open(self.filename, 'r', encoding='utf-8') as f:
                        return json.load(f)
                except:
                    # ファイルが壊れている場合は初期化
                    return {} if self.filename.endswith('.json') else []
            # ファイルがなければ初期化
            if self.filename == "users.json":
                return {}
            elif self.filename == "domains.json":
                return []
            elif self.filename == "chat_history.json":
                return {}
            elif self.filename == "system_settings.json":
                return {}
            elif self.filename == "access_logs.json":
                return []
            else:
                return {}
    
    def save(self, data):
        with self.lock:
            # 保存先のディレクトリがなければ作成
            os.makedirs(os.path.dirname(self.filename) if os.path.dirname(self.filename) else '.', exist_ok=True)
            with open(self.filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

# データストアの初期化
users_store = JSONStore("users.json")
history_store = JSONStore("chat_history.json")
settings_store = JSONStore("system_settings.json")
domains_store = JSONStore("domains.json")
logs_store = JSONStore("access_logs.json")

# ====== ユーティリティ関数 ======
def hash_password(password):
    """パスワードをSHA256でハッシュ化"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password_hash(input_password, stored_hash):
    """入力パスワードをハッシュ化して保存済みハッシュと比較"""
    return hash_password(input_password) == stored_hash

def validate_email(email):
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is not None

def validate_password(password):
    if len(password) < 8:
        return False, "パスワードは8文字以上必要です"
    if not any(c.isalpha() for c in password):
        return False, "パスワードには英字を含めてください"
    if not any(c.isdigit() for c in password):
        return False, "パスワードには数字を含めてください"
    return True, "OK"

def now_iso():
    return datetime.utcnow().isoformat() + 'Z'

def api_response(data=None, error=None, status=200):
    response = {"timestamp": now_iso()}
    if error:
        response["error"] = error
        response["status"] = "error"
    else:
        response["data"] = data
        response["status"] = "success"
    return jsonify(response), status

def log_access(action, user="未認証", endpoint="", status=200):
    """アクセスログを記録"""
    try:
        logs = logs_store.load()
        logs.append({
            'timestamp': now_iso(),
            'ip_address': request.remote_addr,
            'user': user,
            'action': action,
            'endpoint': endpoint,
            'status': status
        })
        logs_store.save(logs)
    except:
        pass

# ====== 管理者認証 ======
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return api_response(error="管理者認証が必要です", status=401)
        return f(*args, **kwargs)
    return decorated

# ====== 静的ファイルサービス ======
@app.route('/')
def serve_index():
    try:
        return send_from_directory(app.static_folder, 'index.html')
    except:
        return """
        <html>
        <head><title>Gemini Chat API</title></head>
        <body>
            <h1>Gemini Chat API Server</h1>
            <p>サーバーは正常に動作しています。</p>
            <p><a href="/admin">管理者ログイン</a></p>
            <p><a href="/health">ヘルスチェック</a></p>
        </body>
        </html>
        """

@app.route('/admin')
def serve_admin():
    """管理者画面"""
    try:
        return send_from_directory(app.static_folder, 'admin.html')
    except:
        return "管理者ページが見つかりません。publicフォルダにadmin.htmlを配置してください。"

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(app.static_folder, path)

# ====== 管理者エンドポイント ======
@app.route('/admin/login', methods=['POST'])
def admin_login():
    try:
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return api_response(error="管理者IDとパスワードが必要です", status=400)
        
        if username != ADMIN_USERNAME:
            return api_response(error="認証失敗", status=401)
        
        if not verify_password_hash(password, ADMIN_PASSWORD_HASH):
            return api_response(error="認証失敗", status=401)
        
        # セッションに管理者ログイン状態を保存
        session['admin_logged_in'] = True
        session['admin_username'] = username
        
        log_access("管理者ログイン", username, "/admin/login", 200)
        
        return api_response({
            "user": username,
            "message": "ログイン成功"
        })
    except Exception as e:
        return api_response(error=f"ログインエラー: {str(e)}", status=500)

@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    username = session.get('admin_username', '不明')
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    
    log_access("管理者ログアウト", username, "/admin/logout", 200)
    
    return api_response({"message": "ログアウトしました"})

@app.route('/admin/status', methods=['GET'])
def admin_status():
    if session.get('admin_logged_in'):
        return api_response({
            "logged_in": True,
            "username": session.get('admin_username')
        })
    return api_response({"logged_in": False})

@app.route('/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    try:
        users = users_store.load()
        history = history_store.load()
        domains = domains_store.load()
        
        total_users = len(users)
        total_messages = sum(len(messages) for messages in history.values())
        
        # 今日のメッセージ数を計算
        today = datetime.utcnow().date()
        new_messages_today = 0
        for messages in history.values():
            for msg in messages:
                if 'timestamp' in msg:
                    try:
                        msg_date = datetime.fromisoformat(msg['timestamp'].replace('Z', '+00:00')).date()
                        if msg_date == today:
                            new_messages_today += 1
                    except:
                        pass
        
        # 今日のユーザー登録数
        new_users_today = 0
        for user_data in users.values():
            if 'created_at' in user_data:
                try:
                    user_date = datetime.fromisoformat(user_data['created_at'].replace('Z', '+00:00')).date()
                    if user_date == today:
                        new_users_today += 1
                except:
                    pass
        
        # ドメイン関連の統計
        total_domains = len(domains)
        
        # API使用状況
        logs = logs_store.load()
        api_calls_today = 0
        for log in logs:
            if '/proxy' in log.get('endpoint', ''):
                try:
                    log_date = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00')).date()
                    if log_date == today:
                        api_calls_today += 1
                except:
                    pass
        
        return api_response({
            "total_users": total_users,
            "new_users_today": new_users_today,
            "total_domains": total_domains,
            "total_messages": total_messages,
            "new_messages_today": new_messages_today,
            "api_status": "正常" if os.environ.get("GOOGLE_API_KEY") else "未設定",
            "api_usage": api_calls_today,
            "server_status": "正常",
            "server_uptime": "0日 00:00:00",
            "database_status": "正常",
            "database_size": "0 KB",
            "api_connection": "接続済み" if os.environ.get("GOOGLE_API_KEY") else "未接続",
            "api_model": FIXED_MODEL
        })
    except Exception as e:
        return api_response(error=f"統計取得エラー: {str(e)}", status=500)

@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_users():
    try:
        users = users_store.load()
        
        # フロントエンドが期待する形式に変換
        user_list = []
        for email, user_data in users.items():
            user_info = {
                'id': email,
                'name': user_data.get('name', email.split('@')[0]),
                'email': email,
                'password': user_data.get('password', ''),
                'created_at': user_data.get('created_at', now_iso()),
                'last_login': user_data.get('last_login', '未ログイン'),
                'role': user_data.get('role', 'user'),
                'status': user_data.get('status', 'active'),
                'provider': user_data.get('provider', 'email'),
                'domain': user_data.get('domain', email.split('@')[1] if '@' in email else '')
            }
            user_list.append(user_info)
        
        # 検索機能
        search_query = request.args.get('search', '').lower()
        if search_query:
            user_list = [
                user for user in user_list 
                if (search_query in user['email'].lower() or 
                    search_query in user['name'].lower() or
                    search_query in user.get('domain', '').lower())
            ]
        
        log_access("ユーザー一覧取得", session.get('admin_username'), "/admin/users", 200)
        return api_response(user_list)
    except Exception as e:
        return api_response(error=f"ユーザー取得エラー: {str(e)}", status=500)

@app.route('/admin/users/add', methods=['POST'])
@admin_required
def admin_add_user():
    """管理者がユーザーを追加"""
    try:
        data = request.json
        
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        role = data.get('role', 'user')
        
        if not name or not email or not password:
            return api_response(error="名前、メールアドレス、パスワードは必須です", status=400)
        
        if not validate_email(email):
            return api_response(error="無効なメールアドレス形式です", status=400)
        
        if len(password) < 1:
            return api_response(error="パスワードは必須です", status=400)
        
        users = users_store.load()
        
        if email in users:
            return api_response(error="このメールアドレスは既に登録されています", status=409)
        
        # ユーザーを作成
        users[email] = {
            'name': name,
            'email': email,
            'password': password,
            'role': role,
            'status': 'active',
            'provider': 'email',
            'domain': email.split('@')[1] if '@' in email else '',
            'created_at': now_iso(),
            'last_login': None
        }
        
        users_store.save(users)
        
        log_access(f"ユーザー追加: {email}", session.get('admin_username'), "/admin/users/add", 200)
        
        return api_response({
            'message': 'ユーザーを追加しました',
            'user': {
                'id': email,
                'name': name,
                'email': email,
                'role': role,
                'status': 'active'
            }
        })
    except Exception as e:
        return api_response(error=f"ユーザー追加エラー: {str(e)}", status=500)

@app.route('/admin/users/update', methods=['POST'])
@admin_required
def admin_update_user():
    """ユーザー情報更新"""
    try:
        data = request.json
        email = data.get('email', '').strip().lower()
        
        if not email:
            return api_response(error="メールアドレスが必要です", status=400)
        
        users = users_store.load()
        
        if email not in users:
            return api_response(error="ユーザーが見つかりません", status=404)
        
        # 更新可能なフィールド
        updatable_fields = ['name', 'role', 'status']
        for field in updatable_fields:
            if field in data:
                users[email][field] = data[field]
        
        # パスワード更新
        if 'password' in data and data['password']:
            if len(data['password']) < 1:
                return api_response(error="パスワードは必須です", status=400)
            users[email]['password'] = data['password']
        
        users_store.save(users)
        
        log_access(f"ユーザー更新: {email}", session.get('admin_username'), "/admin/users/update", 200)
        
        return api_response({
            'message': 'ユーザー情報を更新しました',
            'user': users[email]
        })
    except Exception as e:
        return api_response(error=f"ユーザー更新エラー: {str(e)}", status=500)

@app.route('/admin/users/delete', methods=['POST'])
@admin_required
def admin_delete_user():
    """ユーザー削除"""
    try:
        data = request.json
        email = data.get('email', '').strip().lower()
        
        if not email:
            return api_response(error="メールアドレスが必要です", status=400)
        
        users = users_store.load()
        
        if email not in users:
            return api_response(error="ユーザーが見つかりません", status=404)
        
        # 管理者自身は削除できない
        if email == ADMIN_USERNAME:
            return api_response(error="管理者アカウントは削除できません", status=400)
        
        deleted_user = users.pop(email)
        users_store.save(users)
        
        # 関連する履歴も削除
        history = history_store.load()
        if email in history:
            del history[email]
            history_store.save(history)
        
        log_access(f"ユーザー削除: {email}", session.get('admin_username'), "/admin/users/delete", 200)
        
        return api_response({
            'message': 'ユーザーを削除しました',
            'user': deleted_user
        })
    except Exception as e:
        return api_response(error=f"ユーザー削除エラー: {str(e)}", status=500)

@app.route('/admin/domains', methods=['GET'])
@admin_required
def admin_domains():
    """許可ドメイン一覧取得"""
    try:
        domains = domains_store.load()
        log_access("ドメイン一覧取得", session.get('admin_username'), "/admin/domains", 200)
        return api_response(domains)
    except Exception as e:
        return api_response(error=f"ドメイン取得エラー: {str(e)}", status=500)

@app.route('/admin/domains/add', methods=['POST'])
@admin_required
def admin_add_domain():
    """ドメイン追加"""
    try:
        data = request.json
        domain = data.get('domain', '').strip().lower()
        description = data.get('description', '').strip()
        domain_type = data.get('type', 'exact')
        
        if not domain:
            return api_response(error="ドメイン名が必要です", status=400)
        
        domains = domains_store.load()
        
        # 重複チェック
        if any(d.get('domain') == domain for d in domains):
            return api_response(error="このドメインは既に登録されています", status=409)
        
        new_domain = {
            'domain': domain,
            'description': description,
            'type': domain_type,
            'created_at': now_iso(),
            'created_by': session.get('admin_username', 'admin')
        }
        
        domains.append(new_domain)
        domains_store.save(domains)
        
        log_access(f"ドメイン追加: {domain}", session.get('admin_username'), "/admin/domains/add", 200)
        
        return api_response({
            'message': 'ドメインを追加しました',
            'domain': new_domain
        })
    except Exception as e:
        return api_response(error=f"ドメイン追加エラー: {str(e)}", status=500)

@app.route('/admin/domains/delete', methods=['POST'])
@admin_required
def admin_delete_domain():
    """ドメイン削除"""
    try:
        data = request.json
        domain = data.get('domain', '').strip().lower()
        
        if not domain:
            return api_response(error="ドメイン名が必要です", status=400)
        
        domains = domains_store.load()
        
        # ドメインを検索して削除
        new_domains = [d for d in domains if d.get('domain') != domain]
        
        if len(new_domains) == len(domains):
            return api_response(error="ドメインが見つかりません", status=404)
        
        domains_store.save(new_domains)
        
        log_access(f"ドメイン削除: {domain}", session.get('admin_username'), "/admin/domains/delete", 200)
        
        return api_response({'message': 'ドメインを削除しました'})
    except Exception as e:
        return api_response(error=f"ドメイン削除エラー: {str(e)}", status=500)

@app.route('/admin/history', methods=['GET'])
@admin_required
def admin_history():
    """全ユーザーのチャット履歴取得"""
    try:
        history = history_store.load()
        
        # フロントエンド用に整形
        history_list = []
        for email, messages in history.items():
            user_name = users_store.load().get(email, {}).get('name', email.split('@')[0])
            
            # メッセージをペア（ユーザー/AI）で処理
            for i in range(0, len(messages), 2):
                if i + 1 < len(messages):
                    user_msg = messages[i]
                    ai_msg = messages[i + 1] if messages[i + 1].get('role') == 'ai' else None
                    
                    if user_msg.get('role') == 'user':
                        history_list.append({
                            'user_email': email,
                            'user_name': user_name,
                            'timestamp': user_msg.get('timestamp', now_iso()),
                            'message': user_msg.get('text', ''),
                            'ai_response': ai_msg.get('text', '') if ai_msg else ''
                        })
        
        # 新しい順にソート
        history_list.sort(key=lambda x: x['timestamp'], reverse=True)
        
        log_access("履歴一覧取得", session.get('admin_username'), "/admin/history", 200)
        
        return api_response(history_list[:100])
    except Exception as e:
        return api_response(error=f"履歴取得エラー: {str(e)}", status=500)

@app.route('/admin/history/clear', methods=['POST'])
@admin_required
def admin_clear_history():
    """全履歴削除"""
    try:
        history_store.save({})
        
        log_access("全履歴削除", session.get('admin_username'), "/admin/history/clear", 200)
        
        return api_response({'message': '全履歴を削除しました'})
    except Exception as e:
        return api_response(error=f"履歴削除エラー: {str(e)}", status=500)

@app.route('/admin/settings', methods=['GET'])
@admin_required
def admin_get_settings():
    """システム設定取得"""
    try:
        settings = settings_store.load()
        log_access("設定取得", session.get('admin_username'), "/admin/settings", 200)
        return api_response(settings)
    except Exception as e:
        return api_response(error=f"設定取得エラー: {str(e)}", status=500)

@app.route('/admin/settings', methods=['POST'])
@admin_required
def admin_save_settings():
    """システム設定保存"""
    try:
        data = request.json
        settings = settings_store.load()
        
        # 更新可能な設定項目
        updatable_keys = [
            'session_timeout', 'max_users', 'default_model',
            'maintenance_mode', 'maintenance_message', 'rate_limit'
        ]
        
        for key in updatable_keys:
            if key in data:
                settings[key] = data[key]
        
        settings_store.save(settings)
        
        log_access("設定保存", session.get('admin_username'), "/admin/settings", 200)
        
        return api_response({'message': '設定を保存しました'})
    except Exception as e:
        return api_response(error=f"設定保存エラー: {str(e)}", status=500)

@app.route('/admin/api-test', methods=['GET'])
@admin_required
def admin_api_test():
    """API接続テスト"""
    try:
        api_key = os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            return api_response({
                'status': 'error', 
                'message': 'APIキー未設定',
                'model': FIXED_MODEL
            })
        
        # 実際のAPIテストを行う
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{FIXED_MODEL}:generateContent?key={api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{
                "parts": [{"text": "Hello, this is a test message to verify API connection."}]
            }]
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            
            if response.status_code == 200:
                log_access("API接続テスト成功", session.get('admin_username'), "/admin/api-test", 200)
                return api_response({
                    'status': 'success',
                    'message': 'API接続テスト成功',
                    'model': FIXED_MODEL
                })
            else:
                error_msg = f"API接続エラー: {response.status_code}"
                try:
                    error_detail = response.json()
                    error_msg = f"{error_msg} - {error_detail.get('error', {}).get('message', 'Unknown error')}"
                except:
                    pass
                
                log_access(f"API接続テスト失敗: {error_msg}", session.get('admin_username'), "/admin/api-test", response.status_code)
                return api_response({
                    'status': 'error',
                    'message': error_msg,
                    'model': FIXED_MODEL
                }, status=response.status_code)
                
        except requests.exceptions.RequestException as e:
            log_access(f"API接続テスト失敗: {str(e)}", session.get('admin_username'), "/admin/api-test", 500)
            return api_response({
                'status': 'error',
                'message': f'API接続エラー: {str(e)}',
                'model': FIXED_MODEL
            }, status=500)
            
    except Exception as e:
        log_access(f"API接続テストエラー: {str(e)}", session.get('admin_username'), "/admin/api-test", 500)
        return api_response({
            'status': 'error',
            'message': f'API接続テスト失敗: {str(e)}'
        }, status=500)

@app.route('/admin/logs', methods=['GET'])
@admin_required
def admin_logs():
    """アクセスログ取得"""
    try:
        logs = logs_store.load()
        
        # 最新100件のみ返す
        recent_logs = logs[-100:] if len(logs) > 100 else logs
        
        log_access("ログ取得", session.get('admin_username'), "/admin/logs", 200)
        
        return api_response(recent_logs)
    except Exception as e:
        return api_response(error=f"ログ取得エラー: {str(e)}", status=500)

@app.route('/admin/logs/clear', methods=['POST'])
@admin_required
def admin_clear_logs():
    """アクセスログクリア"""
    try:
        logs_store.save([])
        
        log_access("ログクリア", session.get('admin_username'), "/admin/logs/clear", 200)
        
        return api_response({'message': 'ログをクリアしました'})
    except Exception as e:
        return api_response(error=f"ログクリアエラー: {str(e)}", status=500)

# ====== ユーザー認証エンドポイント ======
@app.route('/auth/register', methods=['POST'])
def register():
    try:
        data = request.json
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        name = data.get('name', '').strip()
        
        if not email or not password:
            return api_response(error="メールアドレスとパスワードが必要です", status=400)
        
        if not validate_email(email):
            return api_response(error="無効なメールアドレス形式です", status=400)
        
        if len(password) < 1:
            return api_response(error="パスワードは必須です", status=400)
        
        if not name:
            name = email.split('@')[0]
        
        users = users_store.load()
        
        if email in users:
            return api_response(error="このメールアドレスは既に登録されています", status=409)
        
        # ユーザーを作成
        users[email] = {
            'name': name,
            'email': email,
            'password': password,
            'role': 'user',
            'status': 'active',
            'provider': 'email',
            'domain': email.split('@')[1] if '@' in email else '',
            'created_at': now_iso(),
            'last_login': now_iso()
        }
        
        users_store.save(users)
        
        session['user'] = {
            'email': email,
            'name': name,
            'logged_in': True,
            'provider': 'email'
        }
        
        log_access("ユーザー登録", email, "/auth/register", 200)
        
        return api_response({
            'email': email,
            'name': name
        })
    except Exception as e:
        return api_response(error=f"登録エラー: {str(e)}", status=500)

@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return api_response(error="メールアドレスとパスワードが必要です", status=400)
        
        users = users_store.load()
        user = users.get(email)
        
        if not user:
            return api_response(error="認証失敗", status=401)
        
        # 平文パスワードチェック
        if user.get('password') != password:
            return api_response(error="認証失敗", status=401)
        
        # アカウント状態チェック
        if user.get('status') == 'suspended':
            return api_response(error="アカウントは一時停止されています", status=403)
        elif user.get('status') == 'banned':
            return api_response(error="アカウントは禁止されています", status=403)
        
        user['last_login'] = now_iso()
        users_store.save(users)
        
        session['user'] = {
            'email': email,
            'name': user.get('name', email.split('@')[0]),
            'logged_in': True,
            'provider': user.get('provider', 'email')
        }
        
        log_access("ユーザーログイン", email, "/auth/login", 200)
        
        return api_response({
            'email': email,
            'name': user.get('name', email.split('@')[0])
        })
    except Exception as e:
        return api_response(error=f"ログインエラー: {str(e)}", status=500)

@app.route('/auth/logout', methods=['POST'])
def logout():
    user_email = session.get('user', {}).get('email', '不明')
    
    session.pop('user', None)
    
    log_access("ユーザーログアウト", user_email, "/auth/logout", 200)
    
    return api_response({"message": "ログアウトしました"})

@app.route('/auth/status', methods=['GET'])
def auth_status():
    user_data = session.get('user', {})
    
    if user_data.get('logged_in'):
        return api_response({
            'logged_in': True,
            'user': user_data
        })
    
    return api_response({'logged_in': False})

# ====== ユーザープロフィール ======
@app.route('/user/profile', methods=['GET'])
def user_profile():
    try:
        user_data = session.get('user', {})
        if not user_data.get('logged_in'):
            return api_response(error="ログインが必要です", status=401)
        
        email = user_data.get('email')
        users = users_store.load()
        user = users.get(email, {})
        
        profile = {
            'name': user.get('name', email.split('@')[0]),
            'email': email,
            'domain': user.get('domain', email.split('@')[1] if '@' in email else ''),
            'created_at': user.get('created_at', now_iso()),
            'last_login': user.get('last_login', '未記録'),
            'provider': user.get('provider', 'email'),
            'status': user.get('status', 'active'),
            'role': user.get('role', 'user')
        }
        
        log_access("プロフィール取得", email, "/user/profile", 200)
        
        return api_response(profile)
    except Exception as e:
        return api_response(error=f"プロフィール取得エラー: {str(e)}", status=500)

# ====== チャット履歴 ======
@app.route('/history', methods=['GET'])
def get_history():
    try:
        user_data = session.get('user', {})
        if not user_data.get('logged_in'):
            return api_response(error="ログインが必要です", status=401)
        
        email = user_data.get('email')
        history = history_store.load()
        
        user_history = history.get(email, [])
        
        log_access("履歴取得", email, "/history", 200)
        
        return api_response(user_history)
    except Exception as e:
        return api_response(error=f"履歴取得エラー: {str(e)}", status=500)

@app.route('/history', methods=['POST'])
def save_history():
    try:
        user_data = session.get('user', {})
        if not user_data.get('logged_in'):
            return api_response(error="ログインが必要です", status=401)
        
        data = request.json
        email = user_data.get('email')
        history_data = data.get('history', [])
        
        history = history_store.load()
        history[email] = history_data
        history_store.save(history)
        
        log_access("履歴保存", email, "/history", 200)
        
        return api_response({"message": "履歴を保存しました"})
    except Exception as e:
        return api_response(error=f"履歴保存エラー: {str(e)}", status=500)

# ====== Gemini API プロキシ ======
@app.route('/proxy', methods=['POST'])
def proxy_to_gemini():
    try:
        data = request.json
        messages = data.get('messages', [])
        
        api_key = os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            return jsonify({
                "error": "APIキーが設定されていません",
                "choices": [{
                    "message": {
                        "content": "申し訳ありませんが、APIキーが設定されていないため、AIサービスを利用できません。管理者に問い合わせてください。"
                    }
                }]
            }), 500
        
        if not messages:
            return jsonify({
                "error": "メッセージがありません",
                "choices": [{
                    "message": {
                        "content": "メッセージが空です。テキストを入力してください。"
                    }
                }]
            }), 400
        
        # 最後のユーザーメッセージを取得
        last_user_message = None
        for msg in reversed(messages):
            if msg.get('role') == 'user':
                last_user_message = msg.get('content')
                break
        
        if not last_user_message:
            return jsonify({
                "error": "ユーザーメッセージが見つかりません",
                "choices": [{
                    "message": {
                        "content": "ユーザーメッセージを取得できませんでした。"
                    }
                }]
            }), 400
        
        # 実際のGoogle Gemini APIを呼び出す
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{FIXED_MODEL}:generateContent?key={api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{
                "parts": [{"text": last_user_message}]
            }]
        }
        
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        if response.status_code == 200:
            response_data = response.json()
            
            # 応答を標準形式に変換
            if 'candidates' in response_data and response_data['candidates']:
                candidate = response_data['candidates'][0]
                if 'content' in candidate and 'parts' in candidate['content']:
                    ai_text = candidate['content']['parts'][0].get('text', '')
                    
                    user_email = session.get('user', {}).get('email', '未認証')
                    log_access("Gemini API呼び出し成功", user_email, "/proxy", 200)
                    
                    return jsonify({
                        "choices": [{
                            "message": {
                                "content": ai_text
                            }
                        }]
                    })
        
        # エラー処理
        error_msg = f"APIエラー: {response.status_code}"
        try:
            error_detail = response.json()
            error_msg = f"{error_msg} - {error_detail.get('error', {}).get('message', 'Unknown error')}"
        except:
            pass
        
        log_access(f"Gemini APIエラー: {error_msg}", "不明", "/proxy", response.status_code)
        
        return jsonify({
            "error": error_msg,
            "choices": [{
                "message": {
                    "content": f"申し訳ありませんが、AI応答の生成中にエラーが発生しました: {error_msg}"
                }
            }]
        }), response.status_code
        
    except requests.exceptions.Timeout:
        log_access("Gemini APIタイムアウト", "不明", "/proxy", 504)
        return jsonify({
            "error": "APIリクエストがタイムアウトしました",
            "choices": [{
                "message": {
                    "content": "応答待ち時間が長すぎます。しばらくしてから再度お試しください。"
                }
            }]
        }), 504
        
    except requests.exceptions.RequestException as e:
        log_access(f"Gemini API接続エラー: {str(e)}", "不明", "/proxy", 502)
        return jsonify({
            "error": f"API接続エラー: {str(e)}",
            "choices": [{
                "message": {
                    "content": "APIへの接続に失敗しました。ネットワーク接続を確認してください。"
                }
            }]
        }), 502
        
    except Exception as e:
        log_access(f"Gemini API内部エラー: {str(e)}", "不明", "/proxy", 500)
        return jsonify({
            "error": f"内部エラー: {str(e)}",
            "choices": [{
                "message": {
                    "content": "申し訳ありませんが、内部エラーが発生しました。しばらく時間をおいて再度お試しください。"
                }
            }]
        }), 500

# ====== ヘルスチェック ======
@app.route('/health', methods=['GET'])
def health_check():
    api_key_set = bool(os.environ.get("GOOGLE_API_KEY"))
    
    health_data = {
        'status': 'healthy',
        'timestamp': now_iso(),
        'api_key_set': api_key_set,
        'model': FIXED_MODEL,
        'users_count': len(users_store.load()),
        'version': '1.0.0'
    }
    
    log_access("ヘルスチェック", request.remote_addr, "/health", 200)
    
    return api_response(health_data)

# ====== 初期化関数 ======
def initialize_data():
    """データの初期化"""
    # users.jsonが空の場合は初期ユーザーを作成
    users = users_store.load()
    if not users:
        # 管理者ユーザー
        users['admin@example.com'] = {
            'name': '管理者',
            'email': 'admin@example.com',
            'password': 'admin123',
            'role': 'admin',
            'status': 'active',
            'provider': 'email',
            'domain': 'example.com',
            'created_at': now_iso(),
            'last_login': now_iso()
        }
        
        # テストユーザー
        users['test@example.com'] = {
            'name': 'テストユーザー',
            'email': 'test@example.com',
            'password': 'test123',
            'role': 'user',
            'status': 'active',
            'provider': 'email',
            'domain': 'example.com',
            'created_at': now_iso(),
            'last_login': now_iso()
        }
        
        users_store.save(users)
        print("初期ユーザーデータを作成しました")
    
    # domains.jsonが空の場合は初期ドメインを作成
    domains = domains_store.load()
    if not domains:
        domains = [
            {
                'domain': 'example.com',
                'description': 'サンプルドメイン',
                'type': 'exact',
                'created_at': now_iso(),
                'created_by': 'system'
            },
            {
                'domain': '*.ac.jp',
                'description': '日本の大学・教育機関',
                'type': 'subdomain',
                'created_at': now_iso(),
                'created_by': 'system'
            },
            {
                'domain': 'company.co.jp',
                'description': '企業ドメイン',
                'type': 'exact',
                'created_at': now_iso(),
                'created_by': 'system'
            }
        ]
        domains_store.save(domains)
        print("初期ドメインデータを作成しました")
    
    # settings.jsonが空の場合は初期設定を作成
    settings = settings_store.load()
    if not settings:
        settings = {
            'session_timeout': 24,
            'max_users': 1000,
            'default_model': FIXED_MODEL,
            'maintenance_mode': False,
            'maintenance_message': 'システムメンテナンス中です',
            'rate_limit': 60,
            'api_key': os.environ.get("GOOGLE_API_KEY", ""),
            'version': '1.0.0'
        }
        settings_store.save(settings)
        print("初期設定データを作成しました")
    
    # アクセスログのダミーデータ生成を削除（本番環境では不要）
    logs = logs_store.load()
    if len(logs) == 0:
        # システム起動ログのみ追加
        logs.append({
            'timestamp': now_iso(),
            'ip_address': '127.0.0.1',
            'user': 'system',
            'action': 'システム起動',
            'endpoint': '/',
            'status': 200
        })
        logs_store.save(logs)
        print("システム起動ログを作成しました")
    
    # チャット履歴のダミーデータ生成を削除（本番環境では不要）

# ====== サーバー起動 ======
if __name__ == "__main__":
    print("=" * 60)
    print("Gemini Chat API Server (完全統合版)")
    print(f"ポート: 3000")
    print(f"管理者ユーザー名: {ADMIN_USERNAME}")
    
    # 管理者パスワードの情報
    if os.path.exists("admin_password.txt"):
        print("管理者パスワード: admin_password.txt から読み込み")
    elif ADMIN_PASSWORD_HASH == "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9":
        print("管理者パスワード: デフォルト (admin123)")
    else:
        print("管理者パスワード: 環境変数から読み込み")
    
    print(f"固定モデル: {FIXED_MODEL}")
    print(f"APIキー設定: {'有効' if os.environ.get('GOOGLE_API_KEY') else '未設定'}")
    print("=" * 60)
    
    # データ初期化
    initialize_data()
    
    # 静的フォルダの確認
    if not os.path.exists('public'):
        os.makedirs('public', exist_ok=True)
        print("'public' フォルダを作成しました")
    
    print("データストアの状態:")
    print(f"  ユーザー数: {len(users_store.load())}")
    print(f"  ドメイン数: {len(domains_store.load())}")
    print(f"  設定項目: {len(settings_store.load())}")
    print(f"  ログエントリ数: {len(logs_store.load())}")
    print("=" * 60)
    print("サーバーを起動しています...")
    print(f"アクセスURL: http://localhost:3000")
    print(f"管理者URL: http://localhost:3000/admin")
    print("=" * 60)
    
    app.run(
        host="0.0.0.0", 
        port=3000, 
        debug=True,
        threaded=True
    )