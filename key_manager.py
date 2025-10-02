from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import sqlite3
from datetime import date, timedelta, datetime
import os
from dotenv import load_dotenv
import requests
import secrets  # Key üretimi için

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY') or 'dev_secret_key'  # Üretimde değiştirin
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD') or 'admin123'

# Veritabanı yolu
DB_PATH = 'keys.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    # Keys tablosu (is_banned eklendi)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            end_date DATE NOT NULL,
            is_banned INTEGER DEFAULT 0
        )
    ''')
    # IP logları tablosu
    conn.execute('''
        CREATE TABLE IF NOT EXISTS ip_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            ip TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action TEXT DEFAULT 'validate'
        )
    ''')
    # Banlı IP'ler tablosu
    conn.execute('''
        CREATE TABLE IF NOT EXISTS banned_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            ban_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            reason TEXT
        )
    ''')
    conn.commit()
    conn.close()

# IP ban kontrolü
def is_ip_banned(ip):
    conn = get_db_connection()
    result = conn.execute('SELECT * FROM banned_ips WHERE ip = ?', (ip,)).fetchone()
    conn.close()
    return result is not None

# IP loglama
def log_ip(key, ip, action='validate'):
    conn = get_db_connection()
    conn.execute('INSERT INTO ip_logs (key, ip, action) VALUES (?, ?, ?)', (key, ip, action))
    conn.commit()
    conn.close()

# Aynı key için son 5 dakikada birden fazla IP kontrolü
def check_simultaneous_use(key):
    conn = get_db_connection()
    five_min_ago = (datetime.now() - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
    logs = conn.execute('SELECT ip FROM ip_logs WHERE key = ? AND timestamp > ? GROUP BY ip', (key, five_min_ago)).fetchall()
    conn.close()
    return len(logs) > 1  # Farklı IP sayısı > 1 ise True

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('admin_panel'))
        return render_template('login.html', error="Geçersiz şifre!")
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/', methods=['GET'])
def admin_panel():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Kullanılmayan key'ler (son 24 saatte log yok)
    unused_keys = conn.execute('''
        SELECT * FROM keys WHERE is_banned = 0 AND key NOT IN (SELECT DISTINCT key FROM ip_logs WHERE timestamp > datetime('now', '-1 day'))
    ''').fetchall()
    
    # Kullanılan key'ler (son 24 saatte log var)
    used_keys = conn.execute('''
        SELECT k.*, COUNT(l.ip) as usage_count FROM keys k
        LEFT JOIN ip_logs l ON k.key = l.key
        WHERE k.is_banned = 0 AND (l.timestamp > datetime('now', '-1 day') OR l.timestamp IS NULL)
        GROUP BY k.key
    ''').fetchall()
    
    # Banlı key'ler
    banned_keys = conn.execute('SELECT * FROM keys WHERE is_banned = 1').fetchall()
    
    # Banlı IP'ler
    banned_ips = conn.execute('SELECT * FROM banned_ips').fetchall()
    
    conn.close()
    return render_template('admin.html', unused_keys=unused_keys, used_keys=used_keys, banned_keys=banned_keys, banned_ips=banned_ips)

@app.route('/create_key', methods=['GET', 'POST'])
def create_key():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        days = request.form.get('days')
        
        if not username or not days:
            return render_template('create_key.html', error="Kullanıcı adı ve süre gerekli!")
        
        try:
            days = int(days)
            if days <= 0:
                return render_template('create_key.html', error="Süre pozitif olmalı!")
            
            random_part = secrets.token_urlsafe(6)[:6].upper()
            new_key = f"ACX_{random_part}"
            end_date = date.today() + timedelta(days=days)
            
            conn = get_db_connection()
            conn.execute('INSERT INTO keys (key, username, end_date) VALUES (?, ?, ?)',
                         (new_key, username, end_date))
            conn.commit()
            conn.close()
            return render_template('create_key.html', message=f"Key oluşturuldu: {new_key}")
        
        except Exception as e:
            return render_template('create_key.html', error=f"Hata: {str(e)}")
    
    return render_template('create_key.html', error=None, message=None)

@app.route('/ban_key', methods=['POST'])
def ban_key():
    if not session.get('logged_in'):
        return jsonify({'error': 'Yetkisiz'}), 403
    
    key = request.json.get('key')
    reason = request.json.get('reason', 'Aynı anda birden fazla IP')
    
    conn = get_db_connection()
    conn.execute('UPDATE keys SET is_banned = 1 WHERE key = ?', (key,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/unban_key', methods=['POST'])
def unban_key():
    if not session.get('logged_in'):
        return jsonify({'error': 'Yetkisiz'}), 403
    
    key = request.json.get('key')
    
    conn = get_db_connection()
    conn.execute('UPDATE keys SET is_banned = 0 WHERE key = ?', (key,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/ban_ip', methods=['POST'])
def ban_ip():
    if not session.get('logged_in'):
        return jsonify({'error': 'Yetkisiz'}), 403
    
    ip = request.json.get('ip')
    reason = request.json.get('reason', 'Manuel ban')
    
    conn = get_db_connection()
    conn.execute('INSERT OR IGNORE INTO banned_ips (ip, reason) VALUES (?, ?)', (ip, reason))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/unban_ip', methods=['POST'])
def unban_ip():
    if not session.get('logged_in'):
        return jsonify({'error': 'Yetkisiz'}), 403
    
    ip = request.json.get('ip')
    
    conn = get_db_connection()
    conn.execute('DELETE FROM banned_ips WHERE ip = ?', (ip,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/get_ip_logs/<key>', methods=['GET'])
def get_ip_logs(key):
    if not session.get('logged_in'):
        return jsonify({'error': 'Yetkisiz'}), 403
    
    conn = get_db_connection()
    logs = conn.execute('SELECT * FROM ip_logs WHERE key = ? ORDER BY timestamp DESC', (key,)).fetchall()
    conn.close()
    return jsonify([dict(row) for row in logs])

@app.route('/validate_key', methods=['POST'])
def validate_key():
    data = request.json
    key = data.get('key')
    ip = data.get('ip')  # Client'tan IP al
    if not key:
        return jsonify({'valid': False, 'message': 'Key gerekli'}), 400
    
    # IP ban kontrolü
    if is_ip_banned(ip):
        return jsonify({'valid': False, 'message': 'IP adresiniz banlanmış'}), 401
    
    conn = get_db_connection()
    key_data = conn.execute('SELECT * FROM keys WHERE key = ?', (key,)).fetchone()
    
    if not key_data:
        conn.close()
        return jsonify({'valid': False, 'message': 'Geçersiz key'}), 401
    
    if key_data['is_banned']:
        conn.close()
        return jsonify({'valid': False, 'message': 'Key banlanmış'}), 401
    
    today = date.today()
    end_date = date.fromisoformat(key_data['end_date'])
    if today > end_date:
        conn.close()
        return jsonify({'valid': False, 'message': 'Key süresi bitmiş'}), 401
    
    # IP loglama
    log_ip(key, ip)
    
    # Aynı anda kullanım kontrolü
    if check_simultaneous_use(key):
        # Key'i banla
        conn.execute('UPDATE keys SET is_banned = 1 WHERE key = ?', (key,))
        conn.commit()
        conn.close()
        return jsonify({'valid': False, 'message': 'Key banlandı (aynı anda birden fazla cihaz)'}), 401
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'valid': True,
        'username': key_data['username'],
        'remaining_days': (end_date - today).days
    })

@app.before_first_request
def initialize_database():
    init_db()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
