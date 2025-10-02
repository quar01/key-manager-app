from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import sqlite3
import secrets
from datetime import date, timedelta
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Session için güvenli anahtar

# Veritabanı yolu
DB_PATH = 'keys.db'

# Admin şifresi (gerçekte environment variable yapın)
ADMIN_PASSWORD = 'admin123'  # Üretimde değiştirin ve .env kullanın!

def get_db_connection():
    """SQLite veritabanına bağlan."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Key'ler için veritabanı tablosu oluştur."""
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            end_date DATE NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Admin paneli giriş sayfası."""
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('admin_panel'))
        return render_template('login.html', error="Geçersiz şifre!")
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    """Admin oturumunu sonlandır."""
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def admin_panel():
    """Admin paneli: Key'leri listele ve işlemler."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    message = None
    conn = get_db_connection()
    
    if request.method == 'POST':
        action = request.form.get('action')
        key = request.form.get('key')
        
        try:
            if action == 'delete':
                conn.execute('DELETE FROM keys WHERE key = ?', (key,))
                conn.commit()
                message = f"Key silindi: {key}"
            
            elif action == 'extend':
                days = int(request.form.get('days', 365))
                conn.execute('UPDATE keys SET end_date = date(end_date, ? || " days") WHERE key = ?',
                             (str(days), key))
                conn.commit()
                message = f"Key süresi uzatıldı: {key} (+{days} gün)"
            
            elif action == 'reduce':
                days = int(request.form.get('days', -30))
                conn.execute('UPDATE keys SET end_date = date(end_date, ? || " days") WHERE key = ?',
                             (str(days), key))
                conn.commit()
                message = f"Key süresi düşürüldü: {key} ({days} gün)"
        
        except Exception as e:
            message = f"Hata: {str(e)}"
    
    keys = conn.execute('SELECT * FROM keys').fetchall()
    conn.close()
    return render_template('admin.html', keys=keys, message=message)

@app.route('/create_key', methods=['GET', 'POST'])
def create_key():
    """Yeni key oluşturma sayfası."""
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
            
            # ACX_xxx formatında key üret
            random_part = secrets.token_urlsafe(6)[:6].upper()  # 6 karakter, büyük harf
            new_key = f"ACX_{random_part}"
            end_date = date.today() + timedelta(days=days)
            
            conn = get_db_connection()
            conn.execute('INSERT INTO keys (key, username, end_date) VALUES (?, ?, ?)',
                         (new_key, username, end_date))
            conn.commit()
            conn.close()
            return render_template('create_key.html', message=f"Key oluşturuldu: {new_key}")
        
        except sqlite3.IntegrityError:
            return render_template('create_key.html', error="Hata: Key zaten var!")
        except Exception as e:
            return render_template('create_key.html', error=f"Hata: {str(e)}")
    
    return render_template('create_key.html', error=None, message=None)

@app.route('/validate_key', methods=['POST'])
def validate_key():
    """API endpoint: Key doğrulama."""
    data = request.json
    key = data.get('key')
    if not key:
        return jsonify({'valid': False, 'message': 'Key gerekli'}), 400
    
    conn = get_db_connection()
    key_data = conn.execute('SELECT * FROM keys WHERE key = ?', (key,)).fetchone()
    conn.close()
    
    if not key_data:
        return jsonify({'valid': False, 'message': 'Geçersiz key'}), 401
    
    today = date.today()
    end_date = date.fromisoformat(key_data['end_date'])
    if today > end_date:
        return jsonify({'valid': False, 'message': 'Key süresi bitmiş'}), 401
    
    return jsonify({
        'valid': True,
        'username': key_data['username'],
        'remaining_days': (end_date - today).days
    })

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)