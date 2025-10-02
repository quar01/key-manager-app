from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import sqlite3
from datetime import date, timedelta
import os
from dotenv import load_dotenv
import secrets

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY') or 'dev_secret_key'
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD') or 'admin123'

# Veritabanı yolu
DB_PATH = 'keys.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            end_date DATE NOT NULL,
            is_banned INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

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
    keys = conn.execute('SELECT * FROM keys').fetchall()
    conn.close()
    return render_template('admin.html', keys=keys)

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
        
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('create_key.html', error="Bu key zaten mevcut!")
        except Exception as e:
            conn.close()
            return render_template('create_key.html', error=f"Hata: {str(e)}")
    
    return render_template('create_key.html', error=None, message=None)

@app.route('/validate_key', methods=['POST'])
def validate_key():
    data = request.json
    key = data.get('key')
    if not key:
        return jsonify({'valid': False, 'message': 'Key gerekli'}), 400
    
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
    
    conn.close()
    
    return jsonify({
        'valid': True,
        'username': key_data['username'],
        'remaining_days': (end_date - today).days
    })

# Veritabanını başlatmadan önce çağır
init_db()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
