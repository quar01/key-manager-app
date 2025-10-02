from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from datetime import date, timedelta, datetime
import os
from dotenv import load_dotenv
import requests
import secrets
from sqlalchemy import create_engine, Column, Integer, String, Date, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func  # func ithalatı eklendi

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY') or 'dev_secret_key'  # Üretimde değiştirin
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD') or 'admin123'

# Veritabanı URL'si
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///keys.db')
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
Base = declarative_base()

# Tabloları tanımla
class Key(Base):
    __tablename__ = 'keys'
    id = Column(Integer, primary_key=True)
    key = Column(String, unique=True, nullable=False)
    username = Column(String, nullable=False)
    end_date = Column(Date, nullable=False)
    is_banned = Column(Boolean, default=False)

class IPLog(Base):
    __tablename__ = 'ip_logs'
    id = Column(Integer, primary_key=True)
    key = Column(String, nullable=False)
    ip = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String, default='validate')

class BannedIP(Base):
    __tablename__ = 'banned_ips'
    id = Column(Integer, primary_key=True)
    ip = Column(String, unique=True, nullable=False)
    ban_date = Column(DateTime, default=datetime.utcnow)
    reason = Column(String)

def get_db_connection():
    return Session()

def init_db():
    Base.metadata.create_all(engine)

# IP ban kontrolü
def is_ip_banned(ip):
    db_session = get_db_connection()
    result = db_session.query(BannedIP).filter_by(ip=ip).first()
    db_session.close()
    return result is not None

# IP loglama
def log_ip(key, ip, action='validate'):
    db_session = get_db_connection()
    new_log = IPLog(key=key, ip=ip, action=action)
    db_session.add(new_log)
    db_session.commit()
    db_session.close()

# Aynı key için son 5 dakikada birden fazla IP kontrolü
def check_simultaneous_use(key):
    db_session = get_db_connection()
    five_min_ago = datetime.utcnow() - timedelta(minutes=5)
    logs = db_session.query(IPLog.ip).filter_by(key=key).filter(IPLog.timestamp > five_min_ago).group_by(IPLog.ip).all()
    db_session.close()
    return len(logs) > 1

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
    
    db_session = get_db_connection()
    # Kullanılmayan key'ler (son 24 saatte log yok)
    unused_keys = db_session.query(Key).filter_by(is_banned=False).filter(~Key.key.in_(
        db_session.query(IPLog.key).filter(IPLog.timestamp > (datetime.utcnow() - timedelta(days=1))).distinct()
    )).all()
    
    # Kullanılan key'ler (son 24 saatte log var)
    used_keys = db_session.query(Key).select_from(Key).outerjoin(IPLog, Key.key == IPLog.key).filter(
        Key.is_banned == False,
        (IPLog.timestamp > (datetime.utcnow() - timedelta(days=1))) | (IPLog.timestamp == None)
    ).group_by(Key.key).add_column(
        db_session.query(IPLog).filter(IPLog.timestamp > (datetime.utcnow() - timedelta(days=1))).group_by(IPLog.key).with_entities(func.count(IPLog.ip).label('usage_count')).subquery().c.usage_count
    ).all()
    
    # Banlı key'ler
    banned_keys = db_session.query(Key).filter_by(is_banned=True).all()
    
    # Banlı IP'ler
    banned_ips = db_session.query(BannedIP).all()
    
    db_session.close()
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
            
            db_session = get_db_connection()
            new_key_entry = Key(key=new_key, username=username, end_date=end_date)
            db_session.add(new_key_entry)
            db_session.commit()
            db_session.close()
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
    
    db_session = get_db_connection()
    key_to_ban = db_session.query(Key).filter_by(key=key).first()
    if key_to_ban:
        key_to_ban.is_banned = True
        db_session.commit()
    db_session.close()
    return jsonify({'success': True})

@app.route('/unban_key', methods=['POST'])
def unban_key():
    if not session.get('logged_in'):
        return jsonify({'error': 'Yetkisiz'}), 403
    
    key = request.json.get('key')
    
    db_session = get_db_connection()
    key_to_unban = db_session.query(Key).filter_by(key=key).first()
    if key_to_unban:
        key_to_unban.is_banned = False
        db_session.commit()
    db_session.close()
    return jsonify({'success': True})

@app.route('/ban_ip', methods=['POST'])
def ban_ip():
    if not session.get('logged_in'):
        return jsonify({'error': 'Yetkisiz'}), 403
    
    ip = request.json.get('ip')
    reason = request.json.get('reason', 'Manuel ban')
    
    db_session = get_db_connection()
    new_ban = BannedIP(ip=ip, reason=reason)
    db_session.add(new_ban)
    db_session.commit()
    db_session.close()
    return jsonify({'success': True})

@app.route('/unban_ip', methods=['POST'])
def unban_ip():
    if not session.get('logged_in'):
        return jsonify({'error': 'Yetkisiz'}), 403
    
    ip = request.json.get('ip')
    
    db_session = get_db_connection()
    ban_to_remove = db_session.query(BannedIP).filter_by(ip=ip).first()
    if ban_to_remove:
        db_session.delete(ban_to_remove)
        db_session.commit()
    db_session.close()
    return jsonify({'success': True})

@app.route('/get_ip_logs/<key>', methods=['GET'])
def get_ip_logs(key):
    if not session.get('logged_in'):
        return jsonify({'error': 'Yetkisiz'}), 403
    
    db_session = get_db_connection()
    logs = db_session.query(IPLog).filter_by(key=key).order_by(IPLog.timestamp.desc()).all()
    db_session.close()
    return jsonify([log.__dict__ for log in logs])

@app.route('/validate_key', methods=['POST'])
def validate_key():
    data = request.json
    key = data.get('key')
    ip = data.get('ip')
    if not key:
        return jsonify({'valid': False, 'message': 'Key gerekli'}), 400
    
    if is_ip_banned(ip):
        return jsonify({'valid': False, 'message': 'IP adresiniz banlanmış'}), 401
    
    db_session = get_db_connection()
    key_data = db_session.query(Key).filter_by(key=key).first()
    
    if not key_data:
        db_session.close()
        return jsonify({'valid': False, 'message': 'Geçersiz key'}), 401
    
    if key_data.is_banned:
        db_session.close()
        return jsonify({'valid': False, 'message': 'Key banlanmış'}), 401
    
    today = date.today()
    end_date = key_data.end_date
    if today > end_date:
        db_session.close()
        return jsonify({'valid': False, 'message': 'Key süresi bitmiş'}), 401
    
    log_ip(key, ip)
    
    if check_simultaneous_use(key):
        key_data.is_banned = True
        db_session.commit()
        db_session.close()
        return jsonify({'valid': False, 'message': 'Key banlandı (aynı anda birden fazla cihaz)'}), 401
    
    db_session.close()
    
    return jsonify({
        'valid': True,
        'username': key_data.username,
        'remaining_days': (end_date - today).days
    })

# Veritabanını başlatmadan önce çağır
init_db()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
