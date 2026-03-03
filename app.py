from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from config import get_connection
from crypto import generate_keys, hash_data, sign_data, encrypt_file, decrypt_file, verify_signature
from blockchain import calculate_hash
import os
import pickle
from functools import wraps
from datetime import datetime, timedelta
import io
import secrets
import base64
import qrcode
from io import BytesIO
import re
from dotenv import load_dotenv

load_dotenv()

from flask_bcrypt import Bcrypt
import pyotp
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'securechain_secret_2025')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.permanent_session_lifetime = timedelta(days=1)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

bcrypt = Bcrypt(app)
mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*")

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('keys', exist_ok=True)

def generate_confirmation_token():
    return secrets.token_urlsafe(32)

def log_action(user_id, action):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        ip = request.remote_addr
        cursor.execute("INSERT INTO Logs (user_id, action, ip_address) VALUES (?, ?, ?)", (user_id, action, ip))
        conn.commit()
        conn.close()
    except:
        pass

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('❌ Vous devez être connecté', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('❌ Vous devez être connecté', 'error')
            return redirect(url_for('login'))
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT is_admin FROM Users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        if not user or not user[0]:
            flash('❌ Accès non autorisé', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def _(key):
    translations = {
        'home': 'Accueil', 'login': 'Connexion', 'register': 'Inscription',
        'upload': 'Uploader', 'verify': 'Vérifier', 'my_files': 'Mes fichiers',
        'logout': 'Déconnexion', 'dashboard': 'Tableau de bord',
    }
    return translations.get(key, key)

@app.context_processor
def inject_language():
    return dict(_=_)

def classify_file(filename):
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    categories = {
        'document': ['pdf', 'doc', 'docx', 'txt', 'rtf', 'odt'],
        'image': ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp'],
        'audio': ['mp3', 'wav', 'ogg', 'flac', 'aac'],
        'video': ['mp4', 'avi', 'mkv', 'mov', 'wmv'],
        'archive': ['zip', 'rar', '7z', 'tar', 'gz'],
        'spreadsheet': ['xls', 'xlsx', 'csv', 'ods'],
        'presentation': ['ppt', 'pptx', 'odp'],
        'code': ['py', 'js', 'html', 'css', 'php', 'java', 'cpp', 'c']
    }
    for cat, extensions in categories.items():
        if ext in extensions:
            return cat
    return 'autre'

@socketio.on('connect')
def handle_connect():
    emit('notification', {'message': 'Connecté au serveur temps réel'})

def notify_user(user_id, message, type='info'):
    socketio.emit(f'user_{user_id}', {'message': message, 'type': type, 'timestamp': datetime.now().strftime('%H:%M:%S')})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        errors = []
        if len(password) < 8: errors.append("8 caractères minimum")
        if not re.search(r'[A-Z]', password): errors.append("une majuscule")
        if not re.search(r'[0-9]', password): errors.append("un chiffre")
        if errors:
            flash(f'❌ Mot de passe faible : {", ".join(errors)}', 'error')
            return redirect(url_for('register'))
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Users WHERE email = ?", (email,))
        if cursor.fetchone():
            conn.close()
            flash('❌ Cet email est déjà utilisé', 'error')
            return redirect(url_for('register'))
        cursor.execute("SELECT id FROM Users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            flash('❌ Ce nom d\'utilisateur est déjà pris', 'error')
            return redirect(url_for('register'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        private_key, public_key = generate_keys()
        token = generate_confirmation_token()
        expires = (datetime.now() + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        try:
            cursor.execute("""
                INSERT INTO Users (username, email, password, public_key, confirmation_token, token_expires)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (username, email, hashed_password, public_key.decode(), token, expires))
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            with open(f'keys/user_{user_id}_private.pem', 'wb') as f:
                f.write(private_key)
            confirm_link = url_for('confirm_email', token=token, _external=True)
            msg = Message(subject="SecureChain - Confirmez votre email", recipients=[email],
                body=f"Bonjour {username},\n\nConfirmez votre compte :\n{confirm_link}\n\nLien valable 24h.\n\nL'équipe SecureChain")
            mail.send(msg)
            flash('✅ Inscription réussie ! Un email de confirmation vous a été envoyé.', 'success')
            log_action(user_id, 'Inscription')
        except Exception as e:
            flash(f'❌ Erreur: {str(e)}', 'error')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, email_confirmed, token_expires FROM Users WHERE confirmation_token = ?", (token,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        flash('❌ Lien invalide', 'error')
        return redirect(url_for('index'))
    user_id, email, confirmed, expires = user
    if confirmed:
        conn.close()
        flash('✅ Email déjà confirmé.', 'success')
        return redirect(url_for('login'))
    if expires and datetime.strptime(expires, '%Y-%m-%d %H:%M:%S') < datetime.now():
        conn.close()
        flash('❌ Lien expiré.', 'error')
        return redirect(url_for('register'))
    cursor.execute("UPDATE Users SET email_confirmed = 1, confirmation_token = NULL WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    log_action(user_id, 'Email confirmé')
    flash('✅ Email confirmé ! Vous pouvez vous connecter.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, password, twofa_secret, twofa_enabled, email_confirmed FROM Users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            flash('❌ Identifiants incorrects', 'error')
            return redirect(url_for('login'))
        user_id, db_username, email, hashed_password, twofa_secret, twofa_enabled, email_confirmed = user
        if not bcrypt.check_password_hash(hashed_password, password):
            log_action(user_id, 'Échec connexion')
            conn.close()
            flash('❌ Identifiants incorrects', 'error')
            return redirect(url_for('login'))
        if not email_confirmed:
            conn.close()
            flash('❌ Veuillez confirmer votre email.', 'error')
            return redirect(url_for('login'))
        if twofa_enabled:
            session['2fa_user_id'] = user_id
            session['2fa_username'] = db_username
            session['2fa_email'] = email
            conn.close()
            return redirect(url_for('verify_2fa'))
        session['user_id'] = user_id
        session['username'] = db_username
        session['email'] = email
        log_action(user_id, 'Connexion réussie')
        conn.close()
        flash(f'✅ Bienvenue {username}', 'success')
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if '2fa_user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        code = request.form['code']
        user_id = session['2fa_user_id']
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT twofa_secret FROM Users WHERE id = ?", (user_id,))
        secret = cursor.fetchone()[0]
        conn.close()
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            session['user_id'] = user_id
            session['username'] = session['2fa_username']
            session['email'] = session['2fa_email']
            session.pop('2fa_user_id', None)
            session.pop('2fa_username', None)
            session.pop('2fa_email', None)
            log_action(user_id, 'Connexion 2FA réussie')
            flash('✅ Authentification réussie', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('❌ Code invalide', 'error')
    return render_template('verify_2fa.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], 'Déconnexion')
    session.clear()
    flash('✅ Déconnexion réussie', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.username, u.email, u.public_key, u.twofa_enabled, u.email_confirmed,
               COUNT(b.id) as file_count, MIN(b.timestamp) as first_upload, u.created_at
        FROM Users u LEFT JOIN Blocks b ON b.user_id = u.id
        WHERE u.id = ? GROUP BY u.id
    """, (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    profile_data = {
        'username': user_data[0], 'email': user_data[1],
        'public_key': user_data[2][:100] + '...' if user_data[2] else 'N/A',
        'full_public_key': user_data[2], 'file_count': user_data[5],
        'first_upload': user_data[6][:10] if user_data[6] else 'Aucun fichier',
        'member_since': user_data[7][:10] if user_data[7] else 'N/A',
        'twofa_enabled': user_data[3], 'email_confirmed': user_data[4]
    }
    return render_template('profile.html', profile=profile_data)

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    old_password = request.form['old_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    if new_password != confirm_password:
        flash('❌ Les nouveaux mots de passe ne correspondent pas', 'error')
        return redirect(url_for('profile'))
    errors = []
    if len(new_password) < 8: errors.append("8 caractères minimum")
    if not re.search(r'[A-Z]', new_password): errors.append("une majuscule")
    if not re.search(r'[0-9]', new_password): errors.append("un chiffre")
    if errors:
        flash(f'❌ Mot de passe faible : {", ".join(errors)}', 'error')
        return redirect(url_for('profile'))
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM Users WHERE id = ?", (user_id,))
    stored_password = cursor.fetchone()[0]
    if not bcrypt.check_password_hash(stored_password, old_password):
        flash('❌ Ancien mot de passe incorrect', 'error')
        conn.close()
        return redirect(url_for('profile'))
    new_hashed = bcrypt.generate_password_hash(new_password).decode('utf-8')
    cursor.execute("UPDATE Users SET password = ? WHERE id = ?", (new_hashed, user_id))
    conn.commit()
    conn.close()
    log_action(user_id, 'Changement mot de passe')
    flash('✅ Mot de passe modifié avec succès', 'success')
    return redirect(url_for('profile'))

@app.route('/setup-2fa')
@login_required
def setup_2fa():
    user_id = session['user_id']
    username = session['username']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT twofa_secret FROM Users WHERE id = ?", (user_id,))
    existing = cursor.fetchone()
    if existing and existing[0]:
        secret = existing[0]
    else:
        secret = pyotp.random_base32()
        cursor.execute("UPDATE Users SET twofa_secret = ? WHERE id = ?", (secret, user_id))
        conn.commit()
    conn.close()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureChain")
    qr = qrcode.make(uri)
    buffer = BytesIO()
    qr.save(buffer, format='PNG')
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    return render_template('setup_2fa.html', secret=secret, qr_code=qr_base64)

@app.route('/verify-2fa-setup', methods=['POST'])
@login_required
def verify_2fa_setup():
    code = request.form['code']
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT twofa_secret FROM Users WHERE id = ?", (user_id,))
    secret = cursor.fetchone()[0]
    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        cursor.execute("UPDATE Users SET twofa_enabled = 1 WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        log_action(user_id, '2FA activée')
        flash('✅ 2FA activée avec succès', 'success')
    else:
        conn.close()
        flash('❌ Code invalide.', 'error')
    return redirect(url_for('profile'))

@app.route('/disable-2fa')
@login_required
def disable_2fa():
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE Users SET twofa_enabled = 0, twofa_secret = NULL WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    log_action(user_id, '2FA désactivée')
    flash('✅ 2FA désactivée', 'success')
    return redirect(url_for('profile'))

@app.route('/share/<int:block_id>')
@login_required
def share_file(block_id):
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT filename, user_id FROM Blocks WHERE id = ?", (block_id,))
    block = cursor.fetchone()
    if not block or block[1] != user_id:
        conn.close()
        flash('❌ Fichier non trouvé', 'error')
        return redirect(url_for('my_files'))
    filename = block[0]
    token = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("INSERT INTO Shares (block_id, token, expires_at, created_by) VALUES (?, ?, ?, ?)", (block_id, token, expires, user_id))
    conn.commit()
    conn.close()
    share_link = url_for('access_shared', token=token, _external=True)
    return render_template('share.html', link=share_link, filename=filename, expires=expires)

@app.route('/shared/<token>')
def access_shared(token):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT s.block_id, b.filename, b.file_hash, s.expires_at FROM Shares s JOIN Blocks b ON s.block_id = b.id WHERE s.token = ?", (token,))
    share = cursor.fetchone()
    conn.close()
    if not share:
        flash('❌ Lien invalide', 'error')
        return redirect(url_for('index'))
    block_id, filename, file_hash, expires = share
    if datetime.strptime(expires, '%Y-%m-%d %H:%M:%S') < datetime.now():
        flash('❌ Lien expiré', 'error')
        return redirect(url_for('index'))
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_hash}.enc")
    meta_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_hash}.meta")
    with open(file_path, 'rb') as f:
        encrypted = f.read()
    with open(meta_path, 'rb') as f:
        meta = pickle.load(f)
    data = decrypt_file(encrypted, meta['key'], meta['nonce'], meta['tag'])
    return send_file(io.BytesIO(data), as_attachment=True, download_name=filename, mimetype='application/octet-stream')

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM Blocks WHERE user_id = ?", (user_id,))
    total_files = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM Blocks")
    total_blocks = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(DISTINCT user_id) FROM Blocks")
    active_users = cursor.fetchone()[0]
    cursor.execute("SELECT filename, timestamp FROM Blocks WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1", (user_id,))
    recent = cursor.fetchone()
    conn.close()
    stats = {
        'total_files': total_files, 'total_blocks': total_blocks, 'active_users': active_users,
        'last_file': recent[0] if recent else 'Aucun',
        'last_date': recent[1][:10] if recent else 'N/A'
    }
    return render_template('dashboard.html', stats=stats)

@app.route('/api/upload-stats')
def upload_stats():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DATE(timestamp) as date, COUNT(*) as count FROM Blocks WHERE timestamp >= DATE('now', '-7 days') GROUP BY DATE(timestamp) ORDER BY date")
    data = cursor.fetchall()
    conn.close()
    return jsonify({'days': [row[0] for row in data], 'counts': [row[1] for row in data]})

@app.route('/api/user-stats')
def user_stats():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT u.username, COUNT(b.id) as file_count FROM Users u LEFT JOIN Blocks b ON u.id = b.user_id GROUP BY u.username ORDER BY file_count DESC LIMIT 5")
    rows = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) FROM Users")
    total_users = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM Blocks")
    total_blocks = cursor.fetchone()[0]
    conn.close()
    return jsonify({'users': [r[0] for r in rows], 'counts': [r[1] for r in rows], 'total_users': total_users, 'total_blocks': total_blocks})

@app.route('/stats')
@login_required
def stats():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT filename FROM Blocks")
    files = cursor.fetchall()
    conn.close()
    categories = {}
    for file in files:
        cat = classify_file(file[0])
        categories[cat] = categories.get(cat, 0) + 1
    return render_template('stats.html', stats={'total_files': len(files), 'categories': categories})

@app.route('/my-files')
@login_required
def my_files():
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename, file_hash, timestamp FROM Blocks WHERE user_id = ? ORDER BY timestamp DESC", (user_id,))
    files = [{'id': r[0], 'filename': r[1], 'hash': r[2][:20] + '...', 'full_hash': r[2], 'date': r[3][:16] if r[3] else 'N/A'} for r in cursor.fetchall()]
    conn.close()
    return render_template('my_files.html', files=files)

@app.route('/upload-page')
@login_required
def upload_page():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('❌ Aucun fichier', 'error')
        return redirect(url_for('upload_page'))
    file = request.files['file']
    if file.filename == '':
        flash('❌ Fichier vide', 'error')
        return redirect(url_for('upload_page'))
    data = file.read()
    filename = file.filename
    file_hash = hash_data(data)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM Blocks WHERE file_hash = ?", (file_hash,))
    existing = cursor.fetchone()
    conn.close()
    if existing:
        session['pending_upload'] = {'data': data, 'filename': filename, 'file_hash': file_hash}
        flash(f'⚠️ Le fichier "{filename}" existe déjà. <a href="/force-upload">Cliquez ici pour l\'ajouter quand même</a>', 'warning')
        return redirect(url_for('my_files'))
    return process_upload(data, filename, file_hash)

@app.route('/force-upload')
@login_required
def force_upload():
    if 'pending_upload' not in session:
        return redirect(url_for('upload_page'))
    pending = session['pending_upload']
    result = process_upload(pending['data'], pending['filename'], pending['file_hash'])
    session.pop('pending_upload', None)
    return result

def process_upload(data, filename, file_hash):
    encrypted, key, nonce, tag = encrypt_file(data)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_hash}.enc")
    with open(file_path, 'wb') as f:
        f.write(encrypted)
    meta_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_hash}.meta")
    with open(meta_path, 'wb') as f:
        pickle.dump({'key': key, 'nonce': nonce, 'tag': tag}, f)
    user_id = session['user_id']
    with open(f'keys/user_{user_id}_private.pem', 'rb') as f:
        private_key = f.read()
    signature = sign_data(file_hash.encode(), private_key)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT file_hash FROM Blocks ORDER BY id DESC LIMIT 1")
    last = cursor.fetchone()
    previous_hash = last[0] if last else "0"
    cursor.execute("INSERT INTO Blocks (filename, file_hash, previous_hash, signature, user_id) VALUES (?, ?, ?, ?, ?)",
        (filename, file_hash, previous_hash, signature, user_id))
    conn.commit()
    block_id = cursor.lastrowid
    conn.close()
    log_action(user_id, f'Upload fichier #{block_id}')
    notify_user(user_id, f'✅ Fichier "{filename}" sécurisé!', 'success')
    flash(f'✅ Fichier sécurisé - Bloc #{block_id}', 'success')
    return redirect(url_for('my_files'))

@app.route('/download/<int:block_id>')
@login_required
def download(block_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT filename, file_hash, user_id FROM Blocks WHERE id = ?", (block_id,))
    block = cursor.fetchone()
    conn.close()
    if not block:
        flash('❌ Bloc introuvable', 'error')
        return redirect(url_for('my_files'))
    filename, file_hash, owner_id = block
    if owner_id != session['user_id']:
        flash('❌ Accès non autorisé', 'error')
        return redirect(url_for('my_files'))
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_hash}.enc")
    meta_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_hash}.meta")
    with open(file_path, 'rb') as f:
        encrypted = f.read()
    with open(meta_path, 'rb') as f:
        meta = pickle.load(f)
    data = decrypt_file(encrypted, meta['key'], meta['nonce'], meta['tag'])
    return send_file(io.BytesIO(data), as_attachment=True, download_name=filename, mimetype='application/octet-stream')

@app.route('/verify-page')
def verify_page():
    return render_template('verify.html', result=None)

@app.route('/verify/<int:block_id>')
def verify(block_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT b.filename, b.file_hash, b.user_id, b.signature, b.timestamp, u.username FROM Blocks b JOIN Users u ON b.user_id = u.id WHERE b.id = ?", (block_id,))
    block = cursor.fetchone()
    if not block:
        conn.close()
        flash('❌ Bloc introuvable', 'error')
        return redirect(url_for('verify_page'))
    filename, stored_hash, user_id, signature, timestamp, owner = block
    cursor.execute("SELECT public_key FROM Users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if not user:
        flash('❌ Utilisateur introuvable', 'error')
        return redirect(url_for('verify_page'))
    public_key = user[0].encode()
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{stored_hash}.enc")
    meta_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{stored_hash}.meta")
    if not os.path.exists(file_path) or not os.path.exists(meta_path):
        flash('❌ Fichier introuvable', 'error')
        return redirect(url_for('verify_page'))
    with open(file_path, 'rb') as f:
        encrypted = f.read()
    with open(meta_path, 'rb') as f:
        meta = pickle.load(f)
    try:
        data = decrypt_file(encrypted, meta['key'], meta['nonce'], meta['tag'])
        new_hash = hash_data(data)
        decrypt_ok = True
    except Exception:
        decrypt_ok = False
        new_hash = None
    signature_valid = verify_signature(stored_hash.encode(), signature, public_key)
    hash_valid = (new_hash == stored_hash) if decrypt_ok else False
    if not decrypt_ok:
        flash(f'❌ Bloc #{block_id} : Fichier corrompu', 'error')
    elif not signature_valid:
        flash(f'❌ Bloc #{block_id} : Signature invalide', 'error')
    elif not hash_valid:
        flash(f'❌ Bloc #{block_id} : Document modifié', 'error')
    else:
        flash(f'✅ Bloc #{block_id} : Document intact et authentique', 'success')
    return redirect(url_for('verify_page'))

@app.route('/verify-block', methods=['POST'])
def verify_block():
    block_id = request.form['block_id']
    return redirect(url_for('verify', block_id=block_id))

@app.route('/admin')
@admin_required
def admin():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, email_confirmed, created_at FROM Users ORDER BY created_at DESC")
    users = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) FROM Users")
    total_users = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM Blocks")
    total_blocks = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM Logs")
    total_logs = cursor.fetchone()[0]
    cursor.execute("SELECT l.action, l.ip_address, l.created_at, u.username FROM Logs l JOIN Users u ON l.user_id = u.id ORDER BY l.created_at DESC LIMIT 20")
    logs = cursor.fetchall()
    conn.close()
    return render_template('admin.html', users=users, total_users=total_users, total_blocks=total_blocks, total_logs=total_logs, logs=logs)

@app.route('/admin/delete-user/<int:user_id>')
@admin_required
def admin_delete_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM Logs WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM Shares WHERE created_by = ?", (user_id,))
    cursor.execute("DELETE FROM Blocks WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM Users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash('✅ Utilisateur supprimé', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/toggle-user/<int:user_id>')
@admin_required
def admin_toggle_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT email_confirmed FROM Users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    new_status = 0 if user[0] else 1
    cursor.execute("UPDATE Users SET email_confirmed = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    flash('✅ Statut modifié', 'success')
    return redirect(url_for('admin'))

@app.route('/')
def index():
    if 'lang' not in session:
        session['lang'] = 'fr'
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT b.id, b.filename, b.file_hash, b.timestamp, u.username FROM Blocks b JOIN Users u ON b.user_id = u.id ORDER BY b.id DESC")
    blocks = [{'id': r[0], 'filename': r[1], 'hash': r[2][:20] + '...', 'date': r[3][:16] if r[3] else 'N/A', 'owner': r[4]} for r in cursor.fetchall()]
    conn.close()
    return render_template('index.html', blocks=blocks)

if __name__ == '__main__':
    socketio.run(app, debug=False)