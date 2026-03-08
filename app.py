from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify, Response
from config import get_connection
from crypto import generate_keys, hash_data, sign_data, encrypt_file, decrypt_file, verify_signature
from blockchain import calculate_hash
from Crypto.Cipher import AES
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
import hashlib

from flask_bcrypt import Bcrypt
import pyotp
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.secret_key = 'securechain_super_secret_key_2025'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024
app.permanent_session_lifetime = timedelta(days=1)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'louhemmeasma@gmail.com'
app.config['MAIL_PASSWORD'] = 'vmtqifjfmgtaimbw'
app.config['MAIL_DEFAULT_SENDER'] = 'louhemmeasma@gmail.com'

bcrypt = Bcrypt(app)
mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*")

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('keys', exist_ok=True)
os.makedirs('qrcodes', exist_ok=True)

login_attempts = {}
MAX_ATTEMPTS = 5
BLOCK_MINUTES = 15

# ============================================
# FONCTIONS UTILES
# ============================================
def generate_confirmation_token():
    return secrets.token_urlsafe(32)

def log_action(user_id, action):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        ip = request.remote_addr
        cursor.execute(
            "INSERT INTO Logs (user_id, action, ip_address) VALUES (?, ?, ?)",
            (user_id, action, ip)
        )
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
        cursor.execute("SELECT role FROM Users WHERE id = ?", (session['user_id'],))
        result = cursor.fetchone()
        conn.close()
        if not result or result[0] != 'admin':
            flash('❌ Accès réservé aux administrateurs', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

def check_login_attempts(ip):
    now = datetime.now()
    if ip in login_attempts:
        data = login_attempts[ip]
        if data['blocked_until'] and now < data['blocked_until']:
            remaining = int((data['blocked_until'] - now).total_seconds() / 60) + 1
            return True, remaining, data['count']
        elif data['blocked_until'] and now >= data['blocked_until']:
            login_attempts[ip] = {'count': 0, 'blocked_until': None}
    return False, 0, login_attempts.get(ip, {}).get('count', 0)

def record_failed_attempt(ip):
    if ip not in login_attempts:
        login_attempts[ip] = {'count': 0, 'blocked_until': None}
    login_attempts[ip]['count'] += 1
    if login_attempts[ip]['count'] >= MAX_ATTEMPTS:
        login_attempts[ip]['blocked_until'] = datetime.now() + timedelta(minutes=BLOCK_MINUTES)
    return login_attempts[ip]['count']

def reset_attempts(ip):
    if ip in login_attempts:
        del login_attempts[ip]

def _(key):
    translations = {
        'home': 'Accueil', 'login': 'Connexion', 'register': 'Inscription',
        'upload': 'Uploader', 'verify': 'Vérifier', 'my_files': 'Mes fichiers',
        'logout': 'Déconnexion', 'dashboard': 'Tableau de bord', 'stats': 'Statistiques',
    }
    return translations.get(key, key)

@app.context_processor
def inject_language():
    return dict(_=_)

@app.context_processor
def inject_admin():
    is_admin = False
    if 'user_id' in session:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT role FROM Users WHERE id = ?", (session['user_id'],))
            result = cursor.fetchone()
            conn.close()
            is_admin = result and result[0] == 'admin'
        except:
            pass
    return dict(is_admin=is_admin)

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

# ============================================
# NOTIFICATIONS
# ============================================
@socketio.on('connect')
def handle_connect():
    emit('notification', {'message': 'Connecté au serveur temps réel'})

@socketio.on('disconnect')
def handle_disconnect():
    pass

def notify_user(user_id, message, type='info'):
    socketio.emit(f'user_{user_id}', {
        'message': message, 'type': type,
        'timestamp': datetime.now().strftime('%H:%M:%S')
    })

# ============================================
# INSCRIPTION
# ============================================
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
                INSERT INTO Users (username, email, password, public_key, confirmation_token, token_expires, role)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (username, email, hashed_password, public_key.decode(), token, expires, 'user'))
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()

            with open(f'keys/user_{user_id}_private.pem', 'wb') as f:
                f.write(private_key)

            confirm_link = url_for('confirm_email', token=token, _external=True)
            msg = Message(
                subject="SecureChain - Confirmez votre email",
                recipients=[email],
                body=f"Bonjour {username},\n\nConfirmez votre compte :\n{confirm_link}\n\nLien valable 24h.\n\nL'équipe SecureChain"
            )
            mail.send(msg)
            flash('✅ Inscription réussie ! Un email de confirmation vous a été envoyé.', 'success')
            log_action(user_id, 'Inscription')
        except Exception as e:
            flash(f'❌ Erreur lors de l\'inscription: {str(e)}', 'error')

        return redirect(url_for('login'))
    return render_template('register.html')

# ============================================
# CONFIRMATION EMAIL
# ============================================
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
    if expires[:16] < datetime.now().strftime('%Y-%m-%d %H:%M'):
        conn.close()
        flash('❌ Lien expiré.', 'error')
        return redirect(url_for('login'))
    cursor.execute("UPDATE Users SET email_confirmed = 1, confirmation_token = NULL WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    log_action(user_id, 'Email confirmé')
    flash('✅ Email confirmé ! Vous pouvez vous connecter.', 'success')
    return redirect(url_for('login'))

# ============================================
# RENVOYER EMAIL CONFIRMATION
# ============================================
@app.route('/resend-confirmation')
@login_required
def resend_confirmation():
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, email, email_confirmed FROM Users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        flash('❌ Utilisateur introuvable', 'error')
        return redirect(url_for('index'))
    username, email, email_confirmed = user
    if email_confirmed:
        conn.close()
        flash('✅ Votre email est déjà confirmé.', 'success')
        return redirect(url_for('dashboard'))
    new_token = generate_confirmation_token()
    new_expires = (datetime.now() + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("UPDATE Users SET confirmation_token = ?, token_expires = ? WHERE id = ?", (new_token, new_expires, user_id))
    conn.commit()
    conn.close()
    confirm_link = url_for('confirm_email', token=new_token, _external=True)
    try:
        msg = Message(
            subject="SecureChain - Nouveau lien de confirmation",
            recipients=[email],
            body=f"Bonjour {username},\n\nVoici votre nouveau lien :\n{confirm_link}\n\nValable 24h.\n\nL'équipe SecureChain"
        )
        mail.send(msg)
        flash('✅ Un nouvel email de confirmation vous a été envoyé.', 'success')
        log_action(user_id, 'Renvoyé email confirmation')
    except Exception as e:
        flash(f'❌ Erreur lors de l\'envoi: {str(e)}', 'error')
    return redirect(url_for('index'))

# ============================================
# MOT DE PASSE OUBLIÉ
# ============================================
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username FROM Users WHERE email = ?", (email,))
        user = cursor.fetchone()
        if user:
            user_id, username = user
            token = generate_confirmation_token()
            expires = (datetime.now() + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute("UPDATE Users SET confirmation_token = ?, token_expires = ? WHERE id = ?", (token, expires, user_id))
            conn.commit()
            conn.close()
            reset_link = url_for('reset_password', token=token, _external=True)
            try:
                msg = Message(
                    subject="SecureChain - Réinitialisation mot de passe",
                    recipients=[email],
                    body=f"Bonjour {username},\n\nRéinitialisez votre mot de passe :\n{reset_link}\n\nLien valable 1 heure.\n\nL'équipe SecureChain"
                )
                mail.send(msg)
            except:
                pass
        else:
            conn.close()
        flash('✅ Si cet email existe, un lien de réinitialisation vous a été envoyé.', 'success')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, token_expires FROM Users WHERE confirmation_token = ?", (token,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        flash('❌ Lien invalide', 'error')
        return redirect(url_for('login'))
    user_id, expires = user
    if expires[:16] < datetime.now().strftime('%Y-%m-%d %H:%M'):
        conn.close()
        flash('❌ Lien expiré.', 'error')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            flash('❌ Les mots de passe ne correspondent pas', 'error')
            return redirect(request.url)
        errors = []
        if len(new_password) < 8: errors.append("8 caractères minimum")
        if not re.search(r'[A-Z]', new_password): errors.append("une majuscule")
        if not re.search(r'[0-9]', new_password): errors.append("un chiffre")
        if errors:
            flash(f'❌ Mot de passe faible : {", ".join(errors)}', 'error')
            return redirect(request.url)
        hashed = bcrypt.generate_password_hash(new_password).decode('utf-8')
        cursor.execute("UPDATE Users SET password = ?, confirmation_token = NULL, token_expires = NULL WHERE id = ?", (hashed, user_id))
        conn.commit()
        conn.close()
        log_action(user_id, 'Mot de passe réinitialisé')
        flash('✅ Mot de passe réinitialisé avec succès !', 'success')
        return redirect(url_for('login'))
    conn.close()
    return render_template('reset_password.html', token=token)

# ============================================
# CONNEXION
# ============================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip = request.remote_addr

        blocked, remaining, attempts = check_login_attempts(ip)
        if blocked:
            flash(f'❌ Trop de tentatives. Réessayez dans {remaining} minute(s).', 'error')
            return redirect(url_for('login'))

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, email, password, twofa_secret, twofa_enabled, email_confirmed, role
            FROM Users WHERE username = ?
        """, (username,))
        user = cursor.fetchone()

        if not user:
            conn.close()
            count = record_failed_attempt(ip)
            remaining_attempts = MAX_ATTEMPTS - count
            if remaining_attempts > 0:
                flash(f'❌ Identifiants incorrects. {remaining_attempts} tentative(s) restante(s).', 'error')
            else:
                flash(f'❌ Compte bloqué pendant {BLOCK_MINUTES} minutes.', 'error')
            return redirect(url_for('login'))

        user_id, db_username, email, hashed_password, twofa_secret, twofa_enabled, email_confirmed, role = user

        if not bcrypt.check_password_hash(hashed_password, password):
            count = record_failed_attempt(ip)
            remaining_attempts = MAX_ATTEMPTS - count
            log_action(user_id, 'Échec connexion')
            conn.close()
            if remaining_attempts > 0:
                flash(f'❌ Identifiants incorrects. {remaining_attempts} tentative(s) restante(s).', 'error')
            else:
                flash(f'❌ Compte bloqué pendant {BLOCK_MINUTES} minutes.', 'error')
            return redirect(url_for('login'))

        if not email_confirmed:
            conn.close()
            flash('❌ Veuillez confirmer votre email avant de vous connecter.', 'error')
            return redirect(url_for('login'))

        reset_attempts(ip)

        if twofa_enabled:
            session['2fa_user_id'] = user_id
            session['2fa_username'] = db_username
            session['2fa_email'] = email
            session['2fa_role'] = role
            conn.close()
            return redirect(url_for('verify_2fa'))

        session['user_id'] = user_id
        session['username'] = db_username
        session['email'] = email
        session['role'] = role
        log_action(user_id, 'Connexion réussie')
        conn.close()
        flash(f'✅ Bienvenue {username}', 'success')
        return redirect(url_for('dashboard'))
    return render_template('login.html')

# ============================================
# VÉRIFICATION 2FA
# ============================================
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
            session['role'] = session['2fa_role']
            session.pop('2fa_user_id', None)
            session.pop('2fa_username', None)
            session.pop('2fa_email', None)
            session.pop('2fa_role', None)
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

# ============================================
# PROFIL
# ============================================
@app.route('/profile')
@login_required
def profile():
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.username, u.email, u.public_key, u.twofa_enabled, u.email_confirmed, u.role,
               COUNT(b.id) as file_count, MIN(b.timestamp) as first_upload, u.created_at
        FROM Users u LEFT JOIN Blocks b ON b.user_id = u.id
        WHERE u.id = ? GROUP BY u.id, u.username, u.email, u.public_key,
        u.twofa_enabled, u.email_confirmed, u.role, u.created_at
    """, (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    profile_data = {
        'username': user_data[0], 'email': user_data[1],
        'public_key': user_data[2][:100] + '...' if user_data[2] else 'N/A',
        'full_public_key': user_data[2], 'file_count': user_data[6],
        'first_upload': user_data[7][:10] if user_data[7] else 'Aucun fichier',
        'member_since': user_data[8][:10] if user_data[8] else 'N/A',
        'twofa_enabled': user_data[3], 'email_confirmed': user_data[4],
        'role': user_data[5]
    }
    return render_template('profile.html', profile=profile_data)

# ============================================
# CHANGEMENT MOT DE PASSE
# ============================================
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

# ============================================
# 2FA
# ============================================
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

# ============================================
# PARTAGE
# ============================================
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
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("""
        SELECT s.block_id, b.filename, b.file_hash, s.expires_at
        FROM Shares s JOIN Blocks b ON s.block_id = b.id
        WHERE s.token = ? AND s.expires_at > ?
    """, (token, now))
    share = cursor.fetchone()
    if not share:
        conn.close()
        flash('❌ Lien invalide ou expiré', 'error')
        return redirect(url_for('index'))
    block_id, filename, file_hash, expires = share
    conn.close()
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_hash}.enc")
    meta_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_hash}.meta")
    if not os.path.exists(file_path) or not os.path.exists(meta_path):
        flash('❌ Fichier introuvable', 'error')
        return redirect(url_for('index'))
    with open(file_path, 'rb') as f:
        encrypted = f.read()
    with open(meta_path, 'rb') as f:
        meta = pickle.load(f)
    data = decrypt_file(encrypted, meta['key'], meta['nonce'], meta['tag'])
    return send_file(io.BytesIO(data), as_attachment=True, download_name=filename, mimetype='application/octet-stream')

# ============================================
# DASHBOARD
# ============================================
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
    cursor.execute("SELECT COUNT(*) FROM MultiSignatures WHERE signer_id = ? AND signed = 0", (user_id,))
    pending_signatures = cursor.fetchone()[0]
    in_7_days = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("""
        SELECT COUNT(*) FROM Blocks WHERE user_id = ? AND expires_at IS NOT NULL
        AND expires_at > ? AND expires_at <= ?
    """, (user_id, now_str, in_7_days))
    expiring_soon = cursor.fetchone()[0]
    conn.close()
    stats = {
        'total_files': total_files, 'total_blocks': total_blocks,
        'active_users': active_users,
        'last_file': recent[0] if recent else 'Aucun',
        'last_date': recent[1][:10] if recent and recent[1] else 'N/A',
        'pending_signatures': pending_signatures,
        'expiring_soon': expiring_soon
    }
    return render_template('dashboard.html', stats=stats)

@app.route('/api/upload-stats')
def upload_stats():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT DATE(timestamp) as date, COUNT(*) as count
        FROM Blocks WHERE timestamp >= DATE('now', '-7 days')
        GROUP BY DATE(timestamp) ORDER BY date
    """)
    data = cursor.fetchall()
    conn.close()
    return jsonify({'days': [row[0] for row in data], 'counts': [row[1] for row in data]})

@app.route('/api/user-stats')
def user_stats():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.username, COUNT(b.id) as file_count
        FROM Users u LEFT JOIN Blocks b ON u.id = b.user_id
        GROUP BY u.username ORDER BY file_count DESC LIMIT 5
    """)
    rows = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) FROM Users")
    total_users = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM Blocks")
    total_blocks = cursor.fetchone()[0]
    conn.close()
    return jsonify({'users': [r[0] for r in rows], 'counts': [r[1] for r in rows],
        'total_users': total_users, 'total_blocks': total_blocks})

# ============================================
# STATISTIQUES
# ============================================
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

# ============================================
# MES FICHIERS + RECHERCHE
# ============================================
@app.route('/my-files')
@login_required
def my_files():
    user_id = session['user_id']
    search = request.args.get('search', '').strip()
    conn = get_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if search:
        cursor.execute("""
            SELECT id, filename, file_hash, timestamp, expires_at, is_valid FROM Blocks
            WHERE user_id = ? AND filename LIKE ? ORDER BY timestamp DESC
        """, (user_id, f'%{search}%'))
    else:
        cursor.execute("""
            SELECT id, filename, file_hash, timestamp, expires_at, is_valid
            FROM Blocks WHERE user_id = ? ORDER BY timestamp DESC
        """, (user_id,))
    files = []
    for row in cursor.fetchall():
        expires_at = row[4]
        is_expired = expires_at and expires_at < now_str
        files.append({
            'id': row[0], 'filename': row[1],
            'hash': row[2][:20] + '...', 'full_hash': row[2],
            'date': row[3][:16] if row[3] else 'N/A',
            'expires_at': expires_at[:10] if expires_at else 'Jamais',
            'is_expired': is_expired,
            'is_valid': row[5]
        })
    cursor.execute("""
        SELECT ms.block_id, b.filename, u.username
        FROM MultiSignatures ms JOIN Blocks b ON ms.block_id = b.id
        JOIN Users u ON b.user_id = u.id
        WHERE ms.signer_id = ? AND ms.signed = 0
    """, (user_id,))
    to_sign = cursor.fetchall()
    conn.close()
    return render_template('my_files.html', files=files, search=search, to_sign=to_sign)

# ============================================
# SUPPRESSION FICHIER
# ============================================
@app.route('/delete/<int:block_id>')
@login_required
def delete_file(block_id):
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT filename, file_hash, user_id FROM Blocks WHERE id = ?", (block_id,))
    block = cursor.fetchone()
    if not block or block[2] != user_id:
        conn.close()
        flash('❌ Fichier non trouvé ou accès non autorisé', 'error')
        return redirect(url_for('my_files'))
    filename, file_hash, _ = block
    cursor.execute("SELECT COUNT(*) FROM Blocks WHERE file_hash = ?", (file_hash,))
    count = cursor.fetchone()[0]
    cursor.execute("DELETE FROM Shares WHERE block_id = ?", (block_id,))
    cursor.execute("DELETE FROM MultiSignatures WHERE block_id = ?", (block_id,))
    cursor.execute("DELETE FROM Blocks WHERE id = ?", (block_id,))
    conn.commit()
    conn.close()
    if count <= 1:
        for ext in ['.enc', '.meta']:
            p = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_hash}{ext}")
            if os.path.exists(p): os.remove(p)
        qr_path = os.path.join('qrcodes', f"block_{block_id}.png")
        if os.path.exists(qr_path): os.remove(qr_path)
    log_action(user_id, f'Suppression fichier #{block_id} - {filename}')
    flash(f'✅ Fichier "{filename}" supprimé avec succès', 'success')
    return redirect(url_for('my_files'))

# ============================================
# UPLOAD AVEC EXPIRATION + SIGNATAIRES
# ============================================
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
    expiration_days = request.form.get('expiration_days', '').strip()
    signers_emails = request.form.get('signers', '').strip()
    expires_at = None
    if expiration_days and expiration_days.isdigit() and int(expiration_days) > 0:
        expires_at = (datetime.now() + timedelta(days=int(expiration_days))).strftime('%Y-%m-%d %H:%M:%S')
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM Blocks WHERE file_hash = ?", (file_hash,))
    existing = cursor.fetchone()
    conn.close()
    if existing:
        session['pending_upload'] = {
            'data': data, 'filename': filename, 'file_hash': file_hash,
            'expires_at': expires_at, 'signers_emails': signers_emails
        }
        flash(f'⚠️ Le fichier "{filename}" existe déjà. <a href="/force-upload">Cliquez ici pour l\'ajouter quand même</a>', 'warning')
        return redirect(url_for('my_files'))
    return process_upload(data, filename, file_hash, expires_at, signers_emails)

@app.route('/force-upload')
@login_required
def force_upload():
    if 'pending_upload' not in session:
        return redirect(url_for('upload_page'))
    pending = session['pending_upload']
    result = process_upload(
        pending['data'], pending['filename'], pending['file_hash'],
        pending.get('expires_at'), pending.get('signers_emails', '')
    )
    session.pop('pending_upload', None)
    return result

def process_upload(data, filename, file_hash, expires_at=None, signers_emails=''):
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

    signers_list = [e.strip() for e in signers_emails.split(',') if e.strip()] if signers_emails else []
    is_valid = 0 if signers_list else 1

    cursor.execute("""
        INSERT INTO Blocks (filename, file_hash, previous_hash, signature, user_id, expires_at, is_valid)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (filename, file_hash, previous_hash, signature, user_id, expires_at, is_valid))
    conn.commit()
    block_id = cursor.lastrowid

    # Enregistrer signature du propriétaire
    cursor.execute("""
        INSERT INTO MultiSignatures (block_id, signer_id, signed, signature, signed_at)
        VALUES (?, ?, 1, ?, ?)
    """, (block_id, user_id, signature, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

    # Enregistrer les autres signataires et envoyer emails
    for email in signers_list:
        cursor.execute("SELECT id, username FROM Users WHERE email = ?", (email,))
        signer = cursor.fetchone()
        if signer:
            signer_id, signer_name = signer
            cursor.execute("""
                INSERT INTO MultiSignatures (block_id, signer_id, signed) VALUES (?, ?, 0)
            """, (block_id, signer_id))
            sign_link = url_for('sign_document', block_id=block_id, _external=True)
            try:
                msg = Message(
                    subject=f"SecureChain - Document à signer : {filename}",
                    recipients=[email],
                    body=f"Bonjour {signer_name},\n\n{session['username']} vous demande de signer :\n\"{filename}\"\n\nSignez ici :\n{sign_link}\n\nCordialement,\nSecureChain"
                )
                mail.send(msg)
            except:
                pass

    conn.commit()

    # Générer QR Code
    verify_link = url_for('verify', block_id=block_id, _external=True)
    qr = qrcode.make(verify_link)
    qr_path = os.path.join('qrcodes', f"block_{block_id}.png")
    qr.save(qr_path)

    conn.close()
    log_action(user_id, f'Upload fichier #{block_id}')
    notify_user(user_id, f'✅ Fichier "{filename}" sécurisé!', 'success')

    if signers_list:
        flash(f'✅ Fichier sécurisé - Bloc #{block_id} | En attente de {len(signers_list)} signature(s)', 'success')
    else:
        flash(f'✅ Fichier sécurisé - Bloc #{block_id}', 'success')
    return redirect(url_for('my_files'))

# ============================================
# ✅ FONCTIONNALITÉ 1 : SIGNATURE MULTIPLE
# ============================================
@app.route('/sign/<int:block_id>')
@login_required
def sign_document(block_id):
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, signed FROM MultiSignatures WHERE block_id = ? AND signer_id = ?", (block_id, user_id))
    sig = cursor.fetchone()
    if not sig:
        conn.close()
        flash('❌ Vous n\'êtes pas requis pour signer ce document', 'error')
        return redirect(url_for('my_files'))
    if sig[1] == 1:
        conn.close()
        flash('✅ Vous avez déjà signé ce document', 'success')
        return redirect(url_for('my_files'))
    cursor.execute("SELECT file_hash, filename FROM Blocks WHERE id = ?", (block_id,))
    block = cursor.fetchone()
    file_hash, filename = block
    with open(f'keys/user_{user_id}_private.pem', 'rb') as f:
        private_key = f.read()
    signature = sign_data(file_hash.encode(), private_key)
    cursor.execute("""
        UPDATE MultiSignatures SET signed = 1, signature = ?, signed_at = ?
        WHERE block_id = ? AND signer_id = ?
    """, (signature, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), block_id, user_id))
    cursor.execute("SELECT COUNT(*) FROM MultiSignatures WHERE block_id = ? AND signed = 0", (block_id,))
    remaining = cursor.fetchone()[0]
    if remaining == 0:
        cursor.execute("UPDATE Blocks SET is_valid = 1 WHERE id = ?", (block_id,))
        cursor.execute("SELECT u.email, u.username FROM Blocks b JOIN Users u ON b.user_id = u.id WHERE b.id = ?", (block_id,))
        owner = cursor.fetchone()
        if owner:
            try:
                msg = Message(
                    subject=f"SecureChain - Document validé : {filename}",
                    recipients=[owner[0]],
                    body=f"Bonjour {owner[1]},\n\nToutes les signatures ont été collectées pour :\n\"{filename}\"\n\nLe document est maintenant valide ✅\n\nCordialement,\nSecureChain"
                )
                mail.send(msg)
            except:
                pass
        flash(f'✅ "{filename}" est maintenant valide ! Toutes les signatures collectées.', 'success')
    else:
        flash(f'✅ Vous avez signé ! Il reste {remaining} signature(s).', 'success')
    conn.commit()
    conn.close()
    log_action(user_id, f'Signé document #{block_id}')
    return redirect(url_for('my_files'))

@app.route('/signatures/<int:block_id>')
@login_required
def view_signatures(block_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ms.signer_id, u.username, u.email, ms.signed, ms.signed_at
        FROM MultiSignatures ms JOIN Users u ON ms.signer_id = u.id WHERE ms.block_id = ?
    """, (block_id,))
    signatures = cursor.fetchall()
    cursor.execute("SELECT filename, is_valid, expires_at FROM Blocks WHERE id = ?", (block_id,))
    block = cursor.fetchone()
    conn.close()
    return render_template('signatures.html', signatures=signatures, block=block, block_id=block_id)

# ============================================
# ✅ FONCTIONNALITÉ 2 : QR CODE
# ============================================
@app.route('/qrcode/<int:block_id>')
def get_qrcode(block_id):
    qr_path = os.path.join('qrcodes', f"block_{block_id}.png")
    if not os.path.exists(qr_path):
        verify_link = url_for('verify', block_id=block_id, _external=True)
        qr = qrcode.make(verify_link)
        qr.save(qr_path)
    return send_file(qr_path, mimetype='image/png')

# ============================================
# TÉLÉCHARGEMENT AVEC ALERTE EMAIL + VÉRIF EXPIRATION
# ============================================
@app.route('/download/<int:block_id>')
@login_required
def download(block_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT filename, file_hash, user_id, expires_at FROM Blocks WHERE id = ?", (block_id,))
    block = cursor.fetchone()
    conn.close()
    if not block:
        flash('❌ Bloc introuvable', 'error')
        return redirect(url_for('my_files'))
    filename, file_hash, owner_id, expires_at = block
    if owner_id != session['user_id']:
        flash('❌ Accès non autorisé', 'error')
        return redirect(url_for('my_files'))

    # ✅ FONCTIONNALITÉ 3 : vérifier expiration
    if expires_at:
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if expires_at < now_str:
            flash(f'❌ Ce document a expiré le {expires_at[:10]}. Téléchargement impossible.', 'error')
            return redirect(url_for('my_files'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_hash}.enc")
    meta_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_hash}.meta")
    if not os.path.exists(file_path) or not os.path.exists(meta_path):
        flash('❌ Fichier introuvable', 'error')
        return redirect(url_for('my_files'))
    with open(file_path, 'rb') as f:
        encrypted = f.read()
    with open(meta_path, 'rb') as f:
        meta = pickle.load(f)
    data = decrypt_file(encrypted, meta['key'], meta['nonce'], meta['tag'])

    # ✅ FONCTIONNALITÉ 4 : alerte email téléchargement
    try:
        conn2 = get_connection()
        cursor2 = conn2.cursor()
        cursor2.execute("SELECT email, username FROM Users WHERE id = ?", (owner_id,))
        owner = cursor2.fetchone()
        conn2.close()
        if owner:
            msg = Message(
                subject=f"SecureChain - Téléchargement : {filename}",
                recipients=[owner[0]],
                body=f"Bonjour {owner[1]},\n\nVotre fichier \"{filename}\" a été téléchargé.\n\nDétails :\n- Par : {session['username']}\n- Date : {datetime.now().strftime('%d/%m/%Y à %H:%M')}\n- IP : {request.remote_addr}\n\nSi ce n'est pas vous, contactez l'administrateur.\n\nCordialement,\nSecureChain"
            )
            mail.send(msg)
    except:
        pass

    log_action(session['user_id'], f'Téléchargement fichier #{block_id}')
    return send_file(io.BytesIO(data), as_attachment=True, download_name=filename, mimetype='application/octet-stream')

# ============================================
# VÉRIFICATION
# ============================================
@app.route('/verify-page')
def verify_page():
    return render_template('verify.html', result=None)

@app.route('/verify/<int:block_id>')
def verify(block_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT b.filename, b.file_hash, b.user_id, b.signature, b.timestamp,
               u.username, b.expires_at, b.is_valid
        FROM Blocks b JOIN Users u ON b.user_id = u.id WHERE b.id = ?
    """, (block_id,))
    block = cursor.fetchone()
    if not block:
        conn.close()
        flash('❌ Bloc introuvable', 'error')
        return redirect(url_for('verify_page'))
    filename, stored_hash, user_id, signature, timestamp, owner, expires_at, is_valid = block
    cursor.execute("SELECT public_key FROM Users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if not user:
        flash('❌ Utilisateur introuvable', 'error')
        return redirect(url_for('verify_page'))
    public_key = user[0].encode()

    # Vérifier expiration
    if expires_at:
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if expires_at < now_str:
            flash(f'❌ Bloc #{block_id} : Document expiré le {expires_at[:10]}', 'error')
            return redirect(url_for('verify_page'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{stored_hash}.enc")
    meta_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{stored_hash}.meta")
    if not os.path.exists(file_path) or not os.path.exists(meta_path):
        flash('❌ Fichier introuvable sur le serveur', 'error')
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
    elif not is_valid:
        flash(f'⏳ Bloc #{block_id} : En attente de signatures', 'warning')
    else:
        flash(f'✅ Bloc #{block_id} : Document intact, authentique et valide', 'success')
    return redirect(url_for('verify_page'))

@app.route('/verify-block', methods=['POST'])
def verify_block():
    block_id = request.form['block_id']
    return redirect(url_for('verify', block_id=block_id))

# ============================================
# BLOCKCHAIN PUBLIQUE
# ============================================
@app.route('/blockchain')
def blockchain():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT b.id, b.filename, b.file_hash, b.timestamp, u.username, b.is_valid, b.expires_at
        FROM Blocks b JOIN Users u ON b.user_id = u.id ORDER BY b.id DESC
    """)
    blocks = []
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    for row in cursor.fetchall():
        is_expired = row[6] and row[6] < now_str
        blocks.append({
            'id': row[0], 'filename': row[1], 'file_hash': row[2],
            'timestamp': row[3][:16] if row[3] else 'N/A',
            'username': row[4], 'is_valid': row[5],
            'expires_at': row[6][:10] if row[6] else 'Jamais',
            'is_expired': is_expired
        })
    conn.close()
    return render_template('blocks.html', blocks=blocks)

# ============================================
# PANEL ADMIN
# ============================================
@app.route('/admin')
@admin_required
def admin_panel():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM Users")
    total_users = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM Blocks")
    total_files = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM Logs")
    total_logs = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM Users WHERE email_confirmed = 0")
    unconfirmed_users = cursor.fetchone()[0]
    cursor.execute("SELECT id, username, email, created_at, role, email_confirmed FROM Users ORDER BY created_at DESC LIMIT 10")
    recent_users = cursor.fetchall()
    cursor.execute("""
        SELECT b.id, b.filename, b.timestamp, u.username
        FROM Blocks b JOIN Users u ON b.user_id = u.id ORDER BY b.timestamp DESC LIMIT 10
    """)
    recent_files = cursor.fetchall()
    cursor.execute("""
        SELECT user_id, action, ip_address, timestamp FROM Logs
        WHERE action LIKE '%échec%' OR action LIKE '%invalide%'
        ORDER BY timestamp DESC LIMIT 10
    """)
    suspicious_logs = cursor.fetchall()
    conn.close()
    return render_template('admin.html',
        total_users=total_users, total_files=total_files,
        total_logs=total_logs, unconfirmed_users=unconfirmed_users,
        recent_users=recent_users, recent_files=recent_files,
        suspicious_logs=suspicious_logs)

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, email_confirmed, twofa_enabled, created_at FROM Users ORDER BY created_at DESC")
    users = cursor.fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)

@app.route('/admin/toggle-role/<int:user_id>')
@admin_required
def toggle_role(user_id):
    if user_id == session['user_id']:
        flash('❌ Vous ne pouvez pas modifier votre propre rôle', 'error')
        return redirect(url_for('admin_users'))
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM Users WHERE id = ?", (user_id,))
    current_role = cursor.fetchone()[0]
    new_role = 'admin' if current_role == 'user' else 'user'
    cursor.execute("UPDATE Users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    flash('✅ Rôle modifié avec succès', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/delete-user/<int:user_id>')
@admin_required
def admin_delete_user(user_id):
    if user_id == session['user_id']:
        flash('❌ Vous ne pouvez pas supprimer votre propre compte', 'error')
        return redirect(url_for('admin_users'))
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM Shares WHERE created_by = ?", (user_id,))
        cursor.execute("DELETE FROM Logs WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM MultiSignatures WHERE signer_id = ?", (user_id,))
        cursor.execute("DELETE FROM Blocks WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM Users WHERE id = ?", (user_id,))
        conn.commit()
        flash('✅ Utilisateur supprimé avec succès', 'success')
    except Exception as e:
        flash(f'❌ Erreur: {str(e)}', 'error')
    finally:
        conn.close()
    return redirect(url_for('admin_users'))

@app.route('/admin/logs')
@admin_required
def admin_logs():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT l.id, l.user_id, u.username, l.action, l.ip_address, l.timestamp
        FROM Logs l LEFT JOIN Users u ON l.user_id = u.id ORDER BY l.timestamp DESC
    """)
    logs = cursor.fetchall()
    conn.close()
    return render_template('admin_logs.html', logs=logs)

@app.route('/admin/stats')
@admin_required
def admin_stats():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT DATE(timestamp) as date, COUNT(*) as uploads, COUNT(DISTINCT user_id) as active_users
        FROM Blocks GROUP BY DATE(timestamp) ORDER BY date DESC
    """)
    daily_stats = cursor.fetchall()
    cursor.execute("""
        SELECT u.username, COUNT(b.id) as upload_count
        FROM Users u LEFT JOIN Blocks b ON u.id = b.user_id
        GROUP BY u.username ORDER BY upload_count DESC LIMIT 10
    """)
    top_users = cursor.fetchall()
    conn.close()
    return render_template('admin_stats.html', daily_stats=daily_stats, top_users=top_users)

# ============================================
# ACCUEIL
# ============================================
@app.route('/')
def index():
    if 'lang' not in session:
        session['lang'] = 'fr'
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT b.id, b.filename, b.file_hash, b.timestamp, u.username
        FROM Blocks b JOIN Users u ON b.user_id = u.id ORDER BY b.id DESC
    """)
    blocks = []
    for row in cursor.fetchall():
        blocks.append({
            'id': row[0], 'filename': row[1], 'hash': row[2][:20] + '...',
            'date': row[3][:16] if row[3] else 'N/A', 'owner': row[4]
        })
    conn.close()
    return render_template('index.html', blocks=blocks)

if __name__ == '__main__':
    socketio.run(app, debug=True)