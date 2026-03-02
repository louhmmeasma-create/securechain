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

# Charger les variables d'environnement
load_dotenv()

# Niveau 1 : Bcrypt
from flask_bcrypt import Bcrypt

# Niveau 2 : 2FA, Logs
import pyotp

# Niveau 3 : Email
from flask_mail import Mail, Message

# Niveau 4 : Notifications temps réel
from flask_socketio import SocketIO, emit

app = Flask(__name__)

# ✅ SECRETS DEPUIS .env
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_secret_key')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.permanent_session_lifetime = timedelta(days=1)

# ✅ Configuration email depuis .env
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# Initialisation des extensions
bcrypt = Bcrypt(app)
mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Créer les dossiers
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('keys', exist_ok=True)

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
            "INSERT INTO Logs (user_id, action, ip_address) VALUES (%s, %s, %s)",
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

# ============================================
# LANGUES (simplifiée)
# ============================================
def _(key):
    translations = {
        'home': 'Accueil', 'login': 'Connexion', 'register': 'Inscription',
        'upload': 'Uploader', 'verify': 'Vérifier', 'my_files': 'Mes fichiers',
        'logout': 'Déconnexion', 'intact': 'Document intact',
        'modified': 'Document modifié', 'file': 'Fichier', 'date': 'Date',
        'action': 'Action', 'block_id': 'ID du bloc', 'verify_btn': 'Vérifier',
        'owner': 'Propriétaire', 'result': 'Résultat', 'back': 'Retour',
        'welcome': 'Bienvenue', 'username': "Nom d'utilisateur",
        'password': 'Mot de passe', 'submit': 'Valider', 'email': 'Email',
        'dashboard': 'Tableau de bord', 'stats': 'Statistiques',
        'download': 'Télécharger', 'hash': 'Empreinte', 'signature': 'Signature',
        'profile': 'Profil', 'change_password': 'Changer mot de passe',
        'old_password': 'Ancien mot de passe', 'new_password': 'Nouveau mot de passe',
        'confirm_password': 'Confirmer', 'update': 'Mettre à jour',
        'member_since': 'Membre depuis', 'public_key': 'Clé publique',
        'enable_2fa': 'Activer 2FA', 'verify_2fa': 'Vérifier code 2FA',
        'share_file': 'Partager', 'share_link': 'Lien de partage',
        'copy_link': 'Copier le lien', 'expires': 'Expire le',
        'total_files': 'Total fichiers', 'first_upload': 'Premier upload',
        'last_file': 'Dernier fichier', 'activity': 'Activité',
        'uploads': 'Uploads', 'quick_actions': 'Actions rapides',
        'recent_activity': 'Activité récente', 'total_blocks': 'Total blocs',
        'active_users': 'Utilisateurs actifs', 'storage': 'Stockage',
        'confirm_email': 'Confirmer email', 'accept_terms': 'Accepter les conditions',
        'already_have_account': 'Déjà un compte ?', 'create_account': 'Créer un compte'
    }
    return translations.get(key, key)

@app.context_processor
def inject_language():
    return dict(_=_)

@app.route('/set-language/<lang>')
def set_language(lang):
    if lang in ['fr', 'en']:
        session['lang'] = lang
    return redirect(request.referrer or url_for('index'))

# ============================================
# CLASSIFICATION DES DOCUMENTS
# ============================================
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
# NOTIFICATIONS TEMPS RÉEL
# ============================================
@socketio.on('connect')
def handle_connect():
    emit('notification', {'message': 'Connecté au serveur temps réel'})

@socketio.on('disconnect')
def handle_disconnect():
    pass

def notify_user(user_id, message, type='info'):
    socketio.emit(f'user_{user_id}', {
        'message': message,
        'type': type,
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
        if len(password) < 8:
            errors.append("8 caractères minimum")
        if not re.search(r'[A-Z]', password):
            errors.append("une majuscule")
        if not re.search(r'[0-9]', password):
            errors.append("un chiffre")
        
        if errors:
            flash(f'❌ Mot de passe faible : {", ".join(errors)}', 'error')
            return redirect(url_for('register'))
        
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM Users WHERE email = %s", (email,))
        if cursor.fetchone():
            conn.close()
            flash('❌ Cet email est déjà utilisé', 'error')
            return redirect(url_for('register'))
        
        cursor.execute("SELECT id FROM Users WHERE username = %s", (username,))
        if cursor.fetchone():
            conn.close()
            flash('❌ Ce nom d\'utilisateur est déjà pris', 'error')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        private_key, public_key = generate_keys()
        token = generate_confirmation_token()
        expires = datetime.now() + timedelta(hours=24)
        
        try:
            # ✅ PostgreSQL : RETURNING id au lieu de @@IDENTITY
            cursor.execute("""
                INSERT INTO Users (username, email, password, public_key, confirmation_token, token_expires)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (username, email, hashed_password, public_key.decode(), token, expires))
            conn.commit()
            user_id = cursor.fetchone()[0]
            
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
            log_action(user_id, 'Inscription - En attente de confirmation')
            
        except Exception as e:
            flash(f'❌ Erreur lors de l\'inscription: {str(e)}', 'error')
        finally:
            conn.close()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

# ============================================
# CONFIRMATION EMAIL
# ============================================
@app.route('/confirm/<token>')
def confirm_email(token):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, email, email_confirmed, token_expires 
        FROM Users WHERE confirmation_token = %s
    """, (token,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        flash('❌ Lien de confirmation invalide', 'error')
        return redirect(url_for('index'))
    
    user_id, email, confirmed, expires = user
    
    if confirmed:
        conn.close()
        flash('✅ Email déjà confirmé.', 'success')
        return redirect(url_for('login'))
    
    if expires < datetime.now():
        conn.close()
        flash('❌ Lien expiré. Veuillez vous réinscrire.', 'error')
        return redirect(url_for('register'))
    
    cursor.execute("""
        UPDATE Users SET email_confirmed = true, confirmation_token = NULL WHERE id = %s
    """, (user_id,))
    conn.commit()
    conn.close()
    
    log_action(user_id, 'Email confirmé')
    flash('✅ Email confirmé ! Vous pouvez vous connecter.', 'success')
    return redirect(url_for('login'))

# ============================================
# CONNEXION
# ============================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, email, password, twofa_secret, twofa_enabled, email_confirmed 
            FROM Users WHERE username = %s
        """, (username,))
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
        cursor.execute("SELECT twofa_secret FROM Users WHERE id = %s", (user_id,))
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
        SELECT u.username, u.email, u.public_key, u.twofa_enabled, u.email_confirmed,
               COUNT(b.id) as file_count,
               MIN(b.timestamp) as first_upload,
               u.created_at
        FROM Users u
        LEFT JOIN Blocks b ON b.user_id = u.id
        WHERE u.id = %s
        GROUP BY u.username, u.email, u.public_key, u.twofa_enabled, u.email_confirmed, u.created_at
    """, (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    profile_data = {
        'username': user_data[0],
        'email': user_data[1],
        'public_key': user_data[2][:100] + '...' if user_data[2] else 'N/A',
        'full_public_key': user_data[2],
        'file_count': user_data[5],
        'first_upload': user_data[6].strftime('%d/%m/%Y') if user_data[6] else 'Aucun fichier',
        'member_since': user_data[7].strftime('%d/%m/%Y') if user_data[7] else 'N/A',
        'twofa_enabled': user_data[3],
        'email_confirmed': user_data[4]
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
    if len(new_password) < 8:
        errors.append("8 caractères minimum")
    if not re.search(r'[A-Z]', new_password):
        errors.append("une majuscule")
    if not re.search(r'[0-9]', new_password):
        errors.append("un chiffre")
    
    if errors:
        flash(f'❌ Nouveau mot de passe faible : {", ".join(errors)}', 'error')
        return redirect(url_for('profile'))
    
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM Users WHERE id = %s", (user_id,))
    stored_password = cursor.fetchone()[0]
    
    if not bcrypt.check_password_hash(stored_password, old_password):
        flash('❌ Ancien mot de passe incorrect', 'error')
        conn.close()
        return redirect(url_for('profile'))
    
    new_hashed = bcrypt.generate_password_hash(new_password).decode('utf-8')
    cursor.execute("UPDATE Users SET password = %s WHERE id = %s", (new_hashed, user_id))
    conn.commit()
    conn.close()
    log_action(user_id, 'Changement mot de passe')
    flash('✅ Mot de passe modifié avec succès', 'success')
    return redirect(url_for('profile'))

# ============================================
# CONFIGURATION 2FA
# ============================================
@app.route('/setup-2fa')
@login_required
def setup_2fa():
    user_id = session['user_id']
    username = session['username']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT twofa_secret FROM Users WHERE id = %s", (user_id,))
    existing = cursor.fetchone()
    
    if existing and existing[0]:
        secret = existing[0]
    else:
        secret = pyotp.random_base32()
        cursor.execute("UPDATE Users SET twofa_secret = %s WHERE id = %s", (secret, user_id))
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
    cursor.execute("SELECT twofa_secret FROM Users WHERE id = %s", (user_id,))
    secret = cursor.fetchone()[0]
    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        cursor.execute("UPDATE Users SET twofa_enabled = true WHERE id = %s", (user_id,))
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
    cursor.execute("UPDATE Users SET twofa_enabled = false, twofa_secret = NULL WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    log_action(user_id, '2FA désactivée')
    flash('✅ 2FA désactivée', 'success')
    return redirect(url_for('profile'))

# ============================================
# PARTAGE DE FICHIERS
# ============================================
@app.route('/share/<int:block_id>')
@login_required
def share_file(block_id):
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT filename, user_id FROM Blocks WHERE id = %s", (block_id,))
    block = cursor.fetchone()
    
    if not block or block[1] != user_id:
        conn.close()
        flash('❌ Fichier non trouvé', 'error')
        return redirect(url_for('my_files'))
    
    filename = block[0]
    token = secrets.token_urlsafe(32)
    expires = datetime.now() + timedelta(hours=24)
    cursor.execute("""
        INSERT INTO Shares (block_id, token, expires_at, created_by) VALUES (%s, %s, %s, %s)
    """, (block_id, token, expires, user_id))
    conn.commit()
    conn.close()
    
    share_link = url_for('access_shared', token=token, _external=True)
    return render_template('share.html', link=share_link, filename=filename, expires=expires)

@app.route('/shared/<token>')
def access_shared(token):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.block_id, b.filename, b.file_hash, s.expires_at
        FROM Shares s
        JOIN Blocks b ON s.block_id = b.id
        WHERE s.token = %s AND s.expires_at > NOW()
    """, (token,))
    share = cursor.fetchone()
    conn.close()
    
    if not share:
        flash('❌ Lien invalide ou expiré', 'error')
        return redirect(url_for('index'))
    
    block_id, filename, file_hash, expires = share
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_hash}.enc")
    meta_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_hash}.meta")
    
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
    cursor.execute("SELECT COUNT(*) FROM Blocks WHERE user_id = %s", (user_id,))
    total_files = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM Blocks")
    total_blocks = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(DISTINCT user_id) FROM Blocks")
    active_users = cursor.fetchone()[0]
    cursor.execute("SELECT filename, timestamp FROM Blocks WHERE user_id = %s ORDER BY timestamp DESC LIMIT 1", (user_id,))
    recent = cursor.fetchone()
    conn.close()
    
    stats = {
        'total_files': total_files,
        'total_blocks': total_blocks,
        'active_users': active_users,
        'last_file': recent[0] if recent else 'Aucun',
        'last_date': recent[1].strftime('%Y-%m-%d') if recent else 'N/A'
    }
    return render_template('dashboard.html', stats=stats)

@app.route('/api/upload-stats')
def upload_stats():
    conn = get_connection()
    cursor = conn.cursor()
    # ✅ PostgreSQL : NOW() - INTERVAL au lieu de DATEADD
    cursor.execute("""
        SELECT DATE(timestamp) as date, COUNT(*) as count
        FROM Blocks
        WHERE timestamp >= NOW() - INTERVAL '7 days'
        GROUP BY DATE(timestamp)
        ORDER BY date
    """)
    data = cursor.fetchall()
    conn.close()
    days = [row[0].strftime('%a') for row in data]
    counts = [row[1] for row in data]
    return jsonify({'days': days, 'counts': counts})

@app.route('/api/user-stats')
def user_stats():
    conn = get_connection()
    cursor = conn.cursor()
    # ✅ PostgreSQL : LIMIT au lieu de TOP
    cursor.execute("""
        SELECT u.username, COUNT(b.id) as file_count
        FROM Users u
        LEFT JOIN Blocks b ON u.id = b.user_id
        GROUP BY u.username
        ORDER BY file_count DESC
        LIMIT 5
    """)
    users = []
    counts = []
    for row in cursor.fetchall():
        users.append(row[0])
        counts.append(row[1])
    cursor.execute("SELECT COUNT(*) FROM Users")
    total_users = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM Blocks")
    total_blocks = cursor.fetchone()[0]
    conn.close()
    return jsonify({'users': users, 'counts': counts, 'total_users': total_users, 'total_blocks': total_blocks})

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
    total = len(files)
    for file in files:
        cat = classify_file(file[0])
        categories[cat] = categories.get(cat, 0) + 1
    return render_template('stats.html', stats={'total_files': total, 'categories': categories})

# ============================================
# MES FICHIERS
# ============================================
@app.route('/my-files')
@login_required
def my_files():
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, filename, file_hash, timestamp 
        FROM Blocks WHERE user_id = %s ORDER BY timestamp DESC
    """, (user_id,))
    files = []
    for row in cursor.fetchall():
        files.append({
            'id': row[0],
            'filename': row[1],
            'hash': row[2][:20] + '...',
            'full_hash': row[2],
            'date': row[3].strftime('%Y-%m-%d %H:%M') if row[3] else 'N/A'
        })
    conn.close()
    return render_template('my_files.html', files=files)

# ============================================
# UPLOAD
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
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM Blocks WHERE file_hash = %s", (file_hash,))
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
    # ✅ PostgreSQL : LIMIT 1 au lieu de TOP 1, RETURNING id
    cursor.execute("SELECT file_hash FROM Blocks ORDER BY id DESC LIMIT 1")
    last = cursor.fetchone()
    previous_hash = last[0] if last else "0"
    cursor.execute("""
        INSERT INTO Blocks (filename, file_hash, previous_hash, signature, user_id)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id
    """, (filename, file_hash, previous_hash, signature, user_id))
    conn.commit()
    block_id = cursor.fetchone()[0]
    conn.close()
    log_action(user_id, f'Upload fichier #{block_id}')
    notify_user(user_id, f'✅ Fichier "{filename}" sécurisé!', 'success')
    flash(f'✅ Fichier sécurisé - Bloc #{block_id}', 'success')
    return redirect(url_for('my_files'))

# ============================================
# TÉLÉCHARGEMENT
# ============================================
@app.route('/download/<int:block_id>')
@login_required
def download(block_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT filename, file_hash, user_id FROM Blocks WHERE id = %s", (block_id,))
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
        SELECT b.filename, b.file_hash, b.user_id, b.signature, b.timestamp, u.username
        FROM Blocks b JOIN Users u ON b.user_id = u.id WHERE b.id = %s
    """, (block_id,))
    block = cursor.fetchone()
    if not block:
        conn.close()
        flash('❌ Bloc introuvable', 'error')
        return redirect(url_for('verify_page'))
    filename, stored_hash, user_id, signature, timestamp, owner = block
    cursor.execute("SELECT public_key FROM Users WHERE id = %s", (user_id,))
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
            'id': row[0],
            'filename': row[1],
            'hash': row[2][:20] + '...',
            'date': row[3].strftime('%Y-%m-%d %H:%M') if row[3] else 'N/A',
            'owner': row[4]
        })
    conn.close()
    return render_template('index.html', blocks=blocks)

# ============================================
# LANCEMENT
# ============================================
if __name__ == '__main__':
    socketio.run(app, debug=False)
