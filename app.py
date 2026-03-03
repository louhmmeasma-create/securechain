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

# Niveau 1 : Bcrypt
from flask_bcrypt import Bcrypt

# Niveau 2 : 2FA, Logs
import pyotp

# Niveau 3 : Email
from flask_mail import Mail, Message

# Niveau 4 : Notifications temps réel
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.secret_key = 'securechain_super_secret_key_2025'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.permanent_session_lifetime = timedelta(days=1)

# Configuration email
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'louhemmeasma@gmail.com'
app.config['MAIL_PASSWORD'] = 'vmtqifjfmgtaimbw'
app.config['MAIL_DEFAULT_SENDER'] = 'louhemmeasma@gmail.com'

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

# ============================================
# DÉCORATEUR ADMIN REQUIRED
# ============================================
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

# ============================================
# LANGUES
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
        'already_have_account': 'Déjà un compte ?', 'create_account': 'Créer un compte',
        'resend_email': 'Renvoyer l\'email'
    }
    return translations.get(key, key)

@app.context_processor
def inject_language():
    return dict(_=_)

@app.context_processor
def utility_processor():
    def check_admin(user_id):
        if not user_id:
            return False
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM Users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result and result[0] == 'admin'
    
    return dict(check_admin=check_admin)

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
    print(f'Client connecté: {request.sid}')
    emit('notification', {'message': 'Connecté au serveur temps réel'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client déconnecté: {request.sid}')

def notify_user(user_id, message, type='info'):
    socketio.emit(f'user_{user_id}', {
        'message': message,
        'type': type,
        'timestamp': datetime.now().strftime('%H:%M:%S')
    })

@app.route('/test-notification')
def test_notification():
    if 'user_id' in session:
        notify_user(session['user_id'], 'Ceci est un test de notification!', 'success')
        return "Notification envoyée!"
    return "Non connecté"

# ============================================
# ROUTE DE DÉBOGAGE POUR TESTER L'EMAIL
# ============================================
@app.route('/debug-email')
def debug_email():
    try:
        test_email = 'louhemmeasma@gmail.com'
        
        msg = Message(
            subject="🔧 Test SecureChain - Debug",
            recipients=[test_email],
            body=f"""Bonjour,

Ceci est un email de test envoyé depuis SecureChain.

Si vous recevez ce message, la configuration email fonctionne correctement !

Heure d'envoi : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}

Cordialement,
L'équipe SecureChain
"""
        )
        mail.send(msg)
        return f"""
        <div style="font-family: Arial; padding: 20px;">
            <h2 style="color: #10b981;">✅ Email envoyé avec succès !</h2>
            <p>Un email de test a été envoyé à : <strong>{test_email}</strong></p>
            <p>Vérifie ta boîte de réception (et les spams).</p>
            <p><a href="/" style="color: #4361ee;">Retour à l'accueil</a></p>
        </div>
        """
    except Exception as e:
        return f"""
        <div style="font-family: Arial; padding: 20px;">
            <h2 style="color: #ef4444;">❌ Erreur d'envoi</h2>
            <p style="background: #fee2e2; padding: 15px; border-radius: 8px;">
                <strong>Message d'erreur :</strong><br>
                {str(e)}
            </p>
            <p><a href="/" style="color: #4361ee;">Retour à l'accueil</a></p>
        </div>
        """

@app.route('/test-email')
def test_email():
    try:
        msg = Message(
            subject="Test SecureChain",
            recipients=['asma.louhmme@gmail.com'],
            body="Ceci est un test d'envoi d'email."
        )
        mail.send(msg)
        return "✅ Email envoyé avec succès ! Vérifie ta boîte."
    except Exception as e:
        return f"❌ Erreur: {str(e)}"

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
        expires = datetime.now() + timedelta(hours=24)
        
        try:
            cursor.execute("""
                INSERT INTO Users (username, email, password, public_key, confirmation_token, token_expires, role)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (username, email, hashed_password, public_key.decode(), token, expires, 'user'))
            conn.commit()
            
            user_id = cursor.lastrowid
            
            with open(f'keys/user_{user_id}_private.pem', 'wb') as f:
                f.write(private_key)
            
            confirm_link = url_for('confirm_email', token=token, _external=True)
            
            msg = Message(
                subject="SecureChain - Confirmez votre email",
                recipients=[email],
                body=f"""Bonjour {username},

Merci de vous être inscrit sur SecureChain.

Pour activer votre compte, veuillez cliquer sur le lien ci-dessous :
{confirm_link}

Ce lien est valable 24 heures.

Si vous n'avez pas reçu l'email, vous pourrez demander un renvoi après connexion.

Cordialement,
L'équipe SecureChain
"""
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
        FROM Users 
        WHERE confirmation_token = ?
    """, (token,))
    
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        flash('❌ Lien de confirmation invalide', 'error')
        return redirect(url_for('index'))
    
    user_id, email, confirmed, expires = user
    
    if confirmed:
        conn.close()
        flash('✅ Email déjà confirmé. Vous pouvez vous connecter.', 'success')
        return redirect(url_for('login'))
    
    # Convertir expires en datetime si c'est une string
    if isinstance(expires, str):
        expires = datetime.strptime(expires, '%Y-%m-%d %H:%M:%S')
    
    if expires < datetime.now():
        conn.close()
        flash('❌ Lien de confirmation expiré. Veuillez demander un renvoi.', 'error')
        return redirect(url_for('login'))
    
    cursor.execute("""
        UPDATE Users 
        SET email_confirmed = 1, confirmation_token = NULL 
        WHERE id = ?
    """, (user_id,))
    conn.commit()
    conn.close()
    
    log_action(user_id, 'Email confirmé')
    flash('✅ Email confirmé avec succès ! Vous pouvez maintenant vous connecter.', 'success')
    return redirect(url_for('login'))

# ============================================
# RENVOYER L'EMAIL DE CONFIRMATION
# ============================================
@app.route('/resend-confirmation')
@login_required
def resend_confirmation():
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT username, email, email_confirmed, confirmation_token, token_expires 
        FROM Users WHERE id = ?
    """, (user_id,))
    
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        flash('❌ Utilisateur introuvable', 'error')
        return redirect(url_for('index'))
    
    username, email, email_confirmed, old_token, old_expires = user
    
    if email_confirmed:
        conn.close()
        flash('✅ Votre email est déjà confirmé. Vous pouvez vous connecter.', 'success')
        return redirect(url_for('dashboard'))
    
    new_token = generate_confirmation_token()
    new_expires = datetime.now() + timedelta(hours=24)
    
    cursor.execute("""
        UPDATE Users 
        SET confirmation_token = ?, token_expires = ? 
        WHERE id = ?
    """, (new_token, new_expires, user_id))
    conn.commit()
    conn.close()
    
    confirm_link = url_for('confirm_email', token=new_token, _external=True)
    
    try:
        msg = Message(
            subject="SecureChain - Confirmez votre email (nouveau lien)",
            recipients=[email],
            body=f"""Bonjour {username},

Vous avez demandé un nouveau lien de confirmation.

Pour activer votre compte, veuillez cliquer sur le lien ci-dessous :
{confirm_link}

Ce lien est valable 24 heures.

Cordialement,
L'équipe SecureChain
"""
        )
        mail.send(msg)
        
        flash('✅ Un nouvel email de confirmation vous a été envoyé.', 'success')
        log_action(user_id, 'Renvoyé email confirmation')
        
    except Exception as e:
        flash(f'❌ Erreur lors de l\'envoi: {str(e)}', 'error')
    
    return redirect(url_for('index'))

# ============================================
# CONNEXION (avec 2FA)
# ============================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, username, email, password, twofa_secret, twofa_enabled, email_confirmed, role
            FROM Users 
            WHERE username = ?
        """, (username,))
        
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            flash('❌ Identifiants incorrects', 'error')
            return redirect(url_for('login'))
        
        user_id, db_username, email, hashed_password, twofa_secret, twofa_enabled, email_confirmed, role = user
        
        if not bcrypt.check_password_hash(hashed_password, password):
            log_action(user_id, 'Échec connexion (mot de passe)')
            conn.close()
            flash('❌ Identifiants incorrects', 'error')
            return redirect(url_for('login'))
        
        if not email_confirmed:
            conn.close()
            flash('❌ Veuillez confirmer votre email avant de vous connecter.', 'error')
            return redirect(url_for('login'))
        
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
# PROFIL (avec activation 2FA)
# ============================================
@app.route('/profile')
@login_required
def profile():
    user_id = session['user_id']
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT username, email, public_key, twofa_enabled, email_confirmed, role,
               (SELECT COUNT(*) FROM Blocks WHERE user_id = ?) as file_count,
               (SELECT MIN(timestamp) FROM Blocks WHERE user_id = ?) as first_upload,
               (SELECT created_at FROM Users WHERE id = ?) as created_at
        FROM Users 
        WHERE id = ?
    """, (user_id, user_id, user_id, user_id))
    
    user_data = cursor.fetchone()
    conn.close()
    
    first_upload = user_data[7]
    if first_upload:
        if isinstance(first_upload, str):
            first_upload = datetime.strptime(first_upload, '%Y-%m-%d %H:%M:%S')
        first_upload = first_upload.strftime('%d/%m/%Y')
    else:
        first_upload = 'Aucun fichier'
    
    created_at = user_data[8]
    if created_at:
        if isinstance(created_at, str):
            created_at = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S')
        created_at = created_at.strftime('%d/%m/%Y')
    else:
        created_at = 'N/A'
    
    profile_data = {
        'username': user_data[0],
        'email': user_data[1],
        'public_key': user_data[2][:100] + '...' if user_data[2] else 'N/A',
        'full_public_key': user_data[2],
        'file_count': user_data[6],
        'first_upload': first_upload,
        'member_since': created_at,
        'twofa_enabled': user_data[3],
        'email_confirmed': user_data[4],
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
# CONFIGURATION 2FA
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
    
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="SecureChain"
    )
    
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
        flash('❌ Code invalide. Veuillez réessayer.', 'error')
    
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
# PARTAGE DE FICHIERS
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
    expires = datetime.now() + timedelta(hours=24)
    
    cursor.execute("""
        INSERT INTO Shares (block_id, token, expires_at, created_by)
        VALUES (?, ?, ?, ?)
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
        WHERE s.token = ? AND datetime(s.expires_at) > datetime('now')
    """, (token,))
    
    share = cursor.fetchone()
    
    if not share:
        cursor.execute("SELECT expires_at FROM Shares WHERE token = ?", (token,))
        expired = cursor.fetchone()
        conn.close()
        
        if expired:
            flash('❌ Ce lien de partage a expiré (valable 24h seulement).', 'error')
        else:
            flash('❌ Ce lien de partage n\'existe pas ou a été supprimé.', 'error')
        return redirect(url_for('index'))
    
    block_id, filename, file_hash, expires = share
    conn.close()
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_hash}.enc")
    meta_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_hash}.meta")
    
    if not os.path.exists(file_path) or not os.path.exists(meta_path):
        flash('❌ Le fichier partagé n\'est plus disponible.', 'error')
        return redirect(url_for('index'))
    
    with open(file_path, 'rb') as f:
        encrypted = f.read()
    with open(meta_path, 'rb') as f:
        meta = pickle.load(f)
    
    data = decrypt_file(encrypted, meta['key'], meta['nonce'], meta['tag'])
    
    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=filename,
        mimetype='application/octet-stream'
    )

# ============================================
# STATISTIQUES DASHBOARD
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
    
    conn.close()
    
    last_date = 'N/A'
    if recent and recent[1]:
        if isinstance(recent[1], str):
            last_date = recent[1][:10]
        else:
            last_date = recent[1].strftime('%Y-%m-%d')
    
    stats = {
        'total_files': total_files,
        'total_blocks': total_blocks,
        'active_users': active_users,
        'last_file': recent[0] if recent else 'Aucun',
        'last_date': last_date
    }
    
    return render_template('dashboard.html', stats=stats)

@app.route('/api/upload-stats')
def upload_stats():
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            date(timestamp) as date,
            COUNT(*) as count
        FROM Blocks
        WHERE timestamp >= datetime('now', '-7 days')
        GROUP BY date(timestamp)
        ORDER BY date
    """)
    
    data = cursor.fetchall()
    conn.close()
    
    days = []
    counts = []
    for row in data:
        if row[0]:
            if isinstance(row[0], str):
                from datetime import datetime
                d = datetime.strptime(row[0], '%Y-%m-%d')
                days.append(d.strftime('%a'))
            else:
                days.append(row[0].strftime('%a'))
            counts.append(row[1])
    
    return jsonify({'days': days, 'counts': counts})

@app.route('/api/user-stats')
def user_stats():
    conn = get_connection()
    cursor = conn.cursor()
    
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
    
    return jsonify({
        'users': users,
        'counts': counts,
        'total_users': total_users,
        'total_blocks': total_blocks
    })

# ============================================
# STATISTIQUES AVEC CLASSIFICATION
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
    
    return render_template('stats.html', stats={
        'total_files': total,
        'categories': categories
    })

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
        FROM Blocks 
        WHERE user_id = ? 
        ORDER BY timestamp DESC
    """, (user_id,))
    
    files = []
    for row in cursor.fetchall():
        date_str = 'N/A'
        if row[3]:
            if isinstance(row[3], str):
                date_str = row[3][:16]
            else:
                date_str = row[3].strftime('%Y-%m-%d %H:%M')
        
        files.append({
            'id': row[0],
            'filename': row[1],
            'hash': row[2][:20] + '...',
            'full_hash': row[2],
            'date': date_str
        })
    
    conn.close()
    return render_template('my_files.html', files=files)

# ============================================
# UPLOAD (AVEC GESTION DES DOUBLONS)
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
    cursor.execute("SELECT id FROM Blocks WHERE file_hash = ?", (file_hash,))
    existing = cursor.fetchone()
    conn.close()
    
    if existing:
        session['pending_upload'] = {
            'data': data,
            'filename': filename,
            'file_hash': file_hash
        }
        
        flash(f'''
        <div style="text-align: center;">
            <p style="font-size: 1.1em; margin-bottom: 15px;">Le fichier <strong>"{filename}"</strong> existe déjà dans la blockchain.</p>
            <p style="margin-bottom: 20px;">Voulez-vous l'ajouter quand même ?</p>
            <div style="display: flex; gap: 15px; justify-content: center;">
                <a href="/force-upload" class="btn btn-primary" style="padding: 10px 25px;">✅ Oui, ajouter</a>
                <a href="/my-files" class="btn btn-secondary" style="padding: 10px 25px;">❌ Non, annuler</a>
            </div>
        </div>
        ''', 'warning')
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
    
    cursor.execute(
        "INSERT INTO Blocks (filename, file_hash, previous_hash, signature, user_id) VALUES (?, ?, ?, ?, ?)",
        (filename, file_hash, previous_hash, signature, user_id)
    )
    conn.commit()
    
    block_id = cursor.lastrowid
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
    
    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=filename,
        mimetype='application/octet-stream'
    )

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
        FROM Blocks b
        JOIN Users u ON b.user_id = u.id
        WHERE b.id = ?
    """, (block_id,))
    
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

# ============================================
# PANEL ADMINISTRATEUR (Version SQLite corrigée)
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
    
    cursor.execute("""
        SELECT id, username, email, created_at, role, email_confirmed 
        FROM Users ORDER BY created_at DESC LIMIT 10
    """)
    recent_users = cursor.fetchall()
    
    cursor.execute("""
        SELECT b.id, b.filename, b.timestamp, u.username 
        FROM Blocks b JOIN Users u ON b.user_id = u.id
        ORDER BY b.timestamp DESC LIMIT 10
    """)
    recent_files = cursor.fetchall()
    
    cursor.execute("""
        SELECT user_id, action, ip_address, timestamp 
        FROM Logs WHERE action LIKE '%échec%' OR action LIKE '%invalide%'
        ORDER BY timestamp DESC LIMIT 10
    """)
    suspicious_logs = cursor.fetchall()
    
    conn.close()
    
    return render_template('admin.html',
                         total_users=total_users,
                         total_files=total_files,
                         total_logs=total_logs,
                         unconfirmed_users=unconfirmed_users,
                         recent_users=recent_users,
                         recent_files=recent_files,
                         suspicious_logs=suspicious_logs)

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, username, email, role, email_confirmed, twofa_enabled, created_at 
        FROM Users ORDER BY created_at DESC
    """)
    users = cursor.fetchall()
    conn.close()
    
    # Convertir les dates pour les templates
    users_list = []
    for user in users:
        user_list = list(user)
        if user_list[6] and isinstance(user_list[6], str):
            try:
                user_list[6] = datetime.strptime(user_list[6], '%Y-%m-%d %H:%M:%S')
            except:
                pass
        users_list.append(user_list)
    
    return render_template('admin_users.html', users=users_list)

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
    
    flash(f'✅ Rôle modifié avec succès', 'success')
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
        FROM Logs l LEFT JOIN Users u ON l.user_id = u.id
        ORDER BY l.timestamp DESC
    """)
    logs = cursor.fetchall()
    conn.close()
    
    # Convertir les dates pour les templates
    logs_list = []
    for log in logs:
        log_list = list(log)
        if log_list[5] and isinstance(log_list[5], str):
            try:
                log_list[5] = datetime.strptime(log_list[5], '%Y-%m-%d %H:%M:%S')
            except:
                pass
        logs_list.append(log_list)
    
    return render_template('admin_logs.html', logs=logs_list)

@app.route('/admin/stats')
@admin_required
def admin_stats():
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT date(timestamp) as date, COUNT(*) as uploads, COUNT(DISTINCT user_id) as active_users
        FROM Blocks GROUP BY date(timestamp) ORDER BY date DESC
    """)
    daily_stats = cursor.fetchall()
    
    cursor.execute("""
        SELECT u.username, COUNT(b.id) as upload_count
        FROM Users u LEFT JOIN Blocks b ON u.id = b.user_id
        GROUP BY u.username ORDER BY upload_count DESC LIMIT 10
    """)
    top_users = cursor.fetchall()
    
    conn.close()
    
    # Convertir les dates pour les templates
    daily_stats_list = []
    for stat in daily_stats:
        stat_list = list(stat)
        if stat_list[0] and isinstance(stat_list[0], str):
            try:
                stat_list[0] = datetime.strptime(stat_list[0], '%Y-%m-%d').date()
            except:
                pass
        daily_stats_list.append(stat_list)
    
    return render_template('admin_stats.html', daily_stats=daily_stats_list, top_users=top_users)

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
        FROM Blocks b JOIN Users u ON b.user_id = u.id
        ORDER BY b.id DESC
    """)
    
    blocks = []
    for row in cursor.fetchall():
        date_str = 'N/A'
        if row[3]:
            if isinstance(row[3], str):
                date_str = row[3][:16]
            else:
                date_str = row[3].strftime('%Y-%m-%d %H:%M')
        
        blocks.append({
            'id': row[0],
            'filename': row[1],
            'hash': row[2][:20] + '...',
            'date': date_str,
            'owner': row[4]
        })
    conn.close()
    
    return render_template('index.html', blocks=blocks)

# ============================================
# LANCEMENT
# ============================================
if __name__ == '__main__':
    socketio.run(app, debug=True)