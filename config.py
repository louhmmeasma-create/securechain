import mysql.connector
import sqlite3
import os

def get_connection():
    """Connexion à la base de données - MySQL sur PythonAnywhere, SQLite en local"""
    
    # Détection de l'environnement PythonAnywhere
    if os.path.exists('/home/asmalouhmme'):
        # Connexion MySQL pour PythonAnywhere
        try:
            conn = mysql.connector.connect(
                host='asmalouhmme.mysql.pythonanywhere-services.com',
                user='asmalouhmme',
                password='asma123',  # CHANGE CE MOT DE PASSE si nécessaire
                database='asmalouhmme$securechain',
                charset='utf8mb4',
                use_unicode=True
            )
            print("✅ Connexion MySQL réussie")
            return conn
        except mysql.connector.Error as err:
            print(f"❌ Erreur de connexion MySQL: {err}")
            raise Exception(f"Impossible de se connecter à MySQL: {err}")
    
    # Connexion SQLite pour le développement local
    else:
        try:
            db_path = os.path.join(os.path.dirname(__file__), 'database.db')
            conn = sqlite3.connect(db_path)
            # Pour pouvoir accéder aux colonnes par nom
            conn.row_factory = sqlite3.Row
            print("✅ Connexion SQLite réussie")
            return conn
        except sqlite3.Error as err:
            print(f"❌ Erreur de connexion SQLite: {err}")
            raise Exception(f"Impossible de se connecter à SQLite: {err}")


# Fonction utilitaire pour exécuter des requêtes facilement
def query_db(query, args=None, one=False):
    """Exécute une requête et retourne les résultats"""
    conn = get_connection()
    cur = conn.cursor()
    
    # Adaptation des placeholders pour MySQL
    if os.path.exists('/home/asmalouhmme'):
        # MySQL utilise %s au lieu de ?
        if args:
            # Convertir les tuples en liste si nécessaire
            if isinstance(args, tuple):
                args = list(args)
            query = query.replace('?', '%s')
    
    try:
        if args:
            cur.execute(query, args)
        else:
            cur.execute(query)
        
        if query.strip().upper().startswith('SELECT'):
            results = cur.fetchall()
            conn.close()
            return (results[0] if results else None) if one else results
        elif query.strip().upper().startswith('INSERT'):
            conn.commit()
            last_id = cur.lastrowid
            conn.close()
            return last_id
        else:
            conn.commit()
            conn.close()
            return True
    except Exception as e:
        conn.close()
        print(f"❌ Erreur SQL: {e}")
        raise e


# Fonction pour initialiser la base de données (à utiliser une seule fois)
def init_db():
    """Crée les tables si elles n'existent pas"""
    conn = get_connection()
    cur = conn.cursor()
    
    # Adaptation pour MySQL
    if os.path.exists('/home/asmalouhmme'):
        # Création des tables pour MySQL
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                password VARCHAR(200) NOT NULL,
                public_key TEXT,
                twofa_secret VARCHAR(32),
                twofa_enabled BOOLEAN DEFAULT FALSE,
                email_confirmed BOOLEAN DEFAULT FALSE,
                confirmation_token VARCHAR(100),
                token_expires DATETIME,
                role VARCHAR(20) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Blocks (
                id INT AUTO_INCREMENT PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                file_hash VARCHAR(64) NOT NULL,
                previous_hash VARCHAR(64),
                signature TEXT,
                user_id INT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES Users(id)
            )
        """)
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                action VARCHAR(255) NOT NULL,
                ip_address VARCHAR(45),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES Users(id)
            )
        """)
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Shares (
                id INT AUTO_INCREMENT PRIMARY KEY,
                block_id INT NOT NULL,
                token VARCHAR(100) UNIQUE NOT NULL,
                expires_at DATETIME NOT NULL,
                created_by INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (block_id) REFERENCES Blocks(id),
                FOREIGN KEY (created_by) REFERENCES Users(id)
            )
        """)
    
    else:
        # Création des tables pour SQLite
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                public_key TEXT,
                twofa_secret TEXT,
                twofa_enabled INTEGER DEFAULT 0,
                email_confirmed INTEGER DEFAULT 0,
                confirmation_token TEXT,
                token_expires TEXT,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                previous_hash TEXT,
                signature TEXT,
                user_id INTEGER NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES Users(id)
            )
        """)
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES Users(id)
            )
        """)
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (block_id) REFERENCES Blocks(id),
                FOREIGN KEY (created_by) REFERENCES Users(id)
            )
        """)
    
    conn.commit()
    conn.close()
    print("✅ Tables créées/vérifiées avec succès")


# Test rapide si le fichier est exécuté directement
if __name__ == "__main__":
    print("Test de connexion à la base de données...")
    try:
        conn = get_connection()
        print("✅ Connexion réussie!")
        conn.close()
        
        # Demander si on veut initialiser les tables
        response = input("Voulez-vous créer les tables ? (o/n): ")
        if response.lower() == 'o':
            init_db()
            print("✅ Base de données initialisée!")
    except Exception as e:
        print(f"❌ Erreur: {e}")