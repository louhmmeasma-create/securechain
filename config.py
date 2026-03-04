import sqlite3
import os

def get_connection():
    """Connexion SQLite - fonctionne en local et sur PythonAnywhere"""
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Crée les tables si elles n'existent pas"""
    conn = get_connection()
    cur = conn.cursor()

    cur.executescript("""
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
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS Blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            previous_hash TEXT,
            signature TEXT,
            user_id INTEGER NOT NULL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES Users(id)
        );

        CREATE TABLE IF NOT EXISTS Logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            ip_address TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES Users(id)
        );

        CREATE TABLE IF NOT EXISTS Shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            created_by INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (block_id) REFERENCES Blocks(id),
            FOREIGN KEY (created_by) REFERENCES Users(id)
        );
    """)

    conn.commit()
    conn.close()
    print("✅ Tables créées/vérifiées avec succès")


if __name__ == "__main__":
    print("Test de connexion...")
    try:
        conn = get_connection()
        print("✅ Connexion SQLite réussie!")
        conn.close()
        init_db()
    except Exception as e:
        print(f"❌ Erreur: {e}")