import psycopg2
import os

def get_connection():
    """Connexion PostgreSQL via variable d'environnement DATABASE_URL"""
    database_url = os.environ.get('DATABASE_URL')
    
    if not database_url:
        raise Exception("❌ DATABASE_URL non définie dans les variables d'environnement")
    
    conn = psycopg2.connect(database_url)
    return conn
