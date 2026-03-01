import pyodbc

def get_connection():
    conn = pyodbc.connect(
        'DRIVER={ODBC Driver 17 for SQL Server};'
        'SERVER=DESKTOP-7A08N1S\\SQLEXPRESS;'
        'DATABASE=SecureChain;'
        'Trusted_Connection=yes;'
    )
    return conn