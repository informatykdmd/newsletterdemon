import mysql.connector
from config_utils import DBDATA as DB
from appslib import handle_error

class Database:
    """Klasa obsługująca stałe połączenie z MySQL"""

    def __init__(self):
        """Inicjalizacja połączenia"""
        self.db = None
        self.cursor = None
        self.connect()

    def connect(self):
        """Tworzy połączenie z bazą danych"""
        try:
            self.db = mysql.connector.connect(
                user=DB['user'],
                password=DB['pass'],
                host=DB['host'],
                database=DB['base'],
                autocommit=True  # Automatyczne commitowanie operacji
            )
            self.cursor = self.db.cursor(buffered=True)
            print("✅ Połączenie z bazą danych MySQL zostało nawiązane.")
        except Exception as e:
            print(f"❌ MySQL connect ERR [{e}]")
            handle_error(e, log_path='./logs/errors.log')

    def execute_query(self, query, values=None):
        """Wykonuje zapytanie SQL"""
        try:
            if not self.db.is_connected():
                self.connect()
            
            self.cursor.execute(query, values)
            return self.cursor.fetchall()
        except Exception as e:
            print(f"❌ MySQL execute_query ERR [{e}]\n query:\n{query}")
            handle_error(e, log_path='./logs/errors.log')
            return []

    def execute_commit(self, query, values=None):
        """Wykonuje zapytanie SQL wymagające commit"""
        try:
            if not self.db.is_connected():
                self.connect()

            self.cursor.execute(query, values)
            self.db.commit()
            return True
        except Exception as e:
            print(f"❌ MySQL execute_commit ERR [{e}]\n query:\n{query}")
            handle_error(e, log_path='./logs/errors.log')
            return False

    def close(self):
        """Zamyka połączenie"""
        if self.db.is_connected():
            self.cursor.close()
            self.db.close()
            print("❌ Połączenie z MySQL zostało zamknięte.")

# Tworzymy jedno stałe połączenie na cały czas działania aplikacji
database = Database()

# ==============================
# ✅ POPRAWIONE FUNKCJE BAZY
# ==============================

def connect_to_database(queryA):
    """Pobiera dane z bazy i zwraca listę wyników."""
    return database.execute_query(queryA)

def safe_connect_to_database(queryA, queryB):
    print(f"[DBDBG] safe_connect_to_database enter | q0={repr((queryA or '').strip()[:20]).lower()} | params_type={type(queryB)} | params_has_none={queryB is not None and any(p is None for p in (queryB if isinstance(queryB,(list,tuple)) else [queryB]))}")
    print(f"[DBDBG] query_head:\n{(queryA or '').strip()[:200]}")
    print(f"[DBDBG] params={queryB}")
    """Wykonuje zapytanie SQL z parametrami i zwraca wynik."""
    return database.execute_query(queryA, queryB)

def insert_to_database(queryA, queryB):
    """Wstawia dane do bazy."""
    return database.execute_commit(queryA, queryB)

def delete_row_from_database(queryA, queryB):
    """Usuwa dane z bazy."""
    return database.execute_commit(queryA, queryB)
