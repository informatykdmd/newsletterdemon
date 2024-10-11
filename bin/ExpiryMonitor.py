from connectAndQuery import connect_to_database, safe_connect_to_database, insert_to_database, delete_row_from_database
from datetime import datetime, timedelta
from appslib import handle_error

def get_table_data(table_name: str, column_id: str, column_date: str, column_status: str) -> list:
    """
    Pobiera dane z danej tabeli, ograniczając się do kolumn ID, daty oraz statusu.
    table_name: nazwa tabeli z bazy danych
    column_id: nazwa kolumny z ID
    column_date: nazwa kolumny z datą do sprawdzenia
    column_status: nazwa kolumny statusu
    Zwraca listę rekordów w formacie [id, date_object, status].
    """
    try:
        query = f"SELECT {column_id}, {column_date}, {column_status} FROM {table_name};"
        data = connect_to_database(query)
        return data
    except Exception as e:
        handle_error(f"Błąd podczas pobierania danych z tabeli {table_name}: {e}")
        return []


def expiry_date(date_object, days: int) -> bool:
    """
    Sprawdza, czy dany rekord jest przeterminowany.
    date_object: obiekt daty z bazy danych (data utworzenia/aktualizacji)
    days: liczba dni ważności rekordu
    Zwraca True, jeśli rekord jest przeterminowany, False w przeciwnym razie.
    """
    expiry_limit = date_object + timedelta(days=days)  # dodajemy liczbę dni do daty
    return expiry_limit < datetime.now()  # sprawdzamy, czy data ważności minęła

def check_expiry_for_table(table_name: str, column_id: str, column_date: str, column_status: str, expiry_days: int) -> list:
    """
    Sprawdza przeterminowane rekordy dla danej tabeli, uwzględniając status.
    table_name: nazwa tabeli
    column_id: nazwa kolumny ID
    column_date: nazwa kolumny daty
    column_status: nazwa kolumny statusu
    expiry_days: liczba dni, po której rekord się przeterminuje
    Zwraca listę przeterminowanych rekordów w formie: [{"table": table_name, "id": record_id, "status": status}, ...]
    """
    records = get_table_data(table_name, column_id, column_date, column_status)
    expired_records = []
    for record in records:
        record_id, date_object, status = record
        if expiry_date(date_object, expiry_days):
            expired_records.append({"table": table_name, "id": record_id, "status": status})
    return expired_records


def check_all_tables_for_expiry() -> list:
    """
    Sprawdza wszystkie tabele i zwraca przeterminowane rekordy, w tym status.
    """
    expired_records = []
    expired_records += check_expiry_for_table('ogloszenia_lento', 'id', 'data_aktualizacji', 'status', 90)
    expired_records += check_expiry_for_table('ogloszenia_otodom', 'id', 'data_aktualizacji', 'status', 30)
    expired_records += check_expiry_for_table('ogloszenia_allegrolokalnie', 'id', 'data_aktualizacji', 'status', 30)
    return expired_records


