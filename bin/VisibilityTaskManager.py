from connectAndQuery import connect_to_database, insert_to_database
from appslib import handle_error

def get_all_records_for_table(table_name: str, column_name: str) -> list:
    """
    Pobiera wszystkie rekordy z tabeli odpowiadającej portalowi.
    table_name: nazwa tabeli
    column_name: nazwa kolumny przechowującej id ogłoszenia na portalu
    Zwraca listę krotek: [(id, id_ogloszenia, status), ...]
    """
    try:
        query = f"SELECT id, {column_name}, status FROM {table_name};"
        records = connect_to_database(query)
        return records
    except Exception as e:
        handle_error(f"Błąd podczas pobierania danych z tabeli {table_name}: {e}")
        return []

def create_task_for_portal(portal_name: str, records: list):
    """
    Tworzy jedno zadanie dla danego portalu, zapisując dane w tabeli tasks_check_visibility.
    portal_name: nazwa portalu (np. "lento", "otodom")
    records: lista krotek z rekordami [(id, id_ogloszenia, status), ...]
    """
    # Konwertujemy listę na string
    task_data = ";".join([f"{record[0]}|{record[1]}|{record[2]}" for record in records])

    query = """
        INSERT INTO tasks_check_visibility (portal_nazwa, dane_wykonawcze, status)
        VALUES (%s, %s, 1)
    """
    try:
        insert_to_database(query, (portal_name, task_data))
        print(f"Zadanie dla portalu {portal_name} utworzone.")
    except Exception as e:
        handle_error(f"Błąd przy tworzeniu zadania dla portalu {portal_name}: {e}")

def create_visibility_tasks():
    """
    Tworzy zadania dla wszystkich portali.
    """
    portals = {
        "otodom": {"table": "ogloszenia_otodom", "column": "id_ogloszenia_na_otodom"},
        "lento": {"table": "ogloszenia_lento", "column": "id_ogloszenia_na_lento"},
        "adresowo": {"table": "ogloszenia_adresowo", "column": "id_ogloszenia_na_adresowo"},
        "allegro": {"table": "ogloszenia_allegrolokalnie", "column": "id_ogloszenia_na_allegro"},
    }

    for portal_name, config in portals.items():
        table_name = config["table"]
        column_name = config["column"]
        records = get_all_records_for_table(table_name, column_name)
        if records:
            create_task_for_portal(portal_name, records)
        else:
            print(f"Brak danych do przetworzenia dla portalu {portal_name}.")
