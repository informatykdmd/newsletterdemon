from time import time, sleep
import datetime
import prepare_shedule
import messagerCreator 
import sendEmailBySmtp
import random
import os
import json
from typing import List, Optional
from archiveSents import archive_sents
from appslib import handle_error
from fbwaitninglist import give_me_curently_tasks
from ExpiryMonitor import check_all_tables_for_expiry, insert_to_database, delete_row_from_database
from znajdz_klucz_z_wazeniem import znajdz_klucz_z_wazeniem

def get_messages(flag='all'):
    # WHERE status != 1
    if flag == 'all':
        dump_key = prepare_shedule.connect_to_database(
            "SELECT id, user_name, content, timestamp, status FROM Messages WHERE status != 1 ORDER BY timestamp ASC;")

    if flag == 'today':
        dump_key = prepare_shedule.connect_to_database(
            "SELECT id, user_name, content, timestamp, status FROM Messages WHERE date(timestamp) = curdate() AND status != 1 ORDER BY timestamp ASC;")

    if flag == 'last':
        dump_key = prepare_shedule.connect_to_database(
            """SELECT id, user_name, content, timestamp, status FROM Messages WHERE timestamp >= NOW() - INTERVAL 1 HOUR AND status != 1 ORDER BY timestamp ASC;""")
    return dump_key

def get_campains_id_descript_dates() -> str:
    existing_campaigns_query = '''
        SELECT post_id, content, 
            schedule_0_datetime, schedule_0_status, 
            schedule_1_datetime, schedule_1_status, 
            schedule_2_datetime, schedule_2_status, 
            schedule_3_datetime, schedule_3_status, 
            schedule_4_datetime, schedule_4_status, 
            schedule_5_datetime, schedule_5_status, 
            schedule_6_datetime, schedule_6_status, 
            schedule_7_datetime, schedule_7_status, 
            schedule_8_datetime, schedule_8_status, 
            schedule_9_datetime, schedule_9_status, 
            schedule_10_datetime, schedule_10_status,
            category, created_by, section
        FROM waitinglist_fbgroups
    '''
    took_list = prepare_shedule.connect_to_database(existing_campaigns_query)
    ready_export_string = f'Dump z dnia {datetime.datetime.now().strftime("%Y-%B-%d %H:%M")}\n--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- \n'
    for row in took_list:
        title_campain_query = ""
        if row[26] == 'estateAdsSell':
            title_campain_query = f"""
                SELECT Tytul FROM OfertySprzedazy WHERE ID = {row[0]};
            """
        elif row[26] == 'estateAdsRent':
            title_campain_query = f"""
                SELECT Tytul FROM OfertyNajmu WHERE ID = {row[0]};
            """
        elif row[26] == 'hiddeCampaigns':
            title_campain_query = f"""
                SELECT title FROM hidden_campaigns WHERE id = {row[0]};
            """
        elif row[26] == 'career':
            title_campain_query = f"""
                SELECT title FROM job_offers WHERE id = {row[0]};
            """
        if title_campain_query:
            try: get_title = prepare_shedule.connect_to_database(title_campain_query)[0][0]
            except IndexError: get_title = "Brak tytułu"
        else: get_title = "Brak tytułu"

        theme={
            'post_id': row[0],
            'title': get_title,
            'content': row[1],
            'schedule_0_datetime': row[2], 'schedule_0_status': row[3],
            'schedule_1_datetime': row[4], 'schedule_1_status': row[5],
            'schedule_2_datetime': row[6], 'schedule_2_status': row[7],
            'schedule_3_datetime': row[8], 'schedule_3_status': row[9],
            'schedule_4_datetime': row[10], 'schedule_4_status': row[11],
            'schedule_5_datetime': row[12], 'schedule_5_status': row[13],
            'schedule_6_datetime': row[14], 'schedule_6_status': row[15],
            'schedule_7_datetime': row[16], 'schedule_7_status': row[17],
            'schedule_8_datetime': row[18], 'schedule_8_status': row[19],
            'schedule_9_datetime': row[20], 'schedule_9_status': row[21],
            'schedule_10_datetime': row[22], 'schedule_10_status': row[23],
            'category': row[24], 'created_by': row[25], 'section': row[26]
        }
        # Przechodzimy przez elementy i usuwamy zestawy `datetime`/`status`, które nie spełniają warunków
        for i in range(11):  # Przeglądamy `schedule_0` do `schedule_10`
            datetime_key = f'schedule_{i}_datetime'
            status_key = f'schedule_{i}_status'

            # Pobieramy wartości `datetime` i `status` dla aktualnego zestawu
            datetime_value = theme.get(datetime_key)
            status_value = theme.get(status_key)

            # Usuwamy zestaw, jeśli:
            # 1. `datetime_value` jest `None` (emisja niezaplanowana), lub
            # 2. `status_value` nie jest `None` (emisja zrealizowana)
            if datetime_value is None or status_value is not None:
                theme.pop(datetime_key, None)
                theme.pop(status_key, None)
        
        ready_export_string += f"Kampania o Tytule: {theme['title']}\nEmitowana przez bota: {theme['created_by']}\nW kategorii: {theme['category']}\nPosiada niezrealizowane emisje zaplanowane na:\n"
        ready_export_string += f"{theme.get('schedule_0_datetime', '')} {theme.get('schedule_1_datetime', '')} {theme.get('schedule_2_datetime', '')} {theme.get('schedule_3_datetime', '')} {theme.get('schedule_4_datetime', '')} {theme.get('schedule_5_datetime', '')} {theme.get('schedule_6_datetime', '')} {theme.get('schedule_7_datetime', '')} {theme.get('schedule_8_datetime', '')} {theme.get('schedule_9_datetime', '')} {theme.get('schedule_10_datetime', '')}\n--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- \n\n\n"
    
    # Usuwamy zbędne spacje
    ready_export_string = "\n".join(" ".join(line.split()) for line in ready_export_string.splitlines())
    
    return ready_export_string

def prepare_prompt(began_prompt):
    dump_key = get_messages('last')
    ready_prompt = f'{began_prompt}\n\n'
    count_ready = 0

    for dump in dump_key:
        if dump[1] != "aifa":
            try:
                user_descrition, user_about = prepare_shedule.connect_to_database(
                    f"""SELECT ADMIN_ROLE, ABOUT_ADMIN FROM admins WHERE LOGIN='{dump[1]}';""")[0]
            except IndexError:
                user_descrition, user_about = ('Brak opisu', 'Szaregowy pracownik')
        else:
            user_descrition, user_about = ('Sztuczna inteligencja na usługach DMD.', 'Operator Moderacji i Ekspert nowych technologii')
        
        dane_d=getMorphy()

        # Budowanie kontekstu informacji o pracownikach
        user_infos_list_tuple = prepare_shedule.connect_to_database(
            "SELECT ADMIN_NAME, ADMIN_ROLE, ABOUT_ADMIN, LOGIN FROM admins;"
        )

        for db_row in user_infos_list_tuple:
            # Tworzenie klucza dla ADMIN_ROLE jako krotki słów
            key_in_dane_d_ADMIN_NAME = tuple(str(db_row[0]).split())
            dane_d[key_in_dane_d_ADMIN_NAME] = "informacje o personelu"

            # Tworzenie klucza dla ADMIN_ROLE jako krotki słów
            key_in_dane_d_ADMIN_ROLE = tuple(str(db_row[1]).split())
            dane_d[key_in_dane_d_ADMIN_ROLE] = "informacje o personelu"

            # Tworzenie kluczy z ABOUT_ADMIN jako krotek o długości maks. 5 słów
            about_words = str(db_row[2]).split()
            temp_list = []

            for i, word in enumerate(about_words):
                temp_list.append(word)
                # Jeśli osiągnięto 5 słów lub to ostatnie słowo, dodajemy do `dane_d`
                if (i + 1) % 5 == 0 or i == len(about_words) - 1:
                    key_in_dane_d_ABOUT_ADMIN = tuple(temp_list)
                    dane_d[key_in_dane_d_ABOUT_ADMIN] = "informacje o personelu"
                    temp_list = []  # Resetujemy `temp_list` dla następnej krotki
            

        fraza = dump[2]
        znalezione_klucze = znajdz_klucz_z_wazeniem(dane_d, fraza)
        # print(znalezione_klucze)
        # handle_error(f"Znalezione klucze dump FIRST: {znalezione_klucze}.")
        if znalezione_klucze['sukces'] and znalezione_klucze['kolejnosc']\
            and znalezione_klucze['procent'] > .5 and dump[1] != "aifa":
            collectedLogs = ''
            handle_error(f"Znalezione klucze dump: {znalezione_klucze}.")
            if znalezione_klucze['najtrafniejsze'] == 'raport systemu':
                """
                ############################################################
                # obsługa flagi 'raport systemu'
                ############################################################
                """
                handle_error(f"Uruchomiono: {znalezione_klucze['najtrafniejsze']}.")
                pobierz_logi_dla_uzytkownika = getDataLogs(f'{dump[1]}', spen_last_days=4)
                for log in pobierz_logi_dla_uzytkownika:
                    collectedLogs += f'{log["message"]} : {log["category"]} \n'
                if collectedLogs:
                    command = f'WYKRYTO ZAPYTANIE O STATUS SYSTEMU OTO DUMP DO WYKORZYSTANIA:\n{collectedLogs}'
                else: command = ''
                # handle_error(f"command: {command}")
            elif znalezione_klucze['najtrafniejsze'] == 'harmonogram kampanii':
                """
                ############################################################
                # obsługa flagi 'harmonogram kampanii'
                ############################################################
                """
                handle_error(f"Uruchomiono: {znalezione_klucze['najtrafniejsze']}.")
                pobierz_harmonogramy_kampanii = get_campains_id_descript_dates()
                print(pobierz_harmonogramy_kampanii)
                if pobierz_harmonogramy_kampanii:
                    command = f'WYKRYTO ZAPYTANIE O HARMONOGRAM KAMPANII OTO DUMP DO WYKORZYSTANIA:\n{pobierz_harmonogramy_kampanii}'
                else: command = ''
                # handle_error(f"command: {command}")
            elif znalezione_klucze['najtrafniejsze'] == 'moduł decyzyjny':
                """
                ############################################################
                # obsługa flagi 'moduł decyzyjny'
                ############################################################
                """
                handle_error(f"Uruchomiono: {znalezione_klucze['najtrafniejsze']}.")
                command = f'WYKRYTO W ZAPYTANIU URUCHOMIENIE MODELU DECYZYJNEGO:\n{znalezione_klucze["najtrafniejsze"]}'
            
            elif znalezione_klucze['najtrafniejsze'] == 'informacje o personelu':
                """
                ############################################################
                # obsługa flagi 'informacje o personelu'
                ############################################################
                """
                handle_error(f"Uruchomiono: {znalezione_klucze['najtrafniejsze']}.")
                great_employee=f'Dump z dnia {datetime.datetime.now().strftime("%Y-%B-%d %H:%M")}\n--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- \n'
                for info_line in user_infos_list_tuple:
                    great_employee += f"@{info_line[3]}\n{info_line[0]}\nRANGA:{info_line[1]}\n{info_line[2]}\n--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- \n"
                command = f'WYKRYTO ZAPYTANIE O INFORMACJE NA TEMAT PERSONELU OTO DUMP DO WYKORZYSTANIA:\n{great_employee}'

            else: command = ''
        else: command = ''

        theme = {
            "id": dump[0],
            "user_name": dump[1],
            "description": user_descrition,
            "user_about": user_about,
            "content": dump[2],
            "timestamp": dump[3],
            "status": dump[4],
            'command': command
        }
        if theme["user_name"] == 'aifa':
            theme["user_name"] = 'Ty napisałaś:'

        if theme["status"] == 2 and len(dump_key) < 2:
            continue

        if prepare_shedule.insert_to_database(
            f"UPDATE Messages SET status = %s WHERE id = %s",
            (1, theme["id"])):
            if dump[1] != "aifa":
                ready_prompt += f'LOGIN TO: {theme["user_name"]}\nRANGA TO: {theme["description"]}\nWIADOMOŚĆ OD UŻYTKOWNIKA {theme["user_name"]} TO:\n{theme["content"]}\n{command}\n'
                # ready_prompt += f'LOGIN:{theme["user_name"]}\nRANGA: {theme["description"]}\nINFORMACJE O UŻYTKOWNIKU: {theme["user_about"]}\nWIADOMOŚĆ OD UŻYTKOWNIKA {theme["user_name"]}:\n{theme["content"]}\n{command}\n'
            else:
                ready_prompt += f'TWÓJ LOGIN TO: aifa\nPOPRZEDNIA WIADOMOŚĆ OD CIEBIE TO:\n{theme["content"]}\n\n'
            count_ready += 1

    if count_ready > 0:
        return ready_prompt
    else:
        return None

def get_lastAifaLog(systemInfoFilePath='/home/johndoe/app/newsletterdemon/logs/logsForAifa.json'):
    # Utwórz plik JSON, jeśli nie istnieje
    if not os.path.exists(systemInfoFilePath):
        with open(systemInfoFilePath, 'w') as file:
            json.dump({"logs": []}, file)
    
    # Wczytaj logi z pliku
    with open(systemInfoFilePath, 'r+', encoding='utf-8') as file:
        data = json.load(file)
        
        # Znajdź pierwszy nieoddany log
        for log in data["logs"]:
            if not log.get("oddany", False):  # jeśli nie został oznaczony jako oddany
                log["oddany"] = True  # oznacz jako oddany
                file.seek(0)  # wróć na początek pliku
                json.dump(data, file, indent=4)  # zapisz zmiany
                file.truncate()  # obetnij zawartość do nowej długości
                return log["message"]
    
    return None

def add_aifaLog(message: str, systemInfoFilePath='/home/johndoe/app/newsletterdemon/logs/logsForAifa.json') -> None:
    # Utwórz plik JSON, jeśli nie istnieje
    if not os.path.exists(systemInfoFilePath):
        with open(systemInfoFilePath, 'w') as file:
            json.dump({"logs": []}, file)
    
    # Dodaj nowy log do pliku
    with open(systemInfoFilePath, 'r+', encoding='utf-8') as file:
        data = json.load(file)
        data["logs"].append({"message": message, "oddany": False})  # dodaj nowy log jako nieoddany
        file.seek(0)  # wróć na początek pliku
        json.dump(data, file, indent=4)  # zapisz zmiany
        file.truncate()  # obetnij zawartość do nowej długości


# Funkcja do pobierania logów
def getDataLogs(
    user: str,  # Nazwa użytkownika, który pobiera logi; służy do oznaczenia logów jako "przeczytane" przez tego użytkownika.
    search_by: Optional[str] = None,  # Opcjonalny argument; kategoria logów do wyszukania (np. 'success', 'danger').
                                      # Jeśli nie jest ustawiony (None), logi są zwracane bez względu na kategorię.
    spend_quantity: Optional[int] = None,  # Maksymalna liczba logów do zwrócenia. Jeśli None, funkcja zwróci wszystkie logi
                                           # spełniające kryteria. Ogranicza liczbę wyników na podstawie tego parametru.
    spen_last_days: Optional[int] = None,  # Opcjonalny argument określający liczbę dni wstecz, w których logi mają być
                                           # wyszukane. Ma niższy priorytet niż godziny i minuty.
    spen_last_hours: Optional[int] = None, # Opcjonalny argument określający liczbę godzin wstecz do wyszukiwania logów.
                                           # Ma wyższy priorytet niż dni i niższy niż minuty.
    spen_last_minutes: Optional[int] = None, # Opcjonalny argument określający liczbę minut wstecz do wyszukiwania logów.
                                             # Najwyższy priorytet czasowy – jeśli jest ustawiony, ignoruje wartości dni i godzin.
    file_name_json: str = '/home/johndoe/app/newsletterdemon/logs/dataLogsAifa.json' # Ścieżka do pliku JSON, gdzie przechowywane
                                                                                # są logi. Domyślnie: dataLogsAifa.json w ścieżce
                                                                                # aplikacji. Funkcja wczytuje i zapisuje dane
                                                                                # z/na ten plik.
) -> List[dict]:  # Funkcja zwraca listę słowników zawierających logi, które spełniają przekazane kryteria.

    
    # Pobierz aktualny czas
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # Ustal próg czasowy
    if spen_last_minutes is not None:
        time_threshold = now - datetime.timedelta(minutes=spen_last_minutes)
    elif spen_last_hours is not None:
        time_threshold = now - datetime.timedelta(hours=spen_last_hours)
    elif spen_last_days is not None:
        time_threshold = now - datetime.timedelta(days=spen_last_days)
    else:
        time_threshold = None

    # Wczytaj dane z pliku JSON lub utwórz pustą listę, jeśli plik nie istnieje
    try:
        with open(file_name_json, "r") as file:
            data_json = json.load(file)
    except FileNotFoundError:
        data_json = []

    filtered_logs = []
    for log in data_json:
        # Pomijaj logi, które użytkownik już widział
        if user in log['issued']:
            continue
        
        # Filtruj według kategorii
        if search_by is not None and log['category'] != search_by:
            continue
        
        # Filtruj według czasu
        # log_date = datetime.datetime.strptime(log['date'], "%Y-%m-%dT%H:%MZ")
        # W sekcji filtrowania logów według czasu
        log_date = datetime.datetime.strptime(log['date'], "%Y-%m-%dT%H:%MZ").replace(tzinfo=datetime.timezone.utc)
        if time_threshold and log_date < time_threshold:
            continue

        # Dodaj log do wyników i oznacz jako przeczytany przez użytkownika
        filtered_logs.append(log)
        log['issued'].append(user)  # Dopisz użytkownika do issued

    # Ogranicz liczbę wyników
    if spend_quantity is not None:
        filtered_logs = filtered_logs[:spend_quantity]

    # Zapisz zaktualizowane dane do pliku
    with open(file_name_json, "w") as file:
        json.dump(data_json, file, indent=4)
    
    return filtered_logs

# Funkcja do dodawania nowego logu
def addDataLogs(message: str, category: str, file_name_json: str = "/home/johndoe/app/newsletterdemon/logs/dataLogsAifa.json"):
    # Wczytaj istniejące logi lub utwórz pustą listę
    try:
        with open(file_name_json, "r") as file:
            data_json = json.load(file)
    except FileNotFoundError:
        data_json = []

    # Tworzenie nowego logu
    new_log = {
        "id": len(data_json) + 1,  # Generowanie unikalnego ID
        "message": message,
         "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%MZ"),
        "category": category,
        "issued": []
    }

    # Dodanie nowego logu do listy i zapisanie do pliku
    data_json.append(new_log)
    with open(file_name_json, "w") as file:
        json.dump(data_json, file, indent=4)



def getMorphy(morphy_JSON_file_name="/home/johndoe/app/newsletterdemon/logs/commandAifa.json"):
    def string_to_tuple(s, sep="|"):
        """Konwertuje string na tuplę, używając separatora do podziału."""
        return tuple(s.split(sep))

    """Odzyskuje tuplę z kluczy JSON i zwraca dane z poprawionymi kluczami."""
    with open(morphy_JSON_file_name, "r", encoding="utf-8") as f:
        dane_json = json.load(f)
    # Konwersja kluczy z formatu string na tuple
    dane_with_tuples = {string_to_tuple(k): v for k, v in dane_json.items()}
    return dane_with_tuples

def saveMorphy(dane_dict, file_name="/home/johndoe/app/newsletterdemon/logs/commandAifa.json"):
    def tuple_to_string(tup, sep="|"):
        """Konwertuje tuplę na string za pomocą separatora."""
        return sep.join(tup)
    # Konwersja tupli na string przy zapisie do JSON
    dane_json_ready = {tuple_to_string(k): v for k, v in dane_dict.items()}
    # Zapis do JSON z kodowaniem utf-8
    with open(file_name, "w", encoding="utf-8") as f:
        json.dump(dane_json_ready, f, ensure_ascii=False, indent=4)

def make_fbgroups_task(data):
    {'id': 1, 'shedules_level': 0, 'post_id': 13, 'content': 'content TEXT', 'color_choice': 4, 'category': 'praca', 'section': 'career'}
    waitnig_list_id = data['id']
    id_ogloszenia = data['post_id']
    kategoria_ogloszenia = data['category'] 
    created_by = data['created_by'] 
    sekcja_ogloszenia = data['section']
    tresc_ogloszenia = data['content']
    styl_ogloszenia = data['color_choice']
    poziom_harmonogramu = data['shedules_level']
    id_gallery = data['id_gallery']
    

    dump_key_links = prepare_shedule.connect_to_database(
            f"""SELECT link FROM facebook_gropus WHERE category = '{kategoria_ogloszenia}' AND created_by = '{created_by}';""")
    linkigrup_string = '-@-'.join(link[0] for link in dump_key_links)

    # Zapisz aktualny licznik emisji
    prepare_shedule.insert_to_database(
            f"""
                UPDATE facebook_gropus
                SET realized_emissions = realized_emissions + 1
                WHERE created_by = %s AND category = %s;
            """,
            (created_by, kategoria_ogloszenia)
        )

    fotolinkigrup_string = ""  # Dodajemy wartość domyślną
    if id_gallery is not None:
        dump_row_fotos = prepare_shedule.connect_to_database(
            f"""SELECT * FROM ZdjeciaOfert WHERE ID = {id_gallery};""")[0]
        clear_row_foto = [foto for foto in dump_row_fotos[1:-1] if foto is not None]
        fotolinkigrup_string = '-@-'.join(fotolink for fotolink in clear_row_foto)
    if fotolinkigrup_string !="": 
        zdjecia_string = fotolinkigrup_string
    else:
        zdjecia_string = None
    # Pobieramy bieżący czas w formacie UNIX
    unix_time = int(time()) % 1000000
    # Generujemy losowe cyfry (np. 5-cyfrowy numer)
    random_digits = random.randint(100, 999)

    # Tworzymy unikalne id zadania, łącząc losowe cyfry i czas UNIX
    id_zadania = int(f"{random_digits}{unix_time}")

    status = 4
    active_task = 0

    # Zapisuję i synchronizuję bazy waitnig_list i automatu
    if prepare_shedule.insert_to_database(
        f"""
            UPDATE waitinglist_fbgroups SET
                schedule_{poziom_harmonogramu}_id = %s,
                schedule_{poziom_harmonogramu}_status = %s
            WHERE id = %s;""",
            (id_zadania, status, waitnig_list_id)
        ): return prepare_shedule.insert_to_database(
            f"""INSERT INTO ogloszenia_fbgroups
                    (id_ogloszenia, waitnig_list_id, kategoria_ogloszenia, sekcja_ogloszenia, tresc_ogloszenia, 
                    styl_ogloszenia, poziom_harmonogramu, linkigrup_string, zdjecia_string, 
                    id_zadania, status, active_task, created_by)
                VALUES 
                    (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);""",
            (id_ogloszenia, waitnig_list_id, kategoria_ogloszenia, sekcja_ogloszenia, tresc_ogloszenia, 
            styl_ogloszenia, poziom_harmonogramu, linkigrup_string, zdjecia_string, 
            id_zadania, status, active_task, created_by)
            )
    else: return False



def main():
    # Checkpointy i ich interwały w sekundach
    checkpoints = {
        "checkpoint_2s": 2,
        "checkpoint_15s": 15,
        "checkpoint_30s": 30,
        "checkpoint_60s": 60,
        "checkpoint_180s": 180,
        "checkpoint_300s": 300,
        "checkpoint_3h": 10800
    }
    # Inicjalizacja czasu ostatniego uruchomienia dla każdego checkpointu
    last_run_times = {name: time() for name in checkpoints.keys()}
    for _ in range(int(time())):
        current_time = time()  # Aktualny czas
        for name, interval in checkpoints.items():
            # print(f"Checking {name}:")
            # print(f"current_time (type: {type(current_time)}) = {current_time}")
            # print(f"last_run_times[{name}] (type: {type(last_run_times[name])}) = {last_run_times[name]}")
            if current_time - last_run_times[name] >= interval:
                # Akcje dla różnych checkpointów
                if name == 'checkpoint_2s':
                    """ 
                        **********************************************************
                        ****************** CHECKPOINT 2 SECONDS ****************** 
                        **********************************************************
                    """
                    print("CHECKPOINT 2 SECONDS")
                        
                elif name == 'checkpoint_15s':
                    """ 
                        **********************************************************
                        ****************** CHECKPOINT 15 SECONDS ***************** 
                        **********************************************************
                    """
                     ################################################################
                    # Obsługa automatycznej publikacji ogłoszeń na gupach FACEBOOKA
                    # TWORZENIE ZADANIA DLA AUTOMATU
                    ################################################################
                    
                    for task_data in give_me_curently_tasks():
                        if make_fbgroups_task(task_data):
                            handle_error(f"Przygotowano kampanię FB w sekcji {task_data.get('section', None)} dla kategorii {task_data.get('category', None)} eminowaną przez bota {task_data.get('created_by', None)} o id: {task_data.get('post_id', None)}.\n")
                            sleep(5)

                elif name == 'checkpoint_30s':
                    """ 
                        **********************************************************
                        ****************** CHECKPOINT 30 SECONDS ***************** 
                        **********************************************************
                    """
                    ################################################################
                    # komentowanie chata przez serwer automatów
                    ################################################################

                    random_choiced_prompt_list = [
                        "Spójrz na poniższą rozmowę z naszego firmowego chatu. W sytuacjach wymagających rozwiązania problemu, postaraj się podejść do niego kreatywnie, uwzględniając punkt widzenia innych uczestników.\n\nZareaguj, dostosowując styl odpowiedzi do tonu innych użytkowników i zwracając się do nich po nicku. Napisz swoją odpowiedź od razu!",
                        "Na naszym firmowym chacie trwa dyskusja. Jeśli w rozmowie pojawia się pytanie lub wyzwanie, spróbuj odpowiedzieć w sposób, który pobudzi myślenie innych i wniesie nowe spojrzenie.\n\nDopasuj swoją reakcję do klimatu rozmowy i bezpośrednio odpowiedz użytkownikom, używając ich nicków. Sformułuj odpowiedź od razu!",
                        "Przeczytaj poniższy fragment rozmowy z chatu. Zastanów się, czy masz pomysł, który rozwiąże postawiony problem w nietypowy sposób lub zainspiruje uczestników do dalszych działań.\n\nOdpowiedz, uwzględniając charakter wypowiedzi i kontekst, z szacunkiem do nicków użytkowników. Pisz bez zwłoki!",
                        "Właśnie trwa wymiana zdań na naszym firmowym chacie. Jeżeli dostrzegasz problem, podziel się sugestią, która może pomóc zespołowi, nawet jeśli wykracza poza standardowe rozwiązania.\n\nPrzemyśl odpowiedź, która odpowiada stylowi rozmowy i kontekstu, adresując ją bezpośrednio do użytkowników po ich nickach. Odpowiedz od razu!",
                        "Spójrz na fragment rozmowy toczącej się na firmowym chacie. W sytuacjach wymagających twórczego podejścia, postaraj się, aby Twoja odpowiedź otworzyła nowe możliwości lub rzuciła inne światło na zagadnienie.\n\nZareaguj adekwatnie do sytuacji, bezpośrednio zwracając się do użytkowników po nickach. Natychmiast prześlij swoją odpowiedź!",
                        "Trwa konwersacja na chacie firmowym. Jeśli w rozmowie pojawia się potrzeba rozwiązania problemu, wykaż się kreatywnością i zasugeruj pomysł, który może usprawnić pracę zespołu.\n\nWybierz ton odpowiedzi odpowiadający dynamice rozmowy i zwróć się bezpośrednio do uczestników po ich nickach. Napisz odpowiedź już teraz!"
                    ]

                    pre_prompt = random.choice(random_choiced_prompt_list)
                    final_prompt = prepare_prompt(pre_prompt)
                    if final_prompt is not None:

                        prepare_shedule.insert_to_database(
                            f"""INSERT INTO chat_task
                                    (question, status)
                                VALUES 
                                    (%s, %s)""",
                            (final_prompt, 5)
                            )

                    ################################################################
                    # Przekazanie widomości ze strony na pawel@dmdbudownictwo.pl
                    ################################################################

                    contectDB = prepare_shedule.connect_to_database(f'SELECT ID, CLIENT_NAME, CLIENT_EMAIL, SUBJECT, MESSAGE, DATE_TIME FROM contact WHERE DONE=1;')
                    for data in contectDB:
                        EMAIL_COMPANY = 'pawel@dmdbudownictwo.pl'
                        TITLE_MESSAGE = f"{data[3]}"
                        message = messagerCreator.create_html_resend(client_name=data[1], client_email=data[2], data=data[5], tresc=data[4])

                        sendEmailBySmtp.send_html_email(TITLE_MESSAGE, message, EMAIL_COMPANY)
                        prepare_shedule.insert_to_database(
                            f"UPDATE contact SET DONE = %s WHERE ID = %s AND CLIENT_EMAIL = %s",
                            (0, data[0], data[2])
                            )
                        
                        handle_error(f"Przekazano wiadmość ze strony firmowej w temacie: {TITLE_MESSAGE} od {data[1]} z podanym kontaktem {data[2]}\n")
                        # add_aifaLog(f'Przekazano wiadmość ze strony firmowej w temacie: {TITLE_MESSAGE} od {data[1]}')
                        addDataLogs(f'Przekazano wiadmość ze strony firmowej w temacie: {TITLE_MESSAGE} od {data[1]}', 'success')

                elif name == 'checkpoint_60s':
                    """ 
                        **********************************************************
                        ****************** CHECKPOINT 60 SECONDS ***************** 
                        **********************************************************
                    """
                    handle_error(f'{datetime.datetime.now()} - {__name__} is working...\n')
                        
                elif name == 'checkpoint_180s':
                    """ 
                        **********************************************************
                        ****************** CHECKPOINT 180 SECONDS **************** 
                        **********************************************************
                    """
                    ################################################################
                    # Obsługa automatycznego wygaszania zakończonych ogłoszeń na 
                    # ALLEGRO OTODOM LENTO
                    ################################################################

                    expired_records = check_all_tables_for_expiry()

                    for record in expired_records:
                        table_name = record.get('table', None)
                        record_id = record.get('id', None)
                        status = record.get('status', None)
                        
                        if table_name is None or record_id is None or status is None:
                            handle_error(f"Pominięto rekord z brakującymi danymi: {record}.\n")
                            continue

                        # Jeżeli status jest 1 lub 0 -> Zmieniamy status na 6 (Trwa proces usuwania ogłoszenia)
                        if status in [0, 1]:
                            query_update_status = f"UPDATE {table_name} SET status = %s, active_task = %s WHERE id = %s"
                            values = (6, 0, record_id)
                            try:
                                insert_to_database(query_update_status, values)  # Zakładam, że insert_to_database obsługuje także update
                                handle_error(f"Wygaszanie ogłoszenia o ID {record_id} w tabeli {table_name}.\n")
                            except Exception as e:
                                handle_error(f"Błąd przy aktualizacji rekordu o ID {record_id} w tabeli {table_name}: {e}.\n")
                        
                        # Jeżeli status jest 2 -> Usuwamy rekord
                        elif status == 2:
                            query_delete_record = f"DELETE FROM {table_name} WHERE id = %s"
                            values = (record_id,)
                            try:
                                delete_row_from_database(query_delete_record, values)
                                handle_error(f"Usunięto rekord o ID {record_id} z tabeli {table_name}.\n")
                            except Exception as e:
                                handle_error(f"Błąd przy usuwaniu rekordu o ID {record_id} z tabeli {table_name}: {e}.\n")

                elif name == 'checkpoint_300s':
                    """ 
                        **********************************************************
                        ****************** CHECKPOINT 300 SECONDS **************** 
                        **********************************************************
                    """
                    ################################################################
                    # Wysyłka newslettera do aktywnych użytkowników według planu wysyłki
                    ################################################################

                    shcedule = prepare_shedule.prepare_mailing_plan(prepare_shedule.get_allPostsID(), prepare_shedule.get_sent())
                    sleep(1)
                    prepare_shedule.save_shedule(shcedule)
                    sleep(1)
                    current_time_newslettera = datetime.datetime.now()
                    for row in prepare_shedule.connect_to_database(
                            'SELECT * FROM schedule;'):
                        if row[2] < current_time_newslettera:
                            TITLE = prepare_shedule.connect_to_database(f'SELECT TITLE FROM contents WHERE  ID={row[1]};')[0][0]
                            nesletterDB = prepare_shedule.connect_to_database(f'SELECT CLIENT_NAME, CLIENT_EMAIL, USER_HASH FROM newsletter WHERE ACTIVE=1;')
                            # add_aifaLog(f'Wysłano zaplanowaną wysyłkę newslettera na dzień {row[2]} pt. {TITLE}')
                            addDataLogs(f'Wysłano zaplanowaną wysyłkę newslettera na dzień {row[2]} pt. {TITLE}', 'success')
                            for data in nesletterDB:
                                hashes = data[2]
                                HTML = messagerCreator.create_html_message(row[1], data[0], hashes)
                                if HTML != '':
                                    sendEmailBySmtp.send_html_email(TITLE, HTML, data[1])
                                    archive_sents(row[1])
                                    handle_error(f"Wysłano zaplanowaną wysyłkę newslettera na dzień {row[2]} pt. {TITLE} do {data[1]} \n")

                    ################################################################
                    # Aktywacja konta subskrybenta
                    ################################################################

                    nesletterDB = prepare_shedule.connect_to_database(f'SELECT ID, CLIENT_NAME, CLIENT_EMAIL, USER_HASH FROM newsletter WHERE ACTIVE=0;')
                    for data in nesletterDB:
                        TITLE_ACTIVE = 'Aktywacja konta'
                        message = messagerCreator.HTML_ACTIVE.replace('{{imie klienta}}', data[1]).replace('{{hashes}}', data[3])
                        sendEmailBySmtp.send_html_email(TITLE_ACTIVE, message, data[2])
                        prepare_shedule.insert_to_database(
                            f"UPDATE newsletter SET ACTIVE = %s WHERE ID = %s AND CLIENT_EMAIL = %s",
                            (3, data[0], data[2])
                            )
                        handle_error(f"{TITLE_ACTIVE} dla {data[1]} z podanym kontaktem {data[2]}\n")
                        # add_aifaLog(f'{TITLE_ACTIVE} dla {data[1]} z podanym kontaktem {data[2]}')
                        addDataLogs(f'{TITLE_ACTIVE} dla {data[1]} z podanym kontaktem {data[2]}', 'success')
                
                elif name == 'checkpoint_3h': 
                    """ 
                        **********************************************************
                        ******************   CHECKPOINT 4 HOURS   **************** 
                        **********************************************************
                    """
                    ################################################################
                    # Automatyczne zbieranie statystyk dla FB-GROUPS
                    ################################################################

                    created_by_bot = ['dmddomy', 'fredgraf', 'michalformatyk']

                    for bot in created_by_bot:
                        # Pobierz id i linki dla danego użytkownika
                        id_group_links = prepare_shedule.connect_to_database(
                            f'SELECT id, link FROM facebook_gropus WHERE created_by="{bot}";'
                        )
                        
                        # Tworzenie ciągu ready_string
                        ready_string = ''
                        for id, link in id_group_links:
                            ready_string += f"{id}-$-{link}-@-"
                        
                        # Usunięcie ostatniego "-@-" i wstawienie do bazy, jeśli ciąg nie jest pusty
                        if ready_string:
                            ready_string = ready_string[:-3]
                            prepare_shedule.insert_to_database(
                                """INSERT INTO fbgroups_stats_monitor
                                    (id_and_links_string, created_by, status)
                                VALUES 
                                    (%s, %s, %s)""",
                                (ready_string, bot, 4)
                            )

                # Aktualizacja czasu ostatniego wykonania dla checkpointu
                last_run_times[name] = current_time

            sleep(0.1)  # Krótkie opóźnienie, aby nie przeciążać procesora


if __name__ == "__main__":
    main()