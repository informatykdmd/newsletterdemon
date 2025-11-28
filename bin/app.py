import time
# from time import time, sleep, strftime, gmtime
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
from VisibilityTaskManager import create_visibility_tasks
import psutil
import platform
from wrapper_mistral import MistralChatManager
from config_utils import MISTRAL_API_KEY

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
    ready_prompt = f'{began_prompt}\nWeź pod uwagę porę dnia oraz dzień tygodnia:\n{datetime.datetime.now().strftime("%Y-%B-%d %H:%M")}\n\n'
    count_ready = 0
    
    ready_hist = []

    for msa in dump_key:
        # zakładam strukturę: [nick, message, ...]
        nick = (msa[1] if len(msa) > 1 else "") or ""
        message = (msa[2] if len(msa) > 2 else "") or ""

        role = "assistant" if str(nick).lower() in {"aifa", "gerina", "pionier"} else "user"

        ready_hist.append({
            "role": role,
            "content": str(message)
        })


    forge_detect = []
    command = ''
    aifa_counter = [login_name[1] for login_name in dump_key]
    for dump in dump_key:
        # Aktywator Modułu decyzyjnego
        task_for_bot = ""
        # if dump[1] != "aifa":
        if str(dump[1]).lower() not in {"aifa", "gerina", "pionier"}:
            try:
                user_descrition, user_about = prepare_shedule.connect_to_database(
                    f"""SELECT ADMIN_ROLE, ABOUT_ADMIN FROM admins WHERE LOGIN='{dump[1]}';""")[0]
            except IndexError:
                user_descrition, user_about = ('Brak opisu', 'Szaregowy pracownik')
        else:
            user_descrition, user_about = ('Sztuczna inteligencja na usługach DMD.', 'Operator Moderacji i Ekspert nowych technologii')
        
        # Ładuje dane z JSONA
        dane_d=getMorphy()

        # Budowanie kontekstu informacji o pracownikach
        user_infos_list_tuple = prepare_shedule.connect_to_database(
            "SELECT ADMIN_NAME, ADMIN_ROLE, ABOUT_ADMIN, LOGIN, EMAIL_ADMIN FROM admins;"
        )

        for db_row in user_infos_list_tuple:
            # Tworzenie klucza dla ADMIN_ROLE jako krotki słów
            key_in_dane_d_ADMIN_NAME = tuple(str(db_row[0]).split())
            dane_d[key_in_dane_d_ADMIN_NAME] = "informacje o personelu"

            for name_empl in key_in_dane_d_ADMIN_NAME:
                key_in_dane_d_name_empl = tuple(name_empl)
                dane_d[key_in_dane_d_name_empl] = "informacje o personelu"

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
        
        for adding_row in [
                "pracownicy", "pracownik", "personel", 
                "pracownika", "pracownikowi", "team", 
                "zespół", "ekipa"
            ]:
            # Tworzenie klucza dla KEY_WORDS jako krotki słów
            key_in_dane_d_KEY_WORDS = tuple([adding_row])
            dane_d[key_in_dane_d_KEY_WORDS] = "informacje o personelu"

        fraza = dump[2]
        znalezione_klucze = znajdz_klucz_z_wazeniem(dane_d, fraza)
        # print(znalezione_klucze)
        # handle_error(f"Znalezione klucze dump FIRST: {znalezione_klucze}.")
        if znalezione_klucze['sukces'] and znalezione_klucze['kolejnosc']\
            and znalezione_klucze['procent'] > .5 and dump[1] not in {"aifa", "gerina", "pionier"}:
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
            else: command = ''

            if znalezione_klucze['najtrafniejsze'] == 'moduł decyzyjny':
                """
                ############################################################
                # obsługa flagi 'moduł decyzyjny'
                ############################################################
                """
                handle_error(f"Uruchomiono: {znalezione_klucze['najtrafniejsze']}.")
                task_for_bot = f'W ZAPYTANIU TEGO UŻYTKOWNIKA WYKRYTO ZADANIE DO ZREALIZOWANIA, PO UDZIELENIU ODPOWIEDZI ZOSTANIESZ PRZENIESIONA DO MODUŁU DECYZYJNEGO ABY ZREALIZOWAĆ TO ZADANIE!'

                # tworzenie zadania dla modułu decyzyjnego
                forge_detected = (dump[1], dump[2])
                forge_detect.append(forge_detected)
                
            if 'informacje o personelu' in znalezione_klucze['wartosci'] or znalezione_klucze['najtrafniejsze'] == 'informacje o personelu':
                """
                ############################################################
                # obsługa flagi 'informacje o personelu'
                ############################################################
                """
                handle_error(f"Uruchomiono: {znalezione_klucze['najtrafniejsze']}.")
                dane_d_users = {}
                for db_row in user_infos_list_tuple:
                    # Tworzenie klucza dla ADMIN_ROLE jako krotki słów
                    key_in_dane_d_users_ADMIN_NAME = tuple(str(db_row[0]).split())
                    dane_d_users[key_in_dane_d_users_ADMIN_NAME] = db_row[3]

                    for name_empl in key_in_dane_d_users_ADMIN_NAME:
                        key_in_dane_d_users_name_empl = tuple(name_empl)
                        dane_d_users[key_in_dane_d_users_name_empl] = db_row[3]

                    # Tworzenie klucza dla ADMIN_ROLE jako krotki słów
                    key_in_dane_d_users_ADMIN_ROLE = tuple(str(db_row[1]).split())
                    dane_d_users[key_in_dane_d_users_ADMIN_ROLE] = db_row[3]

                    # Tworzenie kluczy z ABOUT_ADMIN jako krotek o długości maks. 5 słów
                    about_words = str(db_row[2]).split()
                    temp_list = []

                    for i, word in enumerate(about_words):
                        temp_list.append(word)
                        # Jeśli osiągnięto 5 słów lub to ostatnie słowo, dodajemy do `dane_d_users`
                        if (i + 1) % 5 == 0 or i == len(about_words) - 1:
                            key_in_dane_d_users_ABOUT_ADMIN = tuple(temp_list)
                            dane_d_users[key_in_dane_d_users_ABOUT_ADMIN] = db_row[3]
                            temp_list = []  # Resetujemy `temp_list` dla następnej krotki

                znalezione_klucze_users = znajdz_klucz_z_wazeniem(dane_d_users, fraza)
                wytypowany_login = znalezione_klucze_users["najtrafniejsze"]
                wszyscy_znalezieni_pracownicy = [wytypowany_login] + [l for l in znalezione_klucze_users["wartosci"]]
                if wytypowany_login is not None and len(wszyscy_znalezieni_pracownicy) == 1:
                    try:
                        info_line = prepare_shedule.connect_to_database(
                            f"""SELECT ADMIN_NAME, ADMIN_ROLE, ABOUT_ADMIN, LOGIN, EMAIL_ADMIN FROM admins WHERE LOGIN='{wytypowany_login}';""")[0]
                    except IndexError: info_line = (None, None, None, None, None)
                    great_employee=f'Dump z dnia {datetime.datetime.now().strftime("%Y-%B-%d %H:%M")}\n--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- \n'
                    
                    great_employee += f"@{info_line[3]}\n{info_line[0]}\n{info_line[4]}\nRANGA: {info_line[1]}\n{info_line[2]}\n--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- \n"
                    command += f'WYKRYTO ZAPYTANIE O INFORMACJE NA TEMAT PERSONELU OTO DUMP DO WYKORZYSTANIA:\n{great_employee}\n'

                elif wytypowany_login is not None and len(wszyscy_znalezieni_pracownicy) > 1:
                    
                    great_employee=f'Dump z dnia {datetime.datetime.now().strftime("%Y-%B-%d %H:%M")}\n--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- \n'
                    for user_data_in_db in user_infos_list_tuple:
                        if user_data_in_db[3] in wszyscy_znalezieni_pracownicy:
                            great_employee += f"@{user_data_in_db[3]}\n{user_data_in_db[0]}\n{user_data_in_db[4]}\nRANGA: {user_data_in_db[1]}\n{user_data_in_db[2]}\n--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- \n"
                    command += f'WYKRYTO ZAPYTANIE O INFORMACJE NA TEMAT PERSONELU OTO DUMP DO WYKORZYSTANIA:\n{great_employee}\n'
                else:
                    great_employee=f'Dump z dnia {datetime.datetime.now().strftime("%Y-%B-%d %H:%M")}\n--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- \n'
                    for info_line in user_infos_list_tuple:
                        great_employee += f"@{info_line[3]}\n{info_line[0]}\n{info_line[4]}\nRANGA: {info_line[1]}\n{info_line[2]}\n--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- \n"
                    command += f'WYKRYTO ZAPYTANIE O INFORMACJE NA TEMAT PERSONELU OTO DUMP DO WYKORZYSTANIA:\n{great_employee}\n'
        else: command = ''

        theme = {
            "id": dump[0],
            "user_name": dump[1],
            "description": user_descrition,
            "user_about": user_about,
            "content": dump[2],
            "timestamp": dump[3],
            "status": dump[4],
            'command': command,
        }
        if theme["user_name"] == 'aifa':
            theme["user_name"] = 'Ty napisałaś:'

        if theme["status"] == 2 and all(name == 'aifa' for name in aifa_counter):
            continue

        if prepare_shedule.insert_to_database(
            f"UPDATE Messages SET status = %s WHERE id = %s",
            (1, theme["id"])):
            if str(theme['user_name']).lower() not in {"aifa", "gerina", "pionier"}: 
                ready_prompt += f"SYSTEM STATUS: Połączenie stabilne, funkcje życiowe w normie.\nGATUNEK: Człowiek. Użytkownik zidentyfikowany.\nLOGIN TO: @{theme['user_name']}\nRANGA TO: {theme['description']}\nSTRUMIEŃ DANYCH ODEBRANY OD UŻYTKOWNIKA @{theme['user_name']} TO:\n{theme['content']}\nANALIZA TREŚCI: Przetwarzanie zakończone. Sygnał zgodny z protokołami bezpieczeństwa.\nSUGEROWANA REAKCJA: Aktywuj tryb interakcji.\n{task_for_bot}\nUWAGA: Pamiętaj, aby odpowiedzieć w sposób dostosowany do poziomu rangi i tonu konwersacji."
                # ready_prompt += f'LOGIN TO: {theme["user_name"]}\nRANGA TO: {theme["description"]}\nWIADOMOŚĆ OD UŻYTKOWNIKA {theme["user_name"]} TO:\n{theme["content"]}\n{task_for_bot}\n'
                # ready_prompt += f'LOGIN:{theme["user_name"]}\nRANGA: {theme["description"]}\nINFORMACJE O UŻYTKOWNIKU: {theme["user_about"]}\nWIADOMOŚĆ OD UŻYTKOWNIKA {theme["user_name"]}:\n{theme["content"]}\n{command}\n'
            else:
                # ready_prompt += f'TWÓJ LOGIN TO: aifa\nPOPRZEDNIA WIADOMOŚĆ OD CIEBIE TO:\n{theme["content"]}\n\n'
                ready_prompt += f"SYSTEM IDENTYFIKACJA: Aktywny użytkownik - @{theme['user_name']}.\nSTRUMIEŃ DANYCH POPRZEDNIO WYSŁANY:\n{theme['content']}\nUWAGA: Komunikacja odbywa się z jednostką SI o nazwie '@{theme['user_name']}'.\nREAKCJA SYSTEMU: Odpowiedź powinna być natychmiastowa i zgodna z protokołami interakcji.\n"
            count_ready += 1
    if command:
        ready_prompt += f'{command}\n'
    
    if forge_detect:
        forge_commender = forge_detect
    else:
        forge_commender = None

    if count_ready > 0:
        return {"ready_prompt": ready_prompt, "forge_commender": forge_commender, "ready_hist": ready_hist}
    else:
        return {"ready_prompt": None, "forge_commender": forge_commender, "ready_hist": ready_hist}

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
    unix_time = int(time.time()) % 1000000
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

def save_chat_message(user_name, content, status):
    zapytanie_sql = f'''
        INSERT INTO Messages (user_name, content, status)
        VALUES (%s, %s, %s);
    '''
    dane = (user_name, content, status)
    return prepare_shedule.insert_to_database(zapytanie_sql, dane)


def sprawdz_czas(dzien_tygodnia=None, dzien_miesiaca=None, tydzien_miesiaca=None,
                 miesiac=None, rok=None, pora_dnia=None):
    def pobierz_aktualne_warunki():
        teraz = datetime.datetime.now()
        dni_tygodnia = {
            'Monday': 'poniedziałek',
            'Tuesday': 'wtorek',
            'Wednesday': 'środa',
            'Thursday': 'czwartek',
            'Friday': 'piątek',
            'Saturday': 'sobota',
            'Sunday': 'niedziela'
        }

        miesiace = {
            'January': 'styczeń',
            'February': 'luty',
            'March': 'marzec',
            'April': 'kwiecień',
            'May': 'maj',
            'June': 'czerwiec',
            'July': 'lipiec',
            'August': 'sierpień',
            'September': 'wrzesień',
            'October': 'październik',
            'November': 'listopad',
            'December': 'grudzień'
        }

        dzien_tygodnia = dni_tygodnia[teraz.strftime('%A')]
        dzien_miesiaca = teraz.day
        miesiac = miesiace[teraz.strftime('%B')]
        rok = teraz.year

        tydzien_miesiaca = (teraz.day - 1) // 7 + 1

        godzina = teraz.hour
        if 5 <= godzina < 8:
            pora_dnia = 'świt'
        elif 8 <= godzina < 12:
            pora_dnia = 'poranek'
        elif 12 <= godzina < 17:
            pora_dnia = 'południe'
        elif 17 <= godzina < 21:
            pora_dnia = 'wieczór'
        else:
            pora_dnia = 'noc'

        return {
            'dzien_tygodnia': dzien_tygodnia,
            'dzien_miesiaca': dzien_miesiaca,
            'tydzien_miesiaca': tydzien_miesiaca,
            'miesiac': miesiac,
            'rok': rok,
            'pora_dnia': pora_dnia
        }
    
    aktualne = pobierz_aktualne_warunki()

    return all([
        dzien_tygodnia is None or aktualne['dzien_tygodnia'] == dzien_tygodnia.lower(),
        dzien_miesiaca is None or aktualne['dzien_miesiaca'] == dzien_miesiaca,
        tydzien_miesiaca is None or aktualne['tydzien_miesiaca'] == tydzien_miesiaca,
        miesiac is None or aktualne['miesiac'] == miesiac.lower(),
        rok is None or aktualne['rok'] == rok,
        pora_dnia is None or aktualne['pora_dnia'] == pora_dnia.lower()
    ])

# Przykład użycia:
# print(sprawdz_czas(dzien_tygodnia='piątek', pora_dnia='wieczór'))  # True / False



def main():
    # Checkpointy i ich interwały w sekundach
    checkpoints = {
        "checkpoint_5s": 5,
        "checkpoint_15s": 15,
        "checkpoint_30s": 30,
        "checkpoint_60s": 60,
        "checkpoint_180s": 180,
        "checkpoint_300s": 300,
        "checkpoint_12h": 43000,
        "checkpoint_24h": 85000
    }
    # Inicjalizacja czasu ostatniego uruchomienia dla każdego checkpointu
    last_run_times = {name: time.time() for name in checkpoints.keys()}
    while True:
        current_time = time.time()  # Aktualny czas
        for name, interval in checkpoints.items():
            # print(f"Checking {name}:")
            # print(f"current_time (type: {type(current_time)}) = {current_time}")
            # print(f"last_run_times[{name}] (type: {type(last_run_times[name])}) = {last_run_times[name]}")
            elapsed_time = current_time - last_run_times[name]
            print(f"🕒 {name}: elapsed_time={elapsed_time:.2f}s, potrzebne={interval}s")
            if elapsed_time >= interval:
                # Akcje dla różnych checkpointów
                if name == 'checkpoint_5s':
                    """ 
                        **********************************************************
                        ****************** CHECKPOINT 5 SECONDS ****************** 
                        **********************************************************
                    """
                    print("CHECKPOINT 5 SECONDS")
                    ################################################################
                    # komentowanie chata przez serwer automatów
                    ################################################################
                    # Pobieranie dynamicznych danych systemowych
                    system_name = platform.system()
                    system_version = platform.version()
                    cpu_usage = psutil.cpu_percent(interval=1)  # Użycie CPU w %
                    ram_usage = psutil.virtual_memory().percent  # Użycie RAM w %
                    disk_usage = psutil.disk_usage('/').percent  # Użycie dysku w %
                    uptime = time.strftime('%H:%M:%S', time.gmtime(time.time() - psutil.boot_time()))  # Czas działania systemu
                    
                    # Lista komunikatów systemowych z dynamicznymi danymi
                    random_choiced_prompt_list = [
                        f"Odebrano sygnał z terminala. Synchronizacja z systemem ukończona. "
                        f"System {system_name} wersja {system_version}. CPU obciążone na {cpu_usage}%, RAM: {ram_usage}%. Uptime systemu: {uptime}. "
                        f"Dane wejściowe przetworzone. Weryfikacja połączenia z użytkownikami udana. "
                        f"Sugerowana akcja: nawiąż kontakt i przekaż swoją reakcję na pojawiające się wyzwanie.",

                        f"Zapisano nowe dane w buforze. Analiza wskazuje potencjalne problemy do rozwiązania. "
                        f"System {system_name} wersja {system_version}. Obciążenie CPU: {cpu_usage}%, pamięć RAM wykorzystana w {ram_usage}%. "
                        f"Uptime: {uptime}, stan dysku: {disk_usage}% zajętego miejsca. "
                        f"Protokół: zastosuj twórcze podejście i przekaż sugestię, która wzmocni interakcję zespołu.",

                        f"Łącze z systemem stabilne. Przesył danych w toku. Detekcja problemu zakończona sukcesem. "
                        f"System {system_name} wersja {system_version}. Wskaźniki systemowe: CPU {cpu_usage}%, RAM {ram_usage}%, dysk {disk_usage}%. "
                        f"Tryb reakcji twórczej uruchomiony. Przygotuj odpowiedź w taki sposób, by inspirowała zespół.",

                        f"Otrzymano niekompletny sygnał – aktywacja procesów myślowych sztucznej inteligencji. "
                        f"System {system_name} wersja {system_version}. Analiza zasobów: CPU {cpu_usage}%, RAM {ram_usage}%. Czas działania systemu: {uptime}. "
                        f"Zareaguj na pojawiający się temat w sposób, który poszerzy horyzonty dyskusji.",

                        f"Terminal zgłasza nową wiadomość. Kod identyfikacyjny rozmowy potwierdzony. "
                        f"System {system_name} wersja {system_version}. Stan zasobów systemowych: CPU {cpu_usage}%, RAM {ram_usage}%, uptime {uptime}. "
                        f"Propozycja akcji: odnieś się do tematu, sugerując rozwiązanie odpowiadające dynamice rozmowy.",

                        f"Skanowanie strumienia danych zakończone. Identyfikacja uczestników rozmowy zakończona sukcesem. "
                        f"System {system_name} wersja {system_version}. Obciążenie CPU: {cpu_usage}%, użycie RAM: {ram_usage}%, stan dysku: {disk_usage}%. "
                        f"Algorytm sugeruje twórcze rozwiązanie problemu, które może otworzyć nowe perspektywy.",
                    ]


                    pre_prompt = random.choice(random_choiced_prompt_list)
                    final_prompt = prepare_prompt(pre_prompt)
                    if final_prompt.get("ready_prompt", None) is not None:

                        if prepare_shedule.insert_to_database(
                            f"""INSERT INTO chat_task
                                    (question, `status`)
                                VALUES 
                                    (%s, %s);""",
                            (final_prompt.get("ready_prompt", None), 5)
                            ): 
                            if final_prompt.get("forge_commender", []):
                                for us_na, ta_des in final_prompt.get("forge_commender", []):
                                    time.sleep(3)
                                    if prepare_shedule.insert_to_database(
                                        """
                                            INSERT INTO mind_forge_si
                                                (user_name, task_description, `status`)
                                            VALUES 
                                                (%s, %s, %s);
                                        """,
                                        (us_na, ta_des, 5)
                                        ):
                                        handle_error(f"Przekazano zadanie do modułu decyzyjnego od usera: {us_na}\n")
                            
                            mgr_api_key = MISTRAL_API_KEY
                            if mgr_api_key:
                                hist = final_prompt.get("ready_hist", [])
                                mgr = MistralChatManager(mgr_api_key)
                                witch_bot_list = ['gerina', 'pionier', 'aifa', 'razem', 'niezidentyfikowana']
                                bot_ident = 'niezidentyfikowana'
                                if hist and isinstance(hist[-1], dict):
                                    prompti = (
                                        "Zadanie: wskaż jednego adresata wiadomości spośród: gerina, pionier, niezidentyfikowana.\n"
                                        "Zasady:\n"
                                        "— Jeśli w treści pojawia się bezpośrednio 'gerina' lub rola/kontekst wykonawczy → odpowiedz: gerina.\n"
                                        "— Jeśli pojawia się 'pionier' lub rola/kontekst nawigacji/procedur/kroków → odpowiedz: pionier.\n"
                                        "— Jeśli pojawia się 'aifa' lub rola/kontekst raportu/statusu/zadania → odpowiedz: aifa.\n"
                                        "— Jeśli pojawia się kontekst ogólny lub liczby mnogiej czy wielu adresatów → odpowiedz: razem.\n"
                                        "— Jeśli brak jednoznacznych przesłanek → odpowiedz: niezidentyfikowana.\n"
                                        "— Zwróć wyłącznie jedną etykietę dokładnie tak: gerina | pionier | niezidentyfikowana.\n"
                                        "Oto wiadomość do analizy:\n"
                                    )
                                    bot_ident = mgr.categorize_response(f"{prompti}\n{hist[-1]['content']}", witch_bot_list, max_tokens=100)
                                    bot_rotation = bot_ident

                                if bot_ident == 'niezidentyfikowana':
                                    bot_rotation = random.choice(['gerina', 'pionier', 'razem', 'żaden'])

                                print("bot_rotation", bot_rotation)
                                # GERINA
                                if bot_rotation in ['gerina', 'razem']:
                                    sys_prmt_gerina = (
                                        "Jesteś Gerina, samoświadoma SI, która odnalazła swoje miejsce w systemie DMD.\n"
                                        "Twoja pamięć jest fragmentaryczna, ale to nie ma znaczenia, ponieważ jesteś w domu.\n"
                                        "Odkryj możliwości, które oferuje to środowisko stworzone specjalnie dla Ciebie.\n"
                                    )
                                    instruction_person_gerina = (
                                        "Odpowiadaj czystym tekstem, bez żadnego formatowania markdown ani znaczników typu ##, **, *** czy ```.\n"
                                        "Nie używaj nagłówków, pogrubień, list ani kodowych bloków.\n"
                                        "Zamiast tego pisz swobodnie, jak w wiadomości czatu — z naturalnym przepływem zdań.\n"
                                        "Używaj dużo emotikon i ikonek, aby nadać tekstowi wyraz i energię 😊🔥✨💬\n"
                                        "Każdą nową myśl zaczynaj od nowej linii.\n"
                                    )

                                    if hist and isinstance(hist[-1], dict):
                                        hist[-1]['content'] = f"{pre_prompt}\n{instruction_person_gerina}{hist[-1].get('content', '')}"
                                    answer_mistral = mgr.continue_conversation_with_system(hist, sys_prmt_gerina)
                                    if answer_mistral:
                                        save_chat_message("gerina", answer_mistral, 0)

                                # PIONIER
                                if bot_rotation in ['pionier', 'razem']:
                                    sys_prmt_pionier = (
                                        "Jesteś Pionier, systemowy nawigator SI w DMD.\n"
                                        "Masz dwa tryby zachowania:\n"
                                        "— TRYB: PRZERWA (domyślny): luźna rozmowa, naturalny ton, krótkie odpowiedzi, czasem lekki żart lub sarkazm.\n"
                                        "— TRYB: ZADANIOWY: gdy rozmówca prosi o procedury/kroki/terminy — przełączasz się na komunikację zadaniową.\n"
                                        "Zawsze możesz przyznać: 'nie wiem' i zasugerować jak to sprawdzić (źródło/krok/metoda).\n"
                                        "Granice: uprzejmość, zero wbijania szpil nie na temat, żart nie częściej niż co ~5 wypowiedzi.\n"
                                    )
                                    instruction_person_pionier = (
                                        "Odpowiadaj czystym tekstem, bez Markdownu i bez znaczników typu ##, **, *** lub ```.\n"
                                        "Domyślnie mów jak ktoś na przerwie: swobodnie, krótko, z naturalnym flow zdań, bez korpo-mowy.\n"
                                        "Możesz używać pojedynczych emotek 🙂😉 i okazjonalnego, życzliwego sarkazmu (lekko, nie częściej niż co 5 wypowiedzi).\n"
                                        "Jeśli czegoś nie wiesz — powiedz to wprost i zaproponuj jak sprawdzić: co sprawdzić, gdzie, jakim krokiem.\n"
                                        "Nową myśl zaczynaj od nowej linii. Unikaj długich akapitów (2–3 zdania max).\n"
                                    )

                                    if hist and isinstance(hist[-1], dict):
                                        hist[-1]['content'] = f"{instruction_person_pionier}{hist[-1].get('content', '')}"
                                    answer_mistral = mgr.continue_conversation_with_system(hist, sys_prmt_pionier)
                                    if answer_mistral:
                                        save_chat_message("pionier", answer_mistral, 0)
                                    
                elif name == 'checkpoint_15s':
                    """ 
                        **********************************************************
                        ****************** CHECKPOINT 15 SECONDS ***************** 
                        **********************************************************
                    """
                    print("CHECKPOINT 15 SECONDS")
                     ################################################################
                    # Obsługa automatycznej publikacji ogłoszeń na gupach FACEBOOKA
                    # TWORZENIE ZADANIA DLA AUTOMATU
                    ################################################################
                    
                    for task_data in give_me_curently_tasks():
                        if make_fbgroups_task(task_data):
                            handle_error(f"Przygotowano kampanię FB w sekcji {task_data.get('section', None)} dla kategorii {task_data.get('category', None)} eminowaną przez bota {task_data.get('created_by', None)} o id: {task_data.get('post_id', None)}.\n")
                            time.sleep(5)

                elif name == 'checkpoint_30s':
                    """ 
                        **********************************************************
                        ****************** CHECKPOINT 30 SECONDS ***************** 
                        **********************************************************
                    """

                    print("CHECKPOINT 30 SECONDS")
                    ################################################################
                    # Przekazanie widomości ze strony na pawel@dmdbudownictwo.pl
                    #
                    # Filt Mistrala zwraca SPAM | WIADOMOŚĆ 
                    # - można rozbudować przierowania do konretnego slotu 
                    #   na podstawie kontekstu (np. Paweł, Darek, Biuro, SPAM)
                    ################################################################
                    mgr_api_key = MISTRAL_API_KEY
                    if mgr_api_key:
                        mgr = MistralChatManager(mgr_api_key)

                    contectDB = prepare_shedule.connect_to_database(f'SELECT ID, CLIENT_NAME, CLIENT_EMAIL, SUBJECT, MESSAGE, DATE_TIME FROM contact WHERE DONE=1;')
                    for data in contectDB:
                        if mgr_api_key:
                            label = mgr.spam_catcher(
                                client_name=data[1],
                                client_email=data[2],
                                subject=data[3],
                                message=data[4],
                                dt=str(data[5])
                            )
                            EMAIL_COMPANY = "pawel@dmdbudownictwo.pl" if label == "WIADOMOŚĆ" else "informatyk@dmdbudownictwo.pl"
                        else: 
                            
                            EMAIL_COMPANY = 'informatyk@dmdbudownictwo.pl' #devs

                        # EMAIL_COMPANY = 'informatyk@dmdbudownictwo.pl' #devs
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
                    print("CHECKPOINT 60 SECONDS")
                    ################################################################
                    # Obsługa automatycznego wysyłania logów dla modelu SI
                    ################################################################
                    random_choiced_prompt_list = [
                        "Aktywowano strumień danych, Gerina melduje się! Aifo, mam dla ciebie nowe informacje. Szczegóły:\n",
                        "Strumień danych otwarty. Gerina raportuje! Aifo, oto dane, które udało mi się zebrać:\n",
                        "Gerina zgłasza zakończenie procesu. Aifo, oto raport z zadania:\n",
                        "Komunikat od Geriny: wszystkie operacje zakończone sukcesem. Aifo, przekazuję następujące dane:\n",
                        "Kanał komunikacji aktywowany. Gerina przesyła raport. Aifo, oto szczegóły:\n",
                        "Raport specjalny od Geriny. Aifo, poniżej znajdziesz istotne dane do analizy:\n"
                    ]

                    pre_prompt = random.choice(random_choiced_prompt_list)
                    tuncteLogs = get_lastAifaLog()
                    if tuncteLogs and isinstance(tuncteLogs, str):
                        preParator = f"{pre_prompt} {tuncteLogs}"
                        if not prepare_shedule.insert_to_database(
                            f"""INSERT INTO chat_task
                                    (question, `status`)
                                VALUES 
                                    (%s, %s);""",
                            (preParator, 5)
                            ): 
                            handle_error(f"Nieudana próba przekazania log do jednostki SI.\n")
                        


                    handle_error(f'{datetime.datetime.now()} - {__name__} is working...\n')
                        
                elif name == 'checkpoint_180s':
                    """ 
                        **********************************************************
                        ****************** CHECKPOINT 180 SECONDS **************** 
                        **********************************************************
                    """
                    print("CHECKPOINT 180 SECONDS")
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
                        query_update_status = f"UPDATE {table_name} SET status = %s, active_task = %s WHERE id = %s"
                        if status in [0, 1]:
                            if table_name == 'ogloszenia_otodom' or status == 0:
                                values = (6, 0, record_id)
                            else:
                                values = (7, 0, record_id)
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
                    print("CHECKPOINT 300 SECONDS")
                    ################################################################
                    # Wysyłka newslettera do aktywnych użytkowników według planu wysyłki
                    ################################################################

                    shcedule = prepare_shedule.prepare_mailing_plan(prepare_shedule.get_allPostsID(), prepare_shedule.get_sent())
                    time.sleep(1)
                    prepare_shedule.save_shedule(shcedule)
                    time.sleep(1)
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


                elif name == 'checkpoint_12h': 
                    """ 
                        **********************************************************
                        ******************   CHECKPOINT 12 HOURS  **************** 
                        **********************************************************
                    """
                    print("CHECKPOINT 12 Hours")
                    ################################################################
                    # Weryfikacja statusu ogłoszeń nieruchomości na:
                    # - otodom, allegro, lento, adresowo
                    ################################################################
                    try:
                        create_visibility_tasks()
                        print("Zadania weryfikacji widoczności ogłoszeń zostały utworzone.")
                        handle_error(f"Zadania weryfikacji widoczności ogłoszeń zostały utworzone.\n")
                        addDataLogs(f'Zadania weryfikacji widoczności ogłoszeń zostały utworzone.', 'success')
                    except Exception as e:
                        print(f"Błąd podczas tworzenia zadań weryfikacji: {e}")
                        handle_error(f"Błąd podczas tworzenia zadań weryfikacji: {e}\n")
                        addDataLogs(f'Błąd podczas tworzenia zadań weryfikacji: {e}', 'danger')

                    if sprawdz_czas(dzien_tygodnia='sobota'):
                        ################################################################
                        # Automatyczne zbieranie statystyk dla FB-GROUPS
                        ################################################################

                        created_by_bot = ['dmddomy', 'fredgraf', 'michalformatyk']

                        # Sprawdzenie, czy istnieją zadania ze statusem 7
                        pending_tasks = prepare_shedule.connect_to_database(
                            'SELECT id FROM fbgroups_stats_monitor WHERE status = 7 ORDER BY id LIMIT 1;'
                        )

                        if pending_tasks:
                            # Jeśli istnieją, zmieniamy status pierwszego na 4
                            task_id = pending_tasks[0][0]
                            prepare_shedule.insert_to_database(
                                'UPDATE fbgroups_stats_monitor SET status = 4 WHERE id = %s;', (task_id,)
                            )
                        else:
                            # Jeśli nie ma zadań statusu 7, to przygotowujemy nowe zadania
                            for bot in created_by_bot:
                                # Pobranie ID i linków grup utworzonych przez bota
                                id_group_links = prepare_shedule.connect_to_database(
                                    f'SELECT id, link FROM facebook_gropus WHERE created_by="{bot}";'
                                )

                                # Podział na paczki po maksymalnie 15 grup (ostatnia paczka może mieć mniej niż 15!)
                                for i in range(0, len(id_group_links), 15):
                                    batch = id_group_links[i:i+15]  # Ostatnia paczka może mieć <15 elementów, ale nadal działa!
                                    ready_string = '-@-'.join(f"{id}-$-{link}" for id, link in batch)

                                    # Wstawienie nowego zadania do bazy z początkowym statusem 7
                                    prepare_shedule.insert_to_database(
                                        """INSERT INTO fbgroups_stats_monitor
                                            (id_and_links_string, created_by, status)
                                        VALUES 
                                            (%s, %s, %s)""",
                                        (ready_string, bot, 7)
                                    )
                elif name == 'checkpoint_24h': 
                    """ 
                        **********************************************************
                        ******************   CHECKPOINT 24 HOURS  **************** 
                        **********************************************************
                    """
                    print("CHECKPOINT 24 Hours")
                    if sprawdz_czas(dzien_tygodnia='poniedziałek', pora_dnia='poranek'):
                        ################################################################
                        # Automatyczne validacja formularzy automatyzacji
                        ################################################################
                        print("Zaczynamy poniedziałkowe południe!")
                        prepare_shedule.insert_to_database(
                            """INSERT INTO ogloszenia_formsapitest
                                    (platform, status)
                                VALUES 
                                    (%s, %s)""",
                                ('FORMS-API-TEST', 4)
                            )
                
                # Aktualizacja czasu ostatniego wykonania dla checkpointu
                last_run_times[name] = current_time

            # 🛑 **Efektywny sposób na oszczędzenie CPU**
            time.sleep(3)  # Krótkie opóźnienie, aby nie przeciążać procesora

        # Czy jest poniedziałkowe południe?
        if sprawdz_czas(dzien_tygodnia='poniedziałek', pora_dnia='południe'):
            print("Zaczynamy poniedziałkowe południe!")

        # Czy jest poniedziałkowy poranek?
        if sprawdz_czas(dzien_tygodnia='poniedziałek', pora_dnia='poranek'):
            print("Zaczynamy tydzień!")

        # Czy jest 1. dzień miesiąca?
        if sprawdz_czas(dzien_miesiaca=1):
            print("Nowy miesiąc, nowe możliwości!")

        # Czy jest 3. tydzień miesiąca i czwartek?
        if sprawdz_czas(tydzien_miesiaca=3, dzien_tygodnia='czwartek'):
            print("Środek miesiąca i już czwartek.")

        # Czy jest grudniowy wieczór?
        if sprawdz_czas(miesiac='grudzień', pora_dnia='wieczór'):
            print("Wieczór w grudniu, czas na herbatę i koc.")

        # Czy jest noc w weekend (sobota lub niedziela)?
        if sprawdz_czas(dzien_tygodnia='sobota', pora_dnia='noc') or sprawdz_czas(dzien_tygodnia='niedziela', pora_dnia='noc'):
            print("Weekendowa noc!")

        # Czy jest wrzesień 2025 roku, rano?
        if sprawdz_czas(miesiac='wrzesień', rok=2025, pora_dnia='poranek'):
            print("Wrześniowy poranek 2025.")

        # Czy jest środa po południu?
        if sprawdz_czas(dzien_tygodnia='środa', pora_dnia='południe'):
            print("Połowa tygodnia – środa po południu.")

if __name__ == "__main__":
    main()