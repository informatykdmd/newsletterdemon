from time import time, sleep
from datetime import datetime, timedelta
import prepare_shedule
import messagerCreator 
import sendEmailBySmtp
import random
import os
import json
from archiveSents import archive_sents
from appslib import handle_error
from fbwaitninglist import give_me_curently_tasks
from ExpiryMonitor import check_all_tables_for_expiry, insert_to_database, delete_row_from_database

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

def prepare_prompt(began_prompt):
    dump_key = get_messages('last')
    ready_prompt = f'{began_prompt}\n\n'
    count_ready = 0
    for dump in dump_key:
        if dump[1] != "aifa":
            try:
                user_about, user_descrition = prepare_shedule.connect_to_database(
                    f"""SELECT ADMIN_ROLE, ABOUT_ADMIN FROM admins WHERE LOGIN='{dump[1]}';""")[0]
            except IndexError:
                user_about, user_descrition = ('Szaregowy pracownik', 'Brak opisu')
        else:
            user_about, user_descrition = ('Operator Moderacji i Ekspert nowych technologii', 'Sztuczna inteligencja na usługach DMD.')
        theme = {
            "id": dump[0],
            "user_name": dump[1],
            "description": user_descrition,
            "user_about": user_about,
            "content": dump[2],
            "timestamp": dump[3],
            "status": dump[4],
        }
        if theme["user_name"] == 'aifa':
            theme["user_name"] = 'Ty'

        if theme["status"] == 2 and len(dump_key) < 2:
            continue

        if prepare_shedule.insert_to_database(
                f"UPDATE Messages SET status = %s WHERE id = %s",
                (1, theme["id"])):
            ready_prompt += f'LOGIN:{theme["user_name"]}\nRANGA: ({theme["description"]})\nINFORMACJE O UŻYTKOWNIKU: [{theme["user_about"]}] WIADOMOŚĆ\n{theme["content"]}\nZwracaj się w tonie zgodnym z rangą uzytkownika*\n\n'
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
    for _ in range(int(time())):
        ################################################################
        # Wysyłka newslettera do aktywnych użytkowników według planu wysyłki
        ################################################################

        shcedule = prepare_shedule.prepare_mailing_plan(prepare_shedule.get_allPostsID(), prepare_shedule.get_sent())
        sleep(1)
        prepare_shedule.save_shedule(shcedule)
        sleep(1)
        current_time = datetime.now()
        for row in prepare_shedule.connect_to_database(
                'SELECT * FROM schedule;'):
            if row[2] < current_time:
                TITLE = prepare_shedule.connect_to_database(f'SELECT TITLE FROM contents WHERE  ID={row[1]};')[0][0]
                nesletterDB = prepare_shedule.connect_to_database(f'SELECT CLIENT_NAME, CLIENT_EMAIL, USER_HASH FROM newsletter WHERE ACTIVE=1;')
                add_aifaLog(f'Wysłano zaplanowaną wysyłkę newslettera na dzień {row[2]} pt. {TITLE}')
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
            add_aifaLog(f'{TITLE_ACTIVE} dla {data[1]} z podanym kontaktem {data[2]}')
            
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
            add_aifaLog(f'Przekazano wiadmość ze strony firmowej w temacie: {TITLE_MESSAGE} od {data[1]}')

        ################################################################
        # Przekazywanie logów systemowych 
        # do systemu sztucznej inteligencji
        ################################################################
        lastAifaLog = get_lastAifaLog()
        if lastAifaLog is not None:
            rozmowy = [
                "Jakie masz hobby i dlaczego akurat to?",
                "Gdybyś mógł żyć w dowolnym miejscu na świecie, gdzie by to było?",
                "Co myślisz o sztucznej inteligencji i jej wpływie na naszą przyszłość?",
                "Jaki film lub serial ostatnio oglądałeś, który poleciłbyś innym?",
                "Co najbardziej cenisz w swoim zawodzie?",
                "Gdybyś mógł spotkać dowolną osobę, żyjącą lub nieżyjącą, kto by to był i dlaczego?",
                "Jaka była najdziwniejsza rzecz, którą kiedykolwiek próbowałeś lub jadłeś?",
                "Jaką supermoc chciałbyś mieć, gdybyś mógł wybrać jedną?",
                "Co sprawia, że jesteś szczęśliwy?",
                "Czy masz jakieś plany na najbliższe wakacje? Gdzie chciałbyś pojechać?",
                "Jakie jest Twoje ulubione wspomnienie z dzieciństwa?",
                "Gdybyś miał nieograniczoną ilość pieniędzy, jak zmieniłbyś swoje życie?",
                "Jaki przedmiot w szkole lub na studiach najbardziej lubiłeś?",
                "Jakie marzenie chciałbyś jeszcze zrealizować w życiu?",
                "Jakie umiejętności chciałbyś się jeszcze nauczyć?",
                "Jaki jest Twój ulubiony sposób na relaks?",
                "Co jest Twoją największą inspiracją?",
                "Czy jest coś, czego naprawdę się boisz?",
                "Jakie książki lub filmy miały największy wpływ na Twój sposób myślenia?",
                "Jakie są Twoje cele na najbliższe pięć lat?"
            ]
            temat_rozmowy = random.choice(rozmowy)
            final_prompt = f'SYSTEM INFO DISPATCH: {lastAifaLog}.\nZachowaj te informacje do mementu do puki nie zostaniesz o nie poproszona przez użytownika.*\nInformacje o logowaniach i innych procesach systemowych są tylko do twojej informacji!*** Zmień sprytnie temat rozmowy na zadając pytanie {temat_rozmowy}.'
            prepare_shedule.insert_to_database(
                f"""INSERT INTO chat_task
                        (question, status)
                    VALUES 
                        (%s, %s)""",
                (final_prompt, 4)
                )

        ################################################################
        # komentowanie chata przez serwer automatów
        ################################################################

        random_choiced_prompt_list = [
                "Oto fragment rozmowy, która się toczy na naszym chacie firmowym. Włącz się do rozmowy, zwracając się do użytkowników po nicku. Od razu pisz swoją wypowiedź!",  # Przykład wzorcowy
                "Oto fragment rozmowy, która się toczy na naszym chacie firmowym. Reaguj podekscytowanym tonem, używając nicków użytkowników. Natychmiast pisz swoją odpowiedź!",
                "Oto fragment rozmowy, która się toczy na naszym chacie firmowym. Odpowiedz w sposób neutralny, zwracając się do użytkowników po nicku. Od razu pisz swoją wypowiedź!",
                "Oto fragment rozmowy, która się toczy na naszym chacie firmowym. Reaguj w sposób powściągliwy, używając nicków użytkowników. Natychmiast pisz swoją odpowiedź!",
                "Oto fragment rozmowy, która się toczy na naszym chacie firmowym. Odpowiedz w żartobliwy sposób, zwracając się do użytkowników po nicku. Od razu pisz swoją wypowiedź!",
                "Oto fragment rozmowy, która się toczy na naszym chacie firmowym. Reaguj szyderczo, używając nicków użytkowników. Natychmiast pisz swoją odpowiedź!"
            ]

        pre_prompt = random.choice(random_choiced_prompt_list)
        final_prompt = prepare_prompt(pre_prompt)
        if final_prompt is not None:

            prepare_shedule.insert_to_database(
                f"""INSERT INTO chat_task
                        (question, status)
                    VALUES 
                        (%s, %s)""",
                (final_prompt, 4)
                )

        ################################################################
        # Obsługa automatycznej publikacji ogłoszeń na gupach FACEBOOKA
        # TWORZENIE ZADANIA DLA AUTOMATU
        ################################################################
        
        for task_data in give_me_curently_tasks():
            if make_fbgroups_task(task_data):
                handle_error(f"Przygotowano kampanię FB w sekcji {task_data.get('section', None)} dla kategorii {task_data.get('category', None)} eminowaną przez bota {task_data.get('created_by', None)} o id: {task_data.get('post_id', None)}.\n")
                sleep(5)

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

        handle_error(f'{datetime.now()} - {__name__} is working...\n')
        sleep(60)


if __name__ == "__main__":
    main()