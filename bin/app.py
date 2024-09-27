from time import time, sleep
from datetime import datetime, timedelta
import prepare_shedule
import messagerCreator 
import sendEmailBySmtp
import random
from archiveSents import archive_sents
from appslib import handle_error
from fbwaitninglist import give_me_curently_tasks

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
        theme = {
            "id": dump[0],
            "user_name": dump[1],
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
            ready_prompt += f'{theme["user_name"]}\n{theme["content"]}\n\n'
            count_ready += 1

    if count_ready > 0:
        return ready_prompt
    else:
        return None

def make_fbgroups_task(data):
    {'id': 1, 'shedules_level': 0, 'post_id': 13, 'content': 'content TEXT', 'color_choice': 4, 'category': 'praca', 'section': 'career'}
    id_ogloszenia = data['id']
    kategoria_ogloszenia = data['category'] 
    sekcja_ogloszenia = data['section']
    tresc_ogloszenia = data['content']
    styl_ogloszenia = data['color_choice']
    poziom_harmonogramu = data['shedules_level']
    id_gallery = data['id_gallery']
    

    dump_key_links = prepare_shedule.connect_to_database(
            f"""SELECT link FROM facebook_gropus WHERE category = '{kategoria_ogloszenia}';""")
    linkigrup_string = '-@-'.join(link[0] for link in dump_key_links)

    fotolinkigrup_string = ""  # Dodajemy wartość domyślną
    if id_gallery is not None:
        dump_row_fotos = prepare_shedule.insert_to_database(
            f"""SELECT * FROM ZdjeciaOfert WHERE ID = %s;""", (id_gallery,)
        )[0]
        clear_row_foto = [foto for foto in dump_row_fotos[1:-1] if foto is not None]
        fotolinkigrup_string = '-@-'.join(fotolink for fotolink in clear_row_foto)
    zdjecia_string = fotolinkigrup_string

    # Pobieramy bieżący czas w formacie UNIX
    unix_time = int(time())
    # Generujemy losowe cyfry (np. 5-cyfrowy numer)
    random_digits = random.randint(100, 999)

    # Tworzymy unikalne id zadania, łącząc losowe cyfry i czas UNIX
    id_zadania = int(f"{random_digits}{unix_time}")

    status = 4
    active_task = 0

    return prepare_shedule.insert_to_database(
        f"""INSERT INTO ogloszenia_fbgroups
                (id_ogloszenia, kategoria_ogloszenia, sekcja_ogloszenia, tresc_ogloszenia, 
                styl_ogloszenia, poziom_harmonogramu, linkigrup_string, zdjecia_string, 
                id_zadania, status, active_task)
            VALUES 
                (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);""",
        (id_ogloszenia, kategoria_ogloszenia, sekcja_ogloszenia, tresc_ogloszenia, 
        styl_ogloszenia, poziom_harmonogramu, linkigrup_string, zdjecia_string, 
        id_zadania, status, active_task)
        )


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
                for data in nesletterDB:
                    hashes = data[2]
                    HTML = messagerCreator.create_html_message(row[1], data[0], hashes)
                    if HTML != '':
                        sendEmailBySmtp.send_html_email(TITLE, HTML, data[1])
                        archive_sents(row[1])

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
            
        ################################################################
        # komentowanie chata przez serwer automatów
        ################################################################

        random_choiced_prompt_list = [
                "Oto fragment rozmowy, która się toczy na naszym chacie firmowym. Włącz się do rozmowy, zwracając się do użytkowników po nicku. Odrazu pisz swoją wypowiedź!",  # Przykład wzorcowy
                "Oto wiadomość w chacie. Reaguj podekscytowanym tonem, używając nicków użytkowników. Natychmiast pisz swoją odpowiedź!",
                "Oto wiadomość w chacie. Odpowiedz w sposób neutralny, zwracając się do użytkowników po nicku. Od razu pisz swoją wypowiedź!",
                "Oto wiadomość w chacie. Reaguj w sposób powściągliwy, używając nicków użytkowników. Natychmiast pisz swoją odpowiedź!",
                "Oto wiadomość w chacie. Odpowiedz w żartobliwy sposób, zwracając się do użytkowników po nicku. Od razu pisz swoją wypowiedź!",
                "Oto wiadomość w chacie. Reaguj szyderczo, używając nicków użytkowników. Natychmiast pisz swoją odpowiedź!"
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
                sleep(300)


        handle_error(f'{datetime.now()} - {__name__} is working...\n')
        sleep(60)


if __name__ == "__main__":
    main()