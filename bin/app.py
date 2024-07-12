from time import time, sleep
from datetime import datetime
import prepare_shedule
import messagerCreator 
import sendEmailBySmtp
import random
from archiveSents import archive_sents
from appslib import handle_error

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

def main():
    for _ in range(int(time())):
        # Wysyłka newslettera do aktywnych użytkowników według planu wysyłki
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

        # Aktywacja konta subskrybenta
        nesletterDB = prepare_shedule.connect_to_database(f'SELECT ID, CLIENT_NAME, CLIENT_EMAIL, USER_HASH FROM newsletter WHERE ACTIVE=0;')
        for data in nesletterDB:
            TITLE_ACTIVE = 'Aktywacja konta'
            message = messagerCreator.HTML_ACTIVE.replace('{{imie klienta}}', data[1]).replace('{{hashes}}', data[3])
            sendEmailBySmtp.send_html_email(TITLE_ACTIVE, message, data[2])
            prepare_shedule.insert_to_database(
                f"UPDATE newsletter SET ACTIVE = %s WHERE ID = %s AND CLIENT_EMAIL = %s",
                (3, data[0], data[2])
                )
            
        # Przekazanie widomości ze strony na pawel@dmdbudownictwo.pl
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

        # komentowanie chata przez serwer automatów
        
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


        handle_error(f'{datetime.now()} - {__name__} is working...\n')
        sleep(60)


if __name__ == "__main__":
    main()