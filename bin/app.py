from time import time, sleep
from datetime import datetime
import prepare_shedule
import messagerCreator 
import sendEmailBySmtp
from archiveSents import archive_sents

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
                nesletterDB = prepare_shedule.connect_to_database(f'SELECT CLIENT_NAME, CLIENT_EMAIL FROM newsletter WHERE ACTIVE=1;')
                for data in nesletterDB:
                    HTML = messagerCreator.create_html_message(row[1], data[0])
                    if HTML != '':
                        sendEmailBySmtp.send_html_email(TITLE, HTML, data[1])
                        archive_sents(row[1])

        # Aktywacja konta subskrybenta
        nesletterDB = prepare_shedule.connect_to_database(f'SELECT CLIENT_NAME, CLIENT_EMAIL FROM newsletter WHERE ACTIVE=0;')
        for data in nesletterDB:
            TITLE_ACTIVE = 'Aktywacja konta'
            HTML_ACTIVE = """<!DOCTYPE html>
                                <html lang="pl">
                                <head>
                                    <meta charset="UTF-8">
                                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                    <title>Rejestracja w DMD Newsletter</title>
                                    <style>
                                        /* Dodaj stylizację, dostosowaną do Twoich potrzeb */
                                        body {
                                            font-family: 'Arial', sans-serif;
                                            line-height: 1.6;
                                        }
                                        /* Dodaj więcej stylów, jeśli to konieczne */
                                    </style>
                                </head>
                                <body>
                                    <p>
                                        Witaj, {{imie klienta}}. <br />
                                        Zostałeś zarejestrowany do newslettera DMD. 
                                        Prosimy o potwierdzenie swojej rejestracji klikając w poniższy link.
                                    </p>
                                    <a href="https://dmddomy.pl/aktywacja-newslettera" target="_blank">Potwierdź rejestrację.</a><br/>
                                    <a href="https://dmddomy.pl/usun-newslettera" target="_blank">Edytuj profil subskrybenta DMD.</a><br/>
                                    <a href="https://dmddomy.pl/usun-newslettera" target="_blank">Usuń z newslettera DMD.</a><br/>
                                    <footer>
                                        <p>© 2024 Twoja Firma. Wszelkie prawa zastrzeżone.</p>
                                    </footer>
                                </body>
                                </html>""".replace('{{imie klienta}}', data[0])
            sendEmailBySmtp.send_html_email(TITLE_ACTIVE, HTML_ACTIVE, data[1])

        print(f'{datetime.now()} - {__name__} is working...\n')
        sleep(60)


if __name__ == "__main__":
    main()