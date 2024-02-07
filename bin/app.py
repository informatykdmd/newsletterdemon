from time import time, sleep
from datetime import datetime
import prepare_shedule
import messagerCreator 
import sendEmailBySmtp
from archiveSents import archive_sents

def main():
    for _ in range(int(time())):
        shcedule = prepare_shedule.prepare_mailing_plan(prepare_shedule.get_allPostsID(), prepare_shedule.get_sent())
        sleep(1)
        prepare_shedule.save_shedule(shcedule)
        sleep(1)
        current_time = datetime.now()
        for row in prepare_shedule.connect_to_database(
                'SELECT * FROM schedule;'):
            """
                Jeśli data jest przechowywana jako string w formacie, 
                na przykład 'YYYY-MM-DD HH:MM:SS', musisz najpierw 
                przekonwertować ten string na obiekt datetime.
            """
            print(row[2], current_time)
            print(type(row[2]), type(current_time))
            # scheduled_time = datetime.strptime(row[2], '%Y-%m-%d %H:%M:%S')
            # print(scheduled_time, current_time)
            if row[2] > current_time:
                TITLE = prepare_shedule.connect_to_database(f'SELECT TITLE FROM contents WHERE  ID={row[1]};')[0][0]
                nesletterDB = prepare_shedule.connect_to_database(f'SELECT CLIENT_NAME, CLIENT_EMAIL FROM newsletter;')
                for data in nesletterDB:
                    HTML = messagerCreator.create_html_message(row[1], data[0])
                    if HTML != '':
                        sendEmailBySmtp.send_html_email(TITLE, HTML, data[1])
                        archive_sents(row[1])
        print(f'{datetime.now()} - {__name__} is working...\n')
        sleep(3600)


if __name__ == "__main__":
    main()