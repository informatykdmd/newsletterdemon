from datetime import datetime, timedelta
from connectAndQuery import connect_to_database, insert_to_database
def prepare_mailing_plan(posts, previous_mailings, time_interval_minutes):
    mailing_plan = []
    for post in posts:
        post_id = post['id']

        # Sprawdź, czy post został wcześniej wysłany
        if post_id not in [mailing['post_id'] for mailing in previous_mailings]:
            # Dodaj post do planu wysyłki
            mailing_plan.append({'post_id': post_id, 'send_time': datetime.now()})

    # Ustaw odstęp czasowy między wysyłkami
    for i, mailing in enumerate(mailing_plan):
        mailing['send_time'] += timedelta(minutes=i * time_interval_minutes)

    return mailing_plan
def save_shedule(shcedule):
    exiting_post = []
    get_existing_posts = connect_to_database(
        'SELECT post_id FROM schedule;')
    for row in get_existing_posts:
        exiting_post.append(row[0])
    print(exiting_post)
    for row in shcedule:
        if row["post_id"] not in exiting_post:
            formatedDate = row["send_time"].strftime("%Y-%m-%d %H:%M:%S")
            insert_to_database(
                'INSERT INTO schedule (post_id, send_time) VALUES (%s, %s)',
                (row["post_id"], formatedDate)
            )

def get_allPostsID():
    dumpDB = connect_to_database(
        'SELECT ID FROM contents;')
    export = []
    for data in dumpDB: export.append({'id': data[0]})
    return export

def get_sent():
    dumpDB = connect_to_database(
        'SELECT post_id FROM sent_newsletters;')
    export = []
    for data in dumpDB: export.append({'post_id': data[0]})
    return export

if __name__ == "__main__":
    posts = [
            {"id": 1 },
            {"id": 2 },
            {"id": 3 },
            {"id": 5 },
            {"id": 6 },
            {"id": 7 },
    ]
    previous_mailings = [
        {'post_id': 1},
        {'post_id': 2}
    ]
    time_interval_minutes = 1440
    shcedule = prepare_mailing_plan(get_allPostsID(), get_sent(), time_interval_minutes)
    save_shedule(shcedule)
