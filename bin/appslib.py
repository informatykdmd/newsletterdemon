import configparser
import smtplib


def get_config(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    return config


def send_message(server, from_address, recipient, subject, body):
    message = f"Subject: {subject}\n\n{body}"
    server.sendmail(from_address, recipient, message)


def handle_error(exception):
    print(exception)

def get_database_name():
    """Zwraca nazwę bazy danych MySQL."""
    config = get_config()
    return config["database"]["name"]


def get_database_user():
    """Zwraca nazwę użytkownika do bazy danych MySQL."""
    config = get_config()
    return config["database"]["user"]


def get_database_password():
    """Zwraca hasło do bazy danych MySQL."""
    config = get_config()
    return config["database"]["password"]


def get_recipients_table():
    """Zwraca nazwę tabeli, z której są pobierane adresy e-mail odbiorców."""
    config = get_config()
    return config["database"]["recipients_table"]


def get_subject_table():
    """Zwraca nazwę tabeli, z której jest pobierany temat wiadomości."""
    config = get_config()
    return config["database"]["subject_table"]


def get_body_table():
    """Zwraca nazwę tabeli, z której jest pobierana treść wiadomości."""
    config = get_config()
    return config["database"]["body_table"]


def get_schedule_algorithm():
    """Zwraca algorytm układania planu wysyłki."""
    config = get_config()
    return config["database"]["schedule_algorithm"]


def get_send_email_function():
    """Zwraca funkcję, która wysyła wiadomości e-mail."""
    config = get_config()
    return config["database"]["send_email_function"]

def connect_to_database():
    """Łączy się z bazą danych i zwraca True"""
    return True

def load_recipients():
    """Ładuje adresy e-mail odbiorców z tabeli recipients."""
    database = connect_to_database()
    cursor = database.cursor()
    cursor.execute(f"SELECT email FROM {get_recipients_table()}")
    recipients = [row[0] for row in cursor.fetchall()]
    cursor.close()
    database.close()
    return recipients


def load_subject():
    """Ładuje temat wiadomości z tabeli subject."""
    database = connect_to_database()
    cursor = database.cursor()
    cursor.execute(f"SELECT subject FROM {get_subject_table()}")
    subject = cursor.fetchone()[0]
    cursor.close()
    database.close()
    return subject


def load_body():
    """Ładuje treść wiadomości z tabeli body."""
    database = connect_to_database()
    cursor = database.cursor()
    cursor.execute(f"SELECT body FROM {get_body_table()}")
    body = cursor.fetchone()[0]
    cursor.close()
    database.close()
    return body


def get_next_date():
    """Zwraca datę, w której zostanie wysłana następna wiadomość."""
    schedule = create_schedule()
    return schedule[0][0]

def get_schedule_table():

    return str('')


def create_schedule():
    """Tworzy plan wysyłki wiadomości e-mail."""
    database = connect_to_database()
    cursor = database.cursor()
    cursor.execute(f"SELECT date, recipient FROM {get_schedule_table()}")
    schedule = cursor.fetchall()
    cursor.close()
    database.close()
    return schedule


def send_email():
    """Wysyła wiadomość e-mail."""
    recipient = load_recipients()[0]
    subject = load_subject()
    body = load_body()
    get_send_email_function()(recipient, subject, body)


