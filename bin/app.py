# Główny skrypt demona
import argparse
import configparser
import time
from config_utils import get_config, get_database_name
from smtplib import SMTP
import appslib


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="Plik konfiguracyjny")
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(args.config)

    database_name = get_database_name()
    database_config = get_config()["database"]
    db = appslib.connect_to_database(database_config["name"], database_config["user"], database_config["password"])

    daemon_name = config["general"]["daemon_name"]
    send_interval = int(config["general"]["send_interval"])
    recipients = config["general"]["recipients"]
    subjects = config["general"]["subjects"]
    bodies = config["general"]["bodies"]

    server = SMTP(config["smtp"]["server"])
    server.starttls()
    server.login(config["smtp"]["username"], config["smtp"]["password"])

    while True:
        for recipient, subject, body in zip(recipients, subjects, bodies):
            message = f"Subject: {subject}\n\n{body}"
            server.sendmail(config["smtp"]["from"], recipient, message)

        time.sleep(send_interval)


if __name__ == "__main__":
    main()