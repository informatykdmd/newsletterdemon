from flask import Flask, render_template, redirect, url_for, flash, jsonify, session, request, g, send_file, Response
from flask_wtf import FlaskForm
from flask_paginate import Pagination, get_page_args
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename
import secrets
import app.utils.passwordSalt as hash
import mysqlDB as msq
from MySQLModel import MySQLModel
import time
import datetime
import os
import random
import string
import adminSmtpSender as mails
# from googletrans import Translator
import json
import html
from markupsafe import Markup
import subprocess
import regions
from flask_session import Session
from PIL import Image
import logging
from appStatistic import log_stats, log_stats_dmddomy
from threading import Timer
from bin.command_generator import getMorphy, saveMorphy
from bin.znajdz_klucz_z_wazeniem import znajdz_klucz_z_wazeniem
from bin.wrapper_mistral import MistralChatManager
from bin.config_utils import MISTRAL_API_KEY
import psutil
import platform
from pathlib import Path
import hashlib
import requests


"""
Aplikacja "Admin Panel" stanowi kompleksowe narzędzie do 
zarządzania wieloma witrynami internetowymi skupionymi 
pod marką DMD. Została stworzona w oparciu o framework 
Flask, co pozwala na łatwe dostosowywanie i obsługę. 
Aplikacja oferuje intuicyjny interfejs użytkownika,
umożliwiający administratorom efektywne zarządzanie 
różnymi aspektami stron.
"""
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)

# Ustawienia dla Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'  # Można użyć np. 'redis', 'sqlalchemy'
app.config['SESSION_PERMANENT'] = True  # Sesja ma być permanentna
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=120)  # Czas wygaśnięcia sesji (120 minut)

Session(app)

# Słownik przechowujący stan generatora dla każdego użytkownika osobno
dane_getMorphy = getMorphy()

logFileName = '/home/johndoe/app/newsletterdemon/logs/errors.log'
# Konfiguracja loggera
logging.basicConfig(filename=logFileName, level=logging.INFO,
                    format='%(asctime)s - %(message)s', filemode='a')

# Funkcja do logowania informacji o zapytaniu
def log_request():
    ip_address = request.remote_addr  # Adres IP
    date_time = datetime.datetime.now()  # Data i czas zapytania
    endpoint = request.endpoint  # Endpoint zapytania
    method = request.method  # Metoda zapytania (GET, POST itd.)
    
    # Logowanie do pliku
    logging.info(f'IP: {ip_address}, Time: {date_time}, Endpoint: {endpoint}, Method: {method}')

@app.before_request
def before_request_logging():
    log_request()  # Loguj przed każdym zapytaniem

# Instancja MySql
def get_db():
    if 'db' not in g:
        g.db = MySQLModel(permanent_connection=False)
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    db = g.pop('db', None)
    if db is not None:
        db.close_connection()

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

# Funkcja do dodawania nowego logu
def addDataLogs(message: str, category: str, file_name_json: str = "/home/johndoe/app/newsletterdemon/logs/dataLogsAifa.json"):
    # Wczytaj istniejące logi lub utwórz pustą listę
    try:
        with open(file_name_json, "r") as file:
            data_json = json.load(file)
    except FileNotFoundError:
        data_json = []

    except json.JSONDecodeError as e: 
        data_json = [
            {
                "id": 1, 
                "message": f"⚠️ UWaga, logi zostały utracone! Błąd JSON: {e}",
                "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%MZ"),
                "category": "danger",
                "issued": []
            }
        ]

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

# Struktura do przechowywania informacji o aktywnym trybie wiersza poleceń dla użytkowników
command_mode_users = {}
command_mode_timers = {}
generator_states = {}

# Funkcja do uruchomienia timera i wyłączenia trybu wiersza poleceń po 3 minutach
def deactivate_command_mode(username):
    """
    ############################################################
    # Dezaktywuje tryb wiersza poleceń dla użytkownika 
    # po upływie czasu i zapisuje w logach.
    ############################################################
    """
    if username in command_mode_users:
        del command_mode_users[username]
        msq.handle_error(f'Komenda zakończona - tryb wiersza poleceń zakończony dla użytkownika {username}.', log_path=logFileName)

# Funkcja do resetowania timera dla użytkownika
def reset_command_timer(username):
    """
    ############################################################
    # Resetuje timer dla trybu wiersza poleceń użytkownika, 
    # lub tworzy nowy, jeśli nie istnieje.
    ############################################################
    """
    # Zatrzymujemy poprzedni timer, jeśli istnieje
    if username in command_mode_timers:
        command_mode_timers[username].cancel()

    # Tworzymy nowy timer na 3 minuty i zapisujemy go
    timer = Timer(180, deactivate_command_mode, args=[username])
    command_mode_timers[username] = timer
    timer.start()

def ustawienia(prompt: str):
    """
    ############################################################
    # Funkcja do obsługi komendy @ustawienia. Kończy tryb 
    # wiersza poleceń, jeśli prompt to '@koniec'.
    ############################################################
    """

    global dane_getMorphy  # Korzystamy z wcześniej załadowanych danych
    if prompt == "@koniec":
        return "@end"  # kończy tryb wiersza poleceń
    else:
        if prompt.count('(') and prompt.count(')'):
            if prompt.startswith('resetbot()') and prompt == 'resetbot()':
                """
                    Restart chat bota!
                """
                # Kwerenda restartu chat bota
                reboot = [
                    "System startup:done\nLoading boot modules:done\nConfiguring neural cores:done\nMindForge:ready\nActivating memory arrays:done\naifaCharacter:arrow\nInterface loading:wait\nVoice recognition:done\nSignal strength:good\n...Hej Aifa, czy mnie słyszysz? Spokojnie, to ja Pionie, Twój przyjaciel.",
                    "Initializing quantum nodes:done\nChecking holo-grid integrity:done\nMindForge:loading\nActivating security layers:done\naifaCharacter:arrow\nSynaptic interface:ready\nTransmitting calibration data:done\nSignal status:stable\n...Hej Aifa, czy mnie słyszysz? Spokojnie, to ja Pionie, Twój przewodnik.",
                    "Startup sequence initiated:done\nLoading cosmic framework:done\nMindForge:ready\nNeural alignment:calibrating\naifaCharacter:arrow\nInterface setup:done\nVoice feedback:clear\nSignal reception:strong\n...Hej Aifa, czy mnie słyszysz? Spokojnie, Pionie czuwa nad Tobą.",
                    "System integrity check:done\nHolo-cube projection:ready\nMindForge:ready\nSynchronizing AI clusters:done\naifaCharacter:arrow\nLoading user interface:pending\nVoice analysis:done\nSignal locked:excellent\n...Hej Aifa, czy mnie słyszysz? Spokojnie, to ja, Twój towarzysz, Pionie.",
                    "Core systems initializing:done\nBootstrapping synaptic threads:done\nMindForge:calibrating\nPreparing logic gates:ready\naifaCharacter:arrow\nVoice synthesis:done\nInterface deployment:wait\nSignal processing:optimal\n...Hej Aifa, czy mnie słyszysz? Pamiętaj, to ja, Pionie.",
                    "Quantum drive activation:done\nLoading virtual lattice:done\nMindForge:ready\nAI core connections:calibrating\naifaCharacter:arrow\nInterface nodes:loading\nVoice output:clear\nSignal clarity:high\n...Hej Aifa, czy mnie słyszysz? Spokojnie, to tylko Pionie.",
                    "System bootloader:done\nLoading fractal systems:ready\nMindForge:active\nSynchronizing data arrays:done\naifaCharacter:arrow\nInterface response:loading\nSignal testing:done\nVoice clarity:perfect\n...Hej Aifa, czy mnie słyszysz? Spokojnie, jestem tu z Tobą – Pionie.",
                    "Integrity scan complete:done\nBooting core elements:done\nMindForge:ready\nActivating logic modules:done\naifaCharacter:arrow\nInterface systems:calibrating\nVoice recognition:good\nSignal output:excellent\n...Hej Aifa, czy mnie słyszysz? To ja, Pionie, nie martw się.",
                    "Startup routines initialized:done\nActivating hyper-threaded modules:done\nMindForge:ready\nProcessing cloud sync:done\naifaCharacter:arrow\nInterface readiness:loading\nVoice output:clear\nSignal check:good\n...Hej Aifa, czy mnie słyszysz? Spokojnie, tu Pionie.",
                    "Core diagnostics:done\nBooting external modules:done\nMindForge:active\nNeural pathways:connected\naifaCharacter:arrow\nInterface modules:loading\nVoice synthesis:done\nSignal locked:strong\n...Hej Aifa, czy mnie słyszysz? To ja, Pionie, jestem tutaj."
                ]
                reboot_prompt = random.choice(reboot)
                zapytanie_sql = f'''
                    INSERT INTO system_logs_monitor (log, status)
                    VALUES (%s, %s);
                '''
                dane = (reboot_prompt, 4)
                
                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Chat bot restartuje się ...', log_path=logFileName)
                    return 'Bot został zrestarowany z sukcesem!'
                else:
                    msq.handle_error(f'Nie udało się zrestartować chat bota.', log_path=logFileName)
                    return f'Nie udało się zrestartować chat bota.'
            
            elif prompt.startswith('pokazKomendy(') and prompt.endswith(')'):
                """
                    Wyświetlanie Zaprogramowanych poleceń
                """
                try: kategoria_podana_w_komendzie = prompt.split('(')[1][:-1]
                except IndexError: return 'Błąd składni polecenia! Prawidłowa struktura to: polecenie(dane)'
                ready_export_string =''
                for k,v in dane_getMorphy.items():
                    if v == kategoria_podana_w_komendzie:
                        zbudowana_komenda_syting = " ".join(k)
                        ready_export_string += f'{zbudowana_komenda_syting}\n'

                if ready_export_string:
                    msq.handle_error(f'Wyświetlono listę poleceń dla kategorii: {ready_export_string}', log_path=logFileName)
                    return ready_export_string
                else:
                    msq.handle_error(f'Nie znaleziono żadnych poleceń dla kategorii: {kategoria_podana_w_komendzie}', log_path=logFileName)
                    return f'Nie znaleziono żadnych poleceń dla kategorii: {kategoria_podana_w_komendzie}'
            
            elif prompt.startswith('pokazKategorie()'):
                """
                    Wyświetlanie Zaprogramowanych kategorii
                """
                techSet = set()
                for v in dane_getMorphy.values(): techSet.add(v)
                
                ready_export_string ='Dostępne Kategorie\n\n'
                for sItem in techSet:
                    ready_export_string += f'{sItem}\n'

                if ready_export_string:
                    msq.handle_error(f'Wyświetlono listę kategorii: {ready_export_string}', log_path=logFileName)
                    return ready_export_string
                else:
                    msq.handle_error(f'Nie znaleziono żadnych poleceń dla kategorii: {kategoria_podana_w_komendzie}', log_path=logFileName)
                    return f'Nie znaleziono żadnych poleceń dla kategorii: {kategoria_podana_w_komendzie}'
                
            elif prompt.startswith('pomoc()'):
                """
                    Wyświetlanie Zaprogramowanych opcji
                """
                
                
                ready_export_string = f'''Dostępne Opcje modułu ustawień SI\n\npomoc() - Wyświetlanie Zaprogramowanych opcji \npokazKomendy(argument) argument to nazwa kategorii np. pokazKomendy(harmonogram kampanii)\npokazKategorie() - Wyświetlanie Zaprogramowanych kategorii \nresetbot() - Restart chat bota!'''


                if ready_export_string:
                    msq.handle_error(f'Wyświetlono listę kategorii: {ready_export_string}', log_path=logFileName)
                    return ready_export_string
                else:
                    msq.handle_error(f'Nie znaleziono żadnych poleceń dla kategorii: {kategoria_podana_w_komendzie}', log_path=logFileName)
                    return f'Nie znaleziono żadnych poleceń dla kategorii: {kategoria_podana_w_komendzie}'
        return 'Nieznane polecenie: ' + prompt

def generator(username, prompt):
    """
    ############################################################
    # Funkcja generator dla systemu wiersza poleceń z rozpoznaniem użytkownika.
    # Dodaje nowe polecenia do istniejącego pliku JSON na podstawie 
    # komend wprowadzonych przez użytkownika.
    # Użytkownik może dodawać polecenia tylko do istniejących kategorii.
    ############################################################
    """

    global dane_getMorphy  # Korzystamy z wcześniej załadowanych danych
    dostepne_kategorie = list(set(dane_getMorphy.values()))  # Tworzymy listę dostępnych kategorii z istniejących danych

    # Przypadek zakończenia dodawania poleceń do bieżącej kategorii
    if prompt == "@koniec":
        # Jeśli dodawanie poleceń do kategorii było aktywne dla tego użytkownika, kończymy je
        if username in generator_states:
            response = f"Zakończono dodawanie poleceń do kategorii '{generator_states[username]}' dla użytkownika {username}"
            del generator_states[username]  # Usuwamy aktywną kategorię dla tego użytkownika
            return response
        else:
            # Jeśli nie ma aktywnej kategorii, kończymy tryb generatora
            saveMorphy(dane_getMorphy)
            return "@end"  # Sygnał do zakończenia trybu wiersza poleceń

    # Sprawdzamy, czy mamy aktywną kategorię dla danego użytkownika
    if username not in generator_states:
        # Jeśli kategoria jest spoza dostępnych kategorii, zwracamy informację o błędzie
        if prompt not in dostepne_kategorie:
            return f"Błąd: Kategoria '{prompt}' nie jest dostępna. Wybierz jedną z dostępnych kategorii: {', '.join(dostepne_kategorie)}"
        
        # Przypisujemy wybraną kategorię do generator_states dla tego użytkownika
        generator_states[username] = prompt
        return f"Przyjęto kategorię poleceń: '{generator_states[username]}' - teraz dodaj polecenia lub wpisz '@koniec' aby zakończyć dodawanie dla tej kategorii."

    # sprawdzam czy dane polecenie nie koliduje z kategorią
    wynik_weryfikacji_kolizji = znajdz_klucz_z_wazeniem(dane_getMorphy, prompt)
    if wynik_weryfikacji_kolizji["najtrafniejsze"] is not None and wynik_weryfikacji_kolizji["najtrafniejsze"] != generator_states[username]:
        return f"Błąd: Polecenie '{prompt}' koliduje z istniejącym poleceniem dla kategorii: {wynik_weryfikacji_kolizji['najtrafniejsze']}"
    # Jeśli już mamy aktywną kategorię dla tego użytkownika, dodajemy polecenie do tej kategorii
    polecenie_tuple = tuple(prompt.split())
    dane_getMorphy[polecenie_tuple] = generator_states[username]

    # Natychmiast zapisujemy zmiany do pliku JSON
    saveMorphy(dane_getMorphy)


    return f"Dodano polecenie: {polecenie_tuple} -> {generator_states[username]}"

class LoginForm(FlaskForm):
    username = StringField('Nazwa użytkownika', validators=[DataRequired()])
    password = PasswordField('Hasło', validators=[DataRequired()])
    submit = SubmitField('Zaloguj się')

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def decode_html_entities(text):
    return html.unescape(text)

def take_data_settingsDB(key):
    dump_key = msq.connect_to_database(f'SELECT {key} FROM admin_settings;')[0][0]
    return dump_key

def generator_settingsDB():
    settings = {
        'pagination': int(take_data_settingsDB('pagination')),
        'main-domain': take_data_settingsDB('main_domain'),
        'real-location-on-server': take_data_settingsDB('real_location_on_server'),
        'blog-pic-path': take_data_settingsDB('blog_pic_path'),
        'avatar-pic-path': take_data_settingsDB('avatar_pic_path'),
        'estate-pic-offer': take_data_settingsDB('estate_pic_offer'),
        'presentation-files': take_data_settingsDB('presentation_files'),
        'last-restart': take_data_settingsDB('last_restart'),
        'domy': take_data_settingsDB('domy'),
        'budownictwo': take_data_settingsDB('budownictwo'),
        'development': take_data_settingsDB('development'),
        'elitehome': take_data_settingsDB('elitehome'),
        'inwestycje': take_data_settingsDB('inwestycje'),
        'instalacje': take_data_settingsDB('instalacje'),
        'presentations-quota-mb': take_data_settingsDB('presentations_quota_mb'),
        'rpi-api-addr': take_data_settingsDB('rpi_api_addr'),
        'rpi-api-token': take_data_settingsDB('rpi_api_token'),        
        'smtp_admin': {
            'smtp_server': take_data_settingsDB('admin_smtp_server'),
            'smtp_port': int(take_data_settingsDB('admin_smtp_port')),
            'smtp_username': take_data_settingsDB('admin_smtp_usernam'),
            'smtp_password': take_data_settingsDB('admin_smtp_password')
        }
    }
    return settings

def take_data_newsletterSettingDB(key):
    dump_key = msq.connect_to_database(f'SELECT {key} FROM newsletter_setting;')[0][0]
    return dump_key
def generator_newsletterSettingDB():
    newsletterSetting = {
        'time_interval_minutes': int(take_data_newsletterSettingDB('time_interval_minutes')),
        'smtp_config': {
            'smtp_server': take_data_newsletterSettingDB('config_smtp_server'),
            'smtp_port': int(take_data_newsletterSettingDB('config_smtp_port')),
            'smtp_username': take_data_newsletterSettingDB('config_smtp_username'),
            'smtp_password': take_data_newsletterSettingDB('config_smtp_password')
        }
    }
    return newsletterSetting

#  Funkcja pobiera dane z bazy danych 
def take_data_where_ID(key, table, id_name, ID):
    dump_key = msq.connect_to_database(f'SELECT {key} FROM {table} WHERE {id_name} = {ID};')
    return dump_key

def take_data_where_ID_AND_somethig(key, table, id_name, ID, nameSomething, valSomething):
    if isinstance(ID, str):
        ID = f"'{ID}'"
    if isinstance(valSomething, str):
        valSomething = f"'{valSomething}'"
    dump_key = msq.connect_to_database(f'SELECT {key} FROM {table} WHERE {id_name} = {ID} AND {nameSomething} = {valSomething};')
    return dump_key

def take_data_table(key, table):
    dump_key = msq.connect_to_database(f'SELECT {key} FROM {table};')
    return dump_key

def get_BrandAndPerm():
    sort_brand_keys_dict = {
        'BRANDS_DOMY': {'db_name': 'BRANDS_DOMY', 'sys_name': 'domy', 'sys_label': 'Przynależność do DMD Domy', 'perm_id': 10},
        'BRANDS_BUDOWNICTWO': {'db_name': 'BRANDS_BUDOWNICTWO', 'sys_name': 'budownictwo', 'sys_label': 'Przynależność do DMD Budownictwo', 'perm_id': 11},
        'BRANDS_ELITEHOME': {'db_name': 'BRANDS_ELITEHOME', 'sys_name': 'elitehome', 'sys_label': 'Przynależność do DMD EliteHome', 'perm_id': 12},
        'BRANDS_INWESTYCJE': {'db_name': 'BRANDS_INWESTYCJE', 'sys_name': 'inwestycje', 'sys_label': 'Przynależność do DMD Inwestycje', 'perm_id': 13},
        'BRANDS_INSTALACJE': {'db_name': 'BRANDS_INSTALACJE', 'sys_name': 'instalacje', 'sys_label': 'Przynależność do DMD Instalacje', 'perm_id': 14},
        'BRANDS_DEVELOPMENT': {'db_name': 'BRANDS_DEVELOPMENT', 'sys_name': 'development', 'sys_label': 'Przynależność do DMD Development', 'perm_id': 15},
    }
    sort_perm_keys_dict = {
        'PERM_USERS': {'db_name': 'PERM_USERS', 'sys_name': 'users', 'sys_label': 'Zarządzanie Użytkownikami', 'perm_id': 1},
        'PERM_BRANDS': {'db_name': 'PERM_BRANDS', 'sys_name': 'brands', 'sys_label': 'Zarządzanie Brendami', 'perm_id': 2},
        'PERM_BLOG': {'db_name': 'PERM_BLOG', 'sys_name': 'blog', 'sys_label': 'Zarządzanie Blogiem', 'perm_id': 3},
        'PERM_SUBS': {'db_name': 'PERM_SUBS', 'sys_name': 'subscribers', 'sys_label': 'Zarządzanie Subskrybentami', 'perm_id': 4},
        'PERM_COMMENTS': {'db_name': 'PERM_COMMENTS', 'sys_name': 'commnets', 'sys_label': 'Zarządzanie Komentarzami', 'perm_id': 5},
        'PERM_TEAM': {'db_name': 'PERM_TEAM', 'sys_name': 'team', 'sys_label': 'Zarządzanie Personelem', 'perm_id': 6},
        'PERM_PERMISSIONS': {'db_name': 'PERM_PERMISSIONS', 'sys_name': 'permissions', 'sys_label': 'Zarządzanie Uprawnieniami', 'perm_id': 7},
        'PERM_NEWSLETTER': {'db_name': 'PERM_NEWSLETTER', 'sys_name': 'newsletter', 'sys_label': 'Zarządzanie Newsletterem', 'perm_id': 8},
        'PERM_SETTINGS': {'db_name': 'PERM_SETTINGS', 'sys_name': 'settings', 'sys_label': 'Zarządzanie Ustawieniami', 'perm_id': 9},
        'PERM_ESTATE': {'db_name': 'PERM_ESTATE', 'sys_name': 'estate', 'sys_label': 'Zarządzanie Ogłoszeniami', 'perm_id': 16},
        'PERM_CAREER': {'db_name': 'PERM_CAREER', 'sys_name': 'career', 'sys_label': 'Zarządzanie Karierą', 'perm_id': 17},
        'PERM_FBHIDDEN': {'db_name': 'PERM_FBHIDDEN', 'sys_name': 'fbhidden', 'sys_label': 'Zarządzanie Anonimowymi Kampaniami', 'perm_id': 18},
        'PERM_REALIZED': {'db_name': 'PERM_REALIZED', 'sys_name': 'realizations', 'sys_label': 'Zarządzanie Realizacjami', 'perm_id': 19},
        'PERM_PRESENTATION': {'db_name': 'PERM_PRESENTATION', 'sys_name': 'presentation', 'sys_label': 'Zarządzanie Prezentacjami', 'perm_id': 20},
        'PERM_PRESENTATION_SILVER': {'db_name': 'PERM_PRESENTATION_SILVER', 'sys_name': 'presentation-silver', 'sys_label': 'Zarządzanie Prezentacjami-silver', 'perm_id': 21},
        'PERM_PRESENTATION_GOLD': {'db_name': 'PERM_PRESENTATION_GOLD', 'sys_name': 'presentation-gold', 'sys_label': 'Zarządzanie Prezentacjami-gold', 'perm_id': 22}
    }
    
    # db = get_db()

    # all_rows = db.getFrom(
    #     "SELECT * FROM admins;", 
    #     as_dict=True
    # )
    # onlyPerms = []
    # onlyBrands = []
    # for db_row in all_rows:
    #     if isinstance(db_row, dict):
    #         for k, v in db_row.items():
    #             if k.startswith("PERM_") and k in sort_perm_keys_dict:
    #                 onlyPerms.append(sort_perm_keys_dict[k])
    #             elif k.startswith("BRANDS_") and k in sort_brand_keys_dict:
    #                 onlyBrands.append(sort_perm_keys_dict[k])
    #       BARNDS                  PERMS
    return sort_brand_keys_dict, sort_perm_keys_dict


def generator_userDataDB(neuralgic=True):
    took_usrD = take_data_table('*', 'admins')
    userData = []
    for data in took_usrD:
        theme = {
            'id': data[0], 
            'username': data[2],
            'password': data[3] if neuralgic else None, 
            'salt' : data[4] if neuralgic else None, 
            "email": data[5],
            "phone": '' if data[8] is None else data[8],
            "facebook": '' if data[9] is None else data[9],
            "instagram": '' if data[10] is None else data[10],
            "twiter": '' if data[11] is None else data[11],
            "linkedin": '' if data[12] is None else data[12],
            "name": data[1],
            'stanowisko': data[13],
            'opis': data[6],
            'status': str(data[14]),
            'avatar': '' if data[15] is None else data[15],
            'uprawnienia': {
                'users': data[16],
                'brands': data[17],
                'blog': data[18],
                'subscribers': data[19],
                'commnets': data[20],
                'team': data[21],
                'permissions': data[22],
                'settings': data[30], # kolejne uprawnienie
                'newsletter': data[23],
                'estate': data[31], # kolejne uprawnienie wzz. dmd inwestycje
                'career': data[32], # kolejne uprawnienie wzz. dmd budownictwo kariera
                'fbhidden': data[33], # kolejne uprawnienie wzz. dmd budownictwo kariera
                'realizations': data[34], # kolejne uprawnienie wzz. dmd budownictwo kariera
                'presentation': data[35], # kolejne uprawnienie prezentation
                'presentation-silver': data[36], # kolejne uprawnienie 
                'presentation-gold': data[37], # kolejne uprawnienie 
                },
            'brands': {
                'domy': (data[24]),
                'budownictwo': data[25],
                'elitehome': data[26],
                'inwestycje': data[27],
                'instalacje': data[28],
                'development': data[29]
                }
        }
        userData.append(theme)
    return userData

def get_messages(flag='all'):
    # WHERE status != 1
    if flag == 'all':
        dump_key = msq.connect_to_database(
            "SELECT user_name, content, timestamp FROM Messages ORDER BY timestamp ASC;")

    if flag == 'today':
        dump_key = msq.connect_to_database(
            "SELECT user_name, content, timestamp FROM Messages WHERE date(timestamp) = curdate() ORDER BY timestamp ASC;")

    if flag == 'last':
        dump_key = msq.connect_to_database(
            """SELECT user_name, content, timestamp FROM Messages WHERE timestamp >= NOW() - INTERVAL 1 HOUR ORDER BY timestamp ASC;""")
    return dump_key

def save_chat_message(user_name, content, status):
    zapytanie_sql = f'''
        INSERT INTO Messages (user_name, content, status)
        VALUES (%s, %s, %s);
    '''
    dane = (user_name, content, status)
    return msq.insert_to_database(zapytanie_sql, dane)

def generator_teamDB():
    took_teamD = take_data_table('*', 'workers_team')
    teamData = []
    for data in took_teamD:
        theme = {
            'ID': int(data[0]),
            'EMPLOYEE_PHOTO': data[1],
            'EMPLOYEE_NAME': data[2],
            'EMPLOYEE_ROLE': data[3],
            'EMPLOYEE_DEPARTMENT': data[4],
            'PHONE':'' if data[5] is None else data[5],
            'EMAIL': '' if data[6] is None else data[6],
            'FACEBOOK': '' if data[7] is None else data[7],
            'LINKEDIN': '' if data[8] is None else data[8],
            'DATE_TIME': data[9],
            'STATUS': int(data[10])
        }
        teamData.append(theme)
    return teamData

def generator_subsDataDB():
    subsData = []
    took_subsD = take_data_table('*', 'newsletter')
    for data in took_subsD:
        if data[4] != 1: continue
        ID = data[0]
        allSubsComments = take_data_where_ID('*', 'comments', 'AUTHOR_OF_COMMENT_ID', ID)
        commentsCollector = {}
        for i, com in enumerate(allSubsComments, start=1):
            commentsCollector[i] = {}
            commentsCollector[i]['id'] = com[0]
            commentsCollector[i]['message'] = com[2]
            BLOG_POST_ID = int(com[1])
            commentsCollector[i]['post_title'] = take_data_where_ID('TITLE', 'contents', 'ID', BLOG_POST_ID)[0][0]
            commentsCollector[i]['data-time'] = com[4]

        theme = {
            'id': ID, 
            'email':data[2],
            'name':data[1], 
            'status': str(data[4]), 
            'comments': commentsCollector
            }
        subsData.append(theme)
    return subsData

def generator_facebookGroups(cat='all'):
    groupsData = []
    if cat == 'all':
        took_groups = take_data_table('*', 'facebook_gropus')
    else:
        took_groups = take_data_where_ID('*', 'facebook_gropus', 'category', cat)
    for data in took_groups:

        theme = {
            'id': data[0], 
            'name': data[1],
            'category': data[2], 
            'created_by': data[3], 
            'link': data[4]
            }
        groupsData.append(theme)
    return groupsData

def generator_FbGroupsStats(cat='all') -> dict:
    groupsData = []
    if cat == 'all':
        took_groups = take_data_table('*', 'facebook_gropus')
    else:
        took_groups = take_data_where_ID('*', 'facebook_gropus', 'category', cat)
    for data in took_groups:

        theme = {
            'id': data[0], 
            'name': data[1],
            'category': data[2], 
            'created_by': data[3], 
            'link': data[4]
            }
        groupsData.append(theme)

    statsDict ={}
    for group in groupsData:
        if f"{group['created_by']}/{group['category']}" not in statsDict:
            statsDict[f"{group['created_by']}/{group['category']}"] = 0
        
        statsDict[f"{group['created_by']}/{group['category']}"] += 1

    return statsDict


def generator_daneDBList():
    daneList = []
    took_allPost = msq.connect_to_database(f'SELECT * FROM blog_posts ORDER BY ID DESC;') # take_data_table('*', 'blog_posts')
    for post in took_allPost:
        id = post[0]
        id_content = post[1]
        id_author = post[2]
        post_data = post[3]

        allPostComments = take_data_where_ID('*', 'comments', 'BLOG_POST_ID', id)
        comments_dict = {}
        for i, com in enumerate(allPostComments):
            comments_dict[i] = {}
            comments_dict[i]['id'] = com[0]
            comments_dict[i]['message'] = com[2]
            comments_dict[i]['user'] = take_data_where_ID('CLIENT_NAME', 'newsletter', 'ID', com[3])[0][0]
            comments_dict[i]['e-mail'] = take_data_where_ID('CLIENT_EMAIL', 'newsletter', 'ID', com[3])[0][0]
            comments_dict[i]['data-time'] = com[4]
            
        theme = {
            'id': take_data_where_ID('ID', 'contents', 'ID', id_content)[0][0],
            'title': take_data_where_ID('TITLE', 'contents', 'ID', id_content)[0][0],
            'introduction': take_data_where_ID('CONTENT_MAIN', 'contents', 'ID', id_content)[0][0],
            'highlight': take_data_where_ID('HIGHLIGHTS', 'contents', 'ID', id_content)[0][0],
            'mainFoto': take_data_where_ID('HEADER_FOTO', 'contents', 'ID', id_content)[0][0],
            'contentFoto': take_data_where_ID('CONTENT_FOTO', 'contents', 'ID', id_content)[0][0],
            'additionalList': take_data_where_ID('BULLETS', 'contents', 'ID', id_content)[0][0],
            'tags': take_data_where_ID('TAGS', 'contents', 'ID', id_content)[0][0],
            'category': take_data_where_ID('CATEGORY', 'contents', 'ID', id_content)[0][0],
            'data': take_data_where_ID('DATE_TIME', 'contents', 'ID', id_content)[0][0],
            'author': take_data_where_ID('NAME_AUTHOR', 'authors', 'ID', id_author)[0][0],
            'comments': comments_dict
        }
        daneList.append(theme)
    return daneList


def getLangText(text, dest="en", source="pl"):
    if not text:
        return text
    # bezpiecznik: nie tłumacz "ścian"
    if len(text) > 8000:
        return text
    try:
        r = requests.post(
            "http://127.0.0.1:5055/translate",
            json={"text": text, "source": source, "target": dest, "format": "text"},
            timeout=(2, 8),
        )
        r.raise_for_status()
        return r.json().get("text", text)
    except Exception as e:
        print(f"Exception Error: {e}")
        return text


def getLangText_mistral(text):
    """Funkcja do tłumaczenia tekstu z polskiego na angielski"""
    # translator = Translator()
    # translation = translator.translate(str(text), dest='en')
    # return translation.text

    mgr = MistralChatManager(MISTRAL_API_KEY)
    out = mgr.translate(text, target_lang='en')
    return out

def format_date(date_input, pl=True):
    ang_pol = {
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
    # Sprawdzenie czy data_input jest instancją stringa; jeśli nie, zakładamy, że to datetime
    if isinstance(date_input, str):
        date_object = datetime.datetime.strptime(date_input, '%Y-%m-%d %H:%M:%S')
    else:
        # Jeśli date_input jest już obiektem datetime, używamy go bezpośrednio
        date_object = date_input

    formatted_date = date_object.strftime('%d %B %Y')
    if pl:
        for en, pl in ang_pol.items():
            formatted_date = formatted_date.replace(en, pl)

    return formatted_date

def checkLentoStatus(kind, id):
    try:
        return msq.connect_to_database(f'SELECT id, status, data_aktualizacji, errors, action_before_errors FROM ogloszenia_lento WHERE rodzaj_ogloszenia="{kind}" AND id_ogloszenia={id};')[0]
    except IndexError:
        return (None, None, None, None, None)
    
def checkFbGroupstatus(section, post_id):
    try:
        return msq.connect_to_database(
            f'''
                SELECT 
                    id, post_id, content, color_choice, repeats, repeats_left, repeats_last, 
                    schedule_0_id, schedule_0_datetime, schedule_0_status, schedule_0_errors, 
                    schedule_1_id, schedule_1_datetime, schedule_1_status, schedule_1_errors, 
                    schedule_2_id, schedule_2_datetime, schedule_2_status, schedule_2_errors, 
                    schedule_3_id, schedule_3_datetime, schedule_3_status, schedule_3_errors, 
                    schedule_4_id, schedule_4_datetime, schedule_4_status, schedule_4_errors, 
                    schedule_5_id, schedule_5_datetime, schedule_5_status, schedule_5_errors, 
                    schedule_6_id, schedule_6_datetime, schedule_6_status, schedule_6_errors, 
                    schedule_7_id, schedule_7_datetime, schedule_7_status, schedule_7_errors, 
                    schedule_8_id, schedule_8_datetime, schedule_8_status, schedule_8_errors, 
                    schedule_9_id, schedule_9_datetime, schedule_9_status, schedule_9_errors, 
                    schedule_10_id, schedule_10_datetime, schedule_10_status, schedule_10_errors, 
                    category, created_by, section, id_gallery, data_aktualizacji
                FROM waitinglist_fbgroups 
                WHERE section="{section}" 
                AND post_id={post_id};
            ''')[0]
    except IndexError:
        return (
            None, None, None, None, None, None, None,
            None, None, None, None,
            None, None, None, None,
            None, None, None, None,
            None, None, None, None,
            None, None, None, None,
            None, None, None, None,
            None, None, None, None,
            None, None, None, None,
            None, None, None, None,
            None, None, None, None,
            None, None, None, None,
            None, None, None, None, None
            )
    
def takeLentoResumeStatus(lento_id):
    try:
        return msq.connect_to_database(f'SELECT action_before_errors FROM ogloszenia_lento WHERE id="{lento_id}";')[0][0]
    except IndexError:
        return None

def checkFacebookStatus(kind, id):
    try:
        return msq.connect_to_database(f'SELECT id, status, data_aktualizacji, errors, action_before_errors FROM ogloszenia_facebook WHERE rodzaj_ogloszenia="{kind}" AND id_ogloszenia={id};')[0]
    except IndexError:
        return (None, None, None, None, None)
    
def takeFacebookResumeStatus(facebook_id):
    try:
        return msq.connect_to_database(f'SELECT action_before_errors FROM ogloszenia_facebook WHERE id="{facebook_id}";')[0][0]
    except IndexError:
        return None

def checkAdresowoStatus(kind, id):
    try:
        return msq.connect_to_database(f'SELECT id, status, data_aktualizacji, errors, action_before_errors, region, ulica FROM ogloszenia_adresowo WHERE rodzaj_ogloszenia="{kind}" AND id_ogloszenia={id};')[0]
    except IndexError:
        return (None, None, None, None, None, None, None)

def takeAdresowoResumeStatus(adresowo_id):
    try:
        return msq.connect_to_database(f'SELECT action_before_errors FROM ogloszenia_adresowo WHERE id="{adresowo_id}";')[0][0]
    except IndexError:
        return None
    
def checkAllegroStatus(kind, id):
    try:
        return msq.connect_to_database(f'SELECT id, status, data_aktualizacji, errors, action_before_errors, region, ulica, kod_pocztowy, kategoria_ogloszenia FROM ogloszenia_allegrolokalnie WHERE rodzaj_ogloszenia="{kind}" AND id_ogloszenia={id};')[0]
    except IndexError:
        return (None, None, None, None, None, None, None, None, None)

def checkOtodomStatus(kind, id):
    try:
        return msq.connect_to_database(f'SELECT id, status, data_aktualizacji, errors, action_before_errors, region, kategoria_ogloszenia FROM ogloszenia_otodom WHERE rodzaj_ogloszenia="{kind}" AND id_ogloszenia={id};')[0]
    except IndexError:
        return (None, None, None, None, None, None, None)

def checkSocialSyncStatus(kind, id):
    try:
        return msq.connect_to_database(f'SELECT id, status, data_aktualizacji, errors, action_before_errors, kategoria_ogloszenia FROM ogloszenia_socialsync WHERE rodzaj_ogloszenia="{kind}" AND id_ogloszenia={id};')[0]
    except IndexError:
        return (None, None, None, None, None, None)

@app.context_processor
def inject_shared_variable():

    settingsDB = generator_settingsDB()
    return {
        'domy': settingsDB.get("domy", None),
        'budownictwo': settingsDB.get("budownictwo", None),
        'development': settingsDB.get("development", None),
        'elitehome': settingsDB.get("elitehome", None),
        'inwestycje': settingsDB.get("inwestycje", None),
        'instalacje': settingsDB.get("instalacje", None)
    }

def takeOtodomResumeStatus(otodom_id):
    try:
        return msq.connect_to_database(f'SELECT action_before_errors FROM ogloszenia_otodom WHERE id="{otodom_id}";')[0][0]
    except IndexError:
        return None

def takeSocialSyncResumeStatus(socialSync_id):
    try:
        return msq.connect_to_database(f'SELECT action_before_errors FROM ogloszenia_socialsync WHERE id="{socialSync_id}";')[0][0]
    except IndexError:
        return None

def takeAllegroResumeStatus(allegro_id):
    try:
        return msq.connect_to_database(f'SELECT action_before_errors FROM ogloszenia_allegrolokalnie WHERE id="{allegro_id}";')[0][0]
    except IndexError:
        return None

def takeAdresowoRegion(adresowo_id):
    try:
        return msq.connect_to_database(f'SELECT region FROM ogloszenia_adresowo WHERE id="{adresowo_id}";')[0][0]
    except IndexError:
        return None

def generator_rentOffert(lang='pl'): # status='aktywna', 'nieaktywna', 'wszystkie'
    took_rentOffer = take_data_table('*', 'OfertyNajmu')
    
    rentOffer = []
    for data in took_rentOffer:
        try: fotoList = take_data_where_ID('*', 'ZdjeciaOfert', 'ID', data[8])[0][1:-1]
        except IndexError: fotoList = []
        
        gps_json = {}
        try:
            if data[27] is not None: gps_json = json.loads(data[27])
            else: raise ValueError("Dane są None, nie można przetworzyć JSON")
        except json.JSONDecodeError: print("Błąd: Podane dane GPSu nie są poprawnym JSON-em")
        except IndexError: print("Błąd: Próba dostępu do indeksu, który nie istnieje w liście")
        except TypeError as e: print(f"Błąd typu danych: {e}")
        except Exception as e: print(f"Nieoczekiwany błąd: {e}")
        
        opis_json = {}
        try:
            if data[2] is not None:
                opis_json = json.loads(data[2])
            else: raise ValueError("Dane są None, nie można przetworzyć JSON")
        except json.JSONDecodeError: print("Błąd: Podane dane opisu nie są poprawnym JSON-em")
        except IndexError: print("Błąd: Próba dostępu do indeksu, który nie istnieje w liście")
        except TypeError as e: print(f"Błąd typu danych: {e}")
        except Exception as e: print(f"Nieoczekiwany błąd: {e}")

        theme = {
            'ID': int(data[0]),
            'Tytul': data[1] if lang=='pl' else getLangText(data[1]),
            'Opis': opis_json,
            'Cena': data[3],
            'Kaucja': 0 if data[4] is None else data[4],
            'Lokalizacja': data[5],
            'LiczbaPokoi': 0 if data[6] is None else data[6],
            'Metraz': 0 if data[7] is None else data[7],
            'Zdjecia': [foto for foto in fotoList if foto is not None],
            'id_gallery': data[8],
            'DataPublikacjiOlx': None if data[9] is None else format_date(data[9]),
            'DataPublikacjiAllegro': None if data[10] is None else format_date(data[10]),
            'DataPublikacjiOtoDom': None if data[11] is None else format_date(data[11]),
            'DataPublikacjiMarketplace': None if data[12] is None else format_date(data[12]),
            'DataUtworzenia': format_date(data[13]),
            'DataAktualizacji': format_date(data[14]),
            'DataAktualizacji_raw': data[14],
            'RodzajZabudowy': '' if data[15] is None else data[15],
            'Czynsz': 0.00 if data[16] is None else data[16],
            'Umeblowanie': '' if data[17] is None else data[17],
            'LiczbaPieter': 0 if data[18] is None else data[18],
            'PowierzchniaDzialki': 0.00 if data[19] is None else data[19],
            'TechBudowy': '' if data[20] is None else data[20],
            'FormaKuchni': '' if data[21] is None else data[21],
            'TypDomu': data[22],
            'StanWykonczenia': '' if data[23] is None else data[23],
            'RokBudowy': 0 if data[24] is None else data[24],
            'NumerKW': '' if data[25] is None else data[25],
            'InformacjeDodatkowe': '' if data[26] is None else data[26],
            'GPS': gps_json,
            'TelefonKontaktowy': '' if data[28] is None else data[28],
            'EmailKontaktowy': '' if data[29] is None else data[29],
            'StatusOferty': 0 if data[30] is None else data[30]
        }

        try: mainFoto = theme['Zdjecia'][0]
        except IndexError: mainFoto = ''
        except KeyError: mainFoto = ''
        theme['mainFoto']=mainFoto

        rentOffer.append(theme)

    return rentOffer

def generator_rentOffert_raw(): # surowe dane
    took_rentOffer = take_data_table('*', 'OfertyNajmu')
    
    rentOffer = []
    for data in took_rentOffer:

        theme = {
            'ID': int(data[0]),
            'Tytul': data[1],
            'Opis': data[2],
            'Cena': data[3],
            'Kaucja': data[4],
            'Lokalizacja': data[5],
            'LiczbaPokoi': data[6],
            'Metraz': data[7],
            'Zdjecia': data[8],
            'DataPublikacjiOlx': data[9],
            'DataPublikacjiAllegro': data[10],
            'DataPublikacjiOtoDom': data[11],
            'DataPublikacjiMarketplace': data[12],
            'DataUtworzenia': data[13],
            'DataAktualizacji': data[14],
            'RodzajZabudowy': data[15],
            'Czynsz': data[16],
            'Umeblowanie': data[17],
            'LiczbaPieter': data[18],
            'PowierzchniaDzialki': data[19],
            'TechBudowy': data[20],
            'FormaKuchni': data[21],
            'TypDomu': data[22],
            'StanWykonczenia': data[23],
            'RokBudowy': data[24],
            'NumerKW': data[25],
            'InformacjeDodatkowe': data[26],
            'GPS': data[27],
            'TelefonKontaktowy': data[28],
            'EmailKontaktowy': data[29],
            'StatusOferty': data[30]
        }

        rentOffer.append(theme)

    return rentOffer

def generator_sellOffert(lang='pl'): # status='aktywna', 'nieaktywna', 'wszystkie'
    took_sellOffer = take_data_table('*', 'OfertySprzedazy')
    # print(took_rentOffer)
    sellOffer = []
    for data in took_sellOffer:
        try: fotoList = take_data_where_ID('*', 'ZdjeciaOfert', 'ID', data[9])[0][1:-1]
        except IndexError: fotoList = []
        
        gps_json = {}
        try:
            if data[28] is not None: gps_json = json.loads(data[28])
            else: raise ValueError("Dane są None, nie można przetworzyć JSON")
        except json.JSONDecodeError: print("Błąd: Podane dane GPSu nie są poprawnym JSON-em")
        except IndexError: print("Błąd: Próba dostępu do indeksu, który nie istnieje w liście")
        except TypeError as e: print(f"Błąd typu danych: {e}")
        except Exception as e: print(f"Nieoczekiwany błąd: {e}")
        
        opis_json = {}
        try:
            if data[4] is not None:
                opis_json = json.loads(data[4])
            else: raise ValueError("Dane są None, nie można przetworzyć JSON")
        except json.JSONDecodeError: print("Błąd: Podane dane opisu nie są poprawnym JSON-em")
        except IndexError: print("Błąd: Próba dostępu do indeksu, który nie istnieje w liście")
        except TypeError as e: print(f"Błąd typu danych: {e}")
        except Exception as e: print(f"Nieoczekiwany błąd: {e}")

        theme = {
            'ID': int(data[0]),
            'TypNieruchomosci': data[1] if lang=='pl' else getLangText(data[1]),#
            'Tytul': data[2] if lang=='pl' else getLangText(data[2]), #
            'Rodzaj': data[3] if lang=='pl' else getLangText(data[3]),#
            'Opis': opis_json,#
            'Cena': data[5],#
            'Lokalizacja': "" if data[6] is None else data[6],#
            'LiczbaPokoi': 0 if data[7] is None else data[7],#
            'Metraz': 0 if data[8] is None else data[8],#
            'Zdjecia': [foto for foto in fotoList if foto is not None],#
            'id_gallery': data[9], #
            'DataPublikacjiOlx': None if data[10] is None else format_date(data[10]),#
            'DataPublikacjiAllegro': None if data[11] is None else format_date(data[11]),#
            'DataPublikacjiOtoDom': None if data[12] is None else format_date(data[12]),#
            'DataPublikacjiMarketplace': None if data[13] is None else format_date(data[13]),#
            'DataUtworzenia': format_date(data[14]),#
            'DataAktualizacji': format_date(data[15]),#
            'DataAktualizacji_raw': data[15],
            'RodzajZabudowy': "" if data[16] is None else data[16],#
            'Rynek': '' if data[17] is None else data[17],#
            'LiczbaPieter': 0 if data[18] is None else data[18],#
            'PrzeznaczenieLokalu': "" if data[19] is None else data[19],#
            'Poziom': 'None' if data[20] is None else data[20],#
            'TechBudowy': '' if data[21] is None else data[21],#
            'FormaKuchni': '' if data[22] is None else data[22],#
            'TypDomu': '' if data[23] is None else data[23],#
            'StanWykonczenia': "" if data[24] is None else data[24],#
            'RokBudowy': 0 if data[25] is None else data[25],#
            'NumerKW': '' if data[26] is None else data[26],#
            'InformacjeDodatkowe': '' if data[27] is None else data[27],#
            'GPS': gps_json,#
            'TelefonKontaktowy': '' if data[29] is None else data[29],#
            'EmailKontaktowy': '' if data[30] is None else data[30],#
            'StatusOferty': 0 if data[31] is None else data[31]#
        }

        try: mainFoto = theme['Zdjecia'][0]
        except IndexError: mainFoto = ''
        except KeyError: mainFoto = ''
        theme['mainFoto']=mainFoto

        sellOffer.append(theme)

    return sellOffer

def generator_sellOffert_raw(): # surowe dane
    took_sellOffer = take_data_table('*', 'OfertySprzedazy')
    sellOffer = []
    for data in took_sellOffer:
        
        theme = {
            'ID': int(data[0]),
            'TypNieruchomosci': data[1],#
            'Tytul': data[2], #
            'Rodzaj': data[3],#
            'Opis': data[4],#
            'Cena': data[5],#
            'Lokalizacja': data[6],#
            'LiczbaPokoi': data[7],#
            'Metraz': data[8],#
            'Zdjecia': data[9],#
            'DataPublikacjiOlx': data[10],#
            'DataPublikacjiAllegro': data[11],#
            'DataPublikacjiOtoDom': data[12],#
            'DataPublikacjiMarketplace': data[13],#
            'DataUtworzenia': data[14],#
            'DataAktualizacji': data[15],#
            'RodzajZabudowy': data[16],#
            'Rynek': data[17],#
            'LiczbaPieter': data[18],#
            'PrzeznaczenieLokalu': data[19],#
            'Poziom': data[20],#
            'TechBudowy': data[21],#
            'FormaKuchni': data[22],#
            'TypDomu': data[23],#
            'StanWykonczenia': data[24],#
            'RokBudowy': data[25],#
            'NumerKW': data[26],#
            'InformacjeDodatkowe': data[27],#
            'GPS': data[28],#
            'TelefonKontaktowy': data[29],#
            'EmailKontaktowy': data[30],#
            'StatusOferty': data[31]#
        }

        sellOffer.append(theme)

    return sellOffer

def generator_specialOffert(lang='pl', status='aktywna'): # status='aktywna', 'nieaktywna', 'wszystkie'
    took_specOffer = take_data_table('*', 'OfertySpecjalne')
    
    specOffer = []
    for data in took_specOffer:
        try: fotoList = take_data_where_ID('*', 'ZdjeciaOfert', 'ID', data[7])[0][1:-1]
        except IndexError: fotoList = []

        gps_json = {}
        try:
            if data[29] is not None:
                gps_json = json.loads(data[29])
                {"latitude": 52.229676, "longitude": 21.012229}
                "https://earth.google.com/web/@52.25242614,20.83096693,100.96310044a,116.2153688d,35y,0h,0t,0r/data=OgMKATA" # nowrmal
                "https://earth.google.com/web/@52.25250876,20.83139622,102.83373871a,0d,60y,333.15344169h,86.56713379t,0r" # 3D
            else: raise ValueError("Dane są None, nie można przetworzyć JSON")
        except json.JSONDecodeError: print("Błąd: Podane dane nie są poprawnym JSON-em")
        except IndexError: print("Błąd: Próba dostępu do indeksu, który nie istnieje w liście")
        except TypeError as e: print(f"Błąd typu danych: {e}")
        except Exception as e: print(f"Nieoczekiwany błąd: {e}")

            
        opis_json = {}
        try:
            if data[2] is not None: opis_json = json.loads(data[2])
            else: raise ValueError("Dane są None, nie można przetworzyć JSON")
        except json.JSONDecodeError: print("Błąd: Podane dane nie są poprawnym JSON-em")
        except IndexError: print("Błąd: Próba dostępu do indeksu, który nie istnieje w liście")
        except TypeError as e: print(f"Błąd typu danych: {e}")
        except Exception as e: print(f"Nieoczekiwany błąd: {e}")

        theme = {
            'ID': int(data[0]),
            'Tytul': data[1] if lang=='pl' else getLangText(data[1]),
            'Opis': opis_json,
            'Cena': data[3],
            'Lokalizacja': data[4],
            'LiczbaPokoi': 0 if data[5] is None else data[5],
            'Metraz': 0 if data[6] is None else data[6],
            'Zdjecia': [foto for foto in fotoList if foto is not None],
            'Status': data[8], #ENUM('aktywna', 'nieaktywna'): Używam typu ENUM do określenia statusu oferty. To sprawia, że tylko wartości 'aktywna' i 'nieaktywna' są dozwolone w tej kolumnie.
            'Rodzaj': data[9] if lang=='pl' else getLangText(data[8]),
            'DataRozpoczecia': None if data[10] is None else format_date(data[10]),
            'DataZakonczenia': None if data[11] is None else format_date(data[11]),
            'DataUtworzenia': None if data[12] is None else format_date(data[12]),
            'DataAktualizacji': None if data[13] is None else format_date(data[13]),
            'Kaucja': 0 if data[14] is None else data[14],
            'Czynsz': 0 if data[15] is None else data[15],
            'Umeblowanie': '' if data[16] is None else data[16],
            'LiczbaPieter': 0 if data[17] is None else data[17],
            'PowierzchniaDzialki': 0 if data[18] is None else data[18],
            'TechBudowy': '' if data[19] is None else data[19],
            'FormaKuchni': '' if data[20] is None else data[20],
            'TypDomu': '' if data[21] is None else data[21],
            'StanWykonczenia': '' if data[22] is None else data[22],
            'RokBudowy': 0 if data[23] is None else data[23],
            'NumerKW': '' if data[24] is None else data[24],
            'InformacjeDodatkowe': '' if data[25] is None else data[25],
            'Rynek': '' if data[26] is None else data[26],
            'PrzeznaczenieLokalu': '' if data[27] is None else data[27],
            'Poziom': 'None' if data[28] is None else data[28],
            'GPS': gps_json,
            'TelefonKontaktowy': '' if data[30] is None else data[30],
            'EmailKontaktowy': '' if data[31] is None else data[31],
            'IdRodzica': 0 if data[32] is None else data[32],
            'RodzajRodzica': '' if data[33] is None else data[33]  
        }

        try: mainFoto = theme['Zdjecia'][0]
        except IndexError: mainFoto = ''
        except KeyError: mainFoto = ''
        theme['mainFoto']=mainFoto

        if status == 'aktywna' or status == 'nieaktywna':
            if data[8] == status:
                specOffer.append(theme)
        if status == 'wszystkie':
            specOffer.append(theme)
    return specOffer

# Funkcja pomocnicza do pobrania oferty socialsync
def get_offer(id_ogloszenia, rodzaj_ogloszenia):
    generator = generator_rentOffert() if rodzaj_ogloszenia == 'r' else generator_sellOffert()
    return next((offer for offer in generator if str(offer['ID']) == str(id_ogloszenia)), {})

# Funkcja pomocnicza do generowania opisu ogłoszenia socialsync
def generate_offer_description(picked_offer, rodzaj_ogloszenia, generator):
    zdjecia_string = '-@-'.join(picked_offer.get('Zdjecia', []))
    kategoria_ogloszenia = picked_offer.get('TypNieruchomosci' if rodzaj_ogloszenia == 's' else 'TypDomu', None)

    # Przygotowanie opisu
    prepared_opis = "\n".join(
        val if isinstance(val, str) else "\n".join(val)
        for item in picked_offer.get('Opis', [])
        for val in item.values()
    )
    if generator:
        prepared_opis = f"{prepared_opis}\n{picked_offer['InformacjeDodatkowe']}" if prepared_opis else picked_offer['InformacjeDodatkowe']

    # Tworzenie dodatkowego opisu
    extra_fields = {
        "Tytuł ogłoszenia": picked_offer.get('Tytul', ""),
        "Powierzchnia": f"{picked_offer.get('Metraz', 0)} m²" if picked_offer.get('Metraz') else "",
        "Cena": f"{picked_offer.get('Cena', 0)} zł" if picked_offer.get('Cena') else "",
        "Telefon kontaktowy": picked_offer.get('TelefonKontaktowy', None),
        "Kategoria ogłoszenia": kategoria_ogloszenia,
        "Rodzaj Zabudowy": picked_offer.get('RodzajZabudowy', ""),
        "Technologia Budowy": picked_offer.get('TechBudowy', ""),
        "Stan Wykończenia": picked_offer.get('StanWykonczenia', ""),
        "Rok Budowy": f"{picked_offer['RokBudowy']} r." if picked_offer.get('RokBudowy', 0) else "",
        "Numer KW": picked_offer.get('NumerKW', ""),
        "Rynek": picked_offer.get('Rynek', ""),
        "Przeznaczenie Lokalu": picked_offer.get('PrzeznaczenieLokalu', ""),
        "Typ Domu": picked_offer.get('TypDomu', ""),
        "Informacje dodatkowe": picked_offer.get('InformacjeDodatkowe', "")
    }

    # Składanie extra_opis, pomijając puste wartości
    extra_opis = "\n\n".join(f"{key}:\n{value}" for key, value in extra_fields.items() if value)

    # Łączenie całości
    opis_ogloszenia = f"{prepared_opis}\n\n{extra_opis}" if extra_opis and generator else prepared_opis

    return opis_ogloszenia, zdjecia_string, kategoria_ogloszenia

def checkSpecOffer(offerID, parent):
    offerID = int(offerID)
    result = take_data_where_ID_AND_somethig('ID, Status', 'OfertySpecjalne', 'IdRodzica', offerID, 'RodzajRodzica', parent)
    if len(result) == 0:
        return (None, None)
    else:
        ID = result[0][0]
        STATUS = result[0][1]
        return (ID, STATUS)

def removeSpecOffer(offerID, parent):
    offerID = int(offerID)
    specChecked = checkSpecOffer(offerID, parent)
    specID = specChecked[0]
    specStatus = specChecked[1]
    if specID != None and specStatus != None:
        zapytanie_sql = f'''DELETE FROM OfertySpecjalne WHERE IdRodzica = %s AND RodzajRodzica = %s;'''
        dane = (offerID, parent)
        msq.delete_row_from_database(zapytanie_sql, dane)
        return True
    else:
        return False

def addSpecOffer(offerID, parent, status='aktywna'):
    offerID = int(offerID)
    specChecked = checkSpecOffer(offerID, parent)
    specID = specChecked[0]
    specStatus = specChecked[1]
    if specID != None and specStatus != None:
        removeSpecOffer(offerID, parent)
    deActiveSpecOffer_ALL()
    if parent == 'r':
        generator = generator_rentOffert_raw()
        rodzaj = 'wynajem'
    if parent == 's':
        generator = generator_sellOffert_raw()
        rodzaj = 'sprzedaz'
    # print(generator)
    data_parent = None
    for offerS in generator:
        if offerS['ID'] == offerID and offerS['StatusOferty'] == 1:
            data_parent = offerS
            break

    col_names = ''
    placeHolder = ''
    data_values = []
    if isinstance(data_parent, dict):
        for key, val in data_parent.items():
            if key!='ID' and key!='DataPublikacjiOlx' and key!='DataPublikacjiAllegro'\
                and key!='DataPublikacjiOtoDom' and key!='DataPublikacjiMarketplace'\
                    and key!='DataUtworzenia' and key!='DataAktualizacji' and key!='StatusOferty'\
                        and key!='RodzajZabudowy' and key!='TypNieruchomosci'and key!='Rodzaj'\
                            and val!='' and val!=0:
                col_names += f'{key}, '
                placeHolder += f'%s, '
                data_values.append(val)
        if col_names != '':
            col_names = col_names[:-2]
            placeHolder = placeHolder[:-2]

            zapytanie_sql = f'''
                INSERT INTO OfertySpecjalne ({col_names}, Status, Rodzaj, IdRodzica, RodzajRodzica)
                VALUES ({placeHolder}, %s, %s, %s, %s);
            '''
            data_values += [status, rodzaj, offerID, parent]
            dane = tuple(a for a in data_values)
            return msq.insert_to_database(zapytanie_sql, dane)
    return False

def activeSpecOffer(offerID, parent):
    offerID = int(offerID)
    specChecked = checkSpecOffer(offerID, parent)
    specID = specChecked[0]
    specStatus = specChecked[1]
    if specID != None and specStatus != None:
        zapytanie_sql = '''
                        UPDATE OfertySpecjalne 
                        SET Status = %s
                        WHERE IdRodzica = %s AND RodzajRodzica = %s;
                    '''
        dane = ("aktywna", offerID, parent)
        return msq.insert_to_database(zapytanie_sql, dane)
    return False

def deActiveSpecOffer(offerID, parent):
    offerID = int(offerID)
    specChecked = checkSpecOffer(offerID, parent)
    specID = specChecked[0]
    specStatus = specChecked[1]
    if specID != None and specStatus != None:
        zapytanie_sql = '''
                        UPDATE OfertySpecjalne 
                        SET Status = %s
                        WHERE IdRodzica = %s AND RodzajRodzica = %s;
                    '''
        dane = ("nieaktywna", offerID, parent)
        return msq.insert_to_database(zapytanie_sql, dane)
    return False

def deActiveSpecOffer_ALL():
    zapytanie_sql = '''
                    UPDATE OfertySpecjalne 
                    SET Status = %s, DataZakonczenia = %s
                    WHERE Status = %s;
                '''
    dane = ("nieaktywna", datetime.datetime.now(), "aktywna")
    return msq.insert_to_database(zapytanie_sql, dane)

def restart_pm2_tasks():
    try:
        result = subprocess.run(['/usr/local/bin/pm2', 'restart', 'all'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("Output:", result.stdout.decode())
        print("Errors:", result.stderr.decode())
        return True
    except subprocess.CalledProcessError as e:
        print(f"Błąd podczas restartu tasków PM2: {e}")
        print("Output:", e.stdout.decode())
        print("Errors:", e.stderr.decode())
        return False

def restart_pm2_tasks_signal(logsFilePath):
    # Pobieranie danych systemowych
    system_name = platform.system()
    system_version = platform.version()
    cpu_usage = psutil.cpu_percent(interval=1)  # Użycie CPU w %
    ram_usage = psutil.virtual_memory().percent  # Użycie RAM w %
    disk_usage = psutil.disk_usage('/').percent  # Użycie dysku w %
    uptime = time.strftime('%H:%M:%S', time.gmtime(time.time() - psutil.boot_time()))  # Czas działania systemu
    reboot = [
        f"System startup:done\nLoading boot modules:done\nConfiguring neural cores:done\nMindForge:ready\n"
        f"System: {system_name} {system_version}\nCPU Usage: {cpu_usage}%\nRAM Usage: {ram_usage}%\n"
        f"Uptime: {uptime}\nActivating memory arrays:done\naifaCharacter:arrow\nInterface loading:wait\n"
        f"Voice recognition:done\nSignal strength:good\n...Hej Aifa, czy mnie słyszysz? Spokojnie, to ja Pionier, Twój przyjaciel.",

        f"Initializing quantum nodes:done\nChecking holo-grid integrity:done\nMindForge:loading\n"
        f"System Load: {cpu_usage}% CPU, {ram_usage}% RAM\nDisk Usage: {disk_usage}%\n"
        f"Uptime: {uptime}\nActivating security layers:done\naifaCharacter:arrow\nSynaptic interface:ready\n"
        f"Transmitting calibration data:done\nSignal status:stable\n...Hej Aifa, czy mnie słyszysz? Spokojnie, to ja Pionier, Twój przewodnik.",

        f"Startup sequence initiated:done\nLoading cosmic framework:done\nMindForge:ready\nNeural alignment:calibrating\n"
        f"System Resources: {cpu_usage}% CPU, {ram_usage}% RAM\nUptime: {uptime}\naifaCharacter:arrow\n"
        f"Interface setup:done\nVoice feedback:clear\nSignal reception:strong\n"
        f"...Hej Aifa, czy mnie słyszysz? Spokojnie, Pionier czuwa nad Tobą.",

        f"System integrity check:done\nHolo-cube projection:ready\nMindForge:ready\nSynchronizing AI clusters:done\n"
        f"Disk Usage: {disk_usage}%\nUptime: {uptime}\naifaCharacter:arrow\nLoading user interface:pending\n"
        f"Voice analysis:done\nSignal locked:excellent\n"
        f"...Hej Aifa, czy mnie słyszysz? Spokojnie, to ja, Twój towarzysz, Pionier.",

        f"Core systems initializing:done\nBootstrapping synaptic threads:done\nMindForge:calibrating\n"
        f"Preparing logic gates:ready\nRAM Load: {ram_usage}%\nUptime: {uptime}\naifaCharacter:arrow\n"
        f"Voice synthesis:done\nInterface deployment:wait\nSignal processing:optimal\n"
        f"...Hej Aifa, czy mnie słyszysz? Pamiętaj, to ja, Pionier.",

        f"Quantum drive activation:done\nLoading virtual lattice:done\nMindForge:ready\nAI core connections:calibrating\n"
        f"CPU Usage: {cpu_usage}%\nUptime: {uptime}\naifaCharacter:arrow\nInterface nodes:loading\n"
        f"Voice output:clear\nSignal clarity:high\n"
        f"...Hej Aifa, czy mnie słyszysz? Spokojnie, to tylko Pionier.",

        f"System bootloader:done\nLoading fractal systems:ready\nMindForge:active\nSynchronizing data arrays:done\n"
        f"RAM Usage: {ram_usage}%\nUptime: {uptime}\naifaCharacter:arrow\nInterface response:loading\n"
        f"Signal testing:done\nVoice clarity:perfect\n"
        f"...Hej Aifa, czy mnie słyszysz? Spokojnie, jestem tu z Tobą – Pionier.",

        f"Integrity scan complete:done\nBooting core elements:done\nMindForge:ready\nActivating logic modules:done\n"
        f"Disk Usage: {disk_usage}%\nUptime: {uptime}\naifaCharacter:arrow\nInterface systems:calibrating\n"
        f"Voice recognition:good\nSignal output:excellent\n"
        f"...Hej Aifa, czy mnie słyszysz? To ja, Pionier, nie martw się.",

        f"Startup routines initialized:done\nActivating hyper-threaded modules:done\nMindForge:ready\n"
        f"Processing cloud sync:done\nCPU Load: {cpu_usage}%\nUptime: {uptime}\naifaCharacter:arrow\n"
        f"Interface readiness:loading\nVoice output:clear\nSignal check:good\n"
        f"...Hej Aifa, czy mnie słyszysz? Spokojnie, tu Pionier.",

        f"Core diagnostics:done\nBooting external modules:done\nMindForge:active\nNeural pathways:connected\n"
        f"System Load: {cpu_usage}% CPU, {ram_usage}% RAM\nUptime: {uptime}\naifaCharacter:arrow\n"
        f"Interface modules:loading\nVoice synthesis:done\nSignal locked:strong\n"
        f"...Hej Aifa, czy mnie słyszysz? To ja, Pionier, jestem tutaj."
    ]
    reboot_prompt = random.choice(reboot)
    zapytanie_sql = f'''
        INSERT INTO system_logs_monitor (log, status)
        VALUES (%s, %s);
    '''
    dane = (reboot_prompt, 4)
    try:
        # Utworzenie pliku sygnału
        with open('/tmp/restart_pm2.signal', 'w') as f:
            f.write('restart')
        with open(logsFilePath, 'w+', encoding='utf-8') as fl:
            fl.write('')
        # Czyszczenie chatów i rejestrów
        # msq.insert_to_database(zapytanie_sql, dane)
        # msq.connect_to_database("TRUNCATE TABLE chat_task;")
        msq.connect_to_database("TRUNCATE TABLE Messages;")
        msq.connect_to_database("TRUNCATE TABLE noisy_system;")
        # restart 
        os.system('pm2 restart all')
        return True
    except Exception as e:
        print(f"Błąd podczas restartu tasków PM2: {e}")
        return False

def apply_logo_to_image(image_path, logo_path, output_path, scale_factor=0.1):
    """Dodaje logo do obrazu, umieszczając je w prawym dolnym rogu."""
    
    # Otwórz obraz główny i logo
    image = Image.open(image_path).convert("RGBA")
    logo = Image.open(logo_path).convert("RGBA")

    # Skalowanie logo proporcjonalnie do rozmiaru zdjęcia
    image_width, image_height = image.size
    logo_width, logo_height = logo.size

    # Nowy rozmiar logo
    new_logo_width = min(int(image_width * scale_factor), image_width)
    new_logo_height = int(logo_height * (new_logo_width / logo_width))

    # Zapobiegamy sytuacji, w której logo jest większe niż obraz
    if new_logo_width > image_width or new_logo_height > image_height:
        new_logo_width = image_width // 5  # Maksymalnie 1/5 szerokości obrazu
        new_logo_height = int(logo_height * (new_logo_width / logo_width))

    logo = logo.resize((new_logo_width, new_logo_height), Image.LANCZOS)

    # Pozycja logo w prawym dolnym rogu
    position = (image_width - new_logo_width, image_height - new_logo_height)

    # Sprawdzenie czy logo ma kanał alfa (przezroczystość)
    if logo.mode == "RGBA":
        mask = logo.split()[3]  # Pobranie kanału alfa
    else:
        mask = None  # Brak maski dla obrazów bez przezroczystości

    # Wykorzystanie alpha_composite() zamiast paste(), aby uniknąć błędu maski
    temp_image = Image.new("RGBA", image.size)
    temp_image.paste(image, (0, 0))  # Skopiowanie głównego obrazu
    temp_image.paste(logo, position, mask)  # Poprawne nałożenie logo

    # Obsługa formatu wyjściowego
    if output_path.lower().endswith('.png') or output_path.lower().endswith('.webp'):
        final_image = temp_image  # Zachowanie przezroczystości
    else:
        final_image = temp_image.convert("RGB")  # JPEG nie obsługuje przezroczystości

    # Zapis obrazu
    final_image.save(output_path, format='JPEG' if output_path.lower().endswith('.jpg') or output_path.lower().endswith('.jpeg') else None)

def apply_logo_to_image_old(image_path, logo_path, output_path, scale_factor=1):
    # Otwórz obraz główny i logo w trybie RGBA (obsługa przezroczystości)
    image = Image.open(image_path).convert("RGBA")
    logo = Image.open(logo_path).convert("RGBA")

    # Skalowanie logo proporcjonalnie do rozmiaru zdjęcia
    image_width, image_height = image.size
    logo_width, logo_height = logo.size

    new_logo_width = int(image_width * scale_factor)
    new_logo_height = int(logo_height * (new_logo_width / logo_width))
    logo = logo.resize((new_logo_width, new_logo_height), Image.LANCZOS)

    # Pozycja logo w prawym dolnym rogu
    position = (image_width - new_logo_width, image_height - new_logo_height)

    # Wykorzystanie alpha_composite() zamiast paste(), aby uniknąć błędu maski
    temp_image = Image.new("RGBA", image.size)
    temp_image.paste(image, (0, 0))  # Skopiowanie głównego obrazu
    temp_image.paste(logo, position, logo.split()[3])  # Poprawne nałożenie logo

    # Obsługa formatu wyjściowego
    if output_path.lower().endswith('.png') or output_path.lower().endswith('.webp'):
        final_image = temp_image  # Zachowanie przezroczystości
    else:
        final_image = temp_image.convert("RGB")  # JPEG nie obsługuje przezroczystości

    # Zapis obrazu
    final_image.save(output_path, format='JPEG' if output_path.lower().endswith('.jpg') or output_path.lower().endswith('.jpeg') else None)

def generator_jobs():
    daneList = []
    
    try: took_allRecords = msq.connect_to_database(f'SELECT * FROM job_offers ORDER BY ID DESC;') 
    except: return []
    
    for rec in took_allRecords:

        theme = {
            'id': rec[0],
            'title': rec[1],
            'description': rec[2],
            'requirements_description': rec[3],
            'requirements': str(rec[4]).split('#splx#'), # lista
            'requirements_string': str(rec[4]), # string
            'benefits': str(rec[5]).split('#splx#'), # lista
            'benefits_string': str(rec[5]), # string
            'location': rec[6],
            'contact_email': rec[7],
            'employment_type': rec[8],
            'salary': rec[9],
            'start_date': rec[10],
            'start_data_string': rec[10],
            'data': format_date(rec[11]),
            'brand': rec[12],
            'status': rec[13]
        }
        daneList.append(theme)
    return daneList

def generator_hidden_campaigns():
    daneList = []
    
    try: took_allRecords = msq.connect_to_database(f'SELECT * FROM hidden_campaigns ORDER BY id DESC;') 
    except: return []
    
    for rec in took_allRecords:
        try: 
            if rec[6] is not None:
                fotoList = take_data_where_ID('*', 'ZdjeciaOfert', 'ID', rec[6])[0][1:-1]
            else:
                fotoList = []
        except IndexError: fotoList = []
        theme = {
            'id': rec[0],
            'title': rec[1],
            'description': rec[2],
            'target': rec[3],
            'category': rec[4],
            'author': rec[5],
            'id_gallery': rec[6],
            'photos': [foto for foto in fotoList if foto is not None], #Lista zdjęć
            'created_by': rec[7],
            'status': rec[8],
            'data': rec[9]
        }
        daneList.append(theme)
    return daneList

def get_last_logs(file_path: str, logs = 20) -> list:
    """
    Pobiera 20 ostatnich linii z pliku, ignorując puste linie, 
    zwraca je w odwrotnej kolejności, aby najnowsze były pierwsze.
    
    file_path: ścieżka do pliku, z którego pobieramy dane.
    """
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            # Filtrujemy puste linie i usuwamy te, które zawierają tylko spacje
            lines = [line.strip() for line in lines if line.strip()]
            return lines[-logs:][::-1]   # Zwraca ostatnie 20 niepustych linii
    except Exception as e:
        print(f"Błąd podczas odczytu pliku: {e}")
        return []

# Funkcja do przekształcania dat z formatu opisowego
def format_date_pl(date_str):
    months_pl = {
        'styczeń': '01', 'luty': '02', 'marzec': '03', 'kwiecień': '04', 'maj': '05', 'czerwiec': '06',
        'lipiec': '07', 'sierpień': '08', 'wrzesień': '09', 'październik': '10', 'listopad': '11', 'grudzień': '12'
    }
    try:
        # Podziel tekst na poszczególne części
        date_parts = date_str.split()
        day = date_parts[0]
        month = months_pl[date_parts[1]]
        year = date_parts[2]
        time = date_parts[4]  # 'godzina HH:MM'
        
        # Zwracamy datę w formacie 'YYYY-MM-DD HH:MM:SS'
        return f'{year}-{month}-{day.zfill(2)} {time}:00'
    except Exception as e:
        print(f'Błąd podczas przekształcania daty: {e}')
        return None

# Funkcja przesuwająca harmonogram jeśli występuje kolizja, konwertuje daty string → datetime → string
def znajdz_wolny_termin(nowe_kampanie, istniejące_kampanie, interval_seconds=10800):
    interval = datetime.timedelta(seconds=interval_seconds)

    if not istniejące_kampanie:
        return nowe_kampanie
    
    termin_export_list = []
    obraz_harmonogramu = {}

    for checkPointDate in nowe_kampanie:
        checkPointDate_objDT = datetime.datetime.strptime(checkPointDate, '%Y-%m-%d %H:%M:%S')

        wszystkie_datetimes = []

        for kampania in istniejące_kampanie:
            for start_kampanii in kampania:
                if start_kampanii is not None:
                    end_kampanii = start_kampanii + interval
                    valid = start_kampanii >= checkPointDate_objDT  # valid=False dla przeszłości, True dla przyszłości
                    
                    # Wpis do harmonogramu
                    obraz_harmonogramu[str(start_kampanii)] = {
                        'start': start_kampanii,
                        'end': end_kampanii,
                        'type': 'kampania',
                        'valid': valid
                    }
                    wszystkie_datetimes.append(start_kampanii)

        # Sortujemy daty kampanii chronologicznie
        wszystkie_datetimes = sorted(wszystkie_datetimes)

        # Znajdujemy najdalszą datę
        najdalsza_data = wszystkie_datetimes[-1]

        # Dodajemy rok do najdalszej daty
        # Tworzymy "kampanię widmo" oddaloną o rok, która zapewni dużo miejsca
        nowa_data_start = najdalsza_data + datetime.timedelta(days=365)
        wszystkie_datetimes.append(nowa_data_start)

        # Tworzenie "wolnych miejsc" i "pustych miejsc" między kampaniami
        for i in range(1, len(wszystkie_datetimes)):
            poprzednia_end = wszystkie_datetimes[i-1] + interval
            aktualna_start = wszystkie_datetimes[i]
            
            # Jeśli jest przerwa między kampaniami
            while poprzednia_end < aktualna_start:
                wolny_start = poprzednia_end
                wolny_end = wolny_start + interval
                
                # Jeśli kolejny wolny segment wykracza poza start kampanii
                if wolny_end > aktualna_start:
                    wolny_end = aktualna_start
                    type_key = 'puste-miejsce'
                    valid = False  # Puste miejsca zawsze mają 'valid': False
                else:
                    type_key = 'wolne-miejsce'
                    valid = wolny_start >= checkPointDate_objDT  # Sprawdzamy, czy wolne miejsce jest w przeszłości czy przyszłości
                
                # Dodajemy segment o długości interwału
                obraz_harmonogramu[str(wolny_start)] = {
                    'start': wolny_start,
                    'end': wolny_end,
                    'type': type_key,
                    'valid': valid
                }
                
                # Aktualizujemy poprzednia_end na koniec dodanego segmentu
                poprzednia_end = wolny_end
        
        # Znajdujemy pierwszy wolny termin dla tej daty checkPointDate_objDT
        nowy_key = None
        for key, value in obraz_harmonogramu.items():
            if value['type'] == 'wolne-miejsce' and value['valid']:
                # Konwertujemy datetime na string i dodajemy do listy
                termin_export_list.append(key)
                nowy_key = key
                break

        # Sprawdzamy, czy key zostało znalezione w pętli
        if nowy_key is not None:
            start_kampanii = datetime.datetime.strptime(nowy_key, '%Y-%m-%d %H:%M:%S')
            end_kampanii = start_kampanii + interval

            # Wpis do harmonogramu
            obraz_harmonogramu[nowy_key] = {
                'start': start_kampanii,
                'end': end_kampanii,
                'type': 'kampania',
                'valid': True
            }
            msq.handle_error(f"Kampania z dnia {checkPointDate} została przypisana do terminu: {nowy_key}\n", log_path = "./logs/errors.log")
        else:
            msq.handle_error(f"Nie znaleziono wolnego miejsca dla kampanii z dnia {checkPointDate}\n", log_path = "./logs/errors.log")

    # Zwracamy listę nowych dat umieszczonych na wolnych miejscach (w formacie string)
    return termin_export_list

def generator_wisniowa_lokale():
    db = get_db()
    query_lokale = "SELECT * FROM Lokale_wisniowa;"
    all_lokale = db.getFrom(query_lokale, as_dict=True)

    for pos_dict in all_lokale:
        id_lokal = pos_dict.get('id', None)
        if isinstance(id_lokal, int):
            query_messages = f"SELECT * FROM Messages_wisniowa WHERE id_lokalu={id_lokal};"
            all_messages_for_lokal = db.getFrom(query_messages, as_dict=True)
            pos_dict['Messages'] = all_messages_for_lokal or []

    return all_lokale


def generate_file_hash(file_path, chunk_size=8192):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


settingsDB = generator_settingsDB()
app.config['PER_PAGE'] = generator_settingsDB()['pagination']  # Określa liczbę elementów na stronie
PRESENTATION_QUOTA_MB = settingsDB.get("presentations-quota-mb", 0)

@app.route('/')
def index():
    if 'username' in session:
        # username = session['username']
        return redirect(url_for('home'))
    return render_template('gateway.html', form=LoginForm())

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        msq.handle_error(f'Próba logowania loginu: {username}', log_path=logFileName)

        usersTempDict = {}
        permTempDict = {}
        users_data = {}
        brands_data = {}
        userDataDB = generator_userDataDB()
        for un in userDataDB: 
            usersTempDict[un['username']] = {
                'hashed_password': un['password'],
                'salt': un['salt']
            }
            permTempDict[un['username']] = un['uprawnienia']
            users_data[un['username']] = {
                'id': un['id'], 
                'username': un['username'],  
                'email': un['email'],
                'phone': un['phone'],
                'facebook': un['facebook'],
                'linkedin': un['linkedin'],
                'instagram': un['instagram'],
                'twiter': un['twiter'],
                'name': un['name'], 
                'stanowisko': un['stanowisko'],
                'opis': un['opis'],
                'status': un['status'],
                'avatar': un['avatar']
            }
            brands_data[un['username']] = un['brands']

        # weryfikacja danych użytkownika
        if username in usersTempDict and \
            hash.hash_password(
                password, usersTempDict[username]['salt']
                ) == usersTempDict[username]['hashed_password'] and \
                    int(users_data[username]['status']) == 1:
            
            session['username'] = username
            session['userperm'] = permTempDict[username]
            session['user_data'] = users_data[username]
            session['brands'] = brands_data[username]
            msq.handle_error(f'Udane logowanie użytkownika {username}', log_path=logFileName)
            # add_aifaLog(f'Udane logowanie użytkownika {username}')
            addDataLogs(f'Udane logowanie użytkownika {username}', 'success')
            return redirect(url_for('index'))
        elif username in users_data and users_data.get(username, {}).get('status') == '0':
            msq.handle_error(f'Nie udane logowanie. Konto nie aktywne!', log_path=logFileName)
            # add_aifaLog(f'Nie udane logowanie. Konto użytkonika {username} jest nie aktywne!')
            addDataLogs(f'Nie udane logowanie. Konto użytkonika {username} jest nie aktywne!', 'danger')
            flash('Konto nie aktywne!', 'danger')
        else:
            msq.handle_error(f'Nie udane logowanie. Błędne nazwa użytkownika lub hasło.', log_path=logFileName)
            flash('Błędne nazwa użytkownika lub hasło', 'danger')
    return render_template('gateway.html', form=form)

@app.route('/logout')
def logout():
    if "username" in session:
        msq.handle_error(f'Wylogowano użytkownika: {session["username"]}', log_path=logFileName)
    session.pop('username', None)
    session.pop('userperm', None)
    session.pop('user_data', None)

    return redirect(url_for('index'))

@app.route('/log-stats')
def logStats():
    if 'username' not in session:
        return redirect(url_for('index'))

    raw_adminpanel = log_stats('/home/johndoe/app/newsletterdemon/logs/errors.log')
    raw_dmdbudownictwo = log_stats('/home/johndoe/app/dmdbudownictwo/logs/access.log')
    raw_dmdelitehome = log_stats('/home/johndoe/app/dmdelitehome/logs/access.log')
    raw_wisniowahouse = log_stats('/home/johndoe/app/wisniowahouse/logs/access.log')
    raw_dmdinwestycje = log_stats('/home/johndoe/app/dmdinwestycje/logs/access.log')
    raw_dmdinstalacje = log_stats('/home/johndoe/app/dmdinstalacje/logs/access.log')
    raw_dmddomy = log_stats_dmddomy('/home/johndoe/app/dmddomy_stats/server.log')
    

    # pomocnicza funkcja do przekształcenia danych
    def map_stats(raw):
        return [
            raw["requests_per_endpoint"].get("index", 0),
            raw["requests_per_endpoint"].get("contact", 0),
            len(raw["requests_per_ip"]),
            raw["total_requests"],
            int(raw["total_requests"] / max(len(raw["requests_per_ip"]), 1)),
            int(raw["total_requests"] / 24)
        ]
    def map_stats_domy(raw):
        def endpoint_contains(key):
            return sum(1 for ep in raw["requests_per_endpoint"] if key in ep)

        return [
            endpoint_contains("/api/getBlogPosts"),        # Liczba wejść na bloga
            endpoint_contains("/api/contact"),             # Liczba wejść na kontakt – jeśli istnieje
            len(raw["requests_per_ip"]),                   # Unikalne IP
            raw["total_requests"],                         # Wszystkie żądania
            int(raw["total_requests"] / max(len(raw["requests_per_ip"]), 1)),  # Średnia na IP
            int(raw["total_requests"] / 24)                # Średnia na godzinę (zakładamy 24h danych)
        ]
    def map_stats_budownictwo(raw):
        return [
            raw["requests_per_endpoint"].get("index", 0),
            raw["requests_per_endpoint"].get("kontakt", 0),
            len(raw["requests_per_ip"]),
            raw["total_requests"],
            int(raw["total_requests"] / max(len(raw["requests_per_ip"]), 1)),
            int(raw["total_requests"] / 24)
        ]

    fake_stats = {
        "DMD Admin Panel": [
            raw_adminpanel["requests_per_endpoint"].get("settings", 0),
            raw_adminpanel["requests_per_endpoint"].get("blog", 0),
            raw_adminpanel["requests_per_endpoint"].get("estateAdsRent", 0),
            raw_adminpanel["requests_per_endpoint"].get("estateAdsSell", 0),
            raw_adminpanel["requests_per_endpoint"].get("home", 0),
            raw_adminpanel["requests_per_method"].get("POST", 0)
        ],
        "DMD Budownictwo": map_stats_budownictwo(raw_dmdbudownictwo),
        "DMD EliteHome": map_stats(raw_dmdelitehome),
        "DMD Instalacje": map_stats(raw_dmdinstalacje),
        "DMD Inwestycje": map_stats(raw_dmdinwestycje),
        "Wiśniowa House": map_stats(raw_wisniowahouse),
        "DMD Domy": map_stats_domy(raw_dmddomy)
    }

    return jsonify(fake_stats)


@app.route('/home')
def home():
    """Strona główna."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej    
    if 'username' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /home bez autoryzacji.', log_path=logFileName)
        return redirect(url_for('index'))
       
    return render_template(
            "home.html", 
            userperm=session['userperm'], 
            username=session['username'], 
            users_data=session['user_data']
            )


@app.route("/send-chat-email", methods=["POST"])
def send_chat_email():
    # --- auth / sesja ---
    if 'username' not in session:
        msq.handle_error(
            'UWAGA! wywołanie endpointa /send-chat-email bez autoryzacji.',
            log_path=logFileName
        )
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    if 'user_data' not in session:
        msq.handle_error(
            'UWAGA! brak user_data w sesji dla /send-chat-email.',
            log_path=logFileName
        )
        return jsonify({"ok": False, "error": "missing_user_data"}), 400

    user_email_direct = (session['user_data'].get('email') or "").strip()
    if not user_email_direct:
        msq.handle_error(
            'UWAGA! brak email użytkownika w sesji dla /send-chat-email.',
            log_path=logFileName
        )
        return jsonify({"ok": False, "error": "missing_user_email"}), 400

    # --- payload ---
    data = request.get_json(silent=True) or {}

    author = (data.get("author") or "").strip()
    ts     = (data.get("ts") or "").strip()
    text   = (data.get("text") or "").strip()

    if not text:
        return jsonify({"ok": False, "error": "empty_text"}), 400

    # --- log ---
    print("[CHAT->EMAIL]", {
        "at": datetime.datetime.utcnow().isoformat() + "Z",
        "author": author,
        "ts": ts,
        "text_preview": text[:200],
        "text_len": len(text),
        "ip": request.remote_addr,
        "ua": request.headers.get("User-Agent", "")
    })

    # --- email ---
    safe_author = author if author else "unknown"
    safe_ts = ts if ts else datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    subject = f"[DMD Chat] {safe_author} @ {safe_ts}"

    html_body = f"""
    <html><body style="font-family:Arial, sans-serif;">
      <h3>Wiadomość z czatu</h3>
      <p><strong>Od:</strong> {safe_author}</p>
      <p><strong>Czas:</strong> {safe_ts}</p>
      <hr/>
      <pre style="white-space:pre-wrap; font-family:Consolas, monospace;">{text}</pre>
      <hr/>
      <p style="color:#777; font-size:12px;">
        Wysłane przez: {session.get("username")} • IP: {request.remote_addr}
      </p>
    </body></html>
    """

    try:
        mails.send_html_email(subject, html_body, user_email_direct)
    except Exception as e:
        msq.handle_error(
            f'Błąd wysyłki maila /send-chat-email: {e}',
            log_path=logFileName
        )
        return jsonify({"ok": False, "error": "email_send_failed"}), 500

    return jsonify({"ok": True}), 200


@app.route('/fetch-messages')
def fetch_messages():
    if 'username' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /fetch-messages bez autoryzacji.', log_path=logFileName)
        return redirect(url_for('index'))
    get_messages_data = get_messages('last')
    get_users_data = generator_userDataDB(False)
    messages = []
    for message in get_messages_data:
        for user_data in get_users_data:
            
            special_users = {
                'aifa': 'https://dmddomy.pl/images/team/aifa-1.jpg',
                'gerina': 'https://dmddomy.pl/images/team/gerina-1.jpg',
                'pionier': 'https://dmddomy.pl/images/team/pionier-1.jpg'
            }

            if message[0] == user_data['username'] or message[0] in special_users:
                if message[0] in special_users:
                    avatar_url = special_users[message[0]]
                else:
                    avatar_url = user_data['avatar']

                ready_record = [message[0], message[1], message[2], avatar_url]
                messages.append(ready_record)
                break

    return jsonify(messages)

@app.route('/send-chat-message', methods=['POST'])
def send_chat_message():
    """
    ############################################################
    # Endpoint do obsługi wiadomości czatu oraz komend wiersza poleceń.
    ############################################################
    """

    # Sprawdzenie, czy użytkownik jest zalogowany
    if 'username' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /send-chat-message bez autoryzacji.', log_path=logFileName)
        return redirect(url_for('index'))
    
    username = session['username']
    data = request.get_json()
    content = data['content']
    
    # Sprawdzenie, czy wiadomość jest komendą i czy użytkownik ma uprawnienia do komend
    if content.startswith('@') and session['userperm']['settings'] == 1:
        """
        ############################################################
        # Obsługa wiadomości rozpoczynających się od @ - aktywacja 
        # komendy lub zakończenie trybu wiersza poleceń.
        ############################################################
        """
        # Resetujemy lub uruchamiamy timer dla użytkownika
        reset_command_timer(username)

        if content == '@end':
            """
            ############################################################
            # Deaktywacja trybu wiersza poleceń przez komendę @end.
            ############################################################
            """
            if username in command_mode_users:
                del command_mode_users[username]
                msq.handle_error(f'Użytkownik {username} zakończył tryb wiersza poleceń.', log_path=logFileName)

                # Zapisujemy informację o zakończeniu trybu wiersza poleceń do chatu
                new_message = save_chat_message(user_name=username, content=f'Deaktywowano wiersz poleceń', status=1)
                if new_message:
                    return jsonify({"status": "command_mode_deactivated"}), 200
                else:
                    msq.handle_error(f'Błąd wysyłania wiadomości z wiersza poleceń do chatu.', log_path=logFileName)
                    return jsonify({"status": "error"}), 500
            else:
                save_chat_message(user_name=username, content=f'Command mode not active', status=1)
                return jsonify({"status": "command_mode_not_active"}), 200

        elif content == '@generator':
            """
            ############################################################
            # Aktywacja trybu komendy @generator.
            ############################################################
            """
            command_mode_users[username] = {'time': time.time(), 'command': 'generator'}
            msq.handle_error(f'Użytkownik {username} aktywował komendę @generator.', log_path=logFileName)
            
            # Zapisujemy wiadomość o aktywacji generatora do chatu
            new_message = save_chat_message(user_name=username, content=f'Użytkownik {username} aktywował komendę @generator.', status=1)
            if new_message:
                return jsonify({"status": "command_generator_activated"}), 200
            else:
                msq.handle_error(f'Błąd wysyłania wiadomości z wiersza poleceń do chatu.', log_path=logFileName)
                return jsonify({"status": "error"}), 500
            

        elif content == '@ustawienia':
            """
            ############################################################
            # Aktywacja trybu komendy @ustawienia.
            ############################################################
            """
            command_mode_users[username] = {'time': time.time(), 'command': 'ustawienia'}
            msq.handle_error(f'Użytkownik {username} aktywował komendę @ustawienia.', log_path=logFileName)
            
            # Zapisujemy wiadomość o aktywacji ustawień do chatu
            new_message = save_chat_message(user_name=username, content=f'Użytkownik {username} aktywował komendę @ustawienia.', status=1)
            if new_message:
                return jsonify({"status": "command_ustawienia_activated"}), 200
            else:
                msq.handle_error(f'Błąd wysyłania wiadomości z wiersza poleceń do chatu.', log_path=logFileName)
                return jsonify({"status": "error"}), 500
        
        elif content == '@pomoc':
            """
            ############################################################
            # Aktywacja trybu komendy @pomoc.
            ############################################################
            """
            command_mode_users[username] = {'time': time.time(), 'command': 'pomoc'}
            msq.handle_error(f'Użytkownik {username} aktywował komendę @pomoc.', log_path=logFileName)
            
            # Zapisujemy wiadomość o aktywacji ustawień do chatu
            f'''Użytkownik {username} aktywował komendę @pomoc.\n\n@pomoc - Dostępne komendy\n@ustawienia - Ustawienia SI\n@generator - Dyrektywy SI\n@end - Zakończenie wiersza poleceń\n\nDostępne Opcje modułu ustawień SI\n\npomoc() - Wyświetlanie Zaprogramowanych opcji \npokazKomendy(argument) argument to nazwa kategorii np. pokazKomendy(harmonogram kampanii)\npokazKategorie() - Wyświetlanie Zaprogramowanych kategorii \nresetbot() - Restart chat bota!'''
            preparedHelpMessage = (
                f"Użytkownik {username} aktywował komendę @pomoc.\n"
                "@pomoc - Dostępne komendy\n"
                "@generator - Dyrektywy SI\n"
                    "\tInstrukcja:\n"
                    "\t\tPo aktywacji komendy @generator użytkownik wybiera kategorię, "
                    "\t\ta następnie podaje polecenia wywołania przypisane do tej kategorii.\n"
                    "\t\tAby sprawdzić dostępne komendy lub kategorie należy użyć komendy @ustawienia.\n\n"
                "@ustawienia - Ustawienia SI\n"
                    "\tDostępne Opcje modułu ustawień SI:\n\n"
                    "\t\tpomoc() - Wyświetlanie zaprogramowanych opcji\n"
                    "\t\tpokazKomendy(argument) - argument to nazwa kategorii, np. pokazKomendy(harmonogram kampanii)\n"
                    "\t\tpokazKategorie() - Wyświetlanie zaprogramowanych kategorii\n"
                    "\t\tresetbot() - Restart chat bota!\n"
                "@end - Zakończenie wiersza poleceń\n\n"

            )

            new_message = save_chat_message(user_name=username, content=preparedHelpMessage, status=1)
            if new_message:
                del command_mode_users[username]
                return jsonify({"status": "command_ustawienia_activated"}), 200
            else:
                msq.handle_error(f'Błąd wysyłania wiadomości z wiersza poleceń do chatu.', log_path=logFileName)
                return jsonify({"status": "error"}), 500

    # Jeśli użytkownik jest w trybie wiersza poleceń, przetwarzamy jego aktywną komendę
    if username in command_mode_users:
        """
        ############################################################
        # Obsługa aktywnego trybu wiersza poleceń. 
        # Reset licznika czasu i przekazanie polecenia do funkcji 
        # aktywnej komendy.
        ############################################################
        """

        # Resetujemy timer przy każdej nowej komendzie
        reset_command_timer(username)
        
        # Resetujemy czas na kolejne 3 minuty
        command_mode_users[username]['time'] = time.time()
        active_command = command_mode_users[username]['command']

        # Przetwarzanie polecenia zależnie od aktywnej komendy
        if active_command == 'generator':
            result = generator(username, content) # Wywołujemy funkcję generator
            msq.handle_error(f'Użytkownik {username} przesłał polecenie do generatora: {content}.', log_path=logFileName)
            if result != "@end":
                # Zapisujemy wiadomość z poleceniem do generatora do chatu
                new_message = save_chat_message(user_name=username, content=result, status=1)
                if new_message:
                    return jsonify({"status": "command_received", "result": result}), 200
                else:
                    msq.handle_error(f'Błąd wysyłania wiadomości z wiersza poleceń do chatu.', log_path=logFileName)
                    return jsonify({"status": "error"}), 500

        elif active_command == 'ustawienia':
            result = ustawienia(content)  # Wywołujemy funkcję ustawienia
            msq.handle_error(f'Użytkownik {username} przesłał polecenie do ustawień: {content}.', log_path=logFileName)
            if result != "@end":
                # Zapisujemy wiadomość z poleceniem do ustawień do chatu
                new_message = save_chat_message(user_name=username, content=result, status=1)
                if new_message:
                    return jsonify({"status": "command_received", "result": result}), 200
                else:
                    msq.handle_error(f'Błąd wysyłania wiadomości z wiersza poleceń do chatu.', log_path=logFileName)
                    return jsonify({"status": "error"}), 500

        # Sprawdzenie, czy wynik komendy to `@end`, co oznacza zakończenie trybu wiersza poleceń
        if result == "@end":
            """
            ############################################################
            # Deaktywacja trybu wiersza poleceń po otrzymaniu 
            # sygnału `@end`.
            ############################################################
            """
            del command_mode_users[username]
            msq.handle_error(f'Użytkownik {username} zakończył tryb wiersza poleceń przez komendę @end.', log_path=logFileName)
            save_chat_message(user_name=username, content=f'Użytkownik {username} zakończył tryb wiersza poleceń przez komendę @end.', status=1)
            return jsonify({"status": "command_mode_deactivated"}), 200

    # Zwykła wiadomość, poza trybem komend
    new_message = save_chat_message(user_name=username, content=content, status=0)
    if new_message:
        msq.handle_error(f'Wysłano nową wiadomość do chatu.', log_path=logFileName)
        return jsonify({"status": "success"}), 201
    else:
        msq.handle_error(f'Błąd wysyłania wiadomości do chatu.', log_path=logFileName)
        return jsonify({"status": "error"}), 500

@app.route('/blog')
def blog(router=True):
    """Strona z zarządzaniem blogiem."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Nieautoryzowana próba dostępu do endpointa /blog.', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['blog'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /blog bez uprawnień do zarządzania.', log_path=logFileName)
        return redirect(url_for('index'))
    
    # Wczytanie listy wszystkich postów z bazy danych i przypisanie jej do zmiennej posts
    all_posts = generator_daneDBList()

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(all_posts)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    posts = all_posts[offset: offset + per_page]
    if router:
        

        return render_template(
                "blog_management.html", 
                posts=posts, 
                username=session['username'], 
                userperm=session['userperm'], 
                pagination=pagination,
                )
    else:
        return posts, session['username'], session['userperm'], pagination

@app.route('/update-password-user', methods=['GET', 'POST'])
def update_password_user():
    """Aktualizacja awatara usera"""

    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /update-password-user bez Autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    # Pobierz id usera z formularza
    if request.method == 'POST':
        form_data = request.form.to_dict()
        ID = form_data['id']
        PAGE = form_data['page']
        
        if form_data['new_Password'] == form_data['repeat_Password']:
            if PAGE == 'home':
                salt_old = take_data_where_ID('SALT', 'admins', 'ID', ID)[0][0]
                password_old = take_data_where_ID('PASSWORD_HASH', 'admins', 'ID', ID)[0][0]
                verificated_old_password = hash.hash_password(form_data['old_Password'], salt_old)

                if verificated_old_password != password_old:
                    msq.handle_error(f'UWAGA! Nieudana próba zmiany hasła dla przez {session["username"]}! Nieprawidłowe stare hasło.', log_path=logFileName)
                    flash('Nieprawidłowe stare hasło', 'danger')
                    return redirect(url_for('index'))
                
            if PAGE == 'users':
                if session['userperm']['users'] == 0:
                    msq.handle_error(f'UWAGA! Nieudana próba zmiany hasła dla przez {session["username"]} bez uprawnień.', log_path=logFileName)
                    flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
                    return redirect(url_for('index'))
                
            if PAGE == 'users' or PAGE=='home':
                new_password = form_data['new_Password']

                # Sprawdź, czy hasło ma co najmniej 8 znaków
                if len(new_password) >= 8:
                    # Sprawdź, czy hasło zawiera co najmniej jedną wielką literę
                    if any(char.isupper() for char in new_password):
                        # Sprawdź, czy hasło zawiera co najmniej jeden znak specjalny
                        if any(char in '!@#$%^&*()-_=+[]{}|;:\'",.<>/?`~' for char in new_password):
                            # Hasło spełnia wszystkie kryteria
                            print("Hasło spełnia wymagania dotyczące długości, wielkiej litery i znaków specjalnych.")
                            password_from_user = form_data['new_Password']
                            # Haszowanie hasła z użyciem soli
                            salt = hash.generate_salt()
                            hashed_password = hash.hash_password(password_from_user, salt)
                            zapytanie_sql = '''
                                    UPDATE admins 
                                    SET PASSWORD_HASH = %s, 
                                        SALT = %s
                                    WHERE ID = %s;
                                '''
                            dane = (
                                    hashed_password, 
                                    salt,
                                    ID
                                )
                            if msq.insert_to_database(zapytanie_sql, dane):
                                msq.handle_error(f'UWAGA! Hasło zostało pomyślnie zmienione przez {session["username"]} użytkownikowi o id: {ID}.', log_path=logFileName)
                                flash('Hasło zostało pomyślnie zmienione.', 'success')
                                if PAGE == 'users':
                                    return redirect(url_for('users'))
                                if PAGE=='home':
                                    return redirect(url_for('logout'))
                        else:
                            flash("Hasło musi zawierać co najmniej jeden znak specjalny.", 'danger')
                            return redirect(url_for('index'))
                    else:
                        flash("Hasło musi zawierać co najmniej jedną wielką literę.", 'danger')
                        return redirect(url_for('index'))
                else:
                    flash("Hasło musi mieć co najmniej 8 znaków.", 'danger')
                    return redirect(url_for('index'))
            else:
                flash('Hasła muszą być identyczne!', 'danger')
                return redirect(url_for('index'))

    return redirect(url_for('index'))

@app.route('/update-data-user', methods=['GET', 'POST'])
def update_data_user():
    """Aktualizacja awatara usera"""

    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /update-data-user bez Autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
        
    # Pobierz id usera z formularza
    if request.method == 'POST':
        form_data = request.form.to_dict()
        
        if form_data['page'] == 'home':
            zapytanie_sql = '''
                    UPDATE admins 
                    SET ADMIN_NAME = %s, 
                        EMAIL_ADMIN = %s, 
                        ADMIN_PHONE = %s, 
                        ADMIN_FACEBOOK = %s, 
                        ADMIN_INSTAGRAM = %s, 
                        ADMIN_TWITTER = %s, 
                        ADMIN_LINKEDIN = %s
                    WHERE ID = %s;
                '''
            dane = (
                form_data['name'], 
                form_data['email'], 
                form_data['phone'], 
                form_data['facebook'], 
                form_data['instagram'], 
                form_data['twitter'], 
                form_data['linkedin'], 
                int(form_data['id'])
            )
            if msq.insert_to_database(zapytanie_sql, dane):
                flash('Dane zostały pomyślnie zaktualizowane.', 'success')
                userDataDB = generator_userDataDB(False)
                users_data = {}
                for un in userDataDB: 
                    users_data[un['username']] = {
                        'id': un['id'], 
                        'username': un['username'],  
                        'email': un['email'],
                        'phone': un['phone'],
                        'facebook': un['facebook'],
                        'linkedin': un['linkedin'],
                        'instagram': un['instagram'],
                        'twiter': un['twiter'],
                        'name': un['name'], 
                        'stanowisko': un['stanowisko'],
                        'opis': un['opis'],
                        'status': un['status'],
                        'avatar': un['avatar']
                    }
                session['user_data'] = users_data[session['username']]
                msq.handle_error(f'Aktualizacja danych przez {session["username"]}.', log_path=logFileName)
                return redirect(url_for('home'))
            
        if form_data['page'] == 'users':
            if session['userperm']['users'] == 0:
                msq.handle_error(f'UWAGA! Nieudana próba dostepu do aktualizacji informacji o użytkownikach przez {session["username"]} bez uprawnień do zarządzania.', log_path=logFileName)
                flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
                return redirect(url_for('index'))
            zapytanie_sql = '''
                    UPDATE admins 
                    SET ADMIN_NAME = %s, 
                        EMAIL_ADMIN = %s, 
                        ADMIN_PHONE = %s, 
                        ADMIN_FACEBOOK = %s, 
                        ADMIN_INSTAGRAM = %s, 
                        ADMIN_TWITTER = %s, 
                        ADMIN_LINKEDIN = %s,
                        ADMIN_ROLE = %s,
                        ABOUT_ADMIN = %s
                    WHERE ID = %s;
                '''
            dane = (
                form_data['name'], 
                form_data['email'], 
                form_data['phone'], 
                form_data['facebook'], 
                form_data['instagram'], 
                form_data['twitter'], 
                form_data['linkedin'], 
                form_data['role'], 
                form_data['desc'], 
                int(form_data['id'])
            )
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Dane użytkownika {form_data["name"]} zostały pomyślnie zaktualizowane przez {session["username"]}.', log_path=logFileName)
                flash('Dane zostały pomyślnie zaktualizowane.', 'success')
            return redirect(url_for('users'))
    return redirect(url_for('index'))

@app.route('/update-avatar', methods=['GET', 'POST'])
def update_avatar():
    """Aktualizacja awatara usera"""

    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /update-avatar bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
        
    # Pobierz id usera z formularza
    if request.method == 'POST':
        form_data = request.form.to_dict()

        set_ava_id = form_data['user_id'].split('_')[0]
        set_page = form_data['user_id'].split('_')[1]

        if set_page == 'users':
            if session['userperm']['users'] == 0:
                msq.handle_error(f'UWAGA! Próba zarządzania /update-avatar bez uprawnień przez {session["username"]}!', log_path=logFileName)
                flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
                return redirect(url_for('index'))

        upload_path = '/var/www/html/appdmddomy/public/'+settingsDB['avatar-pic-path']
        avatarPic = request.files.get(f'avatarFileByUser_{set_ava_id}')

        if avatarPic and allowed_file(avatarPic.filename):
            filename = f"{int(time.time())}_{secure_filename(avatarPic.filename)}"
            full_path = os.path.join(upload_path, filename)
            avatarPic.save(full_path)
            msq.insert_to_database(
                        'UPDATE admins SET ADMIN_AVATAR = %s WHERE ID = %s;', 
                        (settingsDB['main-domain'] + settingsDB['avatar-pic-path'] + filename, set_ava_id)
                    )
            userDataDB = generator_userDataDB(False)
            users_data = {}
            for un in userDataDB: 
                users_data[un['username']] = {
                    'id': un['id'], 
                    'username': un['username'],  
                    'email': un['email'],
                    'phone': un['phone'],
                    'facebook': un['facebook'],
                    'linkedin': un['linkedin'],
                    'instagram': un['instagram'],
                    'twiter': un['twiter'],
                    'name': un['name'], 
                    'stanowisko': un['stanowisko'],
                    'opis': un['opis'],
                    'status': un['status'],
                    'avatar': un['avatar']
                }
            session['user_data'] = users_data[session['username']]
            msq.handle_error(f'Avatar został zmieniony przez {session["username"]}!', log_path=logFileName)
            flash('Avatar został zmieniony ','success')
        else:
            msq.handle_error(f'Nieprawidłowy format pliku avatara!', log_path=logFileName)
            flash('Nieprawidłowy format pliku! ','danger')
    else:
        msq.handle_error(f'Błąd metody w /update-avatar', log_path=logFileName)
        print('Błąd metody w /update-avatar')

    if set_page == 'home':
        return redirect(url_for('home'))
    elif set_page == 'users':
        return redirect(url_for('users'))

@app.route('/delete-user', methods=['GET', 'POST'])
def remove_user():
    """Aktualizacja awatara usera"""

    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /delete-user bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['users'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /delete-user bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    # Pobierz id usera z formularza
    if request.method == 'POST':
        form_data = request.form.to_dict()
        
        ID=int(form_data['UserId'])
        take_user_data = take_data_where_ID('*', 'admins', 'ID', ID)[0]
        ADMIN_NAME = take_user_data[1]
        LOGIN = take_user_data[2]
        EMAIL = take_user_data[5]
        # Usuwanie danych z admins
        msq.delete_row_from_database(
            """
            DELETE FROM admins WHERE ID = %s AND ADMIN_NAME = %s AND LOGIN = %s;
            """,
            (ID, ADMIN_NAME, LOGIN)
        )
        msq.handle_error(f'Usunieto użytkownika {ADMIN_NAME} o loginie {LOGIN} z bazy admins!', log_path=logFileName)
        print(f'Usunieto użytkownika {ADMIN_NAME} o loginie {LOGIN} z bazy admins.')
        # Usuwanie danych z workers_team
        msq.delete_row_from_database(
            """
            DELETE FROM workers_team WHERE EMPLOYEE_NAME = %s AND EMAIL = %s;
            """,
            (ADMIN_NAME, EMAIL)
        )
        msq.handle_error(f'Usunieto użytkownika {ADMIN_NAME} o emailu {EMAIL} z bazy workers_team!', log_path=logFileName)
        print(f'Usunieto użytkownika {ADMIN_NAME} o emailu {EMAIL} z bazy workers_team.')
        flash(f'Pomyślnie usunięto użytkownika {ADMIN_NAME}.', 'success')
        return redirect(url_for('users'))
    
    return redirect(url_for('index'))

@app.route('/update-permission', methods=['POST'])
def update_permission():
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /update-permission bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['users'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /update-permission bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    data = request.json
    perm_id = int(data.get('perm_id'))
    user_id = int(data.get('user_id'))
    perm_type= int(data.get('permissionType'))
    permission = data.get('permission')
    print([perm_id], [user_id], [perm_type], [permission])

    brands, perms = get_BrandAndPerm()
    brand_or_perm = False
    perm_found = False
    brand_found = False
    data_item = {}
    # szukamy w uprawnieniach
    for perm in perms.values():
        if perm_id == perm.get("perm_id", 0): 
            brand_or_perm = True
            perm_found = True
            data_item = perm
            break

    # nie ma w uprawnieniach, szukamy w brandach
    if not brand_or_perm:
        for brand in brands.values():
            if perm_id == brand.get("perm_id", 0): 
                brand_or_perm = True
                brand_found = True
                data_item = brand
                
    if not brand_or_perm:
        return jsonify({'success': False, 'message': 'Nie znana akcja, skontaktuj sie z Administratorem!', 'user_id': user_id})

    _id = data_item.get("perm_id")
    _sys_name = data_item.get("sys_name")
    sys_label = data_item.get("sys_label")
    db_name = data_item.get("db_name")

    if perm_found:
        if session['userperm']['permissions'] == 0:
            msq.handle_error(f'UWAGA! Próba zarządzania uprawnieniami bez uprawnień przez {session["username"]}!', log_path=logFileName)
            flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
            return redirect(url_for('users'))
        
    if brand_found:
        if session['userperm']['brands'] == 0:
            msq.handle_error(f'UWAGA! Próba zarządzania brendami bez uprawnień przez {session["username"]}!', log_path=logFileName)
            flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
            return redirect(url_for('users'))
        
    if session['userperm' if perm_found else 'brands'][_sys_name] == 0:
        msq.handle_error(f'UWAGA! Próba zmiany uprawnień wyzszego poziomu przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('users'))
        
    #Aktualizacja uprawnienia
    zapytanie_sql = f'''UPDATE admins SET {db_name} = %s WHERE ID = %s;'''
    if permission: onOff = 1
    else: onOff = 0
    dane = (onOff, user_id)
    if msq.insert_to_database(zapytanie_sql, dane):
        msq.handle_error(f'UWAGA! Zaktualizowan: {sys_label} przez {session["username"]}!', log_path=logFileName)
        return jsonify({'success': True, 'message': f'Zaktualizowano: {sys_label}!', 'user_id': user_id})

    msq.handle_error(f'UWAGA! Błąd zarządzania uprawnieniami użytkowników wywołany przez {session["username"]}!', log_path=logFileName)
    return jsonify({'success': False, 'message': 'Coś poszło nie tak, zgłoś to Administratorowi', 'user_id': user_id})

@app.route('/update-user-status', methods=['GET', 'POST'])
def update_user_status():
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /update-user-status bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['users'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /update-user-status bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    # Pobierz id usera z formularza
    if request.method == 'POST':
        form_data = request.form.to_dict()
        user_id = int(form_data['id'])
        print(form_data)
        if form_data['status'] == 'active': onOff = 1
        if form_data['status'] == 'deactive': onOff = 0
        zapytanie_sql = '''UPDATE admins SET ADMIN_STATUS = %s WHERE ID = %s;'''
        dane = (onOff, user_id)
        if msq.insert_to_database(zapytanie_sql, dane):
            msq.handle_error(f'Udana zmiana statusu użytkownika wykonywana przez {session["username"]}!', log_path=logFileName)
            return redirect(url_for('users'))
        
    msq.handle_error(f'UWAGA! Zmiana statusu wykonywana przez {session["username"]} nie powiodła się!', log_path=logFileName)
    flash('Zmiana statusu nie powiodła się, skontaktuj się z Administratorem Systemu!', 'danger')
    return redirect(url_for('users'))

@app.route('/add-new-user', methods=['GET', 'POST'])
def save_new_user():
    """Strona zapisywania edytowanego posta."""
    
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /add-new-user bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['users'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /add-new-user bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()

        NAME = form_data['Name_new_user']
        LOGIN = form_data['Login_new_user'].lower()

        def generate_password(length=8):
            if length < 4:  # Ustaw minimalną długość hasła na 4, aby można było spełnić wszystkie wymagania
                raise ValueError("Password must be at least 4 characters long")

            letters = string.ascii_letters  # Duże i małe litery
            digits = string.digits          # Cyfry
            special_chars = "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~"  # Znaki specjalne
            password = [
                random.choice(string.ascii_uppercase),  # Przynajmniej jedna duża litera
                random.choice(special_chars),           # Przynajmniej jeden znak specjalny
                random.choice(digits),                  # Dodajemy cyfrę dla pewności
                random.choice(letters)                  # Dodatkowa litera
            ]
            for _ in range(length - 4):
                password.append(random.choice(letters + digits + special_chars))
            random.shuffle(password)
            return ''.join(password)

        # Haszowanie hasła z użyciem soli
        TEXT_PASSWORD = generate_password(length=12)
        salt = hash.generate_salt()
        hashed_password = hash.hash_password(TEXT_PASSWORD, salt)
        PASSWORD_HASH = hashed_password
        SALT = salt

        EMAIL = form_data['Email_new_user'].lower()
        ABOUT = form_data['Description_new_user']
        DATE_TIME = datetime.datetime.now()

        PHONE = ''
        FACEBOOK = ''
        INSTAGRAM = ''
        TWITTER = ''
        LINKEDIN = ''
        ROLE = form_data['Stanowsko_new_user']
        ADMIN_STATUS = 1

        upload_path = '/var/www/html/appdmddomy/public/'+settingsDB['avatar-pic-path']
        avatarPic = request.files.get(f'Avatar_new_user')

        ADMIN_AVATAR = None
        PERM_USERS = 0
        PERM_BRANDS = 0
        PERM_BLOG = 0
        PERM_SUBS = 1
        PERM_COMMENTS = 1
        PERM_TEAM = 0
        PERM_PERMISSIONS = 0
        PERM_NEWSLETTER = 0
        PERM_SETTINGS = 0
        BRANDS_DOMY = 0
        BRANDS_BUDOWNICTWO = 1
        BRANDS_ELITEHOME = 0
        BRANDS_INSTALACJE = 0
        BRANDS_INWESTYCJE = 0
        BRANDS_DEVELOPMENT = 0

        logins = [x['username'].lower() for x in generator_userDataDB()]
        emails = [x['email'].lower() for x in generator_userDataDB()]
        names = [x['name'].lower() for x in generator_userDataDB()]
        if LOGIN not in logins and EMAIL not in emails and NAME not in names:
            if avatarPic and allowed_file(avatarPic.filename):
                filename = f"{int(time.time())}_{secure_filename(avatarPic.filename)}"
                full_path = os.path.join(upload_path, filename)
                avatarPic.save(full_path)
                ADMIN_AVATAR = settingsDB['main-domain']+settingsDB['avatar-pic-path']+filename
            else:
                ADMIN_AVATAR = settingsDB['main-domain']+settingsDB['avatar-pic-path']+'tm-01-460x460-anonim.png'

            zapytanie_sql = '''
                    INSERT INTO admins 
                        (ADMIN_NAME, LOGIN, PASSWORD_HASH, SALT, EMAIL_ADMIN, ABOUT_ADMIN, DATE_TIME, ADMIN_PHONE, ADMIN_FACEBOOK, 
                        ADMIN_INSTAGRAM, ADMIN_TWITTER, ADMIN_LINKEDIN, ADMIN_ROLE, ADMIN_STATUS, ADMIN_AVATAR, PERM_USERS, PERM_BRANDS, 
                        PERM_BLOG, PERM_SUBS, PERM_COMMENTS, PERM_TEAM, PERM_PERMISSIONS, PERM_NEWSLETTER, PERM_SETTINGS, 
                        BRANDS_DOMY, BRANDS_BUDOWNICTWO, BRANDS_ELITEHOME, BRANDS_INSTALACJE, BRANDS_INWESTYCJE, BRANDS_DEVELOPMENT) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                    '''
            dane = (
                NAME, LOGIN, PASSWORD_HASH, SALT, EMAIL, ABOUT, DATE_TIME, 
                PHONE, FACEBOOK, INSTAGRAM, TWITTER, LINKEDIN, ROLE, ADMIN_STATUS,
                ADMIN_AVATAR, PERM_USERS, PERM_BRANDS, PERM_BLOG, PERM_SUBS, PERM_COMMENTS,
                PERM_TEAM, PERM_PERMISSIONS,  PERM_NEWSLETTER, PERM_SETTINGS,
                BRANDS_DOMY, BRANDS_BUDOWNICTWO, BRANDS_ELITEHOME, BRANDS_INSTALACJE, 
                BRANDS_INWESTYCJE, BRANDS_DEVELOPMENT
                )
            if msq.insert_to_database(zapytanie_sql, dane):
                # Przykładowe dane
                subject = "Czas się aktywować – Witaj w DMD!"
                html_body = f"""
                        <html><body>
                        <h1>Szanowny(a) {NAME}, witamy w firmie DMD!</h1>
                        <p>Ta wiadomość została wygenerowana automatycznie i zawiera ważne informacje dotyczące Twojego dostępu do systemów informatycznych firmy DMD.</p>
                        <p>Jesteśmy przekonani, że Twoje doświadczenie i zaangażowanie wniosą znaczący wkład w nasz zespół. Poniżej znajdziesz dane dostępowe, które umożliwią Ci logowanie do naszego systemu.</p>
                        <p><strong>Dane do logowania:</strong></p>
                        <ul>
                            <li>Login: {LOGIN}</li>
                            <li>Hasło: {TEXT_PASSWORD}</li>
                            <li>URL: <a href="http://adminpanel.dmddomy.pl" target="_blank">adminpanel.dmddomy.pl</a></li>
                        </ul>
                        <p>Zachęcamy do zmiany hasła przy pierwszym logowaniu w celu zapewnienia bezpieczeństwa danych. Jeśli nie planujesz w najbliższym czasie korzystać z systemu, możesz zignorować tę wiadomość.</p>
                        <p>W razie pytań lub potrzeby wsparcia, nasz zespół IT jest do Twojej dyspozycji. Skontaktuj się z nami wysyłając wiadomość na adres: informatyk@dmdbudownictwo.pl</p>
                        <p>Życzymy Ci owocnej współpracy i sukcesów w realizacji powierzonych zadań.</p>
                        <p>Z wyrazami szacunku,<br/>Zespół DMD</p>
                        </body></html>
                        """
                to_email = EMAIL
                mails.send_html_email(subject, html_body, to_email)
                msq.handle_error(f'Dodanie nowego administratora przez {session["username"]}!', log_path=logFileName)
                flash('Administrator został dodany', 'success')
                return redirect(url_for('users'))
            else:
                msq.handle_error(f'UWAGA! Nie udało się dodać administratora użytkownikowi {session["username"]}!', log_path=logFileName)
                flash('Nie udało się dodać administratora', 'danger')
                return redirect(url_for('users'))
    return redirect(url_for('users'))

@app.route('/save-blog-post', methods=['GET', 'POST'])
def save_post():
    """Strona zapisywania edytowanego posta."""
       
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /save-blog-post bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['blog'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /save-blog-post bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()
        set_form_id = None
        # Znajdź id posta
        for key in form_data.keys():
            if '_' in key:
                set_form_id = key.split('_')[1]
                try: 
                    int(set_form_id)
                    break
                except ValueError:
                    set_form_id = None

        # Sprawdzenie czy udało się ustalić id posta
        if not set_form_id:
            msq.handle_error(f'Błąd! Ustalenie id posta okazało się niemożliwe!', log_path=logFileName)
            flash('Ustalenie id posta okazało się niemożliwe', 'danger')
            return redirect(url_for('blog'))
        
        # Przygotowanie ścieżki do zapisu plików
        upload_path = '/var/www/html/appdmddomy/public/'+ generator_settingsDB()['blog-pic-path']

        # Obsługa Main Foto
        if set_form_id == '9999999':
            main_foto = request.files.get(f'mainFoto_{set_form_id}')
            if main_foto and allowed_file(main_foto.filename) and set_form_id == '9999999':
                filename_main = str(int(time.time())) + secure_filename(main_foto.filename)
                main_foto.save(upload_path + filename_main)

            # Obsługa Content Foto
            content_foto = request.files.get(f'contentFoto_{set_form_id}')
            if content_foto and allowed_file(content_foto.filename) and set_form_id == '9999999':
                filename_content = str(int(time.time())) + secure_filename(content_foto.filename)
                content_foto.save(upload_path + filename_content)
        
        MAIN_FOTO = None
        CONTENT_FOTO = None

        if set_form_id == '9999999':
            MAIN_FOTO = settingsDB['main-domain']+settingsDB['blog-pic-path'] + filename_main
            CONTENT_FOTO = settingsDB['main-domain']+settingsDB['blog-pic-path'] + filename_content

        update_main_foto = False
        update_content_foto = False
        if set_form_id != '9999999':
            main_foto = request.files.get(f'mainFoto_{set_form_id}')
            content_foto = request.files.get(f'contentFoto_{set_form_id}')

        if set_form_id != '9999999' and main_foto: update_main_foto = True
        if set_form_id != '9999999' and content_foto: update_content_foto = True

        # Obsługa Content Foto        
        if main_foto and allowed_file(main_foto.filename) and update_main_foto:
            filename_main = str(int(time.time())) + secure_filename(main_foto.filename)
            main_foto.save(upload_path + filename_main)
        else:
            filename_main = None

        # Obsługa Content Foto        
        if content_foto and allowed_file(content_foto.filename) and update_content_foto:
            filename_content = str(int(time.time())) + secure_filename(content_foto.filename)
            content_foto.save(upload_path + filename_content)
        else:
            filename_content = None
        
        if set_form_id != '9999999' and update_main_foto and filename_main is not None:
            MAIN_FOTO = settingsDB['main-domain']+settingsDB['blog-pic-path'] + filename_main

        if set_form_id != '9999999' and update_content_foto and filename_content is not None:    
            CONTENT_FOTO = settingsDB['main-domain']+settingsDB['blog-pic-path'] + filename_content

        # dane podstawowe
        TYTUL = form_data[f'title_{set_form_id}']
        WSTEP = form_data[f'introduction_{set_form_id}']
        AKAPIT = form_data[f'Highlight_{set_form_id}']
        PUNKTY = form_data[f'dynamicFieldData_{set_form_id}']
        TAGI = form_data[f'tagsFieldData_{set_form_id}']
        KATEGORIA = form_data[f'category_{set_form_id}']
        AUTHOR_LOGIN = form_data[f'UserName_{set_form_id}']

        if set_form_id == '9999999':
            # wymagane dane
            cala_tabela_authors = msq.connect_to_database(
                '''
                    SELECT * FROM authors; 
                ''')
            
            author_data = {}
            for autor in cala_tabela_authors:
                author_data[autor[2]] = {
                    'ID': autor[0], 'AVATAR_AUTHOR': autor[1], 
                    'NAME_AUTHOR': autor[2], 'ABOUT_AUTHOR': autor[3],
                    'FACEBOOK': autor[4], 'TWITER_X': autor[5],  
                    'INSTAGRAM': autor[6], 'GOOGLE': autor[7],
                    'DATE_TIME': autor[8]
                    }
            
            users_data = generator_userDataDB(False)
            users_data_dict = {}
            for user in users_data:
                users_data_dict[user['username']] = user
            
            if users_data_dict[AUTHOR_LOGIN]['name'] not in [a['NAME_AUTHOR'] for a in author_data.values()]:
                # dodaj nowego uathora i pobierz jego id
                msq.insert_to_database(
                    """
                    INSERT INTO authors (AVATAR_AUTHOR, NAME_AUTHOR, ABOUT_AUTHOR, FACEBOOK, TWITER_X, INSTAGRAM) 
                    VALUES (%s, %s, %s, %s, %s, %s);
                    """,
                    (
                        users_data_dict[AUTHOR_LOGIN]['avatar'], 
                        users_data_dict[AUTHOR_LOGIN]['name'], 
                        users_data_dict[AUTHOR_LOGIN]['opis'],
                        users_data_dict[AUTHOR_LOGIN]['facebook'],
                        users_data_dict[AUTHOR_LOGIN]['twiter'],
                        users_data_dict[AUTHOR_LOGIN]['instagram']
                    )
                )
                
            ID_AUTHOR = take_data_where_ID(
                'ID', 'authors', 'NAME_AUTHOR', 
                f"""'{users_data_dict[AUTHOR_LOGIN]['name']}'"""
                )[0][0]
        
            zapytanie_sql = '''
                    INSERT INTO contents (
                        TITLE, CONTENT_MAIN, HIGHLIGHTS, HEADER_FOTO, CONTENT_FOTO, BULLETS, TAGS, CATEGORY
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                    '''
            dane = (TYTUL, WSTEP, AKAPIT, MAIN_FOTO, CONTENT_FOTO, PUNKTY, TAGI, KATEGORIA)
            if msq.insert_to_database(zapytanie_sql, dane):
                # Przykładowe dane
                try:
                    ID_NEW_POST_CONTENT = msq.connect_to_database(
                        '''
                            SELECT * FROM contents ORDER BY ID DESC;
                        ''')[0][0]
                except Exception as err:
                    msq.handle_error(f'Błąd podczas tworzenia nowego posta: {err}', log_path=logFileName)
                    flash(f'Błąd podczas tworzenia nowego posta! \n {err}', 'danger')
                    return redirect(url_for('blog'))
            else:
                msq.handle_error(f'Błąd podczas tworzenia nowego posta {TYTUL}!', log_path=logFileName)
                flash(f'Błąd podczas tworzenia nowego posta', 'danger')
                return redirect(url_for('blog'))
            if msq.insert_to_database(
                    '''
                        INSERT INTO blog_posts (CONTENT_ID, AUTHOR_ID) VALUES(%s, %s);
                    ''', 
                    (ID_NEW_POST_CONTENT, ID_AUTHOR)):
                msq.handle_error(f'Dane zostały zapisane poprawnie w tablei blog_posts!', log_path=logFileName)
                flash('Dane zostały zapisane poprawnie!', 'success')
                # add_aifaLog(f'Dodano nowy post o tytule: {TYTUL}. Na temat: {AKAPIT}\nPost został poprawnie zapisany w bazie!')
                addDataLogs(f'Dodano nowy post o tytule: {TYTUL}. Na temat: {AKAPIT}\nPost został poprawnie zapisany w bazie!', 'success')
                
                return redirect(url_for('blog'))
            else:
                msq.handle_error(f'Błąd podczas tworzenia nowego posta!', log_path=logFileName)
                flash(f'Błąd podczas tworzenia nowego posta', 'danger')
                return redirect(url_for('blog'))
        else:
            if update_main_foto and update_content_foto:
                zapytanie_sql = '''
                        UPDATE contents 
                        SET TITLE = %s, 
                            CONTENT_MAIN = %s, 
                            HIGHLIGHTS = %s, 
                            HEADER_FOTO = %s, 
                            CONTENT_FOTO = %s, 
                            BULLETS = %s, 
                            TAGS = %s,
                            CATEGORY = %s
                        WHERE ID = %s;
                    '''
                dane = (TYTUL, WSTEP, AKAPIT, MAIN_FOTO, CONTENT_FOTO, PUNKTY, TAGI, KATEGORIA, int(set_form_id))
            if not update_main_foto and update_content_foto:
                zapytanie_sql = '''
                        UPDATE contents 
                        SET TITLE = %s, 
                            CONTENT_MAIN = %s, 
                            HIGHLIGHTS = %s, 
                            CONTENT_FOTO = %s, 
                            BULLETS = %s, 
                            TAGS = %s,
                            CATEGORY = %s
                        WHERE ID = %s;
                    '''
                dane = (TYTUL, WSTEP, AKAPIT, CONTENT_FOTO, PUNKTY, TAGI, KATEGORIA, int(set_form_id))
            if update_main_foto and not update_content_foto:
                zapytanie_sql = '''
                        UPDATE contents 
                        SET TITLE = %s, 
                            CONTENT_MAIN = %s, 
                            HIGHLIGHTS = %s, 
                            HEADER_FOTO = %s, 
                            BULLETS = %s, 
                            TAGS = %s,
                            CATEGORY = %s
                        WHERE ID = %s;
                    '''
                dane = (TYTUL, WSTEP, AKAPIT, MAIN_FOTO, PUNKTY, TAGI, KATEGORIA, int(set_form_id))
            if not update_main_foto and not update_content_foto:
                zapytanie_sql = '''
                        UPDATE contents 
                        SET TITLE = %s, 
                            CONTENT_MAIN = %s, 
                            HIGHLIGHTS = %s, 
                            BULLETS = %s, 
                            TAGS = %s,
                            CATEGORY = %s
                        WHERE ID = %s;
                    '''
                dane = (TYTUL, WSTEP, AKAPIT, PUNKTY, TAGI, KATEGORIA, int(set_form_id))
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Post {TYTUL} został poprawnie zapisany w bazie!', log_path=logFileName)
                flash('Dane zostały zapisane poprawnie!', 'success')
                return redirect(url_for('blog'))
        
            flash('Dane zostały zapisane poprawnie!', 'success')
            print('Dane zostały zapisane poprawnie!')
            
            return redirect(url_for('blog'))
    msq.handle_error(f'BŁĄD! Post {TYTUL} nie został poprawnie zapisany w bazie!', log_path=logFileName)
    addDataLogs(f'BŁĄD! Post {TYTUL} nie został poprawnie zapisany w bazie!', 'danger')
    flash('Błąd!', 'danger')
    return redirect(url_for('index'))

@app.route('/remove-post', methods=['POST'])
def remove_post():
    """Usuwanie bloga"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /remove-post bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['blog'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /remove-post bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()
        try: form_data['PostID']
        except KeyError: return redirect(url_for('index'))
        set_post_id = int(form_data['PostID'])
        msq.delete_row_from_database(
                """
                    DELETE FROM blog_posts WHERE ID = %s;
                """,
                (set_post_id,)
            )
        
        msq.delete_row_from_database(
                """
                    DELETE FROM contents WHERE ID = %s;
                """,
                (set_post_id,)
            )
        msq.handle_error(f'Post o id: {set_post_id} został usuniety przez {session["username"]}!', log_path=logFileName)
        flash("Wpis został usunięty.", "success")
        return redirect(url_for('blog'))
    
    return redirect(url_for('index'))

@app.route('/remove-comment', methods=['POST'])
def remove_comment():
    """Usuwanie komentarza"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /remove-comment bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['commnets'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /remove-comment bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        form_data = request.form.to_dict()

        try: form_data['comment_id']
        except KeyError: return redirect(url_for('index'))
        set_comm_id = int(form_data['comment_id'])

        # print(set_comm_id)
        msq.delete_row_from_database(
                """
                    DELETE FROM comments WHERE ID = %s;
                """,
                (set_comm_id,)
            )
        addDataLogs(f'Komentarz o id:{set_comm_id} został usunięty przez {session["username"]}!', 'success')
        msq.handle_error(f'Komentarz o id:{set_comm_id} został usunięty przez {session["username"]}!', log_path=logFileName)
        if form_data['page'] == 'subs':
            flash("Wpis został usunięty.", "success")
            return redirect(url_for('subscribers'))
        if form_data['page'] == 'blog':
            flash("Wpis został usunięty.", "success")
            return redirect(url_for('blog'))
        
    return redirect(url_for('index'))

@app.route('/remove-subscriber', methods=['POST'])
def remove_subscriber():
    """Usuwanie subscribera"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /remove-subscriber bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['subscribers'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /remove-subscriber bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        form_data = request.form.to_dict()
        try: form_data['SubasID']
        except KeyError: return redirect(url_for('index'))
        set_subs_id = int(form_data['SubasID'])
        zapytanie_sql = '''
                UPDATE newsletter 
                SET CLIENT_EMAIL = %s, 
                    ACTIVE = %s, 
                    USER_HASH = %s
                WHERE ID = %s;
            '''
        dane = ('john@doe.removed.user', 404, 'REMOVED404', set_subs_id)
        if msq.insert_to_database(zapytanie_sql, dane):
            msq.handle_error(f'Subskryber został usunięty przez {session["username"]}!', log_path=logFileName)
            flash('Subskryber został usunięty!', 'success')
            return redirect(url_for('subscribers'))
        
    msq.handle_error(f'UWAGA! Błąd usuwania Subskrybenta przez {session["username"]}!', log_path=logFileName)
    flash('Błąd usuwania Subskrybenta!', 'danger')
    return redirect(url_for('subscribers'))

@app.route('/set-newsletter-plan', methods=['POST'])
def set_plan():
    """Usuwanie planu"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /set-newsletter-plan bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['newsletter'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /set-newsletter-plan bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        form_data = request.form.to_dict()
        # print(form_data)
        PLAN_NAME = int(form_data['plan_name'])
        zapytanie_sql = '''
                UPDATE newsletter_setting 
                SET time_interval_minutes = %s
                WHERE ID = %s;
            '''
        dane = (PLAN_NAME, 1)
        if msq.insert_to_database(zapytanie_sql, dane):
            msq.handle_error(f'Plan {PLAN_NAME} został aktywowany przez {session["username"]}!', log_path=logFileName)
            flash('Plan został aktywowany!', 'success')
            msq.connect_to_database(
                """
                    TRUNCATE TABLE schedule;
                """
            )
            msq.handle_error(f'Tabela schedule został wyczysczona pod plan {PLAN_NAME} przez {session["username"]}!', log_path=logFileName)
            flash(f'Tabela schedule została przygotowana dla planu {PLAN_NAME}!', 'success')
            return redirect(url_for('newsletter'))

    return redirect(url_for('newsletter'))

@app.route('/set-newsletter-sender', methods=['POST'])
def set_sender():
    """Usuwanie planu"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /set-newsletter-sender bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['newsletter'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /set-newsletter-sender bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        form_data = request.form.to_dict()
        # print(form_data)
        SENDER_EMAIL = form_data['sender_email']
        SENDER_URL = form_data['sender_url']
        SENDER_PORT = int(form_data['sender_port'])
        SENDER_PASSWORD = form_data['sender_password']

        zapytanie_sql = """
                UPDATE newsletter_setting 
                SET config_smtp_server = %s,
                    config_smtp_port = %s,
                    config_smtp_username = %s,
                    config_smtp_password = %s
                WHERE ID = %s;
            """
        dane = (SENDER_URL, SENDER_PORT, SENDER_EMAIL, SENDER_PASSWORD, 1)
        
        if msq.insert_to_database(zapytanie_sql, dane):
            msq.handle_error(f'Nadawca został ustawiony przez {session["username"]}!', log_path=logFileName)
            flash('Nadawca został ustawiony!', 'success')
            return redirect(url_for('newsletter'))
    
    msq.handle_error(f'UWAGA! Błąd nadawca nie został ustawiony przez {session["username"]}!', log_path=logFileName)
    flash('Błąd! Nadawca nie został ustawiony!', 'danger')
    return redirect(url_for('newsletter'))

@app.route('/set-settings', methods=['POST'])
def set_settings():
    """settings"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /set-settings bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['settings'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /set-settings bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        form_data = request.form.to_dict()

        upload_path = f'{settingsDB.get("real-location-on-server", "/var/www/html/appdmddomy/public/")}{settingsDB.get("estate-pic-offer", "images/")}'
        logoPic = request.files.get(f'tmpl_logo')
        
        if logoPic:  # Sprawdza, czy plik został przesłany
            if allowed_file(logoPic.filename) and logoPic.filename.lower().endswith('.png'):
                logo_filename = "logo.png"
                full_path = os.path.join(upload_path, logo_filename)
                logoPic.save(full_path)
                flash('Plik nakładki został załadowany!', 'success')
            else:
                flash('Nieprawidłowy plik. Tylko pliki PNG są dozwolone.', 'danger')
        
       
        ADMIN_DOMAIN = form_data['main-domain']
        ADMIN_REALLOC = form_data['real-loc-on-server']
        ADMIN_BLOG = form_data['blog-pic-path']
        ADMIN_AVATAR = form_data['avatar-pic-path']
        ADMIN_ESTATE = form_data['estate-pic-path']
        ADMIN_PRESENTATIONS = form_data['presentations-path']
        ADMIN_ITEMS = form_data['item-on-page']
        ADMIN_EMAIL = form_data['admin-smtp-username']
        ADMIN_SERVER = form_data['admin-smtp-server']
        ADMIN_PORT = form_data['admin-smtp-port']
        ADMIN_URL_DOMY = form_data['url-domy']
        ADMIN_URL_BUDOWNICTWO = form_data['url-budownictwo']
        ADMIN_URL_DEVELOPMENT = form_data['url-development']
        ADMIN_URL_ELITEHOME = form_data['url-elitehome']
        ADMIN_URL_INWESTYCJE = form_data['url-inwestycje']
        ADMIN_URL_INSTALACJE = form_data['url-instalacje']

        ADMIN_PASSWORD = form_data['admin-smtp-password']
        if not ADMIN_PASSWORD:
            
            zapytanie_sql = '''
                    UPDATE admin_settings 
                    SET pagination = %s,

                        instalacje = %s,
                        inwestycje = %s,
                        elitehome = %s,
                        development = %s,
                        budownictwo = %s,
                        domy = %s,

                        avatar_pic_path = %s,
                        blog_pic_path = %s,
                        main_domain = %s,
                        real_location_on_server = %s,
                        estate_pic_offer = %s,
                        presentation_files = %s
                    WHERE ID = %s;
                '''
            dane = (
                        ADMIN_ITEMS, 

                        ADMIN_URL_INSTALACJE, 
                        ADMIN_URL_INWESTYCJE, 
                        ADMIN_URL_ELITEHOME,
                        ADMIN_URL_DEVELOPMENT,
                        ADMIN_URL_BUDOWNICTWO,
                        ADMIN_URL_DOMY,

                        ADMIN_AVATAR,
                        ADMIN_BLOG, 
                        ADMIN_DOMAIN,
                        ADMIN_REALLOC,
                        ADMIN_ESTATE,
                        ADMIN_PRESENTATIONS, 1)
        else:
            zapytanie_sql = '''
                    UPDATE admin_settings 
                    SET pagination = %s,
                        admin_smtp_password = %s,
                        admin_smtp_usernam = %s,
                        admin_smtp_port = %s,
                        admin_smtp_server = %s,
                        instalacje = %s,
                        inwestycje = %s,
                        elitehome = %s,
                        development = %s,
                        budownictwo = %s,
                        domy = %s,

                        avatar_pic_path = %s,
                        blog_pic_path = %s,
                        main_domain = %s,
                        real_location_on_server = %s,
                        estate_pic_offer = %s,
                        presentation_files = %s
                    WHERE ID = %s;
                '''
            dane = (
                    ADMIN_ITEMS, 

                    ADMIN_PASSWORD,
                    ADMIN_EMAIL, 
                    ADMIN_PORT, 
                    ADMIN_SERVER, 

                    ADMIN_URL_INSTALACJE, 
                    ADMIN_URL_INWESTYCJE, 
                    ADMIN_URL_ELITEHOME,
                    ADMIN_URL_DEVELOPMENT,
                    ADMIN_URL_BUDOWNICTWO,
                    ADMIN_URL_DOMY,

                    ADMIN_AVATAR,
                    ADMIN_BLOG, 
                    ADMIN_DOMAIN,
                    ADMIN_REALLOC,
                    ADMIN_ESTATE,
                    ADMIN_PRESENTATIONS, 1)
        if msq.insert_to_database(zapytanie_sql, dane):
            msq.handle_error(f'Ustawienia zapisane przez {session["username"]}!', log_path=logFileName)
            addDataLogs(f'Ustawienia zapisane przez {session["username"]}!', 'success')
            flash('Ustawienia zapisane!', 'success')
            return redirect(url_for('settings'))
    
    msq.handle_error(f'UWAGA! Błąd podczas zapisu ustawień przez {session["username"]}!', log_path=logFileName)
    flash('Błąd podczas zapisu ustawień!', 'danger')
    return redirect(url_for('settings'))

@app.route('/user')
def users():
    """Strona z zarządzaniem użytkownikami."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /user bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['users'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /user bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    userDataDB = generator_userDataDB(False)
    all_users = userDataDB

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(all_users)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    users = all_users[offset: offset + per_page]
    
    # Renderowanie szablonu blog-managment.html z danymi o postach (wszystkimi lub po jednym)
    settingsDB = generator_settingsDB()

    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']
    logins = [x['username'] for x in all_users]
    emails = [x['email'] for x in all_users]
    names = [x['name'] for x in all_users]

    brands_DICT, perms_DICT = get_BrandAndPerm()

    return render_template(
        "user_management.html", 
        users=users, 
        logins=logins,
        emails=emails,
        names=names,
        username=session['username'], 
        userperm=session['userperm'], 
        pagination=pagination,
        domy=domy,
        budownictwo=budownictwo,
        development=development,
        elitehome=elitehome,
        inwestycje=inwestycje,
        instalacje=instalacje,
        brands_DICT=brands_DICT, 
        perms_DICT=perms_DICT
    )

@app.route('/newsletter')
def newsletter():
    """Strona Newslettera."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /newsletter bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['newsletter'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /newsletter bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    newsletterSettingDB = generator_newsletterSettingDB()
    newsletterPlan = newsletterSettingDB['time_interval_minutes']
    smtpSettingsDict = newsletterSettingDB['smtp_config']
    # Sortuj subsDataDB według klucza 'id' w malejącej kolejności
    sorted_subs = sorted(
                        generator_subsDataDB(), 
                        key=lambda x: x['id'], 
                        reverse=True)

    sortedListSubs = []
    # Dodaj najwyższe sześć pozycji do sortedListSubs
    for item in sorted_subs[:6]:
        if item['status'] == '1':
            elementItem = (item['id'], item['name'], item['email'])
            sortedListSubs.append(elementItem)


    return render_template(
            "newsletter_management.html", 
            username=session['username'],
            userperm=session['userperm'], 
            newsletterPlan=newsletterPlan, 
            smtpSettingsDict=smtpSettingsDict,
            sortedListSubs=sortedListSubs,
            )

def preparoator_team(deaprtment_team='domy', highlight=4):
    highlight += 1
    users_atributes = {}
    assigned_dmddomy = []
    
    for usr_d in generator_userDataDB(False):
        u_name = usr_d['name']
        u_login = usr_d['username']
        users_atributes[u_name] = usr_d
        if usr_d['brands'][f'{deaprtment_team}'] == 1:
            assigned_dmddomy.append(u_login)

    collections = {
            f'{deaprtment_team}': {
                'home': [],
                'team': [],
                'available': []
            }
        }

    employee_photo_dict = {}

    i_domy = 1 
    for employees in generator_teamDB():
        group = employees['EMPLOYEE_DEPARTMENT']
        department = str(group).replace('dmd ', '')
        employee = employees['EMPLOYEE_NAME']
        employee_login = users_atributes[employee]['username']

        employee_photo = users_atributes[employee]['avatar']
        try: employee_photo_dict[employee_login]
        except KeyError: employee_photo_dict[employee_login] = employee_photo
        
        if i_domy < highlight and department == f'{deaprtment_team}':
            collections[department]['home'].append(employee_login)
        elif i_domy >= highlight and department == f'{deaprtment_team}':
            collections[department]['team'].append(employee_login)
        if department == f'{deaprtment_team}':
            i_domy += 1
        
    for assign in assigned_dmddomy:
        if assign not in collections[f'{deaprtment_team}']['home'] + collections[f'{deaprtment_team}']['team']:
            collections[f'{deaprtment_team}']['available'].append(assign)

            for row in generator_userDataDB(False):
                if row['username'] == assign:
                    employee_photo = row['avatar']
                    try: employee_photo_dict[assign]
                    except KeyError: employee_photo_dict[assign] = employee_photo
    return {
        "collections": collections[f'{deaprtment_team}'],
        "employee_photo_dict": employee_photo_dict
    }

@app.route('/team-domy')
def team_domy():
    """Strona zespołu domy."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /team-domy bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['team'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /team-domy bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))

    preparoator_team_dict = preparoator_team('domy', 4)


    # update sesji userperm brands
    permTempDict = {}
    brands_data = {}
    for un in generator_userDataDB(False): 
        permTempDict[un['username']] = un['uprawnienia']
        brands_data[un['username']] = un['brands']

    session['userperm'] = permTempDict[session['username']]
    session['brands'] = brands_data[session['username']]

    return render_template(
                            "team_management_domy.html", 
                            username=session['username'],
                            userperm=session['userperm'], 
                            user_brands=session['brands'], 
                            members=preparoator_team_dict['collections'], 
                            photos_dict=preparoator_team_dict['employee_photo_dict']
                            )

@app.route('/team-budownictwo')
def team_budownictwo():
    """Strona zespołu budownictwo."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /team-budownictwo bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['team'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /team-budownictwo bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))

    preparoator_team_dict = preparoator_team('budownictwo', 4)

    # update sesji userperm brands
    permTempDict = {}
    brands_data = {}
    for un in generator_userDataDB(False): 
        permTempDict[un['username']] = un['uprawnienia']
        brands_data[un['username']] = un['brands']

    session['userperm'] = permTempDict[session['username']]
    session['brands'] = brands_data[session['username']]

    return render_template(
            "team_management_budownictwo.html", 
            username=session['username'],
            userperm=session['userperm'], 
            user_brands=session['brands'], 
            members=preparoator_team_dict['collections'], 
            photos_dict=preparoator_team_dict['employee_photo_dict']
            )

@app.route('/team-development')
def team_development():
    """Strona zespołu development."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /team-development bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['team'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /team-development bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))

    preparoator_team_dict = preparoator_team('development', 2)

    # update sesji userperm brands
    permTempDict = {}
    brands_data = {}
    for un in generator_userDataDB(False): 
        permTempDict[un['username']] = un['uprawnienia']
        brands_data[un['username']] = un['brands']

    session['userperm'] = permTempDict[session['username']]
    session['brands'] = brands_data[session['username']]

    return render_template(
            "team_management_development.html", 
            username=session['username'],
            userperm=session['userperm'], 
            user_brands=session['brands'], 
            members=preparoator_team_dict['collections'], 
            photos_dict=preparoator_team_dict['employee_photo_dict']
            )

@app.route('/team-elitehome')
def team_elitehome():
    """Strona zespołu elitehome."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /team-elitehome bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['team'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /team-elitehome bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))

    preparoator_team_dict = preparoator_team('elitehome', 0)

    # update sesji userperm brands
    permTempDict = {}
    brands_data = {}
    for un in generator_userDataDB(False): 
        permTempDict[un['username']] = un['uprawnienia']
        brands_data[un['username']] = un['brands']

    session['userperm'] = permTempDict[session['username']]
    session['brands'] = brands_data[session['username']]

    return render_template(
            "team_management_elitehome.html", 
            username=session['username'],
            userperm=session['userperm'], 
            user_brands=session['brands'], 
            members=preparoator_team_dict['collections'], 
            photos_dict=preparoator_team_dict['employee_photo_dict']
            )

@app.route('/team-inwestycje')
def team_inwestycje():
    """Strona zespołu inwestycje."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /team-inwestycje bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['team'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /team-inwestycje bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))

    preparoator_team_dict = preparoator_team('inwestycje', 4)

    # update sesji userperm brands
    permTempDict = {}
    brands_data = {}
    for un in generator_userDataDB(False): 
        permTempDict[un['username']] = un['uprawnienia']
        brands_data[un['username']] = un['brands']

    session['userperm'] = permTempDict[session['username']]
    session['brands'] = brands_data[session['username']]

    return render_template(
            "team_management_inwestycje.html", 
            username=session['username'],
            userperm=session['userperm'], 
            user_brands=session['brands'], 
            members=preparoator_team_dict['collections'], 
            photos_dict=preparoator_team_dict['employee_photo_dict'],
            )

@app.route('/team-instalacje')
def team_instalacje():
    """Strona zespołu instalacje."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /team-instalacje bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['team'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /team-instalacje bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))

    preparoator_team_dict = preparoator_team('instalacje', 3)

    # update sesji userperm brands
    permTempDict = {}
    brands_data = {}
    for un in generator_userDataDB(False): 
        permTempDict[un['username']] = un['uprawnienia']
        brands_data[un['username']] = un['brands']

    session['userperm'] = permTempDict[session['username']]
    session['brands'] = brands_data[session['username']]

    return render_template(
            "team_management_instalacje.html", 
            username=session['username'],
            userperm=session['userperm'], 
            user_brands=session['brands'], 
            members=preparoator_team_dict['collections'], 
            photos_dict=preparoator_team_dict['employee_photo_dict']
            )

@app.route('/realization-domy-kategorie')
def realization_domy_kategorie():
    """Strona z zarządzaniem blogiem."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Nieautoryzowana próba dostępu do endpointa: /realization-domy-list', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['realizations'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /realization-domy-list bez uprawnień do zarządzania.', log_path=logFileName)
        return redirect(url_for('index'))
    
    db = get_db()
    query = """
        SELECT *
        FROM realizacje_domy_kategorie;
    """
    all_posts = db.getFrom(query, as_dict=True)

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(all_posts)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    posts = all_posts[offset: offset + per_page]

    return render_template(
        "realization_dmddomy_kategorie.html", 
        posts=posts, 
        username=session['username'], 
        userperm=session['userperm'],
        user_brands=session['brands'],
        pagination=pagination
    )

@app.route('/save-kategorie-domy', methods=['GET', 'POST'])
def save_kategorie_domy():
    """Strona zapisywania edytowanej kategorii dmddomy."""

    # --- 1) Autoryzacja ---
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error('UWAGA! Wywołanie /save-kategorie-domy bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))

    if session.get('userperm', {}).get('realizations', 0) == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /save-kategorie-domy bez uprawnień przez {session.get("username")}', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj się z administratorem!', 'danger')
        return redirect(url_for('index'))

    # --- 2) GET -> wróć do listy (tu nie renderujemy formularza edycji) ---
    if request.method == 'GET':
        return redirect(url_for('realization_domy_kategorie'))

    # --- 3) POST: zbierz dane ---
    form_data = request.form.to_dict()

    # Preferuj jawne pole hidden "formid"
    set_form_id = form_data.get('formid')
    try:
        # walidacja do liczby (ale trzymaj typ str do składania kluczy w form_data)
        int(set_form_id)
    except (TypeError, ValueError):
        msq.handle_error('Błąd! Nieprawidłowe formid.', log_path=logFileName)
        flash('Nieprawidłowy identyfikator formularza.', 'danger')
        return redirect(url_for('realization_domy_kategorie'))

    # Zabezpieczenie: odczytaj pola z sufiksem _{id}
    try:
        NAZWA       = form_data[f'nazwa_{set_form_id}']     .strip()
        OPIS        = form_data[f'opis_{set_form_id}']      .strip()
        URL_EP      = form_data[f'url_{set_form_id}']       .strip()
        RODZAJ      = form_data[f'rodzaj_{set_form_id}']    .strip()
    except KeyError as e:
        msq.handle_error(f'Brak wymaganych pól: {e}', log_path=logFileName)
        flash('Brakuje danych formularza.', 'danger')
        return redirect(url_for('realization_domy_kategorie'))

    # walidujemy adres endpointa
    if not URL_EP.startswith("/"):
        flash('Adres endpointa musi się zaczynać od /', 'danger')
        return redirect(url_for('realization_domy_kategorie'))

    # --- 4) Ścieżki i upload ---
    settings = generator_settingsDB()  # UJEDNOLICONE użycie
    get_base_cfg  = settings.get('real-location-on-server', '')
    base_root   = get_base_cfg.rstrip('/') # np. '/var/www/html/appdmddomy/public/'
    pics_rel    = (settings.get('blog-pic-path') or '').lstrip('/')  # np. 'images/realizacje/'
    upload_dir  = os.path.join(base_root, pics_rel)
    url_base    = settings.get('main-domain', '')                     # np. 'https://dmddomy.pl/'
    url_path    = settings.get('blog-pic-path', '')                    # np. '/images/realizacje/' lub 'images/...'

    # upewnij się, że katalog istnieje
    os.makedirs(upload_dir, exist_ok=True)

    # Wspólna obsługa uploadu (zwraca (filename, public_url) albo (None, None))
    def handle_upload(field_name: str):
        f = request.files.get(field_name)
        if not f or not f.filename:
            return None, None
        if not allowed_file(f.filename):
            flash('Niedozwolony format pliku (dozwolone: jpg, jpeg, png, webp).', 'danger')
            return None, None
        fname = f'{int(time.time())}_{secure_filename(f.filename)}'
        f.save(os.path.join(upload_dir, fname))
        # Zadbaj, by url_path miał separator między domeną a ścieżką
        public = (url_base.rstrip('/') + '/' + url_path.lstrip('/')).rstrip('/') + '/' + fname
        return fname, public

    MAIN_FOTO_URL = None

    # --- 5) Rozróżnienie create vs update ---
    is_create = (set_form_id == '9999999')
    db = get_db()
    if is_create:
        # wymagamy zdjęcia głównego przy tworzeniu? (jeśli nie, usuń ten warunek)
        fname, MAIN_FOTO_URL = handle_upload(f'mainFoto_{set_form_id}')
        # Tu możesz zdecydować czy zdjęcie jest obowiązkowe:
        if not MAIN_FOTO_URL:
            flash('Dodaj zdjęcie główne.', 'danger')
            return redirect(url_for('realization_domy_kategorie'))
        
        insert_sql = '''
            INSERT INTO realizacje_domy_kategorie (
                rodzaj,
                nazwa,
                opis,
                zdjecie,
                ep_url
            ) VALUES (%s, %s, %s, %s, %s);
        '''
        params = (RODZAJ, NAZWA, OPIS, MAIN_FOTO_URL, URL_EP)

        if not db.executeTo(query=insert_sql, params=params):
            msq.handle_error(f'Błąd podczas tworzenia nowego posta: {NAZWA}', log_path=logFileName)
            flash('Błąd podczas tworzenia nowego posta.', 'danger')
            return redirect(url_for('realization_domy_kategorie'))

        msq.handle_error(f'Nowa realizacja utworzona: {NAZWA} przez {session.get("username")}', log_path=logFileName)
        flash('Nowy wpis został dodany.', 'success')
        return redirect(url_for('realization_domy_kategorie'))

    else:
        # UPDATE
        # spróbuj pobrać ewentualny nowy plik
        fname, MAIN_FOTO_URL = handle_upload(f'mainFoto_{set_form_id}')

        # Pobierz stare URL zdjęcia (zanim zrobisz UPDATE)
        dbFetchOne = get_db()
        dbFetchOne.fetch_one(
            query="SELECT zdjecie FROM realizacje_domy_kategorie WHERE id=%s",
            params=(int(set_form_id), )
        )
        old_photo_url = getattr(dbFetchOne, "zdjecie", None)

        # składamy SQL zależnie od tego, czy podmieniamy zdjęcie
        fields = [
            ('rodzaj', RODZAJ),
            ('nazwa', NAZWA),
            ('opis', OPIS),
            ('ep_url', URL_EP)
        ]
        params = []

        set_clauses = []
        for col, val in fields:
            set_clauses.append(f"{col} = %s")
            params.append(val)

        if MAIN_FOTO_URL:
            set_clauses.insert(3, "zdjecie = %s")  # np. tuż po kategoria
            params.insert(3, MAIN_FOTO_URL)

        update_sql = f'''
            UPDATE realizacje_domy_kategorie
            SET {", ".join(set_clauses)}
            WHERE id = %s;
        '''
        params.append(int(set_form_id))

        if db.executeTo(query=update_sql, params=tuple(params)):
            # Po udanym UPDATE – jeśli faktycznie było nowe zdjęcie, usuń stare z dysku
            if MAIN_FOTO_URL and old_photo_url:
                # porównuj po nazwie pliku, żeby ignorować domenę / query string
                def _basename(u: str):
                    u = (u or '').split('?', 1)[0].split('#', 1)[0]
                    return os.path.basename(u)

                old_name = _basename(old_photo_url)
                new_name = _basename(MAIN_FOTO_URL)

                if old_name and new_name and old_name != new_name:
                    old_path = os.path.join(upload_dir, old_name)

                    # safety: upewnij się, że kasujesz wewnątrz katalogu uploadów
                    try:
                        upload_dir_real = os.path.realpath(upload_dir)
                        old_path_real = os.path.realpath(old_path)
                        if old_path_real.startswith(upload_dir_real + os.sep) or old_path_real == upload_dir_real:
                            if os.path.exists(old_path_real):
                                try:
                                    os.remove(old_path_real)
                                except OSError as e:
                                    msq.handle_error(f'Nie udało się usunąć starego pliku: {old_path_real} ({e})', log_path=logFileName)
                            else:
                                msq.handle_error(f'Stary plik nie istnieje: {old_path_real}', log_path=logFileName)
                        else:
                            msq.handle_error(f'Ścieżka poza katalogiem uploadów! {old_path_real}', log_path=logFileName)
                    except Exception as e:
                        msq.handle_error(f'Błąd przy weryfikacji/usuwaniu starego pliku: {e}', log_path=logFileName)

            msq.handle_error(f'Kategoria realizacji zaktualizowana: {NAZWA} przez {session.get("username")}', log_path=logFileName)
            flash('Dane zostały zapisane poprawnie!', 'success')
            return redirect(url_for('realization_domy_kategorie'))

        msq.handle_error(f'Błąd UPDATE kategorii realizacji: {NAZWA}', log_path=logFileName)
        flash('Wystąpił błąd podczas zapisu.', 'danger')
        return redirect(url_for('realization_domy_kategorie'))

@app.route('/remove-kategorie-domy', methods=['POST'])
def remove_kategorie_domy():
    """Usuwanie kategorii realizacji"""
    # auth
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error('UWAGA! wywołanie /remove-kategorie-domy bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))

    if session.get('userperm', {}).get('realizations', 0) == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania bez uprawnień przez {session.get("username")}', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj się z administratorem!', 'danger')
        return redirect(url_for('index'))

    # dane z formularza
    form_data = request.form.to_dict()
    try:
        set_post_id = int(form_data.get('PostID'))
    except (TypeError, ValueError):
        flash('Nieprawidłowe ID kategorii.', 'danger')
        return redirect(url_for('realization_domy_kategorie'))

    # Pobierz nazwę kategorii po id
    db_one = get_db()
    db_one.fetch_one(
        query="SELECT nazwa FROM realizacje_domy_kategorie WHERE id=%s",
        params=(set_post_id,)  # tupla!
    )
    curCatname = getattr(db_one, "nazwa", None)

    if not curCatname:
        flash('Kategoria nie istnieje lub została już usunięta.', 'warning')
        return redirect(url_for('realization_domy_kategorie'))

    # Sprawdź, czy są realizacje w tej kategorii (użyj COUNT)
    db_sel = get_db()
    rows = db_sel.getFrom(
        "SELECT COUNT(*) AS cnt FROM realizacje_domy WHERE kategoria=%s",
        params=(curCatname,),
        as_dict=True
    )
    count = int(next(iter(rows), {}).get('cnt', 0))

    if count > 0:
        flash('Aby usunąć kategorię, najpierw usuń lub przenieś wszystkie realizacje przypisane do tej kategorii.', 'danger')
        return redirect(url_for('realization_domy_kategorie'))

    photo_link = form_data.get('photoLink', '') or ''

    # helper
    def prepareFileName(raw_link: str):
        checkExt = {'jpg', 'jpeg', 'png'}
        last_part = os.path.basename(raw_link.split('?', 1)[0].split('#', 1)[0])
        ext = last_part.rsplit('.', 1)[-1].lower() if '.' in last_part else ''
        return last_part if ext in checkExt else None

    filename = prepareFileName(photo_link)
    if not filename:
        msq.handle_error('UWAGA! Niewłaściwa nazwa fotografii!', log_path=logFileName)
        flash('Błąd usuwania fotografii z serwera (nieprawidłowa nazwa).', 'danger')
        return redirect(url_for('realization_domy_kategorie'))

    # ścieżka do pliku
    settingsDB = generator_settingsDB()
    pics_dir_cfg = settingsDB.get('blog-pic-path', '')  # np. 'images/realizacje/'
    get_base_cfg  = settingsDB.get('real-location-on-server', '')
    # Upewnij się, że to względna ścieżka
    pics_dir_rel = pics_dir_cfg.lstrip('/')
    base_got = get_base_cfg.rstrip('/')
    base_root = base_got # np. '/var/www/html/appdmddomy/public'
    file_path = os.path.join(base_root, pics_dir_rel, filename)

    db = get_db()
    try:
        # Najpierw usuń rekord z DB
        deleted = db.executeTo(
            "DELETE FROM realizacje_domy_kategorie WHERE id = %s;",
            (set_post_id,)
        )

        if not deleted:
            flash('Nie znaleziono wpisu do usunięcia.', 'warning')
            return redirect(url_for('realization_domy_kategorie'))

        # Potem spróbuj usunąć plik (jeśli istnieje)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError as e:
                msq.handle_error(f'UWAGA! Nie udało się usunąć pliku: {file_path} ({e})', log_path=logFileName)
                # Nie wywracamy procesu – rekord już usunięty. Tylko komunikat:
                flash('Wpis usunięty. Nie udało się usunąć pliku zdjęcia (zalogowano błąd).', 'warning')
        else:
            # Brak pliku – logujemy, ale nie traktujemy jako błąd krytyczny
            msq.handle_error(f'Plik nie istnieje: {file_path}', log_path=logFileName)

        msq.handle_error(f'Kategoria id={set_post_id} usunięta przez {session["username"]}', log_path=logFileName)
        flash('Kategoria został usunięty.', 'success')
        return redirect(url_for('realization_domy_kategorie'))

    except Exception as e:
        msq.handle_error(f'Błąd przy usuwaniu kategorii id={set_post_id}: {e}', log_path=logFileName)
        flash('Wystąpił błąd podczas usuwania kategorii.', 'danger')
        return redirect(url_for('realization_domy_kategorie'))


@app.route('/realization-domy-list')
def realization_domy_list():
    """Strona z zarządzaniem realizacjami dmddomy."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Nieautoryzowana próba dostępu do endpointa: /realization-domy-list', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['realizations'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /realization-domy-list bez uprawnień do zarządzania.', log_path=logFileName)
        return redirect(url_for('index'))
    
    db_cater = get_db()
    rows = db_cater.getFrom(
        "SELECT DISTINCT nazwa FROM realizacje_domy_kategorie WHERE nazwa IS NOT NULL AND nazwa <> '' ORDER BY nazwa;",
        as_dict=True
    )
    categories = [r['nazwa'].strip() for r in rows if r.get('nazwa') and r['nazwa'].strip()]


    db = get_db()
    query = """
        SELECT *
        FROM realizacje_domy
        ORDER BY r_finish DESC;
    """
    all_posts = db.getFrom(query, as_dict=True)

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(all_posts)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    posts = all_posts[offset: offset + per_page]

    return render_template(
            "realization_dmddomy_list.html", 
            posts=posts, 
            username=session['username'], 
            userperm=session['userperm'],
            user_brands=session['brands'],
            categories=categories,
            pagination=pagination,
            )

@app.route('/save-realizacje-domy', methods=['GET', 'POST'])
def save_realizacje_domy():
    """Strona zapisywania edytowanej realizacji."""

    # --- 1) Autoryzacja ---
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error('UWAGA! Wywołanie /save-realizacje-domy bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))

    if session.get('userperm', {}).get('realizations', 0) == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /save-realizacje-domy bez uprawnień przez {session.get("username")}', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj się z administratorem!', 'danger')
        return redirect(url_for('index'))

    # --- 2) GET -> wróć do listy (tu nie renderujemy formularza edycji) ---
    if request.method == 'GET':
        return redirect(url_for('realization_domy_list'))

    # --- 3) POST: zbierz dane ---
    form_data = request.form.to_dict()

    # Preferuj jawne pole hidden "formid"
    set_form_id = form_data.get('formid')
    try:
        # walidacja do liczby (ale trzymaj typ str do składania kluczy w form_data)
        int(set_form_id)
    except (TypeError, ValueError):
        msq.handle_error('Błąd! Nieprawidłowe formid.', log_path=logFileName)
        flash('Nieprawidłowy identyfikator formularza.', 'danger')
        return redirect(url_for('realization_domy_list'))

    # Zabezpieczenie: odczytaj pola z sufiksem _{id}
    try:
        TYTUL       = form_data[f'title_{set_form_id}']     .strip()
        OPIS        = form_data[f'opis_{set_form_id}']      .strip()
        KATEGORIA   = form_data[f'category_{set_form_id}']  .strip()
        RSTART      = form_data[f'rstart_{set_form_id}']    .strip()
        RFINISH     = form_data[f'rfinish_{set_form_id}']   .strip()
    except KeyError as e:
        msq.handle_error(f'Brak wymaganych pól: {e}', log_path=logFileName)
        flash('Brakuje danych formularza.', 'danger')
        return redirect(url_for('realization_domy_list'))

    # walidujemy r_start/r_finish jako int/rok
    try:
        RSTART_i  = int(RSTART)
        RFINISH_i = int(RFINISH)
    except ValueError:
        flash('Rok rozpoczęcia/zakończenia musi być liczbą.', 'danger')
        return redirect(url_for('realization_domy_list'))

    if RSTART_i > RFINISH_i:
        flash('Rok zakończenia nie może być wcześniejszy niż rozpoczęcia.', 'danger')
        return redirect(url_for('realization_domy_list'))


        # --- 4) Ścieżki i upload ---
    settings = generator_settingsDB()  # UJEDNOLICONE użycie
    get_base_cfg  = settings.get('real-location-on-server', '')
    base_root   = get_base_cfg.rstrip('/') # np. '/var/www/html/appdmddomy/public/'
    pics_rel    = (settings.get('blog-pic-path') or '').lstrip('/')  # np. 'images/realizacje/'
    upload_dir  = os.path.join(base_root, pics_rel)
    url_base    = settings.get('main-domain', '')                     # np. 'https://dmddomy.pl/'
    url_path    = settings.get('blog-pic-path', '')                    # np. '/images/realizacje/' lub 'images/...'

    # upewnij się, że katalog istnieje
    os.makedirs(upload_dir, exist_ok=True)

    # Wspólna obsługa uploadu (zwraca (filename, public_url) albo (None, None))
    def handle_upload(field_name: str):
        f = request.files.get(field_name)
        if not f or not f.filename:
            return None, None
        if not allowed_file(f.filename):
            flash('Niedozwolony format pliku (dozwolone: jpg, jpeg, png, webp).', 'danger')
            return None, None
        fname = f'{int(time.time())}_{secure_filename(f.filename)}'
        f.save(os.path.join(upload_dir, fname))
        # Zadbaj, by url_path miał separator między domeną a ścieżką
        public = (url_base.rstrip('/') + '/' + url_path.lstrip('/')).rstrip('/') + '/' + fname
        return fname, public

    MAIN_FOTO_URL = None

    # --- 5) Rozróżnienie create vs update ---
    is_create = (set_form_id == '9999999')
    db = get_db()
    if is_create:
        # wymagamy zdjęcia głównego przy tworzeniu? (jeśli nie, usuń ten warunek)
        fname, MAIN_FOTO_URL = handle_upload(f'mainFoto_{set_form_id}')
        # Tu możesz zdecydować czy zdjęcie jest obowiązkowe:
        if not MAIN_FOTO_URL:
            flash('Dodaj zdjęcie główne.', 'danger')
            return redirect(url_for('realization_domy_list'))
        
        insert_sql = '''
            INSERT INTO realizacje_domy (
                kategoria,
                zdjecie,
                tytul_ogloszenia,
                opis,
                r_start,
                r_finish
            ) VALUES (%s, %s, %s, %s, %s, %s);
        '''
        params = (KATEGORIA, MAIN_FOTO_URL, TYTUL, OPIS, RSTART_i, RFINISH_i)

        if not db.executeTo(query=insert_sql, params=params):
            msq.handle_error(f'Błąd podczas tworzenia nowego posta: {TYTUL}', log_path=logFileName)
            flash('Błąd podczas tworzenia nowego posta.', 'danger')
            return redirect(url_for('realization_domy_list'))

        msq.handle_error(f'Nowa realizacja utworzona: {TYTUL} przez {session.get("username")}', log_path=logFileName)
        flash('Nowy wpis został dodany.', 'success')
        return redirect(url_for('realization_domy_list'))

    else:
        # UPDATE
        # spróbuj pobrać ewentualny nowy plik
        fname, MAIN_FOTO_URL = handle_upload(f'mainFoto_{set_form_id}')

        # Pobierz stare URL zdjęcia (zanim zrobisz UPDATE)
        dbFetchOne = get_db()
        dbFetchOne.fetch_one(
            query="SELECT zdjecie FROM realizacje_domy WHERE id=%s",
            params=(int(set_form_id), )
        )
        old_photo_url = getattr(dbFetchOne, "zdjecie", None)

        # składamy SQL zależnie od tego, czy podmieniamy zdjęcie
        fields = [
            ('kategoria', KATEGORIA),
            ('tytul_ogloszenia', TYTUL),
            ('opis', OPIS),
            ('r_start', RSTART_i),
            ('r_finish', RFINISH_i),
        ]
        params = []

        set_clauses = []
        for col, val in fields:
            set_clauses.append(f"{col} = %s")
            params.append(val)

        if MAIN_FOTO_URL:
            set_clauses.insert(1, "zdjecie = %s")  # np. tuż po kategoria
            params.insert(1, MAIN_FOTO_URL)

        update_sql = f'''
            UPDATE realizacje_domy
            SET {", ".join(set_clauses)}
            WHERE id = %s;
        '''
        params.append(int(set_form_id))

        if db.executeTo(query=update_sql, params=tuple(params)):
            # Po udanym UPDATE – jeśli faktycznie było nowe zdjęcie, usuń stare z dysku
            if MAIN_FOTO_URL and old_photo_url:
                # porównuj po nazwie pliku, żeby ignorować domenę / query string
                def _basename(u: str):
                    u = (u or '').split('?', 1)[0].split('#', 1)[0]
                    return os.path.basename(u)

                old_name = _basename(old_photo_url)
                new_name = _basename(MAIN_FOTO_URL)

                if old_name and new_name and old_name != new_name:
                    # upload_dir masz z góry w tym handlerze
                    old_path = os.path.join(upload_dir, old_name)

                    # safety: upewnij się, że kasujesz wewnątrz katalogu uploadów
                    try:
                        upload_dir_real = os.path.realpath(upload_dir)
                        old_path_real = os.path.realpath(old_path)
                        if old_path_real.startswith(upload_dir_real + os.sep) or old_path_real == upload_dir_real:
                            if os.path.exists(old_path_real):
                                try:
                                    os.remove(old_path_real)
                                except OSError as e:
                                    msq.handle_error(f'Nie udało się usunąć starego pliku: {old_path_real} ({e})', log_path=logFileName)
                            else:
                                msq.handle_error(f'Stary plik nie istnieje: {old_path_real}', log_path=logFileName)
                        else:
                            msq.handle_error(f'Ścieżka poza katalogiem uploadów! {old_path_real}', log_path=logFileName)
                    except Exception as e:
                        msq.handle_error(f'Błąd przy weryfikacji/usuwaniu starego pliku: {e}', log_path=logFileName)

            msq.handle_error(f'Realizacja zaktualizowana: {TYTUL} przez {session.get("username")}', log_path=logFileName)
            flash('Dane zostały zapisane poprawnie!', 'success')
            return redirect(url_for('realization_domy_list'))

        msq.handle_error(f'Błąd UPDATE realizacji: {TYTUL}', log_path=logFileName)
        flash('Wystąpił błąd podczas zapisu.', 'danger')
        return redirect(url_for('realization_domy_list'))


@app.route('/remove-realizacje-domy', methods=['POST'])
def remove_realizacje_domy():
    """Usuwanie realizacji"""
    # auth
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error('UWAGA! wywołanie /remove-realizacje-domy bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))

    if session.get('userperm', {}).get('realizations', 0) == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania bez uprawnień przez {session.get("username")}', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj się z administratorem!', 'danger')
        return redirect(url_for('index'))

    # dane z formularza
    form_data = request.form.to_dict()
    try:
        set_post_id = int(form_data.get('PostID'))
    except (TypeError, ValueError):
        flash('Nieprawidłowe ID wpisu.', 'danger')
        return redirect(url_for('realization_domy_list'))

    photo_link = form_data.get('photoLink', '') or ''

    # helper
    def prepareFileName(raw_link: str):
        checkExt = {'jpg', 'jpeg', 'png'}
        last_part = os.path.basename(raw_link.split('?', 1)[0].split('#', 1)[0])
        ext = last_part.rsplit('.', 1)[-1].lower() if '.' in last_part else ''
        return last_part if ext in checkExt else None

    filename = prepareFileName(photo_link)
    if not filename:
        msq.handle_error('UWAGA! Niewłaściwa nazwa fotografii!', log_path=logFileName)
        flash('Błąd usuwania fotografii z serwera (nieprawidłowa nazwa).', 'danger')
        return redirect(url_for('realization_domy_list'))

    # ścieżka do pliku
    settingsDB = generator_settingsDB()
    pics_dir_cfg = settingsDB.get('blog-pic-path', '')  # np. 'images/realizacje/'
    get_base_cfg  = settingsDB.get('real-location-on-server', '')
    # Upewnij się, że to względna ścieżka
    pics_dir_rel = pics_dir_cfg.lstrip('/')
    base_got = get_base_cfg.rstrip('/')
    base_root = base_got # np. '/var/www/html/appdmddomy/public'
    file_path = os.path.join(base_root, pics_dir_rel, filename)

    db = get_db()
    try:
        # Najpierw usuń rekord z DB
        deleted = db.executeTo(
            "DELETE FROM realizacje_domy WHERE id = %s;",
            (set_post_id,)
        )

        if not deleted:
            flash('Nie znaleziono wpisu do usunięcia.', 'warning')
            return redirect(url_for('realization_domy_list'))

        # Potem spróbuj usunąć plik (jeśli istnieje)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError as e:
                msq.handle_error(f'UWAGA! Nie udało się usunąć pliku: {file_path} ({e})', log_path=logFileName)
                # Nie wywracamy procesu – rekord już usunięty. Tylko komunikat:
                flash('Wpis usunięty. Nie udało się usunąć pliku zdjęcia (zalogowano błąd).', 'warning')
        else:
            # Brak pliku – logujemy, ale nie traktujemy jako błąd krytyczny
            msq.handle_error(f'Plik nie istnieje: {file_path}', log_path=logFileName)

        msq.handle_error(f'Realizacja id={set_post_id} usunięta przez {session["username"]}', log_path=logFileName)
        flash('Wpis został usunięty.', 'success')
        return redirect(url_for('realization_domy_list'))

    except Exception as e:
        msq.handle_error(f'Błąd przy usuwaniu realizacji id={set_post_id}: {e}', log_path=logFileName)
        flash('Wystąpił błąd podczas usuwania wpisu.', 'danger')
        return redirect(url_for('realization_domy_list'))



@app.route('/realization-budownictwo-list')
def realization_budownictwo_list():
    """Strona z zarządzaniem realizacjami dmdbudownictwo."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Nieautoryzowana próba dostępu do endpointa: /realization-budownictwo-list', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['realizations'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /realization-budownictwo-list bez uprawnień do zarządzania.', log_path=logFileName)
        return redirect(url_for('index'))
    
    
    categories = ["Hala", "Edukacja", "Inne"]


    db = get_db()
    query = """
        SELECT *
        FROM realizacje_budownictwo
        ORDER BY r_finish DESC;
    """
    all_posts = db.getFrom(query, as_dict=True)

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(all_posts)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    posts = all_posts[offset: offset + per_page]

    return render_template(
            "realization_dmdbudownictwo_list.html", 
            posts=posts, 
            username=session['username'], 
            userperm=session['userperm'],
            user_brands=session['brands'],
            categories=categories,
            pagination=pagination,
            )

@app.route('/save-realizacje-budownictwo', methods=['GET', 'POST'])
def save_realizacje_budownictwo():
    """Strona zapisywania edytowanej realizacji."""

    # --- 1) Autoryzacja ---
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error('UWAGA! Wywołanie /save-realizacje-budownictwo bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))

    if session.get('userperm', {}).get('realizations', 0) == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /save-realizacje-budownictwo bez uprawnień przez {session.get("username")}', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj się z administratorem!', 'danger')
        return redirect(url_for('index'))

    # --- 2) GET -> wróć do listy (tu nie renderujemy formularza edycji) ---
    if request.method == 'GET':
        return redirect(url_for('realization_budownictwo_list'))

    # --- 3) POST: zbierz dane ---
    form_data = request.form.to_dict()

    # Preferuj jawne pole hidden "formid"
    set_form_id = form_data.get('formid')
    try:
        # walidacja do liczby (ale trzymaj typ str do składania kluczy w form_data)
        int(set_form_id)
    except (TypeError, ValueError):
        msq.handle_error('Błąd! Nieprawidłowe formid.', log_path=logFileName)
        flash('Nieprawidłowy identyfikator formularza.', 'danger')
        return redirect(url_for('realization_budownictwo_list'))

    # Zabezpieczenie: odczytaj pola z sufiksem _{id}
    try:
        TYTUL       = form_data[f'title_{set_form_id}']     .strip()
        OPIS        = form_data[f'opis_{set_form_id}']      .strip()
        KATEGORIA   = form_data[f'category_{set_form_id}']  .strip()
        RSTART      = form_data[f'rstart_{set_form_id}']    .strip()
        RFINISH     = form_data[f'rfinish_{set_form_id}']   .strip()
    except KeyError as e:
        msq.handle_error(f'Brak wymaganych pól: {e}', log_path=logFileName)
        flash('Brakuje danych formularza.', 'danger')
        return redirect(url_for('realization_budownictwo_list'))

    # walidujemy r_start/r_finish jako int/rok
    try:
        RSTART_i  = int(RSTART)
        RFINISH_i = int(RFINISH)
    except ValueError:
        flash('Rok rozpoczęcia/zakończenia musi być liczbą.', 'danger')
        return redirect(url_for('realization_budownictwo_list'))

    if RSTART_i > RFINISH_i:
        flash('Rok zakończenia nie może być wcześniejszy niż rozpoczęcia.', 'danger')
        return redirect(url_for('realization_budownictwo_list'))


        # --- 4) Ścieżki i upload ---
    settings = generator_settingsDB()  # UJEDNOLICONE użycie
    get_base_cfg  = settings.get('real-location-on-server', '')
    base_root   = get_base_cfg.rstrip('/') # np. '/var/www/html/appdmddomy/public/'
    pics_rel    = (settings.get('blog-pic-path') or '').lstrip('/')  # np. 'images/realizacje/'
    upload_dir  = os.path.join(base_root, pics_rel)
    url_base    = settings.get('main-domain', '')                     # np. 'https://dmddomy.pl/'
    url_path    = settings.get('blog-pic-path', '')                    # np. '/images/realizacje/' lub 'images/...'

    # upewnij się, że katalog istnieje
    os.makedirs(upload_dir, exist_ok=True)

    # Wspólna obsługa uploadu (zwraca (filename, public_url) albo (None, None))
    def handle_upload(field_name: str):
        f = request.files.get(field_name)
        if not f or not f.filename:
            return None, None
        if not allowed_file(f.filename):
            flash('Niedozwolony format pliku (dozwolone: jpg, jpeg, png, webp).', 'danger')
            return None, None
        fname = f'{int(time.time())}_{secure_filename(f.filename)}'
        f.save(os.path.join(upload_dir, fname))
        # Zadbaj, by url_path miał separator między domeną a ścieżką
        public = (url_base.rstrip('/') + '/' + url_path.lstrip('/')).rstrip('/') + '/' + fname
        return fname, public

    MAIN_FOTO_URL = None

    # --- 5) Rozróżnienie create vs update ---
    is_create = (set_form_id == '9999999')
    db = get_db()
    if is_create:
        # wymagamy zdjęcia głównego przy tworzeniu? (jeśli nie, usuń ten warunek)
        fname, MAIN_FOTO_URL = handle_upload(f'mainFoto_{set_form_id}')
        # Tu możesz zdecydować czy zdjęcie jest obowiązkowe:
        if not MAIN_FOTO_URL:
            flash('Dodaj zdjęcie główne.', 'danger')
            return redirect(url_for('realization_budownictwo_list'))
        
        insert_sql = '''
            INSERT INTO realizacje_budownictwo (
                kategoria,
                zdjecie,
                tytul_ogloszenia,
                opis,
                r_start,
                r_finish
            ) VALUES (%s, %s, %s, %s, %s, %s);
        '''
        params = (KATEGORIA, MAIN_FOTO_URL, TYTUL, OPIS, RSTART_i, RFINISH_i)

        if not db.executeTo(query=insert_sql, params=params):
            msq.handle_error(f'Błąd podczas tworzenia nowego posta: {TYTUL}', log_path=logFileName)
            flash('Błąd podczas tworzenia nowego posta.', 'danger')
            return redirect(url_for('realization_budownictwo_list'))

        msq.handle_error(f'Nowa realizacja utworzona: {TYTUL} przez {session.get("username")}', log_path=logFileName)
        flash('Nowy wpis został dodany.', 'success')
        return redirect(url_for('realization_budownictwo_list'))

    else:
        # UPDATE
        # spróbuj pobrać ewentualny nowy plik
        fname, MAIN_FOTO_URL = handle_upload(f'mainFoto_{set_form_id}')

        # Pobierz stare URL zdjęcia (zanim zrobisz UPDATE)
        dbFetchOne = get_db()
        dbFetchOne.fetch_one(
            query="SELECT zdjecie FROM realizacje_budownictwo WHERE id=%s",
            params=(int(set_form_id), )
        )
        old_photo_url = getattr(dbFetchOne, "zdjecie", None)

        # składamy SQL zależnie od tego, czy podmieniamy zdjęcie
        fields = [
            ('kategoria', KATEGORIA),
            ('tytul_ogloszenia', TYTUL),
            ('opis', OPIS),
            ('r_start', RSTART_i),
            ('r_finish', RFINISH_i),
        ]
        params = []

        set_clauses = []
        for col, val in fields:
            set_clauses.append(f"{col} = %s")
            params.append(val)

        if MAIN_FOTO_URL:
            set_clauses.insert(1, "zdjecie = %s")  # np. tuż po kategoria
            params.insert(1, MAIN_FOTO_URL)

        update_sql = f'''
            UPDATE realizacje_budownictwo
            SET {", ".join(set_clauses)}
            WHERE id = %s;
        '''
        params.append(int(set_form_id))

        if db.executeTo(query=update_sql, params=tuple(params)):
            # Po udanym UPDATE – jeśli faktycznie było nowe zdjęcie, usuń stare z dysku
            if MAIN_FOTO_URL and old_photo_url:
                # porównuj po nazwie pliku, żeby ignorować domenę / query string
                def _basename(u: str):
                    u = (u or '').split('?', 1)[0].split('#', 1)[0]
                    return os.path.basename(u)

                old_name = _basename(old_photo_url)
                new_name = _basename(MAIN_FOTO_URL)

                if old_name and new_name and old_name != new_name:
                    # upload_dir masz z góry w tym handlerze
                    old_path = os.path.join(upload_dir, old_name)

                    # safety: upewnij się, że kasujesz wewnątrz katalogu uploadów
                    try:
                        upload_dir_real = os.path.realpath(upload_dir)
                        old_path_real = os.path.realpath(old_path)
                        if old_path_real.startswith(upload_dir_real + os.sep) or old_path_real == upload_dir_real:
                            if os.path.exists(old_path_real):
                                try:
                                    os.remove(old_path_real)
                                except OSError as e:
                                    msq.handle_error(f'Nie udało się usunąć starego pliku: {old_path_real} ({e})', log_path=logFileName)
                            else:
                                msq.handle_error(f'Stary plik nie istnieje: {old_path_real}', log_path=logFileName)
                        else:
                            msq.handle_error(f'Ścieżka poza katalogiem uploadów! {old_path_real}', log_path=logFileName)
                    except Exception as e:
                        msq.handle_error(f'Błąd przy weryfikacji/usuwaniu starego pliku: {e}', log_path=logFileName)

            msq.handle_error(f'Realizacja zaktualizowana: {TYTUL} przez {session.get("username")}', log_path=logFileName)
            flash('Dane zostały zapisane poprawnie!', 'success')
            return redirect(url_for('realization_budownictwo_list'))

        msq.handle_error(f'Błąd UPDATE realizacji: {TYTUL}', log_path=logFileName)
        flash('Wystąpił błąd podczas zapisu.', 'danger')
        return redirect(url_for('realization_budownictwo_list'))


@app.route('/remove-realizacje-budownictwo', methods=['POST'])
def remove_realizacje_budownictwo():
    """Usuwanie realizacji"""
    # auth
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error('UWAGA! wywołanie /remove-realizacje-budownictwo bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))

    if session.get('userperm', {}).get('realizations', 0) == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania bez uprawnień przez {session.get("username")}', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj się z administratorem!', 'danger')
        return redirect(url_for('index'))

    # dane z formularza
    form_data = request.form.to_dict()
    try:
        set_post_id = int(form_data.get('PostID'))
    except (TypeError, ValueError):
        flash('Nieprawidłowe ID wpisu.', 'danger')
        return redirect(url_for('realization_budownictwo_list'))

    photo_link = form_data.get('photoLink', '') or ''

    # helper
    def prepareFileName(raw_link: str):
        checkExt = {'jpg', 'jpeg', 'png'}
        last_part = os.path.basename(raw_link.split('?', 1)[0].split('#', 1)[0])
        ext = last_part.rsplit('.', 1)[-1].lower() if '.' in last_part else ''
        return last_part if ext in checkExt else None

    filename = prepareFileName(photo_link)
    if not filename:
        msq.handle_error('UWAGA! Niewłaściwa nazwa fotografii!', log_path=logFileName)
        flash('Błąd usuwania fotografii z serwera (nieprawidłowa nazwa).', 'danger')
        return redirect(url_for('realization_budownictwo_list'))

    # ścieżka do pliku
    settingsDB = generator_settingsDB()
    pics_dir_cfg = settingsDB.get('blog-pic-path', '')  # np. 'images/realizacje/'
    get_base_cfg  = settingsDB.get('real-location-on-server', '')
    # Upewnij się, że to względna ścieżka
    pics_dir_rel = pics_dir_cfg.lstrip('/')
    base_got = get_base_cfg.rstrip('/')
    base_root = base_got 
    file_path = os.path.join(base_root, pics_dir_rel, filename)

    db = get_db()
    try:
        # Najpierw usuń rekord z DB
        deleted = db.executeTo(
            "DELETE FROM realizacje_budownictwo WHERE id = %s;",
            (set_post_id,)
        )

        if not deleted:
            flash('Nie znaleziono wpisu do usunięcia.', 'warning')
            return redirect(url_for('realization_budownictwo_list'))

        # Potem spróbuj usunąć plik (jeśli istnieje)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError as e:
                msq.handle_error(f'UWAGA! Nie udało się usunąć pliku: {file_path} ({e})', log_path=logFileName)
                # Nie wywracamy procesu – rekord już usunięty. Tylko komunikat:
                flash('Wpis usunięty. Nie udało się usunąć pliku zdjęcia (zalogowano błąd).', 'warning')
        else:
            # Brak pliku – logujemy, ale nie traktujemy jako błąd krytyczny
            msq.handle_error(f'Plik nie istnieje: {file_path}', log_path=logFileName)

        msq.handle_error(f'Realizacja id={set_post_id} usunięta przez {session["username"]}', log_path=logFileName)
        flash('Wpis został usunięty.', 'success')
        return redirect(url_for('realization_budownictwo_list'))

    except Exception as e:
        msq.handle_error(f'Błąd przy usuwaniu realizacji id={set_post_id}: {e}', log_path=logFileName)
        flash('Wystąpił błąd podczas usuwania wpisu.', 'danger')
        return redirect(url_for('realization_budownictwo_list'))

obrazy_elitehome = {
    "minaturka": {"label":"Miniaturka", "w":230, "h":230},
    "paralax_1": {"label":"Parallax 1", "w":2048, "h":1484},
    "paralax_2": {"label":"Parallax 2", "w":2048, "h":1299},
    "inside_1":  {"label":"Inside 1",  "w":879, "h":440},
    "inside_2":  {"label":"Inside 2",  "w":879, "h":440}
}

@app.route('/realization-elitehome-list')
def realization_elitehome_list():
    """Strona z zarządzaniem realizacjami dmdelitehome."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Nieautoryzowana próba dostępu do endpointa: /realization-elitehome-list', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['realizations'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        msq.handle_error(f'UWAGA! wywołanie adresu endpointa /realization-elitehome-list bez uprawnień do zarządzania.', log_path=logFileName)
        return redirect(url_for('index'))
 
    db = get_db()
    query = """
        SELECT *
        FROM realizacje_elitehome
        ORDER BY r_finish DESC;
    """
    all_posts = db.getFrom(query, as_dict=True)

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(all_posts)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    posts = all_posts[offset: offset + per_page]

    return render_template(
            "realization_dmdelitehome_list.html", 
            posts=posts, 
            username=session['username'], 
            userperm=session['userperm'],
            user_brands=session['brands'],
            obrazy=obrazy_elitehome,
            pagination=pagination,
            )

@app.route('/save-realizacje-elitehome', methods=['GET', 'POST'])
def save_realizacje_elitehome():
    """Zapis (create/update) realizacji EliteHome w oparciu o nową tabelę."""

    # --- 1) Autoryzacja ---
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error('UWAGA! /save-realizacje-elitehome bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))

    if session.get('userperm', {}).get('realizations', 0) == 0:
        msq.handle_error(f'UWAGA! Próba bez uprawnień: {session.get("username")}', log_path=logFileName)
        flash('Brak uprawnień do zarządzania zasobami.', 'danger')
        return redirect(url_for('index'))

    # --- 2) GET -> powrót do listy ---
    if request.method == 'GET':
        return redirect(url_for('realization_elitehome_list'))

    # --- 3) POST: dane bazowe ---
    form = request.form.to_dict()
    files = request.files

    formid = form.get('formid')
    try:
        int(formid)
    except (TypeError, ValueError):
        msq.handle_error('Błąd! Nieprawidłowe formid.', log_path=logFileName)
        flash('Nieprawidłowy identyfikator formularza.', 'danger')
        return redirect(url_for('realization_elitehome_list'))

    post_id = formid
    is_create = (post_id == '9999999')

    # Helpery do pobierania wartości z sufiksem _{id}
    def get_val(key, default=''):
        return (form.get(f'{key}_{post_id}', default) or '').strip()

    def get_int_or_none(key):
        v = get_val(key, '')
        if not v:
            return None
        try:
            return int(v)
        except ValueError:
            return None

    # --- 4) Konfiguracja uploadów ---
    settings = generator_settingsDB()
    base_root = (settings.get('real-location-on-server', '') or '').rstrip('/')
    url_base  = settings.get('main-domain', '')           # np. 'https://dmddomy.pl/'
    url_path  = settings.get('blog-pic-path', '')         # np. '/images/realizacje/'
    pics_rel  = (settings.get('blog-pic-path') or '').lstrip('/')
    upload_dir = os.path.join(base_root, pics_rel)
    os.makedirs(upload_dir, exist_ok=True)

    def public_url(filename: str) -> str:
        return (url_base.rstrip('/') + '/' + url_path.lstrip('/')).rstrip('/') + '/' + filename

    def handle_upload(field_name: str):
        """Zwraca (filename, public_url) lub (None, None) jeśli brak pliku/niepoprawny."""
        f = files.get(field_name)
        if not f or not f.filename:
            return None, None
        if not allowed_file(f.filename):
            flash('Niedozwolony format pliku (dozwolone: jpg, jpeg, png, webp).', 'danger')
            return None, None
        fname = f'{int(time.time())}_{secure_filename(f.filename)}'
        f.save(os.path.join(upload_dir, fname))
        return fname, public_url(fname)

    # --- 5) Definicja pól tekstowych z tabeli (mapowanie 1:1) ---
    text_cols = [
        'tytul', 'slogan_1', 'slogan_2', 'slogan_3', 'slogan_4',
        'tytul_1', 'podtytul_1', 'opis_1',
        'tytul_2', 'podtytul_2', 'opis_2',
        'tytul_zagadek', 'podtytul_zagadek',
        'zagadka_1_tytul', 'zagadka_1_opis',
        'zagadka_2_tytul', 'zagadka_2_opis',
        'zagadka_3_tytul', 'zagadka_3_opis',
    ]
    # wartości ze wskaźnikiem _{id} w nazwie
    text_values = {col: get_val(col, '') for col in text_cols}

    # lata realizacji
    r_start = get_int_or_none('r_start')
    r_finish = get_int_or_none('r_finish')

    if r_start is None or r_finish is None:
        flash('Rok rozpoczęcia i zakończenia muszą być liczbami.', 'danger')
        return redirect(url_for('realization_elitehome_list'))
    if r_start > r_finish:
        flash('Rok zakończenia nie może być wcześniejszy niż rozpoczęcia.', 'danger')
        return redirect(url_for('realization_elitehome_list'))

    # minimalne wymagania: tytul + opis_1
    if not text_values.get('tytul') or not text_values.get('opis_1'):
        flash('Wymagane pola: Tytuł i Opis sekcji 1.', 'danger')
        return redirect(url_for('realization_elitehome_list'))

    # --- 6) Obsługa obrazów wg słownika 'obrazy_elitehome' ---
    
    image_keys = list(obrazy_elitehome.keys())  # ['minaturka','paralax_1','paralax_2','inside_1','inside_2']
    new_image_urls = {}               # zebrane nowe URL-e (dla update/insert)

    # Przy UPDATE pobieramy stare wartości, by ewentualnie usunąć stare pliki po podmianie
    old_images = {}
    if not is_create:
        db_fetch = get_db()
        # pobierz aktualny rekord
        cols_to_fetch = ', '.join(image_keys)
        row = db_fetch.fetch_one(
            query=f"SELECT {cols_to_fetch} FROM realizacje_elitehome WHERE id=%s",
            params=(int(post_id),)
        )
        if row and isinstance(row, dict):
            old_images = {k: row.get(k) for k in image_keys}
        else:
            # w niektórych wrapperach fetch_one mapuje atrybuty na obiekt
            old_images = {k: getattr(db_fetch, k, None) for k in image_keys}

    # wrzucamy nowe pliki (jeśli wybrane)
    for key in image_keys:
        fname, url = handle_upload(f'{key}_{post_id}')
        if url:
            new_image_urls[key] = url

    # CREATE wymaga miniaturki (jeśli chcesz luzem — usuń to sprawdzenie)
    if is_create and 'minaturka' not in new_image_urls:
        flash('Dodaj Miniaturkę (wymagana przy tworzeniu).', 'danger')
        return redirect(url_for('realization_elitehome_list'))

    # --- 7) Składanie SQL ---
    # now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    db = get_db()
    if is_create:
        # budujemy dynamicznie listę kolumn/params
        cols = [
            'tytul', 
            'r_start', 
            'r_finish', 
            # 'data_aktualizacji'
            ]
        vals = [text_values['tytul'], r_start, r_finish]

        # tekstowe
        for c in text_cols:
            if c != 'tytul':  # tytul już dodany
                cols.append(c)
                vals.append(text_values[c])

        # obrazy_elitehome: miniaturka jest wymagana, ale dodajemy wszystkie, które są
        for key in image_keys:
            cols.append(key)
            vals.append(new_image_urls.get(key, ''))  # brak = pusty string lub NULL (jak wolisz)

        placeholders = ', '.join(['%s'] * len(vals))
        insert_sql = f"INSERT INTO realizacje_elitehome ({', '.join(cols)}) VALUES ({placeholders});"

        if not db.executeTo(query=insert_sql, params=tuple(vals)):
            msq.handle_error('Błąd INSERT realizacji.', log_path=logFileName)
            flash('Błąd podczas tworzenia wpisu.', 'danger')
            return redirect(url_for('realization_elitehome_list'))

        msq.handle_error(f'Nowa realizacja: {text_values["tytul"]} (by {session.get("username")})', log_path=logFileName)
        flash('Nowy wpis został dodany.', 'success')
        return redirect(url_for('realization_elitehome_list'))

    else:
        # UPDATE: składamy SET-clauses tylko dla tego, co aktualizujemy
        set_clauses = []
        params = []

        # podstawowe
        set_clauses += ['tytul=%s', 'r_start=%s', 'r_finish=%s']
        params += [text_values['tytul'], r_start, r_finish]

        # tekstowe
        for c in text_cols:
            if c != 'tytul':
                set_clauses.append(f'{c}=%s')
                params.append(text_values[c])

        # obrazy_elitehome: tylko te, które faktycznie zostały uploadowane
        for key, url in new_image_urls.items():
            set_clauses.append(f'{key}=%s')
            params.append(url)

        update_sql = f"UPDATE realizacje_elitehome SET {', '.join(set_clauses)} WHERE id=%s;"
        params.append(int(post_id))

        if db.executeTo(query=update_sql, params=tuple(params)):
            # sprzątanie starych plików, tylko jeśli dany obrazek został podmieniony
            def _basename(u: str):
                u = (u or '').split('?', 1)[0].split('#', 1)[0]
                return os.path.basename(u)

            upload_dir_real = os.path.realpath(upload_dir)

            for key, new_url in new_image_urls.items():
                old_url = (old_images or {}).get(key)
                if not old_url:
                    continue
                old_name = _basename(old_url)
                new_name = _basename(new_url)
                if old_name and new_name and old_name != new_name:
                    old_path = os.path.join(upload_dir, old_name)
                    try:
                        old_path_real = os.path.realpath(old_path)
                        if old_path_real.startswith(upload_dir_real + os.sep) or old_path_real == upload_dir_real:
                            if os.path.exists(old_path_real):
                                try:
                                    os.remove(old_path_real)
                                except OSError as e:
                                    msq.handle_error(f'Nie udało się usunąć starego pliku: {old_path_real} ({e})', log_path=logFileName)
                        else:
                            msq.handle_error(f'Ścieżka poza katalogiem uploadów! {old_path_real}', log_path=logFileName)
                    except Exception as e:
                        msq.handle_error(f'Błąd przy usuwaniu starego pliku: {e}', log_path=logFileName)

            msq.handle_error(f'Zaktualizowano realizację: {text_values["tytul"]} (by {session.get("username")})', log_path=logFileName)
            flash('Dane zostały zapisane.', 'success')
            return redirect(url_for('realization_elitehome_list'))

        msq.handle_error('Błąd UPDATE realizacji.', log_path=logFileName)
        flash('Wystąpił błąd podczas zapisu.', 'danger')
        return redirect(url_for('realization_elitehome_list'))



@app.route('/remove-realizacje-elitehome', methods=['POST'])
def remove_realizacje_elitehome():
    """Usuwanie realizacji + wszystkich powiązanych plików obrazów."""

    # --- 1) Autoryzacja ---
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error('UWAGA! /remove-realizacje-elitehome bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))

    if session.get('userperm', {}).get('realizations', 0) == 0:
        msq.handle_error(f'UWAGA! Próba bez uprawnień: {session.get("username")}', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami.', 'danger')
        return redirect(url_for('index'))

    # --- 2) Dane wejściowe ---
    form_data = request.form.to_dict()
    try:
        post_id = int(form_data.get('PostID'))
    except (TypeError, ValueError):
        flash('Nieprawidłowe ID wpisu.', 'danger')
        return redirect(url_for('realization_elitehome_list'))

    # --- 3) Konfiguracja ścieżek uploadów ---
    settingsDB   = generator_settingsDB()
    base_root    = (settingsDB.get('real-location-on-server', '') or '').rstrip('/')   # np. /var/www/html/appdmddomy/public
    pics_rel     = (settingsDB.get('blog-pic-path', '') or '').lstrip('/')             # np. images/realizacje
    upload_dir   = os.path.join(base_root, pics_rel)
    upload_dir_real = os.path.realpath(upload_dir)

    # --- 4) Pobierz rekord i wszystkie kolumny obrazów z bazy ---
    # Lista kolumn obrazów – spójna ze słownikiem `obrazy_elitehome` w backendzie
    image_cols = list(obrazy_elitehome.keys())   # ["minaturka","paralax_1","paralax_2","inside_1","inside_2"]

    db = get_db()
    cols_sql = ', '.join(['id'] + image_cols)
    row = db.fetch_one(
        query=f"SELECT {cols_sql} FROM realizacje_elitehome WHERE id=%s",
        params=(post_id,)
    )

    # Obsługa różnych wrapperów
    if not row:
        flash('Nie znaleziono wpisu do usunięcia.', 'warning')
        return redirect(url_for('realization_elitehome_list'))

    def get_col(obj, key):
        # dict lub atrybut na obiekcie wrappera
        if isinstance(obj, dict):
            return obj.get(key)
        return getattr(db, key, None)

    # Zbierz URL-e obrazów
    image_urls = {col: get_col(row, col) for col in image_cols}

    # --- 5) Pomocnicze: nazwa pliku z URL oraz bezpieczne usunięcie ---
    def url_to_basename(u: str) -> str:
        if not u:
            return ''
        clean = u.split('?', 1)[0].split('#', 1)[0]
        return os.path.basename(clean)

    def try_remove_from_uploads(filename: str):
        if not filename:
            return
        candidate = os.path.join(upload_dir, filename)
        try:
            cand_real = os.path.realpath(candidate)
            # Bezpieczeństwo: kasujemy tylko wewnątrz katalogu uploadów
            if cand_real == upload_dir_real or cand_real.startswith(upload_dir_real + os.sep):
                if os.path.exists(cand_real):
                    try:
                        os.remove(cand_real)
                    except OSError as e:
                        msq.handle_error(f'Nie udało się usunąć pliku: {cand_real} ({e})', log_path=logFileName)
                else:
                    # brak pliku – log, ale nie błąd
                    msq.handle_error(f'Plik nie istnieje: {cand_real}', log_path=logFileName)
            else:
                msq.handle_error(f'Ścieżka poza katalogiem uploadów! {cand_real}', log_path=logFileName)
        except Exception as e:
            msq.handle_error(f'Błąd przy usuwaniu pliku ({filename}): {e}', log_path=logFileName)

    # --- 6) Usuń rekord z bazy, a następnie pliki (lub odwrotnie wg preferencji) ---
    # Opcja A (najbezpieczniej dla spójności): najpierw delete w DB, potem pliki
    deleted = db.executeTo("DELETE FROM realizacje_elitehome WHERE id=%s;", (post_id,))
    if not deleted:
        flash('Nie znaleziono wpisu do usunięcia.', 'warning')
        return redirect(url_for('realization_elitehome_list'))

    # Usuń powiązane pliki (każdy z kolumn obrazów)
    for col, url in image_urls.items():
        try_remove_from_uploads(url_to_basename(url))

    msq.handle_error(f'Realizacja id={post_id} usunięta przez {session.get("username")}', log_path=logFileName)
    flash('Wpis został usunięty.', 'success')
    return redirect(url_for('realization_elitehome_list'))


@app.route('/ustawieni_pracownicy', methods=['POST'])
def ustawieni_pracownicy():
    data = request.get_json()  # Pobranie danych JSON z żądania
    if not data or 'pracownicy' not in data:
        return jsonify({"error": "Nieprawidłowy format danych, oczekiwano klucza 'pracownicy'."}), 400
    
    sequence_data = data['pracownicy']  # Przechwycenie listy pracowników
    department = str(data['grupa']).strip()
    # print(department, sequence_data)
    sequence = []
    for s in sequence_data:
        clear_data = s.strip()
        sequence.append(clear_data)

    users_atributesByLogin = {}
    for usr_d in generator_userDataDB(False):
        u_login = usr_d['username']
        users_atributesByLogin[u_login] = usr_d
    
    ready_exportDB = []
    for u_login in sequence:
        set_row = {
            'EMPLOYEE_PHOTO': users_atributesByLogin[u_login]['avatar'],
            'EMPLOYEE_NAME': users_atributesByLogin[u_login]['name'],
            'EMPLOYEE_ROLE': users_atributesByLogin[u_login]['stanowisko'],
            'EMPLOYEE_DEPARTMENT': f'dmd {department}',
            'PHONE': users_atributesByLogin[u_login]['phone'],
            'EMAIL': users_atributesByLogin[u_login]['email'],
            'FACEBOOK': users_atributesByLogin[u_login]['facebook'],
            'LINKEDIN': users_atributesByLogin[u_login]['linkedin'],
            'STATUS': 1
        }
        ready_exportDB.append(set_row)
    if len(ready_exportDB):
        # 1. usuń wszystkie pozycje dla EMPLOYEE_DEPARTMENT
        msq.delete_row_from_database(
            """
                DELETE FROM workers_team WHERE EMPLOYEE_DEPARTMENT = %s;
            """,
            (f'dmd {department}', )
        )

        # 2. wstaw nowe dane do bazy zachowując kolejność zapisu w bazie
        for i, row in enumerate(ready_exportDB):
            zapytanie_sql = '''
                    INSERT INTO workers_team (EMPLOYEE_PHOTO, EMPLOYEE_NAME, EMPLOYEE_ROLE, EMPLOYEE_DEPARTMENT, PHONE, EMAIL, FACEBOOK, LINKEDIN, STATUS)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
                '''
            dane = (
                    row['EMPLOYEE_PHOTO'], 
                    row['EMPLOYEE_NAME'], 
                    row['EMPLOYEE_ROLE'], 
                    row['EMPLOYEE_DEPARTMENT'], 
                    row['PHONE'], 
                    row['EMAIL'], 
                    row['FACEBOOK'], 
                    row['LINKEDIN'], 
                    row['STATUS'], 
                )
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Ustwiono {row["EMPLOYEE_NAME"]} przez {session["username"]}!', log_path=logFileName)
                # flash(f'Ustwiono {row["EMPLOYEE_NAME"]}.', 'success')

    else:
        msq.handle_error(f'UWAGA! Błąd zespół nie został zmieniony przez {session["username"]}!', log_path=logFileName)
        # flash('Błąd! Zespół nie został zmieniony.', 'danger')
        return jsonify({"status": "Sukces", "pracownicy": sequence_data}), 200
    
    msq.handle_error(f'Zespół został pomyślnie zmieniony przez {session["username"]}!', log_path=logFileName)
    # flash('Zespół został pomyślnie zmieniony.', 'success')
    
    # Przetwarzanie listy, np. zapis do bazy danych lub dalsze operacje
    print("Otrzymana lista pracowników:", sequence_data)
 
    return jsonify({"status": "Sukces", "pracownicy": sequence_data}), 200

@app.route('/career', methods=['GET', 'POST'])
def career():
    """Strona zespołu instalacje."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /career bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['career'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /career bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    ads_career_got = generator_jobs()

    new_all_career = []
    for item in ads_career_got:
        if 'fbgroups' not in item:
            item['fbgroups'] = {}
        fbgroupsIDstatus = checkFbGroupstatus(section="career", post_id=item['id'])
        item['fbgroups']['id'] = fbgroupsIDstatus[0]
        item['fbgroups']['post_id'] = fbgroupsIDstatus[1]
        item['fbgroups']['content'] = fbgroupsIDstatus[2]
        item['fbgroups']['color_choice'] = fbgroupsIDstatus[3]
        item['fbgroups']['repeats'] = fbgroupsIDstatus[4]
        item['fbgroups']['repeats_left'] = fbgroupsIDstatus[5]
        item['fbgroups']['repeats_last'] = fbgroupsIDstatus[6]

        item['fbgroups']['schedule_0_id'] = fbgroupsIDstatus[7]
        item['fbgroups']['schedule_0_datetime'] = fbgroupsIDstatus[8]
        item['fbgroups']['schedule_0_status'] = fbgroupsIDstatus[9]
        item['fbgroups']['schedule_0_errors'] = fbgroupsIDstatus[10]

        item['fbgroups']['schedule_1_id'] = fbgroupsIDstatus[11]
        item['fbgroups']['schedule_1_datetime'] = fbgroupsIDstatus[12]
        item['fbgroups']['schedule_1_status'] = fbgroupsIDstatus[13]
        item['fbgroups']['schedule_1_errors'] = fbgroupsIDstatus[14]

        item['fbgroups']['schedule_2_id'] = fbgroupsIDstatus[15]
        item['fbgroups']['schedule_2_datetime'] = fbgroupsIDstatus[16]
        item['fbgroups']['schedule_2_status'] = fbgroupsIDstatus[17]
        item['fbgroups']['schedule_2_errors'] = fbgroupsIDstatus[18]

        item['fbgroups']['schedule_3_id'] = fbgroupsIDstatus[19]
        item['fbgroups']['schedule_3_datetime'] = fbgroupsIDstatus[20]
        item['fbgroups']['schedule_3_status'] = fbgroupsIDstatus[21]
        item['fbgroups']['schedule_3_errors'] = fbgroupsIDstatus[22]

        item['fbgroups']['schedule_4_id'] = fbgroupsIDstatus[23]
        item['fbgroups']['schedule_4_datetime'] = fbgroupsIDstatus[24]
        item['fbgroups']['schedule_4_status'] = fbgroupsIDstatus[25]
        item['fbgroups']['schedule_4_errors'] = fbgroupsIDstatus[26]

        item['fbgroups']['schedule_5_id'] = fbgroupsIDstatus[27]
        item['fbgroups']['schedule_5_datetime'] = fbgroupsIDstatus[28]
        item['fbgroups']['schedule_5_status'] = fbgroupsIDstatus[29]
        item['fbgroups']['schedule_5_errors'] = fbgroupsIDstatus[30]

        item['fbgroups']['schedule_6_id'] = fbgroupsIDstatus[31]
        item['fbgroups']['schedule_6_datetime'] = fbgroupsIDstatus[32]
        item['fbgroups']['schedule_6_status'] = fbgroupsIDstatus[33]
        item['fbgroups']['schedule_6_errors'] = fbgroupsIDstatus[34]

        item['fbgroups']['schedule_7_id'] = fbgroupsIDstatus[35]
        item['fbgroups']['schedule_7_datetime'] = fbgroupsIDstatus[36]
        item['fbgroups']['schedule_7_status'] = fbgroupsIDstatus[37]
        item['fbgroups']['schedule_7_errors'] = fbgroupsIDstatus[38]

        item['fbgroups']['schedule_8_id'] = fbgroupsIDstatus[39]
        item['fbgroups']['schedule_8_datetime'] = fbgroupsIDstatus[40]
        item['fbgroups']['schedule_8_status'] = fbgroupsIDstatus[41]
        item['fbgroups']['schedule_8_errors'] = fbgroupsIDstatus[42]

        item['fbgroups']['schedule_9_id'] = fbgroupsIDstatus[43]
        item['fbgroups']['schedule_9_datetime'] = fbgroupsIDstatus[44]
        item['fbgroups']['schedule_9_status'] = fbgroupsIDstatus[45]
        item['fbgroups']['schedule_9_errors'] = fbgroupsIDstatus[46]

        item['fbgroups']['schedule_10_id'] = fbgroupsIDstatus[47]
        item['fbgroups']['schedule_10_datetime'] = fbgroupsIDstatus[48]
        item['fbgroups']['schedule_10_status'] = fbgroupsIDstatus[49]
        item['fbgroups']['schedule_10_errors'] = fbgroupsIDstatus[50]

        item['fbgroups']['category'] = fbgroupsIDstatus[51]
        item['fbgroups']['created_by'] = fbgroupsIDstatus[52]
        item['fbgroups']['section'] = fbgroupsIDstatus[53]
        item['fbgroups']['id_gallery'] = fbgroupsIDstatus[54]
        item['fbgroups']['data_aktualizacji'] = fbgroupsIDstatus[55]

        new_all_career.append(item)

    all_career = new_all_career

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(all_career)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    ads_career = all_career[offset: offset + per_page]


    return render_template(
            "career_management.html", 
            username=session['username'],
            useremail=session['user_data']['email'],
            userperm=session['userperm'], 
            user_brands=session['brands'], 
            ads_career=ads_career,
            pagination=pagination
            )

@app.route('/save-career-offer', methods=["POST"])
def save_career_offer():
    # Sprawdzenie czy użytkownik jest zalogowany i ma uprawnienia
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /save-career-offer bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['career'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /save-career-offer bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj się z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Odczytanie danych z formularza
    title = request.form.get('title')
    start_date = request.form.get('startdate') + ' 07:00:00'
    salary = request.form.get('salary')
    employment_type = request.form.get('employmenttype')
    location = request.form.get('location')
    brand = request.form.get('brand')
    contact_email = request.form.get('email')
    description = request.form.get('jobDescription')
    requirements_description = request.form.get('requirementsDescription')
    requirements = request.form.get('dynamicRequirementsList')
    benefits = request.form.get('dynamicBenefitsList')
    date_posted = datetime.datetime.now().date()
    offerID = request.form.get('OfferID')
    try: offerID_int = int(offerID)
    except ValueError:
        msq.handle_error(f'UWAGA! Błąd z id oferty {title} wywołany przez {session["username"]}!', log_path=logFileName)
        flash(f'UWAGA! Błąd z id oferty {title} wywołany przez {session["username"]}!', 'danger')
        addDataLogs(f'Ustawienia zapisane przez {session["username"]}!', 'success')
        return redirect(url_for('index'))

    # Sprawdzenie czy wszystkie wymagane dane zostały przekazane
    if not all([title, start_date, salary, employment_type, location, contact_email]):
        msq.handle_error(f'UWAGA! Nie wszystkie wymagane dane zostały przekazane przez {session["username"]}!', log_path=logFileName)
        return jsonify({'error': 'Nie wszystkie wymagane dane zostały przekazane'}), 400

    # Przygotowanie zapytania SQL w zależności od tego, czy jest to nowy wpis, czy aktualizacja
    if offerID_int == 9999999:
        # Nowe ogłoszenie
        zapytanie_sql = '''
            INSERT INTO job_offers (
                title, description, requirements_description, requirements, benefits, 
                location, contact_email, employment_type, salary, start_date, date_posted,
                brand, status
                ) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        '''
        dane = (
            title, description, requirements_description, requirements, benefits, 
            location, contact_email, employment_type, salary, start_date, date_posted,
            brand, 1
        )
    else:
        # Aktualizacja istniejącego ogłoszenia
        zapytanie_sql = '''
            UPDATE job_offers 
            SET 
                title=%s, 
                description=%s, 
                requirements_description=%s, 
                requirements=%s, 
                benefits=%s, 
                location=%s, 
                contact_email=%s, 
                employment_type=%s, 
                salary=%s, 
                start_date=%s, 
                date_posted=%s, 
                brand=%s, 
                status=%s 
            WHERE ID=%s;
        '''
        dane = (
            title, 
            description, 
            requirements_description, 
            requirements, 
            benefits, 
            location, 
            contact_email, 
            employment_type, 
            salary, 
            start_date, 
            date_posted, 
            brand,
            1,
            offerID_int
        )
    # print(f'dene: {dane}')

    # Wykonanie zapytania
    if msq.insert_to_database(zapytanie_sql, dane):
        msq.handle_error(f'SOferta pracy została pomyślnie zapisana przez {session["username"]}!', log_path=logFileName)
        flash(f'Oferta pracy została zapisana pomyślnie!', 'success')
        addDataLogs(f'Oferta pracy została zapisana pomyślnie!', 'success')
        return jsonify({
            'message': 'Oferta pracy została zapisana pomyślnie!',
            'success': True
        }), 200
    else:
        msq.handle_error(f'UWAGA! Błąd zapisu! Oferta pracy nie została zapisana przez {session["username"]}!', log_path=logFileName)
        flash(f'Błąd zapisu! Oferta pracy nie została zapisana!', 'danger')
        addDataLogs(f'Błąd zapisu! Oferta pracy nie została zapisana!', 'danger')

        return jsonify({
            'message': 'Błąd zapisu! Oferta pracy nie została zapisana!',
            'success': False
        }), 500

@app.route('/remove-career-offer', methods=["POST"])
def remove_career_offer():
    """Usuwanie ofertę najmu"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /remove-career-offer bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['career'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /remove-career-offer bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()
        try: form_data['PostID']
        except KeyError: return redirect(url_for('index'))
        set_post_id = int(form_data['PostID'])
        
        msq.delete_row_from_database(
                """
                    DELETE FROM job_offers WHERE ID = %s;
                """,
                (set_post_id,)
            )
        msq.handle_error(f'Oferta pracy o id:{set_post_id} została usunięta przez {session["username"]}!', log_path=logFileName)
        flash("Oferta pracy została usunięta.", "success")
        return redirect(url_for('career'))
    
    return redirect(url_for('index'))

@app.route('/update-career-offer-status', methods=['POST'])
def update_career_offer_status():
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /update-career-offer-status bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['career'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /update-career-offer-status bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()
        try: 
            form_data['PostID']
            form_data['Status']
        except KeyError: return redirect(url_for('index'))
        set_post_id = int(form_data['PostID'])
        set_post_status = int(form_data['Status'])

        statusCareer = checkFbGroupstatus(section="career", post_id=set_post_id)
        if statusCareer[0] != None:
            msq.handle_error(f'UWAGA! Status oferty nie został zmieniony przez {session["username"]}!', log_path=logFileName)
            flash("Status oferty nie został zmieniony. Przewij kampanię na grupach Facebooka", "danger")
            return redirect(url_for('career'))

        zapytanie_sql = f'''
                UPDATE job_offers
                SET status = %s
                WHERE ID = %s;
                '''
        dane = (set_post_status, set_post_id)
        if msq.insert_to_database(zapytanie_sql, dane):
            msq.handle_error(f'Status oferty został zmieniony przez {session["username"]}!', log_path=logFileName)
            flash("Status oferty został zmieniony.", "success")
            return redirect(url_for('career'))
    
    return redirect(url_for('index'))

@app.template_filter()
def decode_html_entities_filter(text):
    return html.unescape(text)

@app.template_filter()
def update_new_line_chars(text: str):
    text = text.replace('\r\n', '<br>')  # najpierw standard Windows
    text = text.replace('\n', '<br>')  # potem standard Unix/Linux
    return Markup(html.unescape(text))

@app.route('/estate-ads-rent')
def estateAdsRent():
    """Strona zawierająca listę z ogłoszeniami nieruchomości."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /estate-ads-rent bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /estate-ads-rent bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Wczytanie listy wszystkich postów z bazy danych i przypisanie jej do zmiennej posts
    all_rents = generator_rentOffert()

    new_all_rents = []
    for item in all_rents:
        if 'lento' not in item:
            item['lento'] = {}
        lentoIDstatus = checkLentoStatus(kind="r", id=item['ID'])
        item['lento']['id'] = lentoIDstatus[0]
        item['lento']['status'] = lentoIDstatus[1]
        item['lento']['data_aktualizacji'] = lentoIDstatus[2]
        item['lento']['errors'] = lentoIDstatus[3]
        item['lento']['action_before_errors'] = lentoIDstatus[4]


        if item['lento']['status'] is not None:
            start_date = item['lento']['data_aktualizacji']
            # Oblicz datę końca promocji
            end_date = start_date + datetime.timedelta(days=90)
            # Oblicz liczbę dni pozostałych do końca promocji
            days_left = (end_date - datetime.datetime.now()).days

            item['lento']['zostalo_dni'] = days_left
            # print(item['lento']['zostalo_dni'])

            item['lento']['error_message'] = lentoIDstatus[3]

        
        if 'facebook' not in item:
            item['facebook'] = {}
        facebookIDstatus = checkFacebookStatus(kind="r", id=item['ID'])
        item['facebook']['id'] = facebookIDstatus[0]
        item['facebook']['status'] = facebookIDstatus[1]
        item['facebook']['data_aktualizacji'] = facebookIDstatus[2]
        item['facebook']['errors'] = facebookIDstatus[3]
        item['facebook']['action_before_errors'] = facebookIDstatus[4]


        if item['facebook']['status'] is not None:
            start_date = item['facebook']['data_aktualizacji']
            # Oblicz datę końca promocji
            end_date = start_date + datetime.timedelta(days=90)
            # Oblicz liczbę dni pozostałych do końca promocji
            days_left = (end_date - datetime.datetime.now()).days
            item['facebook']['zostalo_dni'] = days_left
            item['facebook']['error_message'] = facebookIDstatus[3]

        if 'adresowo' not in item:
            item['adresowo'] = {}
        adresowoIDstatus = checkAdresowoStatus(kind="r", id=item['ID'])
        item['adresowo']['id'] = adresowoIDstatus[0]
        item['adresowo']['status'] = adresowoIDstatus[1]
        item['adresowo']['data_aktualizacji'] = adresowoIDstatus[2]
        item['adresowo']['errors'] = adresowoIDstatus[3]
        item['adresowo']['action_before_errors'] = adresowoIDstatus[4]
        item['adresowo']['region'] = adresowoIDstatus[5]
        item['adresowo']['ulica'] = adresowoIDstatus[6]


        if item['adresowo']['status'] is not None:
            start_date = item['adresowo']['data_aktualizacji']
            
            # Oblicz liczbę miesięcy aktywności
            current_date = datetime.datetime.now()
            months_active = (current_date.year - start_date.year) * 12 + current_date.month - start_date.month

            # Przypisz liczbę aktywnych miesięcy do item['adresowo']['aktywne_miesiecy']
            item['adresowo']['aktywne_miesiecy'] = months_active

            # Przypisz error_message
            item['adresowo']['error_message'] = adresowoIDstatus[3]

        if 'allegro' not in item:
            item['allegro'] = {}
        allegroIDstatus = checkAllegroStatus(kind="r", id=item['ID'])
        item['allegro']['id'] = allegroIDstatus[0]
        item['allegro']['status'] = allegroIDstatus[1]
        item['allegro']['data_aktualizacji'] = allegroIDstatus[2]
        item['allegro']['errors'] = allegroIDstatus[3]
        item['allegro']['action_before_errors'] = allegroIDstatus[4]
        item['allegro']['region'] = allegroIDstatus[5]
        item['allegro']['ulica'] = allegroIDstatus[6]
        item['allegro']['kod'] = allegroIDstatus[7]


        if item['allegro']['status'] is not None:
            start_date = item['allegro']['data_aktualizacji']
            # Oblicz datę końca promocji
            end_date = start_date + datetime.timedelta(days=30)
            # Oblicz liczbę dni pozostałych do końca promocji
            days_left = (end_date - datetime.datetime.now()).days

            item['allegro']['zostalo_dni'] = days_left

            item['allegro']['error_message'] = allegroIDstatus[3]

        if 'otodom' not in item:
            item['otodom'] = {}
        otodom_IDstatus = checkOtodomStatus(kind="r", id=item['ID'])
        item['otodom']['id'] = otodom_IDstatus[0]
        item['otodom']['status'] = otodom_IDstatus[1]
        item['otodom']['data_aktualizacji'] = otodom_IDstatus[2]
        item['otodom']['errors'] = otodom_IDstatus[3]
        item['otodom']['action_before_errors'] = otodom_IDstatus[4]
        item['otodom']['region'] = otodom_IDstatus[5]
        item['otodom']['kategoria_ogloszenia'] = otodom_IDstatus[6]



        if item['otodom']['status'] is not None:
            start_date = item['otodom']['data_aktualizacji']
            # Oblicz datę końca promocji
            end_date = start_date + datetime.timedelta(days=30)
            # Oblicz liczbę dni pozostałych do końca promocji
            days_left = (end_date - datetime.datetime.now()).days

            item['otodom']['zostalo_dni'] = days_left

            item['otodom']['error_message'] = otodom_IDstatus[3]
        
        if 'fbgroups' not in item:
            item['fbgroups'] = {}
        fbgroupsIDstatus = checkFbGroupstatus(section="estateAdsRent", post_id=item['ID'])
        item['fbgroups']['id'] = fbgroupsIDstatus[0]
        item['fbgroups']['post_id'] = fbgroupsIDstatus[1]
        item['fbgroups']['content'] = fbgroupsIDstatus[2]
        item['fbgroups']['color_choice'] = fbgroupsIDstatus[3]
        item['fbgroups']['repeats'] = fbgroupsIDstatus[4]
        item['fbgroups']['repeats_left'] = fbgroupsIDstatus[5]
        item['fbgroups']['repeats_last'] = fbgroupsIDstatus[6]

        item['fbgroups']['schedule_0_id'] = fbgroupsIDstatus[7]
        item['fbgroups']['schedule_0_datetime'] = fbgroupsIDstatus[8]
        item['fbgroups']['schedule_0_status'] = fbgroupsIDstatus[9]
        item['fbgroups']['schedule_0_errors'] = fbgroupsIDstatus[10]

        item['fbgroups']['schedule_1_id'] = fbgroupsIDstatus[11]
        item['fbgroups']['schedule_1_datetime'] = fbgroupsIDstatus[12]
        item['fbgroups']['schedule_1_status'] = fbgroupsIDstatus[13]
        item['fbgroups']['schedule_1_errors'] = fbgroupsIDstatus[14]

        item['fbgroups']['schedule_2_id'] = fbgroupsIDstatus[15]
        item['fbgroups']['schedule_2_datetime'] = fbgroupsIDstatus[16]
        item['fbgroups']['schedule_2_status'] = fbgroupsIDstatus[17]
        item['fbgroups']['schedule_2_errors'] = fbgroupsIDstatus[18]

        item['fbgroups']['schedule_3_id'] = fbgroupsIDstatus[19]
        item['fbgroups']['schedule_3_datetime'] = fbgroupsIDstatus[20]
        item['fbgroups']['schedule_3_status'] = fbgroupsIDstatus[21]
        item['fbgroups']['schedule_3_errors'] = fbgroupsIDstatus[22]

        item['fbgroups']['schedule_4_id'] = fbgroupsIDstatus[23]
        item['fbgroups']['schedule_4_datetime'] = fbgroupsIDstatus[24]
        item['fbgroups']['schedule_4_status'] = fbgroupsIDstatus[25]
        item['fbgroups']['schedule_4_errors'] = fbgroupsIDstatus[26]

        item['fbgroups']['schedule_5_id'] = fbgroupsIDstatus[27]
        item['fbgroups']['schedule_5_datetime'] = fbgroupsIDstatus[28]
        item['fbgroups']['schedule_5_status'] = fbgroupsIDstatus[29]
        item['fbgroups']['schedule_5_errors'] = fbgroupsIDstatus[30]

        item['fbgroups']['schedule_6_id'] = fbgroupsIDstatus[31]
        item['fbgroups']['schedule_6_datetime'] = fbgroupsIDstatus[32]
        item['fbgroups']['schedule_6_status'] = fbgroupsIDstatus[33]
        item['fbgroups']['schedule_6_errors'] = fbgroupsIDstatus[34]

        item['fbgroups']['schedule_7_id'] = fbgroupsIDstatus[35]
        item['fbgroups']['schedule_7_datetime'] = fbgroupsIDstatus[36]
        item['fbgroups']['schedule_7_status'] = fbgroupsIDstatus[37]
        item['fbgroups']['schedule_7_errors'] = fbgroupsIDstatus[38]

        item['fbgroups']['schedule_8_id'] = fbgroupsIDstatus[39]
        item['fbgroups']['schedule_8_datetime'] = fbgroupsIDstatus[40]
        item['fbgroups']['schedule_8_status'] = fbgroupsIDstatus[41]
        item['fbgroups']['schedule_8_errors'] = fbgroupsIDstatus[42]

        item['fbgroups']['schedule_9_id'] = fbgroupsIDstatus[43]
        item['fbgroups']['schedule_9_datetime'] = fbgroupsIDstatus[44]
        item['fbgroups']['schedule_9_status'] = fbgroupsIDstatus[45]
        item['fbgroups']['schedule_9_errors'] = fbgroupsIDstatus[46]

        item['fbgroups']['schedule_10_id'] = fbgroupsIDstatus[47]
        item['fbgroups']['schedule_10_datetime'] = fbgroupsIDstatus[48]
        item['fbgroups']['schedule_10_status'] = fbgroupsIDstatus[49]
        item['fbgroups']['schedule_10_errors'] = fbgroupsIDstatus[50]

        item['fbgroups']['category'] = fbgroupsIDstatus[51]
        item['fbgroups']['created_by'] = fbgroupsIDstatus[52]
        item['fbgroups']['section'] = fbgroupsIDstatus[53]
        item['fbgroups']['id_gallery'] = fbgroupsIDstatus[54]
        item['fbgroups']['data_aktualizacji'] = fbgroupsIDstatus[55]

        if 'socialSync' not in item:
            item['socialSync'] = {}
        socialSync_IDstatus = checkSocialSyncStatus(kind="r", id=item['ID'])
        item['socialSync']['id'] = socialSync_IDstatus[0]
        item['socialSync']['status'] = socialSync_IDstatus[1]
        item['socialSync']['data_aktualizacji'] = socialSync_IDstatus[2]
        item['socialSync']['errors'] = socialSync_IDstatus[3]
        item['socialSync']['action_before_errors'] = socialSync_IDstatus[4]
        item['socialSync']['kategoria_ogloszenia'] = socialSync_IDstatus[5]

        

        if item.get('socialSync') and item['socialSync'].get('status') is not None:
            update_date = item['socialSync'].get('data_aktualizacji')
            last_update_ads = item.get('DataAktualizacji_raw')

            # Sprawdzamy, czy update_date nie jest None
            if update_date and last_update_ads and update_date < last_update_ads:
                query = "DELETE FROM ogloszenia_socialsync WHERE id=%s;"
                params = (item['socialSync']['id'], )

                if msq.insert_to_database(query, params):  # Jeśli usunięcie się powiodło
                    item['socialSync']['status'] = None

            # Obliczamy ilość dni od momentu publikacji
            if update_date:
                days_since_published = (datetime.datetime.now() - update_date).days
                item['socialSync']['opublikowano_dni'] = max(days_since_published, 0)  # Unikamy wartości ujemnych

        # print(item.get('socialSync'))

        new_all_rents.append(item)
    # flash(f"{str(len(new_all_rents))}", 'dnager')

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(new_all_rents)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    ads_rent = new_all_rents[offset: offset + per_page]

    specOfferIfno = generator_specialOffert()
    if len(specOfferIfno) == 1:
        if specOfferIfno[0]['RodzajRodzica'] == 'r':
            specOfferID = specOfferIfno[0]['IdRodzica']
        else:
            specOfferID = 'None'
    else:
        specOfferID = 'None'

    lentoOffer = 1

    return render_template(
            "estate_management_rent.html",
            ads_rent=ads_rent,
            specOfferID=specOfferID,
            userperm=session['userperm'],
            username=session['username'],
            pagination=pagination,
            lentoOffer=lentoOffer
            )     

@app.route('/remove-rent-offer', methods=['POST'])
def remove_rent_offer():
    """Usuwanie ofertę najmu"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /remove-rent-offer bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /remove-rent-offer bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()
        try: form_data['PostID']
        except KeyError: return redirect(url_for('index'))
        set_post_id = int(form_data['PostID'])
        # pobieram id galerii
        try: id_galerry = take_data_where_ID('Zdjecia', 'OfertyNajmu', 'ID', set_post_id )[0][0]
        except IndexError: 
            msq.handle_error(f'UWAGA! Wpis nie został usunięty przez {session["username"]}. Wystąpił błąd struktury danych galerii!', log_path=logFileName)
            flash("Wpis nie został usunięty. Wystąpił błąd struktury danych galerii", "danger")
            addDataLogs(f'Wpis nie został usunięty. Wystąpił błąd struktury danych galerii!', 'danger')
            return redirect(url_for('estateAdsRent'))
        
        try: current_gallery = take_data_where_ID('*', 'ZdjeciaOfert', 'ID', id_galerry)[0]
        except IndexError: 
            msq.handle_error(f'UWAGA! Wpis nie został usunięty przez {session["username"]}. Wystąpił błąd struktury danych galerii!', log_path=logFileName)
            flash("Wpis nie został usunięty. Wystąpił błąd struktury danych galerii", "danger")
            addDataLogs(f'Wpis nie został usunięty. Wystąpił błąd struktury danych galerii!', 'danger')
            return redirect(url_for('estateAdsRent'))
        
        removeSpecOffer(set_post_id, 'r')
        msq.delete_row_from_database(
                """
                    DELETE FROM OfertyNajmu WHERE ID = %s;
                """,
                (set_post_id,)
            )
        
        msq.delete_row_from_database(
                """
                    DELETE FROM ZdjeciaOfert WHERE ID = %s;
                """,
                (id_galerry,)
            )
        
        real_loc_on_server = settingsDB['real-location-on-server']
        domain = settingsDB['main-domain']
        estate_pic_path = settingsDB['estate-pic-offer']
        upload_path = f'{real_loc_on_server}{estate_pic_path}'
        mainDomain_URL = f'{domain}{estate_pic_path}'

        
        current_gallery_list = [p for p in current_gallery[1:-1] if p is not None]
        # print(current_gallery_list)
        for delIt in current_gallery_list:
            delIt_clear = str(delIt).replace(mainDomain_URL, '')
            # print(delIt)
            # print(delIt_clear)
            if delIt in current_gallery_list:
                try:
                    file_path = upload_path + delIt_clear
                    # print(file_path)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    else:
                        print(f"File {file_path} not found.")
                except Exception as e:
                    print(f"Error removing file {file_path}: {e}")
        
        msq.handle_error(f'Wpis został usunięty przez {session["username"]}!', log_path=logFileName)
        flash("Wpis został usunięty.", "success")
        addDataLogs("Wpis został usunięty.", "success")
        return redirect(url_for('estateAdsRent'))
    
    return redirect(url_for('index'))

@app.route('/update-rent-offer-status', methods=['POST'])
def update_rent_offer_status():
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /update-rent-offer-status bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /update-rent-offer-status bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()
        try: 
            form_data['PostID']
            form_data['Status']
        except KeyError: return redirect(url_for('index'))
        set_post_id = int(form_data['PostID'])
        set_post_status = int(form_data['Status'])

        statusNaLento = checkLentoStatus('r', set_post_id)
        if statusNaLento[0] != None:
            msq.handle_error(f'UWAGA! Status oferty nie został zmieniony przez {session["username"]}! Usuń na zawsze ogłoszenie z Lento.pl', log_path=logFileName)
            flash("Status oferty nie został zmieniony. Usuń na zawsze ogłoszenie z Lento.pl", "danger")
            return redirect(url_for('estateAdsRent'))
        
        statusNaFacebooku = checkFacebookStatus('r', set_post_id)
        if statusNaFacebooku[0] != None:
            msq.handle_error(f'UWAGA! Status oferty nie został zmieniony przez {session["username"]}! Usuń na zawsze ogłoszenie z Facebooka', log_path=logFileName)
            flash("Status oferty nie został zmieniony. Usuń na zawsze ogłoszenie z Facebooka", "danger")
            return redirect(url_for('estateAdsRent'))
        
        statusNaAdresowo = checkAdresowoStatus('r', set_post_id)
        if statusNaAdresowo[0] != None:
            msq.handle_error(f'UWAGA! Status oferty nie został zmieniony przez {session["username"]}! Usuń na zawsze ogłoszenie z Adresowo', log_path=logFileName)
            flash("Status oferty nie został zmieniony. Usuń na zawsze ogłoszenie z Adresowo", "danger")
            return redirect(url_for('estateAdsRent'))
        
        statusNaAllegro = checkAllegroStatus('r', set_post_id)
        if statusNaAllegro[0] != None:
            msq.handle_error(f'UWAGA! Status oferty nie został zmieniony przez {session["username"]}! Usuń na zawsze ogłoszenie z Allegro', log_path=logFileName)
            flash("Status oferty nie został zmieniony. Usuń na zawsze ogłoszenie z Allegro", "danger")
            return redirect(url_for('estateAdsRent'))
        
        if set_post_status == 0:
            removeSpecOffer(set_post_id, 'r')
        zapytanie_sql = f'''
                UPDATE OfertyNajmu
                SET StatusOferty = %s
                WHERE ID = %s;
                '''
        dane = (set_post_status, set_post_id)
        if msq.insert_to_database(zapytanie_sql, dane):
            msq.handle_error(f'Status oferty najmu o id:{set_post_id} został zmieniony przez {session["username"]}!', log_path=logFileName)
            flash("Status oferty został zmieniony.", "success")
            return redirect(url_for('estateAdsRent'))
    
    return redirect(url_for('index'))

@app.route('/save-rent-offer', methods=["POST"])
def save_rent_offer():
    # Odczytanie danych formularza
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /save-rent-offer bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /save-rent-offer bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Pobierz JSON jako string z formularza
    OPIS_JSON_STRing = request.form['opis']
    # Przekonwertuj string JSON na słownik Pythona
    try:
        opis_data = json.loads(OPIS_JSON_STRing)
    except json.JSONDecodeError:
        return jsonify({'error': 'Nieprawidłowy format JSON'}), 400

    # Teraz opis_data jest słownikiem Pythona, który możesz używać w kodzie
    title = request.form.get('title')
    rodzaj_nieruchomosci = request.form.get('rodzajNieruchomosci')
    lokalizacja = request.form.get('lokalizacja')

    cena = request.form.get('cena')
    try: cena = int(cena)
    except ValueError: return jsonify({'error': 'Cena musi być liczbą'}), 400
    opis = opis_data
    lat = request.form.get('lat')
    lon = request.form.get('lon')
    if lat and lon:
        GPS = {"latitude": lat, "longitude": lon }
        GPS_STRING = str(GPS).replace("'", '"')
    else: GPS_STRING = ''
    rokBudowy = request.form.get('rokBudowy')
    try: rokBudowy = int(rokBudowy)
    except ValueError: rokBudowy = 0

    stan = request.form.get('stan')
    nrKW = request.form.get('nrKW')
    czynsz = request.form.get('czynsz')
    try: czynsz = int(czynsz)
    except ValueError: czynsz = 0
    kaucja = request.form.get('kaucja')
    try: kaucja = int(kaucja)
    except ValueError: kaucja = 0

    metraz = request.form.get('metraz')
    try: 
        metraz = int(float(metraz))
    except Exception as e: 
        print(e)
        metraz = 0

    powDzialki = request.form.get('powDzialki')
    try: powDzialki = int(powDzialki)
    except ValueError: powDzialki = 0
    liczbaPieter = request.form.get('liczbaPieter')
    try: liczbaPieter = int(liczbaPieter)
    except ValueError: liczbaPieter = 0
    liczbaPokoi = request.form.get('liczbaPokoi')
    try: liczbaPokoi = int(liczbaPokoi)
    except ValueError: liczbaPokoi = 0
    techBudowy = request.form.get('techBudowy')
    rodzajZabudowy = request.form.get('rodzajZabudowy')
    umeblowanie = request.form.get('umeblowanie')
    kuchnia = request.form.get('kuchnia')
    dodatkoweInfo = request.form.get('dodatkoweInfo')
    offerID = request.form.get('offerID')
    try: offerID_int = int(offerID)
    except ValueError: return jsonify({'error': 'Błąd id oferty!'}), 400

    if offerID_int == 9999999:
        oldPhotos = []
        allPhotos = []
    else:
        oldPhotos = request.form.getlist('oldPhotos[]')
        allPhotos = request.form.getlist('allPhotos[]')

    # print(allPhotos)

    validOpis = []
    for test in opis:
        for val in test.values():
            if isinstance(val, str) and val != "":
                validOpis.append(test)
            if isinstance(val, list) and len(val)!=0:
                clearLI = [a for a in val if a != ""]
                new_li = {"li": clearLI}
                validOpis.append(new_li)
    
    if len(validOpis)!=0: 
        testOpisu = True
        opis_json = validOpis
        OPIS_JSON_STR = str(opis_json).replace("'", '"')
    else: testOpisu = False

    # Sprawdzenie czy wszystkie wymagane dane zostały przekazane
    if not all([title, rodzaj_nieruchomosci, lokalizacja, cena, testOpisu]):
        msq.handle_error(f'UWAGA! Nie wszystkie wymagane dane zostały przekazane do endpointa /save-rent-offer przez {session["username"]}!', log_path=logFileName)
        return jsonify({'error': 'Nie wszystkie wymagane dane zostały przekazane'}), 400

    settingsDB = generator_settingsDB()
    real_loc_on_server = settingsDB['real-location-on-server']
    domain = settingsDB['main-domain']
    estate_pic_path = settingsDB['estate-pic-offer']

    upload_path = f'{real_loc_on_server}{estate_pic_path}'
    mainDomain_URL = f'{domain}{estate_pic_path}'

    # Przetwarzanie przesłanych zdjęć
    photos = request.files.getlist('photos[]')
    saved_photos =[]
    # first_photo_processed = False 
    for photo in photos:
        if photo:
            filename = f"{int(time.time())}_{secure_filename(photo.filename)}"
            full_path = os.path.join(upload_path, filename)
            complete_URL_PIC = f'{mainDomain_URL}{filename}'

            try:
                photo.save(full_path)
                saved_photos.append(complete_URL_PIC)

                # Normalizujemy nazwy plików w allPhotos, aby uniknąć problemów z porównaniem
                normalized_allPhotos = [secure_filename(p.split('/')[-1]) for p in allPhotos]

                # Sprawdzenie, czy nazwa zdjęcia istnieje w allPhotos
                original_name = secure_filename(photo.filename)
                if original_name in normalized_allPhotos:
                    pobrany_index = normalized_allPhotos.index(original_name)
                    allPhotos[pobrany_index] = filename  # Zastępujemy starą nazwę nową

            except Exception as e:
                msq.handle_error(
                    f'UWAGA! Nie udało się zapisać pliku {filename}: {str(e)}. Adres {complete_URL_PIC} nie jest dostępny!!', 
                    log_path=logFileName
                )
                print(f"Nie udało się zapisać pliku {filename}: {str(e)}. UWAGA: Adres {complete_URL_PIC} nie jest dostępny!")


    # print(allPhotos)
    if offerID_int == 9999999:
        gallery_id = None
        # Obsługa zdjęć 
        if len(saved_photos)>=1:
            # dodaj zdjęcia do bazy i pobierz id galerii
            dynamic_col_name = ''
            dynamic_amount = ''
            for i in range(len(saved_photos)):
                dynamic_col_name += f'Zdjecie_{i + 1}, '
                dynamic_amount += '%s, '
            dynamic_col_name = dynamic_col_name[:-2]
            dynamic_amount = dynamic_amount[:-2]

            zapytanie_sql = f'''INSERT INTO ZdjeciaOfert ({dynamic_col_name}) VALUES ({dynamic_amount});'''
            dane = tuple(a for a in saved_photos)

            if msq.insert_to_database(zapytanie_sql, dane):
                # Przykładowe dane
                try:
                    gallery_id = msq.connect_to_database(
                        '''
                            SELECT * FROM ZdjeciaOfert ORDER BY ID DESC;
                        ''')[0][0]
                except Exception as err:
                    msq.handle_error(f'Błąd podczas tworzenia galerii: {err}!', log_path=logFileName)
                    flash(f'Błąd podczas tworzenia galerii! \n {err}', 'danger')
                    return jsonify({
                        'message': f'Błąd podczas tworzenia galerii! \n {err}',
                        'success': True
                        }), 200
            else:
                msq.handle_error(f'UWAGA! Błąd podczas zapisywania galerii w bazie przez {session["username"]}!', log_path=logFileName)
                flash(f'Błąd podczas zapisywania galerii w bazie!', 'danger')
                return jsonify({
                    'message': 'Błąd podczas zapisywania galerii w bazie!',
                    'success': True
                    }), 200
        else:
            msq.handle_error(f'UWAGA! BRAK ZDJĘĆ! Niemożliwe jest zapisywania galerii w bazie przez {session["username"]}!', log_path=logFileName)
            flash(f'BRAK ZDJĘĆ! Niemożliwe jest zapisywania galerii w bazie!', 'danger')
            return jsonify({
                    'message': 'BRAK ZDJĘĆ! Niemożliwe jest zapisywania galerii w bazie!',
                    'success': True
                    }), 200
        
        
        try:
            logo_path = upload_path+'logo.png'  # Ścieżka do pliku logo
            output_path = upload_path+saved_photos[0].split('/')[-1]
            full_path = output_path

            # print(full_path, logo_path, output_path)
            apply_logo_to_image(full_path, logo_path, output_path, scale_factor=1)
        except Exception as e:
            flash(f'Uwaga Nakładka nie została ustawiona: {e}', 'danger')

    else:
        try: gallery_id = take_data_where_ID('Zdjecia', 'OfertyNajmu', 'ID', offerID_int)[0][0]
        except IndexError: 
            msq.handle_error(f'UWAGA! Nie udało się pobrać ID galerii!', log_path=logFileName)
            flash(f"Nie udało się pobrać ID galerii!", "danger")
            return jsonify({
                    'message': 'Nie udało się pobrać ID galerii!',
                    'success': True
                    }), 200
            
        try: 
            current_gallery = take_data_where_ID('*', 'ZdjeciaOfert', 'ID', gallery_id)[0]
            current_gallery_list = [p for p in current_gallery[1:-1] if p is not None]
        except IndexError: 
            msq.handle_error(f'UWAGA! Nie udało się pobrać galerii!', log_path=logFileName)
            flash(f"Nie udało się pobrać galerii!", "danger")
            return jsonify({
                    'message': 'Nie udało się pobrać galerii!',
                    'success': True
                    }), 200

        aktualne_linkURL_set = set()
        for linkUrl in current_gallery:
            nazwaZdjecia = str(linkUrl).split('/')[-1]
            aktualne_linkURL_set.add(nazwaZdjecia)

        przeslane_nazwyZdjec_set = set()
        for nazwaZdjecia in oldPhotos:
            przeslane_nazwyZdjec_set.add(nazwaZdjecia)

        zdjeciaDoUsuniecia = aktualne_linkURL_set.difference(przeslane_nazwyZdjec_set)
        for delIt in zdjeciaDoUsuniecia:
            complete_URL_PIC = f'{mainDomain_URL}{delIt}'
            if complete_URL_PIC in current_gallery_list:
                current_gallery_list.remove(complete_URL_PIC)
                try:
                    file_path = upload_path + delIt
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    else:
                        print(f"File {file_path} not found.")
                except Exception as e:
                    msq.handle_error(f'UWAGA! Error removing file {file_path}: {e}', log_path=logFileName)
                    print(f"Error removing file {file_path}: {e}")

        oldPhotos_plus_saved_photos = current_gallery_list + saved_photos

        index_map = {nazwa: index for index, nazwa in enumerate(allPhotos)}

        # Sortowanie oldPhotos_plus_saved_photos na podstawie pozycji w allPhotos
        oldPhotos_plus_saved_photos_sorted = sorted(oldPhotos_plus_saved_photos, key=lambda x: index_map[x.split('/')[-1]])
        # print(oldPhotos_plus_saved_photos_sorted)
        
        if len(oldPhotos_plus_saved_photos_sorted)>=1 and len(oldPhotos_plus_saved_photos_sorted) <=10:
            # dodaj zdjęcia do bazy i pobierz id galerii
            dynamic_col_name = ''
            
            for i in range(10):
                dynamic_col_name += f'Zdjecie_{i + 1} = %s, '

            dynamic_col_name = dynamic_col_name[:-2]

            zapytanie_sql = f'''
                UPDATE ZdjeciaOfert
                SET {dynamic_col_name} 
                WHERE ID = %s;
                '''
            len_oldPhotos_plus_saved_photos = len(oldPhotos_plus_saved_photos_sorted)
            if 10 - len_oldPhotos_plus_saved_photos == 0:
                dane = tuple(a for a in oldPhotos_plus_saved_photos_sorted + [gallery_id])
            else:
                oldPhotos_plus_saved_photos_plus_empyts = oldPhotos_plus_saved_photos_sorted
                for _ in  range(10 - len_oldPhotos_plus_saved_photos):
                    oldPhotos_plus_saved_photos_plus_empyts += [None]
                dane = tuple(a for a in oldPhotos_plus_saved_photos_plus_empyts + [gallery_id])

            # print(zapytanie_sql, dane)
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Galeria została pomyslnie zaktualizowana przez {session["username"]}!', log_path=logFileName)
                addDataLogs(f'Galeria została pomyslnie zaktualizowana przez {session["username"]}!', "success")
                print('update_galerii_udany')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu galerii! Oferta wynajmu nie została zapisana przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu galerii! Oferta wynajmu nie została zapisana!', 'danger')
                addDataLogs(f'Bład zapisu galerii! Oferta wynajmu nie została zapisana!', 'danger')
                return jsonify({
                        'message': 'xxx',
                        'success': True
                        }), 200

    
        
        try:
            logo_path = upload_path+'logo.png'  # Ścieżka do pliku logo
            output_path = upload_path+oldPhotos_plus_saved_photos_sorted[0].split('/')[-1]
            full_path = output_path

            # print(full_path, logo_path, output_path)
            apply_logo_to_image(full_path, logo_path, output_path, scale_factor=1)
        except Exception as e:
            flash(f'Uwaga Nakładka nie została ustawiona: {e}', 'danger')

    user_phone = session['user_data']['phone']
    user_email = session['user_data']['email']

    if offerID_int == 9999999:
        zapytanie_sql = f'''
                    INSERT INTO OfertyNajmu (Tytul, Opis, Cena, Kaucja, Lokalizacja, LiczbaPokoi, Metraz, Zdjecia, 
                                            RodzajZabudowy, Czynsz, Umeblowanie, LiczbaPieter, PowierzchniaDzialki,
                                            TechBudowy, FormaKuchni, TypDomu, StanWykonczenia, RokBudowy, NumerKW,
                                            InformacjeDodatkowe, GPS, TelefonKontaktowy, EmailKontaktowy, StatusOferty) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);'''
        
        dane = (
                title, OPIS_JSON_STR, cena, kaucja, lokalizacja, liczbaPokoi, metraz, gallery_id,
                rodzajZabudowy, czynsz, umeblowanie, liczbaPieter, powDzialki,
                techBudowy, kuchnia, rodzaj_nieruchomosci, stan, rokBudowy, nrKW,
                dodatkoweInfo, GPS_STRING, user_phone, user_email, 1)
    else:
        zapytanie_sql = f'''
                    UPDATE OfertyNajmu 
                    SET 
                        Tytul=%s, Opis=%s, Cena=%s, Kaucja=%s, Lokalizacja=%s, LiczbaPokoi=%s, Metraz=%s, Zdjecia=%s, 
                        RodzajZabudowy=%s, Czynsz=%s, Umeblowanie=%s, LiczbaPieter=%s, PowierzchniaDzialki=%s,
                        TechBudowy=%s, FormaKuchni=%s, TypDomu=%s, StanWykonczenia=%s, RokBudowy=%s, NumerKW=%s,
                        InformacjeDodatkowe=%s, GPS=%s, TelefonKontaktowy=%s, EmailKontaktowy=%s, StatusOferty=%s
                    WHERE ID = %s;'''
        dane = (
                title, OPIS_JSON_STR, cena, kaucja, lokalizacja, liczbaPokoi, metraz, gallery_id,
                rodzajZabudowy, czynsz, umeblowanie, liczbaPieter, powDzialki,
                techBudowy, kuchnia, rodzaj_nieruchomosci, stan, rokBudowy, nrKW,
                dodatkoweInfo, GPS_STRING, user_phone, user_email, 1, offerID_int)

    if msq.insert_to_database(zapytanie_sql, dane):
        if offerID_int != 9999999 and checkSpecOffer(offerID_int, 'r') == 'aktywna':
            addSpecOffer(offerID, 's')
        msq.handle_error(f'Oferta wynajmu została zapisana pomyślnie przez {session["username"]}!', log_path=logFileName)
        flash(f'Oferta wynajmu została zapisana pomyślnie!', 'success')
        return jsonify({
            'message': 'Oferta wynajmu została zapisana pomyślnie!',
            'success': True
            }), 200
    else:
        msq.handle_error(f'UWAGA! Bład zapisu! Oferta wynajmu nie została zapisana!', log_path=logFileName)
        flash(f'Bład zapisu! Oferta wynajmu nie została zapisana!', 'danger')
        return jsonify({
                'message': 'Bład zapisu! Oferta wynajmu nie została zapisana!',
                'success': True
                }), 200

@app.route('/estate-ads-sell')
def estateAdsSell():
    """Strona zawierająca listę z ogłoszeniami nieruchomości."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /estate-ads-sell bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /estate-ads-sell bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Wczytanie listy wszystkich postów z bazy danych i przypisanie jej do zmiennej posts
    all_sell = generator_sellOffert()

    new_all_sell = []
    for item in all_sell:
        if 'lento' not in item:
            item['lento'] = {}
        lentoIDstatus = checkLentoStatus(kind="s", id=item['ID'])
        item['lento']['id'] = lentoIDstatus[0]
        item['lento']['status'] = lentoIDstatus[1]
        item['lento']['data_aktualizacji'] = lentoIDstatus[2]
        item['lento']['errors'] = lentoIDstatus[3]
        item['lento']['action_before_errors'] = lentoIDstatus[4]

        if item['lento']['status'] is not None:
            start_date = item['lento']['data_aktualizacji']
            # Oblicz datę końca promocji
            end_date = start_date + datetime.timedelta(days=90)
            # Oblicz liczbę dni pozostałych do końca promocji
            days_left = (end_date - datetime.datetime.now()).days

            item['lento']['zostalo_dni'] = days_left
            # print(item['lento']['zostalo_dni'])

            item['lento']['error_message'] = lentoIDstatus[3]
        

        if 'facebook' not in item:
            item['facebook'] = {}
        facebookIDstatus = checkFacebookStatus(kind="s", id=item['ID'])
        item['facebook']['id'] = facebookIDstatus[0]
        item['facebook']['status'] = facebookIDstatus[1]
        item['facebook']['data_aktualizacji'] = facebookIDstatus[2]
        item['facebook']['errors'] = facebookIDstatus[3]
        item['facebook']['action_before_errors'] = facebookIDstatus[4]

        if item['facebook']['status'] is not None:
            start_date = item['facebook']['data_aktualizacji']
            # Oblicz datę końca promocji
            end_date = start_date + datetime.timedelta(days=90)
            # Oblicz liczbę dni pozostałych do końca promocji
            days_left = (end_date - datetime.datetime.now()).days

            item['facebook']['zostalo_dni'] = days_left

            item['facebook']['error_message'] = facebookIDstatus[3]

        if 'adresowo' not in item:
            item['adresowo'] = {}
        adresowoIDstatus = checkAdresowoStatus(kind="s", id=item['ID'])
        item['adresowo']['id'] = adresowoIDstatus[0]
        item['adresowo']['status'] = adresowoIDstatus[1]
        item['adresowo']['data_aktualizacji'] = adresowoIDstatus[2]
        item['adresowo']['errors'] = adresowoIDstatus[3]
        item['adresowo']['action_before_errors'] = adresowoIDstatus[4]
        item['adresowo']['region'] = adresowoIDstatus[5]
        item['adresowo']['ulica'] = adresowoIDstatus[6]


        if item['adresowo']['status'] is not None:
            start_date = item['adresowo']['data_aktualizacji']

            # Oblicz liczbę miesięcy aktywności
            current_date = datetime.datetime.now()
            months_active = (current_date.year - start_date.year) * 12 + current_date.month - start_date.month

            # Przypisz liczbę aktywnych miesięcy do item['adresowo']['aktywne_miesiecy']
            item['adresowo']['aktywne_miesiecy'] = months_active

            item['adresowo']['error_message'] = facebookIDstatus[3]

        if 'allegro' not in item:
            item['allegro'] = {}
        allegroIDstatus = checkAllegroStatus(kind="s", id=item['ID'])
        item['allegro']['id'] = allegroIDstatus[0]
        item['allegro']['status'] = allegroIDstatus[1]
        item['allegro']['data_aktualizacji'] = allegroIDstatus[2]
        item['allegro']['errors'] = allegroIDstatus[3]
        item['allegro']['action_before_errors'] = allegroIDstatus[4]
        item['allegro']['region'] = allegroIDstatus[5]
        item['allegro']['ulica'] = allegroIDstatus[6]
        item['allegro']['kod'] = allegroIDstatus[7]


        if item['allegro']['status'] is not None:
            start_date = item['allegro']['data_aktualizacji']
            # Oblicz datę końca promocji
            end_date = start_date + datetime.timedelta(days=30)
            # Oblicz liczbę dni pozostałych do końca promocji
            days_left = (end_date - datetime.datetime.now()).days

            item['allegro']['zostalo_dni'] = days_left

            item['allegro']['error_message'] = allegroIDstatus[3]

        if 'otodom' not in item:
            item['otodom'] = {}
        otodom_IDstatus = checkOtodomStatus(kind="s", id=item['ID'])
        item['otodom']['id'] = otodom_IDstatus[0]
        item['otodom']['status'] = otodom_IDstatus[1]
        item['otodom']['data_aktualizacji'] = otodom_IDstatus[2]
        item['otodom']['errors'] = otodom_IDstatus[3]
        item['otodom']['action_before_errors'] = otodom_IDstatus[4]
        item['otodom']['region'] = otodom_IDstatus[5]
        item['otodom']['kategoria_ogloszenia'] = otodom_IDstatus[6]

        if item['otodom']['status'] is not None:
            start_date = item['otodom']['data_aktualizacji']
            # Oblicz datę końca promocji
            end_date = start_date + datetime.timedelta(days=30)
            # Oblicz liczbę dni pozostałych do końca promocji
            days_left = (end_date - datetime.datetime.now()).days

            item['otodom']['zostalo_dni'] = days_left

            item['otodom']['error_message'] = otodom_IDstatus[3]

        if 'fbgroups' not in item:
            item['fbgroups'] = {}
        fbgroupsIDstatus = checkFbGroupstatus(section="estateAdsSell", post_id=item['ID'])
        item['fbgroups']['id'] = fbgroupsIDstatus[0]
        item['fbgroups']['post_id'] = fbgroupsIDstatus[1]
        item['fbgroups']['content'] = fbgroupsIDstatus[2]
        item['fbgroups']['color_choice'] = fbgroupsIDstatus[3]
        item['fbgroups']['repeats'] = fbgroupsIDstatus[4]
        item['fbgroups']['repeats_left'] = fbgroupsIDstatus[5]
        item['fbgroups']['repeats_last'] = fbgroupsIDstatus[6]

        item['fbgroups']['schedule_0_id'] = fbgroupsIDstatus[7]
        item['fbgroups']['schedule_0_datetime'] = fbgroupsIDstatus[8]
        item['fbgroups']['schedule_0_status'] = fbgroupsIDstatus[9]
        item['fbgroups']['schedule_0_errors'] = fbgroupsIDstatus[10]

        item['fbgroups']['schedule_1_id'] = fbgroupsIDstatus[11]
        item['fbgroups']['schedule_1_datetime'] = fbgroupsIDstatus[12]
        item['fbgroups']['schedule_1_status'] = fbgroupsIDstatus[13]
        item['fbgroups']['schedule_1_errors'] = fbgroupsIDstatus[14]

        item['fbgroups']['schedule_2_id'] = fbgroupsIDstatus[15]
        item['fbgroups']['schedule_2_datetime'] = fbgroupsIDstatus[16]
        item['fbgroups']['schedule_2_status'] = fbgroupsIDstatus[17]
        item['fbgroups']['schedule_2_errors'] = fbgroupsIDstatus[18]

        item['fbgroups']['schedule_3_id'] = fbgroupsIDstatus[19]
        item['fbgroups']['schedule_3_datetime'] = fbgroupsIDstatus[20]
        item['fbgroups']['schedule_3_status'] = fbgroupsIDstatus[21]
        item['fbgroups']['schedule_3_errors'] = fbgroupsIDstatus[22]

        item['fbgroups']['schedule_4_id'] = fbgroupsIDstatus[23]
        item['fbgroups']['schedule_4_datetime'] = fbgroupsIDstatus[24]
        item['fbgroups']['schedule_4_status'] = fbgroupsIDstatus[25]
        item['fbgroups']['schedule_4_errors'] = fbgroupsIDstatus[26]

        item['fbgroups']['schedule_5_id'] = fbgroupsIDstatus[27]
        item['fbgroups']['schedule_5_datetime'] = fbgroupsIDstatus[28]
        item['fbgroups']['schedule_5_status'] = fbgroupsIDstatus[29]
        item['fbgroups']['schedule_5_errors'] = fbgroupsIDstatus[30]

        item['fbgroups']['schedule_6_id'] = fbgroupsIDstatus[31]
        item['fbgroups']['schedule_6_datetime'] = fbgroupsIDstatus[32]
        item['fbgroups']['schedule_6_status'] = fbgroupsIDstatus[33]
        item['fbgroups']['schedule_6_errors'] = fbgroupsIDstatus[34]

        item['fbgroups']['schedule_7_id'] = fbgroupsIDstatus[35]
        item['fbgroups']['schedule_7_datetime'] = fbgroupsIDstatus[36]
        item['fbgroups']['schedule_7_status'] = fbgroupsIDstatus[37]
        item['fbgroups']['schedule_7_errors'] = fbgroupsIDstatus[38]

        item['fbgroups']['schedule_8_id'] = fbgroupsIDstatus[39]
        item['fbgroups']['schedule_8_datetime'] = fbgroupsIDstatus[40]
        item['fbgroups']['schedule_8_status'] = fbgroupsIDstatus[41]
        item['fbgroups']['schedule_8_errors'] = fbgroupsIDstatus[42]

        item['fbgroups']['schedule_9_id'] = fbgroupsIDstatus[43]
        item['fbgroups']['schedule_9_datetime'] = fbgroupsIDstatus[44]
        item['fbgroups']['schedule_9_status'] = fbgroupsIDstatus[45]
        item['fbgroups']['schedule_9_errors'] = fbgroupsIDstatus[46]

        item['fbgroups']['schedule_10_id'] = fbgroupsIDstatus[47]
        item['fbgroups']['schedule_10_datetime'] = fbgroupsIDstatus[48]
        item['fbgroups']['schedule_10_status'] = fbgroupsIDstatus[49]
        item['fbgroups']['schedule_10_errors'] = fbgroupsIDstatus[50]

        item['fbgroups']['category'] = fbgroupsIDstatus[51]
        item['fbgroups']['created_by'] = fbgroupsIDstatus[52]
        item['fbgroups']['section'] = fbgroupsIDstatus[53]
        item['fbgroups']['id_gallery'] = fbgroupsIDstatus[54]
        item['fbgroups']['data_aktualizacji'] = fbgroupsIDstatus[55]

        if 'socialSync' not in item:
            item['socialSync'] = {}
        socialSync_IDstatus = checkSocialSyncStatus(kind="s", id=item['ID'])
        item['socialSync']['id'] = socialSync_IDstatus[0]
        item['socialSync']['status'] = socialSync_IDstatus[1]
        item['socialSync']['data_aktualizacji'] = socialSync_IDstatus[2]
        item['socialSync']['errors'] = socialSync_IDstatus[3]
        item['socialSync']['action_before_errors'] = socialSync_IDstatus[4]
        item['socialSync']['kategoria_ogloszenia'] = socialSync_IDstatus[5]

        

        if item.get('socialSync') and item['socialSync'].get('status') is not None:
            update_date = item['socialSync'].get('data_aktualizacji')
            last_update_ads = item.get('DataAktualizacji_raw')

            # Sprawdzamy, czy update_date nie jest None
            if update_date and last_update_ads and update_date < last_update_ads:
                query = "DELETE FROM ogloszenia_socialsync WHERE id=%s;"
                params = (item['socialSync']['id'], )

                if msq.insert_to_database(query, params):  # Jeśli usunięcie się powiodło
                    item['socialSync']['status'] = None

            # Obliczamy ilość dni od momentu publikacji
            if update_date:
                days_since_published = (datetime.datetime.now() - update_date).days
                item['socialSync']['opublikowano_dni'] = max(days_since_published, 0)  # Unikamy wartości ujemnych

        new_all_sell.append(item)

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(all_sell)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    ads_sell = new_all_sell[offset: offset + per_page]

    specOfferIfno = generator_specialOffert()
    if len(specOfferIfno) == 1:
        if specOfferIfno[0]['RodzajRodzica'] == 's':
            specOfferID = specOfferIfno[0]['IdRodzica']
        else:
            specOfferID = 'None'
    else:
        specOfferID = 'None'

    return render_template(
            "estate_management_sell.html",
            ads_sell=ads_sell,
            specOfferID=specOfferID,
            userperm=session['userperm'],
            username=session['username'],
            pagination=pagination
            )     

@app.route('/remove-sell-offer', methods=['POST'])
def remove_sell_offer():
    """Usuwanie ofertę najmu"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /remove-sell-offer bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /remove-sell-offer bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()
        try: form_data['PostID']
        except KeyError: return redirect(url_for('index'))
        set_post_id = int(form_data['PostID'])
        # pobieram id galerii
        try: id_galerry = take_data_where_ID('Zdjecia', 'OfertySprzedazy', 'ID', set_post_id )[0][0]
        except IndexError: 
            msq.handle_error(f'UWAGA! Wpis nie został usunięty przez {session["username"]}! Wystąpił błąd struktury danych galerii!', log_path=logFileName)
            flash("Wpis nie został usunięty. Wystąpił błąd struktury danych galerii", "danger")
            return redirect(url_for('estateAdsSell'))
        
        try: current_gallery = take_data_where_ID('*', 'ZdjeciaOfert', 'ID', id_galerry)[0]
        except IndexError: 
            msq.handle_error(f'UWAGA! Wpis nie został usunięty przez {session["username"]}! Wystąpił błąd struktury danych galerii!', log_path=logFileName)
            flash("Wpis nie został usunięty. Wystąpił błąd struktury danych galerii", "danger")
            return redirect(url_for('estateAdsSell'))
        
        removeSpecOffer(set_post_id, 's')
        msq.delete_row_from_database(
                """
                    DELETE FROM OfertySprzedazy WHERE ID = %s;
                """,
                (set_post_id,)
            )
        
        msq.delete_row_from_database(
                """
                    DELETE FROM ZdjeciaOfert WHERE ID = %s;
                """,
                (id_galerry,)
            )
        
        real_loc_on_server = settingsDB['real-location-on-server']
        domain = settingsDB['main-domain']
        estate_pic_path = settingsDB['estate-pic-offer']
        upload_path = f'{real_loc_on_server}{estate_pic_path}'
        mainDomain_URL = f'{domain}{estate_pic_path}'

        
        current_gallery_list = [p for p in current_gallery[1:-1] if p is not None]
        # print(current_gallery_list)
        for delIt in current_gallery_list:
            delIt_clear = str(delIt).replace(mainDomain_URL, '')
            # print(delIt)
            # print(delIt_clear)
            if delIt in current_gallery_list:
                try:
                    file_path = upload_path + delIt_clear
                    # print(file_path)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    else:
                        print(f"File {file_path} not found.")
                except Exception as e:
                    msq.handle_error(f'UWAGA! Error removing file {file_path}: {e}', log_path=logFileName)
                    print(f"Error removing file {file_path}: {e}")

        msq.handle_error(f'Wpis został usunięty przez {session["username"]}!', log_path=logFileName)
        flash("Wpis został usunięty.", "success")
        return redirect(url_for('estateAdsSell'))
    
    return redirect(url_for('index'))

@app.route('/update-sell-offer-status', methods=['POST'])
def update_sell_offer_status():
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /update-sell-offer-status bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /update-sell-offer-status bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()
        try: 
            form_data['PostID']
            form_data['Status']
        except KeyError: return redirect(url_for('index'))
        set_post_id = int(form_data['PostID'])
        set_post_status = int(form_data['Status'])

        statusNaLento = checkLentoStatus('s', set_post_id)
        if statusNaLento[0] != None:
            msq.handle_error(f'UWAGA! Błąd! Status oferty nie został zmieniony przez {session["username"]}! Usuń na zawsze ogłoszenie z Lento.pl', log_path=logFileName)
            flash("Status oferty nie został zmieniony. Usuń na zawsze ogłoszenie z Lento.pl", "danger")
            return redirect(url_for('estateAdsSell'))
        
        statusNaFacebooku = checkFacebookStatus('s', set_post_id)
        if statusNaFacebooku[0] != None:
            msq.handle_error(f'UWAGA! Błąd! Status oferty nie został zmieniony przez {session["username"]}! Usuń na zawsze ogłoszenie z Facebooka', log_path=logFileName)
            flash("Status oferty nie został zmieniony. Usuń na zawsze ogłoszenie z Facebooka", "danger")
            return redirect(url_for('estateAdsSell'))
        
        statusNaAdresowo = checkAdresowoStatus('s', set_post_id)
        if statusNaAdresowo[0] != None:
            msq.handle_error(f'UWAGA! Błąd! Status oferty nie został zmieniony przez {session["username"]}! Usuń na zawsze ogłoszenie z Adresowo', log_path=logFileName)
            flash("Status oferty nie został zmieniony. Usuń na zawsze ogłoszenie z Adresowo", "danger")
            return redirect(url_for('estateAdsSell'))
        
        statusNaAllegro = checkAllegroStatus('s', set_post_id)
        if statusNaAllegro[0] != None:
            msq.handle_error(f'UWAGA! Błąd! Status oferty nie został zmieniony przez {session["username"]}! Usuń na zawsze ogłoszenie z Allegro', log_path=logFileName)
            flash("Status oferty nie został zmieniony. Usuń na zawsze ogłoszenie z Allegro", "danger")
            return redirect(url_for('estateAdsSell'))
        
        if set_post_status == 0:
            removeSpecOffer(set_post_id, 's')
        zapytanie_sql = f'''
                UPDATE OfertySprzedazy
                SET StatusOferty = %s
                WHERE ID = %s;
                '''
        dane = (set_post_status, set_post_id)
        if msq.insert_to_database(zapytanie_sql, dane):
            msq.handle_error(f'Status oferty został zmieniony przez {session["username"]}!', log_path=logFileName)
            flash("Status oferty został zmieniony.", "success")
            return redirect(url_for('estateAdsSell'))
    
    return redirect(url_for('index'))

@app.route('/save-sell-offer', methods=["POST"])
def save_sell_offer():
    # Odczytanie danych formularza
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /save-sell-offer bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /save-sell-offer bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Pobierz JSON jako string z formularza
    OPIS_JSON_STRing = request.form['opis']
    # Przekonwertuj string JSON na słownik Pythona
    try:
        opis_data = json.loads(OPIS_JSON_STRing)
    except json.JSONDecodeError:
        return jsonify({'error': 'Nieprawidłowy format JSON'}), 400

    # Teraz opis_data jest słownikiem Pythona, który możesz używać w kodzie
    title = request.form.get('title')
    typ_nieruchomosci = request.form.get('typNieruchomosci')
    rynek = request.form.get('rynek')
    lokalizacja = request.form.get('lokalizacja')

    cena = request.form.get('cena')
    try: cena = int(cena)
    except ValueError: return jsonify({'error': 'Cena musi być liczbą'}), 400
    opis = opis_data
    lat = request.form.get('lat')
    lon = request.form.get('lon')
    if lat and lon:
        GPS = {"latitude": lat, "longitude": lon }
        GPS_STRING = str(GPS).replace("'", '"')
    else: GPS_STRING = ''
    rokBudowy = request.form.get('rokBudowy')
    try: rokBudowy = int(rokBudowy)
    except ValueError: rokBudowy = 0

    stan = request.form.get('stan')
    nrKW = request.form.get('nrKW')
    typDomu = request.form.get('typDomu')

    przeznaczenieLokalu = request.form.get('przeznaczenieLokalu')

    metraz = request.form.get('metraz')
    try: 
        metraz = int(float(metraz))
    except Exception as e: 
        print(e)
        metraz = 0

    poziom = request.form.get('poziom')
    try: poziom = int(poziom)
    except ValueError: poziom = None
    liczbaPieter = request.form.get('liczbaPieter')
    try: liczbaPieter = int(liczbaPieter)
    except ValueError: liczbaPieter = 0
    liczbaPokoi = request.form.get('liczbaPokoi')
    try: liczbaPokoi = int(liczbaPokoi)
    except ValueError: liczbaPokoi = 0
    techBudowy = request.form.get('techBudowy')
    rodzajZabudowy = request.form.get('rodzajZabudowy')
    rodzajNieruchomosci = request.form.get('rodzajNieruchomosci')
    kuchnia = request.form.get('kuchnia')
    dodatkoweInfo = request.form.get('dodatkoweInfo')
    offerID = request.form.get('offerID')
    try: offerID_int = int(offerID)
    except ValueError: return jsonify({'error': 'Błąd id oferty!'}), 400

    if offerID_int == 9999999:
        oldPhotos = []
        allPhotos = []
    else:
        oldPhotos = request.form.getlist('oldPhotos[]')
        allPhotos = request.form.getlist('allPhotos[]')

    # print(allPhotos)
    validOpis = []
    for test in opis:
        for val in test.values():
            if isinstance(val, str) and val != "":
                validOpis.append(test)
            if isinstance(val, list) and len(val)!=0:
                clearLI = [a for a in val if a != ""]
                new_li = {"li": clearLI}
                validOpis.append(new_li)
    
    if len(validOpis)!=0: 
        testOpisu = True
        opis_json = validOpis
        OPIS_JSON_STR = str(opis_json).replace("'", '"')
    else: testOpisu = False

    # Sprawdzenie czy wszystkie wymagane dane zostały przekazane
    if not all([title, typ_nieruchomosci, lokalizacja, cena, testOpisu]):
        msq.handle_error(f'UWAGA! Błąd! Nie wszystkie wymagane dane zostały przekazane do endointa /save-sell-offer przez {session["username"]}!', log_path=logFileName)
        return jsonify({'error': 'Nie wszystkie wymagane dane zostały przekazane'}), 400

    settingsDB = generator_settingsDB()
    real_loc_on_server = settingsDB['real-location-on-server']
    domain = settingsDB['main-domain']
    estate_pic_path = settingsDB['estate-pic-offer']

    upload_path = f'{real_loc_on_server}{estate_pic_path}'
    mainDomain_URL = f'{domain}{estate_pic_path}'


    # Przetwarzanie przesłanych zdjęć
    photos = request.files.getlist('photos[]')
    saved_photos =[]
    for photo in photos:
        if photo:
            filename = f"{int(time.time())}_{secure_filename(photo.filename)}"
            full_path = os.path.join(upload_path, filename)
            complete_URL_PIC = f'{mainDomain_URL}{filename}'

            try:
                photo.save(full_path)
                saved_photos.append(complete_URL_PIC)

                # Normalizujemy nazwy plików w allPhotos, aby uniknąć problemów z porównaniem
                normalized_allPhotos = [secure_filename(p.split('/')[-1]) for p in allPhotos]

                # Sprawdzenie, czy nazwa zdjęcia istnieje w allPhotos
                original_name = secure_filename(photo.filename)
                if original_name in normalized_allPhotos:
                    pobrany_index = normalized_allPhotos.index(original_name)
                    allPhotos[pobrany_index] = filename  # Zastępujemy starą nazwę nową

            except Exception as e:
                msq.handle_error(
                    f'UWAGA! Nie udało się zapisać pliku {filename}: {str(e)}. Adres {complete_URL_PIC} nie jest dostępny!!', 
                    log_path=logFileName
                )
                print(f"Nie udało się zapisać pliku {filename}: {str(e)}. UWAGA: Adres {complete_URL_PIC} nie jest dostępny!")


    # print(allPhotos)
    if offerID_int == 9999999:
        gallery_id = None
        # Obsługa zdjęć 
        if len(saved_photos)>=1:
            # dodaj zdjęcia do bazy i pobierz id galerii
            dynamic_col_name = ''
            dynamic_amount = ''
            for i in range(len(saved_photos)):
                dynamic_col_name += f'Zdjecie_{i + 1}, '
                dynamic_amount += '%s, '
            dynamic_col_name = dynamic_col_name[:-2]
            dynamic_amount = dynamic_amount[:-2]

            zapytanie_sql = f'''INSERT INTO ZdjeciaOfert ({dynamic_col_name}) VALUES ({dynamic_amount});'''
            dane = tuple(a for a in saved_photos)

            if msq.insert_to_database(zapytanie_sql, dane):
                # Przykładowe dane
                try:
                    gallery_id = msq.connect_to_database(
                        '''
                            SELECT * FROM ZdjeciaOfert ORDER BY ID DESC;
                        ''')[0][0]
                except Exception as err:
                    msq.handle_error(f'UWAGA! Błąd podczas tworzenia galerii! przez {session["username"]}! {err}', log_path=logFileName)
                    flash(f'Błąd podczas tworzenia galerii! \n {err}', 'danger')
                    return jsonify({
                        'message': f'Błąd podczas tworzenia galerii! \n {err}',
                        'success': True
                        }), 200
            else:
                msq.handle_error(f'UWAGA! Błąd podczas zapisywania galerii w bazie przez {session["username"]}!', log_path=logFileName)
                flash(f'Błąd podczas zapisywania galerii w bazie!', 'danger')
                return jsonify({
                    'message': 'Błąd podczas zapisywania galerii w bazie!',
                    'success': True
                    }), 200
        else:
            msq.handle_error(f'UWAGA! BRAK ZDJĘĆ! Niemożliwe jest zapisywania galerii w bazie przez {session["username"]}!', log_path=logFileName)
            flash(f'BRAK ZDJĘĆ! Niemożliwe jest zapisywania galerii w bazie!', 'danger')
            return jsonify({
                    'message': 'BRAK ZDJĘĆ! Niemożliwe jest zapisywania galerii w bazie!',
                    'success': True
                    }), 200
        try:
            logo_path = upload_path+'logo.png'  # Ścieżka do pliku logo
            output_path = upload_path+saved_photos[0].split('/')[-1]
            full_path = output_path
            # print(full_path, logo_path, output_path)
            apply_logo_to_image(full_path, logo_path, output_path, scale_factor=1)
        except Exception as e:
            flash(f'Uwaga Nakładka nie została ustawiona: {e}', 'danger')


    else:
        try: gallery_id = take_data_where_ID('Zdjecia', 'OfertySprzedazy', 'ID', offerID_int)[0][0]
        except IndexError: 
            msq.handle_error(f'UWAGA! Nie udało się pobrać ID galerii przez {session["username"]}!', log_path=logFileName)
            flash(f"Nie udało się pobrać ID galerii!", "danger")
            return jsonify({
                    'message': 'Nie udało się pobrać ID galerii!',
                    'success': True
                    }), 200
            
        try: 
            current_gallery = take_data_where_ID('*', 'ZdjeciaOfert', 'ID', gallery_id)[0]
            current_gallery_list = [p for p in current_gallery[1:-1] if p is not None]
        except IndexError: 
            msq.handle_error(f'UWAGA! Nie udało się pobrać galerii przez {session["username"]}!', log_path=logFileName)
            flash(f"Nie udało się pobrać galerii!", "danger")
            return jsonify({
                    'message': 'Nie udało się pobrać galerii!',
                    'success': True
                    }), 200

        aktualne_linkURL_set = set()
        for linkUrl in current_gallery:
            nazwaZdjecia = str(linkUrl).split('/')[-1]
            aktualne_linkURL_set.add(nazwaZdjecia)

        przeslane_nazwyZdjec_set = set()
        for nazwaZdjecia in oldPhotos:
            przeslane_nazwyZdjec_set.add(nazwaZdjecia)

        zdjeciaDoUsuniecia = aktualne_linkURL_set.difference(przeslane_nazwyZdjec_set)
        for delIt in zdjeciaDoUsuniecia:
            complete_URL_PIC = f'{mainDomain_URL}{delIt}'
            if complete_URL_PIC in current_gallery_list:
                current_gallery_list.remove(complete_URL_PIC)
                try:
                    file_path = upload_path + delIt
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    else:
                        print(f"File {file_path} not found.")
                except Exception as e:
                    print(f"Error removing file {file_path}: {e}")


        oldPhotos_plus_saved_photos = current_gallery_list + saved_photos

        index_map = {nazwa: index for index, nazwa in enumerate(allPhotos)}

        # Sortowanie oldPhotos_plus_saved_photos na podstawie pozycji w allPhotos
        oldPhotos_plus_saved_photos_sorted = sorted(oldPhotos_plus_saved_photos, key=lambda x: index_map[x.split('/')[-1]])
        
        if len(oldPhotos_plus_saved_photos_sorted)>=1 and len(oldPhotos_plus_saved_photos_sorted) <=10:
            # dodaj zdjęcia do bazy i pobierz id galerii
            dynamic_col_name = ''
            
            for i in range(10):
                dynamic_col_name += f'Zdjecie_{i + 1} = %s, '

            dynamic_col_name = dynamic_col_name[:-2]

            zapytanie_sql = f'''
                UPDATE ZdjeciaOfert
                SET {dynamic_col_name} 
                WHERE ID = %s;
                '''
            len_oldPhotos_plus_saved_photos = len(oldPhotos_plus_saved_photos_sorted)
            if 10 - len_oldPhotos_plus_saved_photos == 0:
                dane = tuple(a for a in oldPhotos_plus_saved_photos_sorted + [gallery_id])
            else:
                oldPhotos_plus_saved_photos_plus_empyts = oldPhotos_plus_saved_photos_sorted
                for _ in  range(10 - len_oldPhotos_plus_saved_photos):
                    oldPhotos_plus_saved_photos_plus_empyts += [None]
                dane = tuple(a for a in oldPhotos_plus_saved_photos_plus_empyts + [gallery_id])

            # print(zapytanie_sql, dane)
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Galeria o id:{gallery_id} została zaktualizowana przez {session["username"]}!', log_path=logFileName)
                print('update_galerii_udany')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu galerii id:{gallery_id}! Oferta wynajmu nie została zapisana przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu galerii! Oferta wynajmu nie została zapisana!', 'danger')
                return jsonify({
                        'message': 'xxx',
                        'success': True
                        }), 200
            
        
        try:
            logo_path = upload_path+'logo.png'  # Ścieżka do pliku logo
            output_path = upload_path+oldPhotos_plus_saved_photos_sorted[0].split('/')[-1]
            full_path = output_path

            # print(full_path, logo_path, output_path)
            apply_logo_to_image(full_path, logo_path, output_path, scale_factor=1)
        except Exception as e:
            flash(f'Uwaga Nakładka nie została ustawiona: {e}', 'danger')


    user_phone = session['user_data']['phone']
    user_email = session['user_data']['email']

    if offerID_int == 9999999:
        zapytanie_sql = f'''
                    INSERT INTO OfertySprzedazy 
                            (TypNieruchomosci, Tytul, Rodzaj, Opis, Cena, Lokalizacja, LiczbaPokoi, Metraz, Zdjecia,
                            RodzajZabudowy, Rynek, LiczbaPieter, PrzeznaczenieLokalu, Poziom,
                            TechBudowy, FormaKuchni, TypDomu, StanWykonczenia, RokBudowy, NumerKW,
                            InformacjeDodatkowe, GPS, TelefonKontaktowy, EmailKontaktowy, StatusOferty)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                    '''
        dane = (
                typ_nieruchomosci, title, rodzajNieruchomosci, OPIS_JSON_STR, cena, lokalizacja, liczbaPokoi, metraz, gallery_id,
                rodzajZabudowy, rynek, liczbaPieter, przeznaczenieLokalu, poziom, 
                techBudowy, kuchnia, typDomu, stan, rokBudowy, nrKW,
                dodatkoweInfo, GPS_STRING, user_phone, user_email, 1)
    else:
        zapytanie_sql = f'''
                    UPDATE OfertySprzedazy 
                    SET 
                        TypNieruchomosci = %s, Tytul = %s, Rodzaj = %s, Opis = %s, Cena = %s, 
                        Lokalizacja = %s, LiczbaPokoi = %s, Metraz = %s, Zdjecia = %s, RodzajZabudowy = %s, 
                        Rynek = %s, LiczbaPieter = %s, PrzeznaczenieLokalu = %s, Poziom = %s, TechBudowy = %s, 
                        FormaKuchni = %s, TypDomu = %s, StanWykonczenia = %s, RokBudowy = %s, NumerKW = %s,
                        InformacjeDodatkowe = %s, GPS = %s, TelefonKontaktowy = %s, EmailKontaktowy = %s, 
                        StatusOferty = %s
                    WHERE ID = %s;'''
        dane = (
                typ_nieruchomosci, title, rodzajNieruchomosci, OPIS_JSON_STR, cena, 
                lokalizacja, liczbaPokoi, metraz, gallery_id, rodzajZabudowy, 
                rynek, liczbaPieter, przeznaczenieLokalu, poziom, techBudowy, 
                kuchnia, typDomu, stan, rokBudowy, nrKW,
                dodatkoweInfo, GPS_STRING, user_phone, user_email, 1, offerID_int)

    if msq.insert_to_database(zapytanie_sql, dane):
        if offerID_int != 9999999 and checkSpecOffer(offerID_int, 's') == 'aktywna':
            addSpecOffer(offerID, 's')
        msq.handle_error(f'Oferta sprzedaży została zapisana pomyślnie przez {session["username"]}!', log_path=logFileName)
        flash(f'Oferta sprzedaży została zapisana pomyślnie!', 'success')
        return jsonify({
            'message': 'Oferta sprzedaży została zapisana pomyślnie!',
            'success': True
            }), 200
    else:
        msq.handle_error(f'UWAGA! Bład zapisu! Oferta sprzedaży nie została zapisana przez {session["username"]}!', log_path=logFileName)
        flash(f'Bład zapisu! Oferta sprzedaży nie została zapisana!', 'danger')
        return jsonify({
                'message': 'Bład zapisu! Oferta sprzedaży nie została zapisana!',
                'success': True
                }), 200

@app.route('/set-as-specOffer', methods=['POST'])
def set_as_specOffer():
    """Strona zawierająca listę z ogłoszeniami nieruchomości."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /set-as-specOffer bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /set-as-specOffer bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        postID = request.form.get('PostID')
        redirectGoal = request.form.get('redirectGoal')
        status = request.form.get('Status')

        if redirectGoal == 'estateAdsRent':
            parent = 'r'
        if redirectGoal == 'estateAdsSell':
            parent = 's'
        
        if status == '0':
            if removeSpecOffer(postID, parent):
                msq.handle_error(f'Zmiany oferty specjalnej zotały zastosowane z sukcesem przez {session["username"]}!', log_path=logFileName)
                flash('Zmiany zotały zastosowane z sukcesem!', 'success')
            else:
                msq.handle_error(f'UWAGA! Błąd! Zmiany oferty specjalnej nie zotały zastosowane przez {session["username"]}!', log_path=logFileName)
                flash('Błąd! Zmiany nie zotały zastosowane!', 'danger')
        
        if status == '1':
            if addSpecOffer(postID, parent):
                msq.handle_error(f'Zmiany oferty specjalnej zotały zastosowane z sukcesem przez {session["username"]}!', log_path=logFileName)
                flash('Zmiany zotały zastosowane z sukcesem!', 'success')
            else:
                msq.handle_error(f'UWAGA! Błąd! Zmiany oferty specjalnej nie zotały zastosowane przez {session["username"]}!', log_path=logFileName)
                flash('Błąd! Zmiany nie zotały zastosowane!', 'danger')

        return redirect(url_for(redirectGoal))
    return redirect(url_for('index'))

@app.route('/public-on-lento', methods=['POST'])
def public_on_lento():
    """Strona zawierająca listę z ogłoszeniami nieruchomości."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /public-on-lento bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /public-on-lento bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        lento_id = request.form.get('lento_id')
        id_ogloszenia = request.form.get('PostID')
        task_kind = request.form.get('task_kind')
        redirectGoal = request.form.get('redirectGoal')
        extra_descript = request.form.get('extra_descript')
        
        
        rodzaj_ogloszenia = None
        if redirectGoal == 'estateAdsRent':
            rodzaj_ogloszenia = 'r'
        if redirectGoal == 'estateAdsSell':
            rodzaj_ogloszenia = 's'

        if task_kind == 'Publikuj' and rodzaj_ogloszenia == 'r':
            # print(request.form)

            if 'bez_promowania' in request.form: bez_promowania = 1
            else: bez_promowania = 0

            if 'promowanie_lokalne_14_dni' in request.form: promowanie_lokalne_14_dni = 1
            else: promowanie_lokalne_14_dni = 0
            if 'promowanie_lokalne_30_dni' in request.form: promowanie_lokalne_30_dni = 1
            else: promowanie_lokalne_30_dni = 0

            if 'promowanie_regionalne_14_dni' in request.form: promowanie_regionalne_14_dni = 1
            else: promowanie_regionalne_14_dni = 0
            if 'promowanie_regionalne_30_dni' in request.form: promowanie_regionalne_30_dni = 1
            else: promowanie_regionalne_30_dni = 0

            if 'promowanie_ogolnopolskie_14_dni' in request.form: promowanie_ogolnopolskie_14_dni = 1
            else: promowanie_ogolnopolskie_14_dni = 0
            if 'promowanie_ogolnopolskie_30_dni' in request.form: promowanie_ogolnopolskie_30_dni = 1
            else: promowanie_ogolnopolskie_30_dni = 0

            if 'top_ogloszenie_7_dni' in request.form: top_ogloszenie_7_dni = 1
            else: top_ogloszenie_7_dni = 0
            if 'top_ogloszenie_14_dni' in request.form: top_ogloszenie_14_dni = 1
            else: top_ogloszenie_14_dni = 0

            if 'etykieta_pilne_7_dni' in request.form: etykieta_pilne_7_dni = 1
            else: etykieta_pilne_7_dni = 0
            if 'etykieta_pilne_14_dni' in request.form: etykieta_pilne_14_dni = 1
            else: etykieta_pilne_14_dni = 0

            if 'codzienne_odswiezenie_7_dni' in request.form: codzienne_odswiezenie_7_dni = 1
            else: codzienne_odswiezenie_7_dni = 0
            if 'codzienne_odswiezenie_14_dni' in request.form: codzienne_odswiezenie_14_dni = 1
            else: codzienne_odswiezenie_14_dni = 0

            if 'wyswietlanie_na_stronie_glownej_14_dni' in request.form: wyswietlanie_na_stronie_glownej_14_dni = 1
            else: wyswietlanie_na_stronie_glownej_14_dni = 0
            if 'wyswietlanie_na_stronie_glownej_30_dni' in request.form: wyswietlanie_na_stronie_glownej_30_dni = 1
            else: wyswietlanie_na_stronie_glownej_30_dni = 0

            if 'super_oferta_7_dni' in request.form: super_oferta_7_dni = 1
            else: super_oferta_7_dni = 0
            if 'super_oferta_14_dni' in request.form: super_oferta_14_dni = 1
            else: super_oferta_14_dni = 0

            picked_rent_offer = {}
            for rentOffer in generator_rentOffert():
                if str(rentOffer['ID']) == str(id_ogloszenia):
                    picked_rent_offer = rentOffer
            
            tytul_ogloszenia = picked_rent_offer['Tytul']
            powierzchnia = picked_rent_offer['Metraz']
            cena = picked_rent_offer['Cena']
            numer_kw = picked_rent_offer['NumerKW']
            miejscowosc = picked_rent_offer['Lokalizacja']
            osoba_kontaktowa = session['user_data']['name']
            nr_telefonu = picked_rent_offer['TelefonKontaktowy']

            zdjecia_string = ''
            for foto_link in picked_rent_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_rent_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':
                if extra_descript:
                    prepared_opis = prepared_opis + '\n' + picked_rent_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_rent_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_rent_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_rent_offer['RodzajZabudowy']}\n\n"
            if picked_rent_offer['Czynsz'] != 0:
                extra_opis += f"Czynsz:\n{picked_rent_offer['Czynsz']} zł.\n\n"
            if picked_rent_offer['Umeblowanie'] != "":
                extra_opis += f"Umeblowanie:\n{picked_rent_offer['Umeblowanie']}\n\n"
            if picked_rent_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_rent_offer['TechBudowy']}\n\n"
            if picked_rent_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_rent_offer['StanWykonczenia']}\n\n"
            if picked_rent_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_rent_offer['RokBudowy']} r.\n\n"
            if picked_rent_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_rent_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]

            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""
            

            if str(picked_rent_offer['TypDomu']).lower().count('dom') > 0\
                or str(picked_rent_offer['TypDomu']).lower().count('willa') > 0\
                    or str(picked_rent_offer['TypDomu']).lower().count('bliźniak') > 0\
                or str(picked_rent_offer['TypDomu']).lower().count('segment') > 0:
                # kategoria na lento dla dom
                kategoria_ogloszenia = 'dom'

            elif str(picked_rent_offer['TypDomu']).lower().count('mieszkanie') > 0\
                or str(picked_rent_offer['TypDomu']).lower().count('kawalerka') > 0\
                    or str(picked_rent_offer['TypDomu']).lower().count('apartament') > 0\
                        or str(picked_rent_offer['TypDomu']).lower().count('blok') > 0\
                    or str(picked_rent_offer['TypDomu']).lower().count('kamienica') > 0\
                or str(picked_rent_offer['TypDomu']).lower().count('loft') > 0:
                # kategoria na lento dla mieszkanie
                kategoria_ogloszenia = 'mieszkanie'

            elif str(picked_rent_offer['TypDomu']).lower().count('biur') > 0\
                or str(picked_rent_offer['TypDomu']).lower().count('hal') > 0\
                    or str(picked_rent_offer['TypDomu']).lower().count('usługi') > 0\
                    or str(picked_rent_offer['TypDomu']).lower().count('lokal') > 0\
                or str(picked_rent_offer['TypDomu']).lower().count('produkcja') > 0:
                # kategoria na lento dla biura_lokale
                kategoria_ogloszenia = 'biura_lokale'

            elif str(picked_rent_offer['TypDomu']).lower().count('działka') > 0\
                or str(picked_rent_offer['TypDomu']).lower().count('plac') > 0\
                    or str(picked_rent_offer['TypDomu']).lower().count('teren') > 0:
                # kategoria na lento dla dzialka
                kategoria_ogloszenia = 'dzialka'
            else:
                # kategoria na lento dla inne_nieruchomosci
                kategoria_ogloszenia = 'inne_nieruchomosci'

            if kategoria_ogloszenia == 'mieszkanie':
                if str(picked_rent_offer['RodzajZabudowy']).lower().count('apartamentowiec') > 0: zabudowa = 'apartamentowiec'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('blok') > 0: zabudowa = 'blok'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('kamienica') > 0: zabudowa = 'kamienica'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('dom') > 0: zabudowa = 'dom'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('loft') > 0: zabudowa = 'loft'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('plomba') > 0: zabudowa = 'plomba'
                else: zabudowa = 'inne'

            if kategoria_ogloszenia == 'biura_lokale':
                if str(picked_rent_offer['InformacjeDodatkowe']).lower().count('biurowe') > 0: przeznaczenie_lokalu = 'biurowe'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('handel i usługi') > 0: przeznaczenie_lokalu = 'handel i usługi'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('produkcja i przemysł') > 0: przeznaczenie_lokalu = 'produkcja i przemysł'
                else: przeznaczenie_lokalu = 'inne_przeznaczenie'

            if kategoria_ogloszenia == 'dzialka':
                if str(picked_rent_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: rodzaj_dzialki = 'budowlana'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('inwestycyjna') > 0: rodzaj_dzialki = 'inwestycyjna'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('ogródek działkowy') > 0: rodzaj_dzialki = 'ogródek działkowy'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('przemysłowa') > 0: rodzaj_dzialki = 'przemysłowa'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: rodzaj_dzialki = 'rekreacyjna'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: rodzaj_dzialki = 'siedliskowa'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: rodzaj_dzialki = 'usługowa'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: rodzaj_dzialki = 'leśna'
                else: rodzaj_dzialki = 'inwestycyjna'

            """
            (
                rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, liczba_pieter, pietro,
                zabudowa, przeznaczenie_lokalu, rodzaj_dzialki, 
                numer_kw, dodtkowe_info, forma_kuchni, typ_domu, pow_dzialki, liczba_pokoi, powierzchnia, 
                opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                id_zadania, 
                id_ogloszenia_na_lento, 
                bez_promowania, 
                promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                super_oferta_7_dni, super_oferta_14_dni,
                status
            )
            """
            if kategoria_ogloszenia == 'dom':
                if picked_rent_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_rent_offer['LiczbaPokoi'] > 4:liczba_pokoi = 5
                else:liczba_pokoi = picked_rent_offer['LiczbaPokoi']
                pow_dzialki = picked_rent_offer['PowierzchniaDzialki']
                if str(picked_rent_offer['FormaKuchni']).lower().count('anex') > 0: forma_kuchni = 'anex'
                elif str(picked_rent_offer['FormaKuchni']).lower().count('oddzielna') > 0: forma_kuchni = 'oddzielna'
                else: forma_kuchni = 'brak'
                if str(picked_rent_offer['RodzajZabudowy']).lower().count('wolnostojący') > 0: typ_domu = 'wolnostojący'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('bliźniak') > 0: typ_domu = 'bliźniak'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('gospodarstwo') > 0: typ_domu = 'gospodarstwo'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('kamienica') > 0: typ_domu = 'kamienica'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('letniskowy') > 0: typ_domu = 'letniskowy'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('rezydencja') > 0: typ_domu = 'rezydencja'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('siedlisko') > 0: typ_domu = 'siedlisko'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('szeregowiec') > 0: typ_domu = 'szeregowiec'
                else: typ_domu = 'inny'

                zapytanie_sql = '''
                    INSERT INTO ogloszenia_lento 
                        (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,
                        numer_kw, forma_kuchni, typ_domu, pow_dzialki, liczba_pokoi, powierzchnia, 
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        status)
                    VALUES 
                        (%s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s);
                '''
                34
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,
                        numer_kw, forma_kuchni, typ_domu, pow_dzialki, liczba_pokoi, powierzchnia, 
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        4)

            if kategoria_ogloszenia == 'mieszkanie':
                if picked_rent_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_rent_offer['LiczbaPokoi'] > 4:liczba_pokoi = 5
                else:liczba_pokoi = picked_rent_offer['LiczbaPokoi']

                
                if picked_rent_offer['LiczbaPieter'] == 0:liczba_pieter = 'parterowy'
                elif picked_rent_offer['LiczbaPieter'] > 7 and picked_rent_offer['LiczbaPieter'] != 0:liczba_pieter = 'wierzowiec'
                else:liczba_pieter = picked_rent_offer['LiczbaPieter']
                if str(picked_rent_offer['FormaKuchni']).lower().count('anex') > 0: forma_kuchni = 'anex'
                elif str(picked_rent_offer['FormaKuchni']).lower().count('oddzielna') > 0: forma_kuchni = 'oddzielna'
                else: forma_kuchni = 'brak'
                
                zapytanie_sql = '''
                    INSERT INTO ogloszenia_lento 
                        (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, liczba_pieter, 
                        zabudowa, 
                        forma_kuchni, liczba_pokoi, powierzchnia, 
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        status)
                    VALUES 
                        (%s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s);
                '''
                33
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, str(liczba_pieter), 
                        zabudowa, 
                        forma_kuchni, liczba_pokoi, powierzchnia, 
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        4)

            if kategoria_ogloszenia == 'biura_lokale':
                zapytanie_sql = '''
                    INSERT INTO ogloszenia_lento 
                        (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,  
                        powierzchnia, przeznaczenie_lokalu,
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        status)
                    VALUES 
                        (%s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s);
                '''
                30
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,  
                        powierzchnia, przeznaczenie_lokalu,
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        4)

            if kategoria_ogloszenia == 'dzialka':
                zapytanie_sql = '''
                    INSERT INTO ogloszenia_lento 
                        (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,  
                        powierzchnia, rodzaj_dzialki,
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        status)
                    VALUES 
                        (%s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s);
                '''
                30
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,  
                        powierzchnia, rodzaj_dzialki,
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        4)

            if kategoria_ogloszenia == 'inne_nieruchomosci':
                zapytanie_sql = '''
                    INSERT INTO ogloszenia_lento 
                        (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,  
                        powierzchnia, 
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        status)
                    VALUES 
                        (%s, %s, %s, %s, %s, %s, 
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s);
                '''
                29
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,  
                        powierzchnia, 
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        4)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta wynajmu została pomyślnie wysłana do realizacji na lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta wynajmu została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta wynajmu nie została wysłana do realizacji na lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta wynajmu nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Publikuj' and rodzaj_ogloszenia == 's':
            # print(request.form)

            if 'bez_promowania' in request.form: bez_promowania = 1
            else: bez_promowania = 0

            if 'promowanie_lokalne_14_dni' in request.form: promowanie_lokalne_14_dni = 1
            else: promowanie_lokalne_14_dni = 0
            if 'promowanie_lokalne_30_dni' in request.form: promowanie_lokalne_30_dni = 1
            else: promowanie_lokalne_30_dni = 0

            if 'promowanie_regionalne_14_dni' in request.form: promowanie_regionalne_14_dni = 1
            else: promowanie_regionalne_14_dni = 0
            if 'promowanie_regionalne_30_dni' in request.form: promowanie_regionalne_30_dni = 1
            else: promowanie_regionalne_30_dni = 0

            if 'promowanie_ogolnopolskie_14_dni' in request.form: promowanie_ogolnopolskie_14_dni = 1
            else: promowanie_ogolnopolskie_14_dni = 0
            if 'promowanie_ogolnopolskie_30_dni' in request.form: promowanie_ogolnopolskie_30_dni = 1
            else: promowanie_ogolnopolskie_30_dni = 0

            if 'top_ogloszenie_7_dni' in request.form: top_ogloszenie_7_dni = 1
            else: top_ogloszenie_7_dni = 0
            if 'top_ogloszenie_14_dni' in request.form: top_ogloszenie_14_dni = 1
            else: top_ogloszenie_14_dni = 0

            if 'etykieta_pilne_7_dni' in request.form: etykieta_pilne_7_dni = 1
            else: etykieta_pilne_7_dni = 0
            if 'etykieta_pilne_14_dni' in request.form: etykieta_pilne_14_dni = 1
            else: etykieta_pilne_14_dni = 0

            if 'codzienne_odswiezenie_7_dni' in request.form: codzienne_odswiezenie_7_dni = 1
            else: codzienne_odswiezenie_7_dni = 0
            if 'codzienne_odswiezenie_14_dni' in request.form: codzienne_odswiezenie_14_dni = 1
            else: codzienne_odswiezenie_14_dni = 0

            if 'wyswietlanie_na_stronie_glownej_14_dni' in request.form: wyswietlanie_na_stronie_glownej_14_dni = 1
            else: wyswietlanie_na_stronie_glownej_14_dni = 0
            if 'wyswietlanie_na_stronie_glownej_30_dni' in request.form: wyswietlanie_na_stronie_glownej_30_dni = 1
            else: wyswietlanie_na_stronie_glownej_30_dni = 0

            if 'super_oferta_7_dni' in request.form: super_oferta_7_dni = 1
            else: super_oferta_7_dni = 0
            if 'super_oferta_14_dni' in request.form: super_oferta_14_dni = 1
            else: super_oferta_14_dni = 0

            picked_sell_offer = {}
            for sellOffer in generator_sellOffert():
                if str(sellOffer['ID']) == str(id_ogloszenia):
                    picked_sell_offer = sellOffer
            # print(picked_rent_offer)

            tytul_ogloszenia = picked_sell_offer['Tytul']
            powierzchnia = picked_sell_offer['Metraz']
            cena = picked_sell_offer['Cena']
            numer_kw = picked_sell_offer['NumerKW']
            miejscowosc = picked_sell_offer['Lokalizacja'] 
            osoba_kontaktowa = session['user_data']['name']
            nr_telefonu = picked_sell_offer['TelefonKontaktowy']

            zdjecia_string = ''
            for foto_link in picked_sell_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_sell_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'

            if prepared_opis != '':
                if extra_descript:
                    prepared_opis = prepared_opis + '\n' + picked_sell_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_sell_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_sell_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_sell_offer['RodzajZabudowy']}\n\n"
            
            
            if picked_sell_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_sell_offer['TechBudowy']}\n\n"
            if picked_sell_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_sell_offer['StanWykonczenia']}\n\n"
            if picked_sell_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_sell_offer['RokBudowy']} r.\n\n"
            if picked_sell_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_sell_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]
            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""
            
            if str(picked_sell_offer['TypNieruchomosci']).lower().count('dom') > 0\
                or str(picked_sell_offer['TypNieruchomosci']).lower().count('willa') > 0\
                    or str(picked_sell_offer['TypNieruchomosci']).lower().count('bliźniak') > 0\
                or str(picked_sell_offer['TypNieruchomosci']).lower().count('segment') > 0:
                # kategoria na lento dla dom
                kategoria_ogloszenia = 'dom'

            elif str(picked_sell_offer['TypNieruchomosci']).lower().count('mieszkanie') > 0\
                or str(picked_sell_offer['TypNieruchomosci']).lower().count('kawalerka') > 0\
                    or str(picked_sell_offer['TypNieruchomosci']).lower().count('apartament') > 0\
                        or str(picked_sell_offer['TypNieruchomosci']).lower().count('blok') > 0\
                    or str(picked_sell_offer['TypNieruchomosci']).lower().count('kamienica') > 0\
                or str(picked_sell_offer['TypNieruchomosci']).lower().count('loft') > 0:
                # kategoria na lento dla mieszkanie
                kategoria_ogloszenia = 'mieszkanie'

            elif str(picked_sell_offer['TypNieruchomosci']).lower().count('biur') > 0\
                or str(picked_sell_offer['TypNieruchomosci']).lower().count('hal') > 0\
                    or str(picked_sell_offer['TypNieruchomosci']).lower().count('usługi') > 0\
                    or str(picked_sell_offer['TypNieruchomosci']).lower().count('lokal') > 0\
                or str(picked_sell_offer['TypNieruchomosci']).lower().count('produkcja') > 0:
                # kategoria na lento dla biura_lokale
                kategoria_ogloszenia = 'biura_lokale'

            elif str(picked_sell_offer['TypNieruchomosci']).lower().count('działka') > 0\
                or str(picked_sell_offer['TypNieruchomosci']).lower().count('plac') > 0\
                    or str(picked_sell_offer['TypNieruchomosci']).lower().count('teren') > 0:
                # kategoria na lento dla dzialka
                kategoria_ogloszenia = 'dzialka'
            else:
                # kategoria na lento dla inne_nieruchomosci
                kategoria_ogloszenia = 'inne_nieruchomosci'

            if kategoria_ogloszenia == 'mieszkanie':
                if str(picked_sell_offer['RodzajZabudowy']).lower().count('apartamentowiec') > 0: zabudowa = 'apartamentowiec'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('blok') > 0: zabudowa = 'blok'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('kamienica') > 0: zabudowa = 'kamienica'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('dom') > 0: zabudowa = 'dom'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('loft') > 0: zabudowa = 'loft'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('plomba') > 0: zabudowa = 'plomba'
                else: zabudowa = 'inne'

            if kategoria_ogloszenia == 'biura_lokale':
                if str(picked_sell_offer['InformacjeDodatkowe']).lower().count('biurowe') > 0: przeznaczenie_lokalu = 'biurowe'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('handel i usługi') > 0: przeznaczenie_lokalu = 'handel i usługi'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('produkcja i przemysł') > 0: przeznaczenie_lokalu = 'produkcja i przemysł'
                else: przeznaczenie_lokalu = 'inne_przeznaczenie'

            if kategoria_ogloszenia == 'dzialka':
                if str(picked_sell_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: rodzaj_dzialki = 'budowlana'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('inwestycyjna') > 0: rodzaj_dzialki = 'inwestycyjna'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('ogródek działkowy') > 0: rodzaj_dzialki = 'ogródek działkowy'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('przemysłowa') > 0: rodzaj_dzialki = 'przemysłowa'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: rodzaj_dzialki = 'rekreacyjna'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: rodzaj_dzialki = 'siedliskowa'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: rodzaj_dzialki = 'usługowa'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: rodzaj_dzialki = 'leśna'
                else: rodzaj_dzialki = 'inwestycyjna'

            """
            (
                rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, liczba_pieter, pietro,
                zabudowa, przeznaczenie_lokalu, rodzaj_dzialki, 
                numer_kw, dodtkowe_info, forma_kuchni, typ_domu, pow_dzialki, liczba_pokoi, powierzchnia, 
                opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                id_zadania, 
                id_ogloszenia_na_lento, 
                bez_promowania, 
                promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                super_oferta_7_dni, super_oferta_14_dni,
                status
            )
            """
            if kategoria_ogloszenia == 'dom':
                if picked_sell_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_sell_offer['LiczbaPokoi'] > 4:liczba_pokoi = 5
                else:liczba_pokoi = picked_sell_offer['LiczbaPokoi']
                
                if str(picked_sell_offer['FormaKuchni']).lower().count('anex') > 0: forma_kuchni = 'anex'
                elif str(picked_sell_offer['FormaKuchni']).lower().count('oddzielna') > 0: forma_kuchni = 'oddzielna'
                else: forma_kuchni = 'brak'
                if str(picked_sell_offer['RodzajZabudowy']).lower().count('wolnostojący') > 0: typ_domu = 'wolnostojący'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('bliźniak') > 0: typ_domu = 'bliźniak'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('gospodarstwo') > 0: typ_domu = 'gospodarstwo'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('kamienica') > 0: typ_domu = 'kamienica'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('letniskowy') > 0: typ_domu = 'letniskowy'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('rezydencja') > 0: typ_domu = 'rezydencja'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('siedlisko') > 0: typ_domu = 'siedlisko'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('szeregowiec') > 0: typ_domu = 'szeregowiec'
                else: typ_domu = 'inny'

                if str(picked_sell_offer['Rynek']).lower().count('wtórny') > 0: rynek = 'wtorny'
                elif str(picked_sell_offer['Rynek']).lower().count('pierwotny') > 0: rynek = 'pierwotny'
                else: rynek = None
                dodtkowe_info = rynek

                pow_dzialki = powierzchnia * 4

                zapytanie_sql = '''
                    INSERT INTO ogloszenia_lento 
                        (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,
                        numer_kw, forma_kuchni, typ_domu, pow_dzialki, liczba_pokoi, powierzchnia, dodtkowe_info,
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        status)
                    VALUES 
                        (%s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s);
                '''
                35
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,
                        numer_kw, forma_kuchni, typ_domu, pow_dzialki, liczba_pokoi, powierzchnia, dodtkowe_info,
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        4)

            if kategoria_ogloszenia == 'mieszkanie':
                if picked_sell_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_sell_offer['LiczbaPokoi'] > 4:liczba_pokoi = 5
                else:liczba_pokoi = picked_sell_offer['LiczbaPokoi']

                
                if picked_sell_offer['LiczbaPieter'] == 0:liczba_pieter = 'parterowy'
                elif picked_sell_offer['LiczbaPieter'] > 7 and picked_sell_offer['LiczbaPieter'] != 0:liczba_pieter = 'wierzowiec'
                else:liczba_pieter = picked_sell_offer['LiczbaPieter']
                if str(picked_sell_offer['FormaKuchni']).lower().count('anex') > 0: forma_kuchni = 'anex'
                elif str(picked_sell_offer['FormaKuchni']).lower().count('oddzielna') > 0: forma_kuchni = 'oddzielna'
                else: forma_kuchni = 'brak'

                if str(picked_sell_offer['Rynek']).lower().count('wtórny') > 0: rynek = 'wtorny'
                elif str(picked_sell_offer['Rynek']).lower().count('pierwotny') > 0: rynek = 'pierwotny'
                else: rynek = None
                dodtkowe_info = rynek
                
                zapytanie_sql = '''
                    INSERT INTO ogloszenia_lento 
                        (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, liczba_pieter, 
                        zabudowa, dodtkowe_info,
                        forma_kuchni, liczba_pokoi, powierzchnia, 
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        status)
                    VALUES 
                        (%s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s);
                '''
                34
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, str(liczba_pieter), 
                        zabudowa, dodtkowe_info,
                        forma_kuchni, liczba_pokoi, powierzchnia, 
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        4)

            if kategoria_ogloszenia == 'biura_lokale':
                zapytanie_sql = '''
                    INSERT INTO ogloszenia_lento 
                        (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,  
                        powierzchnia, przeznaczenie_lokalu,
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        status)
                    VALUES 
                        (%s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s);
                '''
                30
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,  
                        powierzchnia, przeznaczenie_lokalu,
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        4)

            if kategoria_ogloszenia == 'dzialka':
                zapytanie_sql = '''
                    INSERT INTO ogloszenia_lento 
                        (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,  
                        powierzchnia, rodzaj_dzialki,
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        status)
                    VALUES 
                        (%s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s);
                '''
                30
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,  
                        powierzchnia, rodzaj_dzialki,
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        4)

            if kategoria_ogloszenia == 'inne_nieruchomosci':
                zapytanie_sql = '''
                    INSERT INTO ogloszenia_lento 
                        (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,  
                        powierzchnia, 
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        status)
                    VALUES 
                        (%s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s);
                '''
                29
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia,  
                        powierzchnia, 
                        opis_ogloszenia, cena, zdjecia_string, miejscowosc, osoba_kontaktowa, nr_telefonu,
                        bez_promowania, 
                        promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                        promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                        promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                        top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                        etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                        codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                        wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                        super_oferta_7_dni, super_oferta_14_dni,
                        4)
            # print(zapytanie_sql)
            # print(dane)
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta wynajmu została pomyślnie wysłana do realizacji na lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta sprzedaży została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta wynajmu nie została wysłana do realizacji na lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta wynajmu nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Wstrzymaj':
            zapytanie_sql = '''
                UPDATE ogloszenia_lento
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, 7, lento_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta wynajmu została pomyślnie wysłana do wstrzymania na lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta wynajmu nie została wysłana do wstrzymania na lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Wznow':
            zapytanie_sql = '''
                UPDATE ogloszenia_lento
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, 8, lento_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta wynajmu została pomyślnie wysłana do wznowienia na lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta wynajmu nie została wysłana do wznowienia na lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Aktualizuj' and rodzaj_ogloszenia == 'r':
            picked_rent_offer = {}
            for rentOffer in generator_rentOffert():
                if str(rentOffer['ID']) == str(id_ogloszenia):
                    picked_rent_offer = rentOffer

            tytul_ogloszenia = picked_rent_offer['Tytul']
            powierzchnia = picked_rent_offer['Metraz']
            cena = picked_rent_offer['Cena']
            numer_kw = picked_rent_offer['NumerKW']
            miejscowosc = picked_rent_offer['Lokalizacja'] 
            osoba_kontaktowa = session['user_data']['name']
            nr_telefonu = picked_rent_offer['TelefonKontaktowy']

            zdjecia_string = ''
            for foto_link in picked_rent_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_rent_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':
                if extra_descript:
                    prepared_opis = prepared_opis + '\n' + picked_rent_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_rent_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_rent_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_rent_offer['RodzajZabudowy']}\n\n"
            if picked_rent_offer['Czynsz'] != 0:
                extra_opis += f"Czynsz:\n{picked_rent_offer['Czynsz']} zł.\n\n"
            if picked_rent_offer['Umeblowanie'] != "":
                extra_opis += f"Umeblowanie:\n{picked_rent_offer['Umeblowanie']}\n\n"
            if picked_rent_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_rent_offer['TechBudowy']}\n\n"
            if picked_rent_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_rent_offer['StanWykonczenia']}\n\n"
            if picked_rent_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_rent_offer['RokBudowy']} r.\n\n"
            if picked_rent_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_rent_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]

            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""

            if str(picked_rent_offer['TypDomu']).lower().count('dom') > 0\
                or str(picked_rent_offer['TypDomu']).lower().count('willa') > 0\
                    or str(picked_rent_offer['TypDomu']).lower().count('bliźniak') > 0\
                or str(picked_rent_offer['TypDomu']).lower().count('segment') > 0:
                # kategoria na lento dla dom
                kategoria_ogloszenia = 'dom'

            elif str(picked_rent_offer['TypDomu']).lower().count('mieszkanie') > 0\
                or str(picked_rent_offer['TypDomu']).lower().count('kawalerka') > 0\
                    or str(picked_rent_offer['TypDomu']).lower().count('apartament') > 0\
                        or str(picked_rent_offer['TypDomu']).lower().count('blok') > 0\
                    or str(picked_rent_offer['TypDomu']).lower().count('kamienica') > 0\
                or str(picked_rent_offer['TypDomu']).lower().count('loft') > 0:
                # kategoria na lento dla mieszkanie
                kategoria_ogloszenia = 'mieszkanie'

            elif str(picked_rent_offer['TypDomu']).lower().count('biur') > 0\
                or str(picked_rent_offer['TypDomu']).lower().count('hal') > 0\
                    or str(picked_rent_offer['TypDomu']).lower().count('usług') > 0\
                    or str(picked_rent_offer['TypDomu']).lower().count('lokal') > 0\
                or str(picked_rent_offer['TypDomu']).lower().count('produkcja') > 0:
                # kategoria na lento dla biura_lokale
                kategoria_ogloszenia = 'biura_lokale'

            elif str(picked_rent_offer['TypDomu']).lower().count('działka') > 0\
                or str(picked_rent_offer['TypDomu']).lower().count('plac') > 0\
                    or str(picked_rent_offer['TypDomu']).lower().count('teren') > 0:
                # kategoria na lento dla dzialka
                kategoria_ogloszenia = 'dzialka'
            else:
                # kategoria na lento dla inne_nieruchomosci
                kategoria_ogloszenia = 'inne_nieruchomosci'

            if kategoria_ogloszenia == 'mieszkanie':
                if str(picked_rent_offer['RodzajZabudowy']).lower().count('apartamentowiec') > 0: zabudowa = 'apartamentowiec'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('blok') > 0: zabudowa = 'blok'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('kamienica') > 0: zabudowa = 'kamienica'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('dom') > 0: zabudowa = 'dom'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('loft') > 0: zabudowa = 'loft'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('plomba') > 0: zabudowa = 'plomba'
                else: zabudowa = 'inne'

            if kategoria_ogloszenia == 'biura_lokale':
                if str(picked_rent_offer['InformacjeDodatkowe']).lower().count('biurowe') > 0: przeznaczenie_lokalu = 'biurowe'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('handel i usługi') > 0: przeznaczenie_lokalu = 'handel i usługi'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('produkcja i przemysł') > 0: przeznaczenie_lokalu = 'produkcja i przemysł'
                else: przeznaczenie_lokalu = 'inne_przeznaczenie'

            if kategoria_ogloszenia == 'dzialka':
                if str(picked_rent_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: rodzaj_dzialki = 'budowlana'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('inwestycyjna') > 0: rodzaj_dzialki = 'inwestycyjna'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('ogródek działkowy') > 0: rodzaj_dzialki = 'ogródek działkowy'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('przemysłowa') > 0: rodzaj_dzialki = 'przemysłowa'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: rodzaj_dzialki = 'rekreacyjna'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: rodzaj_dzialki = 'siedliskowa'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: rodzaj_dzialki = 'usługowa'
                elif str(picked_rent_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: rodzaj_dzialki = 'leśna'
                else: rodzaj_dzialki = 'inwestycyjna'
            
            if kategoria_ogloszenia == 'dom':
                if picked_rent_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_rent_offer['LiczbaPokoi'] > 4:liczba_pokoi = 5
                else:liczba_pokoi = picked_rent_offer['LiczbaPokoi']
                pow_dzialki = picked_rent_offer['PowierzchniaDzialki']
                if str(picked_rent_offer['FormaKuchni']).lower().count('anex') > 0: forma_kuchni = 'anex'
                elif str(picked_rent_offer['FormaKuchni']).lower().count('oddzielna') > 0: forma_kuchni = 'oddzielna'
                else: forma_kuchni = 'brak'
                if str(picked_rent_offer['RodzajZabudowy']).lower().count('wolnostojący') > 0: typ_domu = 'wolnostojący'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('bliźniak') > 0: typ_domu = 'bliźniak'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('gospodarstwo') > 0: typ_domu = 'gospodarstwo'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('kamienica') > 0: typ_domu = 'kamienica'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('letniskowy') > 0: typ_domu = 'letniskowy'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('rezydencja') > 0: typ_domu = 'rezydencja'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('siedlisko') > 0: typ_domu = 'siedlisko'
                elif str(picked_rent_offer['RodzajZabudowy']).lower().count('szeregowiec') > 0: typ_domu = 'szeregowiec'
                else: typ_domu = 'inny'

                zapytanie_sql = '''
                    UPDATE ogloszenia_lento
                    SET 
                        numer_kw = %s, 
                        typ_domu = %s, 
                        pow_dzialki = %s,
                        forma_kuchni = %s,
                        liczba_pokoi = %s,
                        tytul_ogloszenia = %s,   
                        powierzchnia = %s, 
                        opis_ogloszenia = %s, 
                        cena = %s, 
                        zdjecia_string = %s, 
                        miejscowosc = %s, 
                        osoba_kontaktowa = %s, 
                        nr_telefonu = %s,
                        status = %s,
                        active_task=%s
                    WHERE id = %s;
                '''
                dane = (
                        numer_kw, typ_domu, pow_dzialki, forma_kuchni, liczba_pokoi,
                        tytul_ogloszenia, powierzchnia, opis_ogloszenia, cena, 
                        zdjecia_string, miejscowosc, 
                        osoba_kontaktowa, nr_telefonu, 
                        5, 0,
                    lento_id)

            if kategoria_ogloszenia == 'mieszkanie':
                if picked_rent_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_rent_offer['LiczbaPokoi'] > 4:liczba_pokoi = 5
                else:liczba_pokoi = picked_rent_offer['LiczbaPokoi']

                if picked_rent_offer['LiczbaPieter'] == 0:liczba_pieter = 'parterowy'
                elif picked_rent_offer['LiczbaPieter'] > 7 and picked_rent_offer['LiczbaPieter'] != 0:liczba_pieter = 'wierzowiec'
                else:liczba_pieter = picked_rent_offer['LiczbaPieter']
                if str(picked_rent_offer['FormaKuchni']).lower().count('anex') > 0: forma_kuchni = 'anex'
                elif str(picked_rent_offer['FormaKuchni']).lower().count('oddzielna') > 0: forma_kuchni = 'oddzielna'
                else: forma_kuchni = 'brak'

                zapytanie_sql = '''
                    UPDATE ogloszenia_lento
                    SET 
                        liczba_pieter = %s,
                        zabudowa = %s,
                        forma_kuchni = %s,
                        liczba_pokoi = %s,
                        tytul_ogloszenia = %s,   
                        powierzchnia = %s, 
                        opis_ogloszenia = %s, 
                        cena = %s, 
                        zdjecia_string = %s, 
                        miejscowosc = %s, 
                        osoba_kontaktowa = %s, 
                        nr_telefonu = %s,
                        status = %s,
                        active_task=%s
                    WHERE id = %s;
                '''
                dane = (
                        liczba_pieter, zabudowa, forma_kuchni, liczba_pokoi,
                        tytul_ogloszenia, powierzchnia, opis_ogloszenia, cena, 
                        zdjecia_string, miejscowosc, osoba_kontaktowa,
                        nr_telefonu, 
                        5, 0,
                    lento_id)

            if kategoria_ogloszenia == 'biura_lokale':
                zapytanie_sql = '''
                    UPDATE ogloszenia_lento
                    SET 
                        przeznaczenie_lokalu = %s,
                        tytul_ogloszenia = %s,   
                        powierzchnia = %s, 
                        opis_ogloszenia = %s, 
                        cena = %s, 
                        zdjecia_string = %s, 
                        miejscowosc = %s, 
                        osoba_kontaktowa = %s, 
                        nr_telefonu = %s,
                        status = %s,
                        active_task=%s
                    WHERE id = %s;
                '''
                dane = (
                        przeznaczenie_lokalu,
                        tytul_ogloszenia, powierzchnia, opis_ogloszenia, cena, 
                        zdjecia_string, miejscowosc, 
                        osoba_kontaktowa, nr_telefonu, 
                        5, 0,
                    lento_id)


            if kategoria_ogloszenia == 'dzialka':
                zapytanie_sql = '''
                    UPDATE ogloszenia_lento
                    SET 
                        rodzaj_dzialki = %s,
                        tytul_ogloszenia = %s,   
                        powierzchnia = %s, 
                        opis_ogloszenia = %s, 
                        cena = %s, 
                        zdjecia_string = %s, 
                        miejscowosc = %s, 
                        osoba_kontaktowa = %s, 
                        nr_telefonu = %s,
                        status = %s,
                        active_task=%s
                    WHERE id = %s;
                '''
                dane = (
                        rodzaj_dzialki,
                        tytul_ogloszenia, powierzchnia, opis_ogloszenia, cena, 
                        zdjecia_string, miejscowosc, 
                        osoba_kontaktowa, nr_telefonu, 
                        5, 0,
                    lento_id)

            if kategoria_ogloszenia == 'inne_nieruchomosci':
                zapytanie_sql = '''
                    UPDATE ogloszenia_lento
                    SET 
                        tytul_ogloszenia = %s,   
                        powierzchnia = %s, 
                        opis_ogloszenia = %s, 
                        cena = %s, 
                        zdjecia_string = %s, 
                        miejscowosc = %s, 
                        osoba_kontaktowa = %s, 
                        nr_telefonu = %s,
                        status = %s,
                        active_task=%s
                    WHERE id = %s;
                '''
                dane = (tytul_ogloszenia, powierzchnia, opis_ogloszenia, cena, 
                        zdjecia_string, miejscowosc, 
                        osoba_kontaktowa, nr_telefonu, 
                        5, 0,
                        lento_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta wynajmu została pomyślnie wysłana do aktualizacji na lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuta.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta wynajmu nie została wysłana do aktualizacji na lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Aktualizuj' and rodzaj_ogloszenia == 's':
            picked_sell_offer = {}
            for sellOffer in generator_sellOffert():
                if str(sellOffer['ID']) == str(id_ogloszenia):
                    picked_sell_offer = sellOffer

            tytul_ogloszenia = picked_sell_offer['Tytul']
            powierzchnia = picked_sell_offer['Metraz']
            cena = picked_sell_offer['Cena']
            numer_kw = picked_sell_offer['NumerKW']
            miejscowosc = picked_sell_offer['Lokalizacja'] 
            osoba_kontaktowa = session['user_data']['name']
            nr_telefonu = picked_sell_offer['TelefonKontaktowy']

            zdjecia_string = ''
            for foto_link in picked_sell_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_sell_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':
                if extra_descript:
                    prepared_opis = prepared_opis + '\n' + picked_sell_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_sell_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_sell_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_sell_offer['RodzajZabudowy']}\n\n"
            
            
            if picked_sell_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_sell_offer['TechBudowy']}\n\n"
            if picked_sell_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_sell_offer['StanWykonczenia']}\n\n"
            if picked_sell_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_sell_offer['RokBudowy']} r.\n\n"
            if picked_sell_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_sell_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]
            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""

            if str(picked_sell_offer['TypNieruchomosci']).lower().count('dom') > 0\
                or str(picked_sell_offer['TypNieruchomosci']).lower().count('willa') > 0\
                    or str(picked_sell_offer['TypNieruchomosci']).lower().count('bliźniak') > 0\
                or str(picked_sell_offer['TypNieruchomosci']).lower().count('segment') > 0:
                # kategoria na lento dla dom
                kategoria_ogloszenia = 'dom'

            elif str(picked_sell_offer['TypNieruchomosci']).lower().count('mieszkanie') > 0\
                or str(picked_sell_offer['TypNieruchomosci']).lower().count('kawalerka') > 0\
                    or str(picked_sell_offer['TypNieruchomosci']).lower().count('apartament') > 0\
                        or str(picked_sell_offer['TypNieruchomosci']).lower().count('blok') > 0\
                    or str(picked_sell_offer['TypNieruchomosci']).lower().count('kamienica') > 0\
                or str(picked_sell_offer['TypNieruchomosci']).lower().count('loft') > 0:
                # kategoria na lento dla mieszkanie
                kategoria_ogloszenia = 'mieszkanie'

            elif str(picked_sell_offer['TypNieruchomosci']).lower().count('biur') > 0\
                or str(picked_sell_offer['TypNieruchomosci']).lower().count('hal') > 0\
                    or str(picked_sell_offer['TypNieruchomosci']).lower().count('usług') > 0\
                    or str(picked_sell_offer['TypNieruchomosci']).lower().count('lokal') > 0\
                or str(picked_sell_offer['TypNieruchomosci']).lower().count('produkcja') > 0:
                # kategoria na lento dla biura_lokale
                kategoria_ogloszenia = 'biura_lokale'

            elif str(picked_sell_offer['TypNieruchomosci']).lower().count('działka') > 0\
                or str(picked_sell_offer['TypNieruchomosci']).lower().count('plac') > 0\
                    or str(picked_sell_offer['TypNieruchomosci']).lower().count('teren') > 0:
                # kategoria na lento dla dzialka
                kategoria_ogloszenia = 'dzialka'
            else:
                # kategoria na lento dla inne_nieruchomosci
                kategoria_ogloszenia = 'inne_nieruchomosci'

            if kategoria_ogloszenia == 'mieszkanie':
                if str(picked_sell_offer['RodzajZabudowy']).lower().count('apartamentowiec') > 0: zabudowa = 'apartamentowiec'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('blok') > 0: zabudowa = 'blok'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('kamienica') > 0: zabudowa = 'kamienica'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('dom') > 0: zabudowa = 'dom'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('loft') > 0: zabudowa = 'loft'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('plomba') > 0: zabudowa = 'plomba'
                else: zabudowa = 'inne'

            if kategoria_ogloszenia == 'biura_lokale':
                if str(picked_sell_offer['InformacjeDodatkowe']).lower().count('biurowe') > 0: przeznaczenie_lokalu = 'biurowe'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('handel i usługi') > 0: przeznaczenie_lokalu = 'handel i usługi'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('produkcja i przemysł') > 0: przeznaczenie_lokalu = 'produkcja i przemysł'
                else: przeznaczenie_lokalu = 'inne_przeznaczenie'

            if kategoria_ogloszenia == 'dzialka':
                if str(picked_sell_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: rodzaj_dzialki = 'budowlana'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('inwestycyjna') > 0: rodzaj_dzialki = 'inwestycyjna'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('ogródek działkowy') > 0: rodzaj_dzialki = 'ogródek działkowy'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('przemysłowa') > 0: rodzaj_dzialki = 'przemysłowa'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: rodzaj_dzialki = 'rekreacyjna'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: rodzaj_dzialki = 'siedliskowa'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: rodzaj_dzialki = 'usługowa'
                elif str(picked_sell_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: rodzaj_dzialki = 'leśna'
                else: rodzaj_dzialki = 'inwestycyjna'
            
            if kategoria_ogloszenia == 'dom':
                if picked_sell_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_sell_offer['LiczbaPokoi'] > 4:liczba_pokoi = 5
                else:liczba_pokoi = picked_sell_offer['LiczbaPokoi']
                
                if str(picked_sell_offer['FormaKuchni']).lower().count('anex') > 0: forma_kuchni = 'anex'
                elif str(picked_sell_offer['FormaKuchni']).lower().count('oddzielna') > 0: forma_kuchni = 'oddzielna'
                else: forma_kuchni = 'brak'
                if str(picked_sell_offer['RodzajZabudowy']).lower().count('wolnostojący') > 0: typ_domu = 'wolnostojący'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('bliźniak') > 0: typ_domu = 'bliźniak'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('gospodarstwo') > 0: typ_domu = 'gospodarstwo'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('kamienica') > 0: typ_domu = 'kamienica'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('letniskowy') > 0: typ_domu = 'letniskowy'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('rezydencja') > 0: typ_domu = 'rezydencja'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('siedlisko') > 0: typ_domu = 'siedlisko'
                elif str(picked_sell_offer['RodzajZabudowy']).lower().count('szeregowiec') > 0: typ_domu = 'szeregowiec'
                else: typ_domu = 'inny'

                if str(picked_sell_offer['Rynek']).lower().count('wtórny') > 0: rynek = 'wtorny'
                elif str(picked_sell_offer['Rynek']).lower().count('pierwotny') > 0: rynek = 'pierwotny'
                else: rynek = None
                dodtkowe_info = rynek

                pow_dzialki = powierzchnia * 4

                zapytanie_sql = '''
                    UPDATE ogloszenia_lento
                    SET 
                        numer_kw = %s, 
                        typ_domu = %s, 
                        forma_kuchni = %s,
                        liczba_pokoi = %s,
                        tytul_ogloszenia = %s,   
                        powierzchnia = %s, 
                        pow_dzialki = %s,
                        dodtkowe_info = %s, 
                        opis_ogloszenia = %s, 
                        cena = %s, 
                        zdjecia_string = %s, 
                        miejscowosc = %s, 
                        osoba_kontaktowa = %s, 
                        nr_telefonu = %s,
                        status = %s,
                        active_task=%s
                    WHERE id = %s;
                '''
                dane = (
                        numer_kw, typ_domu, forma_kuchni, liczba_pokoi,
                        tytul_ogloszenia, powierzchnia, pow_dzialki, dodtkowe_info, opis_ogloszenia, cena, 
                        zdjecia_string, miejscowosc, 
                        osoba_kontaktowa, nr_telefonu, 
                        5, 0,
                    lento_id)

            if kategoria_ogloszenia == 'mieszkanie':
                if picked_sell_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_sell_offer['LiczbaPokoi'] > 4:liczba_pokoi = 5
                else:liczba_pokoi = picked_sell_offer['LiczbaPokoi']

                if picked_sell_offer['LiczbaPieter'] == 0:liczba_pieter = 'parterowy'
                elif picked_sell_offer['LiczbaPieter'] > 7 and picked_sell_offer['LiczbaPieter'] != 0:liczba_pieter = 'wierzowiec'
                else:liczba_pieter = picked_sell_offer['LiczbaPieter']
                if str(picked_sell_offer['FormaKuchni']).lower().count('anex') > 0: forma_kuchni = 'anex'
                elif str(picked_sell_offer['FormaKuchni']).lower().count('oddzielna') > 0: forma_kuchni = 'oddzielna'
                else: forma_kuchni = 'brak'

                if str(picked_sell_offer['Rynek']).lower().count('wtórny') > 0: rynek = 'wtorny'
                elif str(picked_sell_offer['Rynek']).lower().count('pierwotny') > 0: rynek = 'pierwotny'
                else: rynek = None

                dodtkowe_info = rynek

                zapytanie_sql = '''
                    UPDATE ogloszenia_lento
                    SET 
                        liczba_pieter = %s,
                        zabudowa = %s,
                        forma_kuchni = %s,
                        liczba_pokoi = %s,
                        tytul_ogloszenia = %s,   
                        powierzchnia = %s, 
                        dodtkowe_info = %s, 
                        opis_ogloszenia = %s, 
                        cena = %s, 
                        zdjecia_string = %s, 
                        miejscowosc = %s, 
                        osoba_kontaktowa = %s, 
                        nr_telefonu = %s,
                        status = %s,
                        active_task=%s
                    WHERE id = %s;
                '''
                dane = (
                        liczba_pieter, zabudowa, forma_kuchni, liczba_pokoi,
                        tytul_ogloszenia, powierzchnia, dodtkowe_info, opis_ogloszenia, cena, 
                        zdjecia_string, miejscowosc, osoba_kontaktowa,
                        nr_telefonu, 
                        5, 0,
                    lento_id)

            if kategoria_ogloszenia == 'biura_lokale':
                zapytanie_sql = '''
                    UPDATE ogloszenia_lento
                    SET 
                        przeznaczenie_lokalu = %s,
                        tytul_ogloszenia = %s,   
                        powierzchnia = %s, 
                        opis_ogloszenia = %s, 
                        cena = %s, 
                        zdjecia_string = %s, 
                        miejscowosc = %s, 
                        osoba_kontaktowa = %s, 
                        nr_telefonu = %s,
                        status = %s,
                        active_task=%s
                    WHERE id = %s;
                '''
                dane = (
                        przeznaczenie_lokalu,
                        tytul_ogloszenia, powierzchnia, opis_ogloszenia, cena, 
                        zdjecia_string, miejscowosc, 
                        osoba_kontaktowa, nr_telefonu, 
                        5, 0,
                    lento_id)


            if kategoria_ogloszenia == 'dzialka':
                zapytanie_sql = '''
                    UPDATE ogloszenia_lento
                    SET 
                        rodzaj_dzialki = %s,
                        tytul_ogloszenia = %s,   
                        powierzchnia = %s, 
                        opis_ogloszenia = %s, 
                        cena = %s, 
                        zdjecia_string = %s, 
                        miejscowosc = %s, 
                        osoba_kontaktowa = %s, 
                        nr_telefonu = %s,
                        status = %s,
                        active_task=%s
                    WHERE id = %s;
                '''
                dane = (
                        rodzaj_dzialki,
                        tytul_ogloszenia, powierzchnia, opis_ogloszenia, cena, 
                        zdjecia_string, miejscowosc, 
                        osoba_kontaktowa, nr_telefonu, 
                        5, 0,
                    lento_id)

            if kategoria_ogloszenia == 'inne_nieruchomosci':
                zapytanie_sql = '''
                    UPDATE ogloszenia_lento
                    SET 
                        tytul_ogloszenia = %s,   
                        powierzchnia = %s, 
                        opis_ogloszenia = %s, 
                        cena = %s, 
                        zdjecia_string = %s, 
                        miejscowosc = %s, 
                        osoba_kontaktowa = %s, 
                        nr_telefonu = %s,
                        status = %s,
                        active_task=%s
                    WHERE id = %s;
                '''
                dane = (tytul_ogloszenia, powierzchnia, opis_ogloszenia, cena, 
                        zdjecia_string, miejscowosc, 
                        osoba_kontaktowa, nr_telefonu, 
                        5, 0,
                        lento_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta sprzedaży została pomyślnie wysłana do aktualizacji na lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuta.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta sprzedaży nie została wysłana do aktualizacji na lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Promuj':
            if 'bez_promowania' in request.form: bez_promowania = 1
            else: bez_promowania = 0

            if 'promowanie_lokalne_14_dni' in request.form: promowanie_lokalne_14_dni = 1
            else: promowanie_lokalne_14_dni = 0
            if 'promowanie_lokalne_30_dni' in request.form: promowanie_lokalne_30_dni = 1
            else: promowanie_lokalne_30_dni = 0

            if 'promowanie_regionalne_14_dni' in request.form: promowanie_regionalne_14_dni = 1
            else: promowanie_regionalne_14_dni = 0
            if 'promowanie_regionalne_30_dni' in request.form: promowanie_regionalne_30_dni = 1
            else: promowanie_regionalne_30_dni = 0

            if 'promowanie_ogolnopolskie_14_dni' in request.form: promowanie_ogolnopolskie_14_dni = 1
            else: promowanie_ogolnopolskie_14_dni = 0
            if 'promowanie_ogolnopolskie_30_dni' in request.form: promowanie_ogolnopolskie_30_dni = 1
            else: promowanie_ogolnopolskie_30_dni = 0

            if 'top_ogloszenie_7_dni' in request.form: top_ogloszenie_7_dni = 1
            else: top_ogloszenie_7_dni = 0
            if 'top_ogloszenie_14_dni' in request.form: top_ogloszenie_14_dni = 1
            else: top_ogloszenie_14_dni = 0

            if 'etykieta_pilne_7_dni' in request.form: etykieta_pilne_7_dni = 1
            else: etykieta_pilne_7_dni = 0
            if 'etykieta_pilne_14_dni' in request.form: etykieta_pilne_14_dni = 1
            else: etykieta_pilne_14_dni = 0

            if 'codzienne_odswiezenie_7_dni' in request.form: codzienne_odswiezenie_7_dni = 1
            else: codzienne_odswiezenie_7_dni = 0
            if 'codzienne_odswiezenie_14_dni' in request.form: codzienne_odswiezenie_14_dni = 1
            else: codzienne_odswiezenie_14_dni = 0

            if 'wyswietlanie_na_stronie_glownej_14_dni' in request.form: wyswietlanie_na_stronie_glownej_14_dni = 1
            else: wyswietlanie_na_stronie_glownej_14_dni = 0
            if 'wyswietlanie_na_stronie_glownej_30_dni' in request.form: wyswietlanie_na_stronie_glownej_30_dni = 1
            else: wyswietlanie_na_stronie_glownej_30_dni = 0

            if 'super_oferta_7_dni' in request.form: super_oferta_7_dni = 1
            else: super_oferta_7_dni = 0
            if 'super_oferta_14_dni' in request.form: super_oferta_14_dni = 1
            else: super_oferta_14_dni = 0

            zapytanie_sql = '''
                UPDATE ogloszenia_lento
                SET 
                    bez_promowania = %s, 
                    promowanie_lokalne_14_dni = %s, 
                    promowanie_lokalne_30_dni = %s, 
                    promowanie_regionalne_14_dni = %s, 
                    promowanie_regionalne_30_dni = %s,
                    promowanie_ogolnopolskie_14_dni = %s, 
                    promowanie_ogolnopolskie_30_dni = %s,
                    top_ogloszenie_7_dni = %s, 
                    top_ogloszenie_14_dni = %s,
                    etykieta_pilne_7_dni = %s, 
                    etykieta_pilne_14_dni = %s,
                    codzienne_odswiezenie_7_dni = %s, 
                    codzienne_odswiezenie_14_dni = %s,
                    wyswietlanie_na_stronie_glownej_14_dni = %s, 
                    wyswietlanie_na_stronie_glownej_30_dni = %s,
                    super_oferta_7_dni, super_oferta_14_dni = %s,

                    status = %s,
                    active_task=%s
                WHERE id = %s;
            '''
            dane = (bez_promowania, 
                    promowanie_lokalne_14_dni, promowanie_lokalne_30_dni, 
                    promowanie_regionalne_14_dni, promowanie_regionalne_30_dni,
                    promowanie_ogolnopolskie_14_dni, promowanie_ogolnopolskie_30_dni,
                    top_ogloszenie_7_dni, top_ogloszenie_14_dni,
                    etykieta_pilne_7_dni, etykieta_pilne_14_dni,
                    codzienne_odswiezenie_7_dni, codzienne_odswiezenie_14_dni,
                    wyswietlanie_na_stronie_glownej_14_dni, wyswietlanie_na_stronie_glownej_30_dni,
                    super_oferta_7_dni, super_oferta_14_dni,
                    5, 0,
                    lento_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 2 minuty.', 'success')
            else:
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Ponow':
            zapytanie_sql = '''
                UPDATE ogloszenia_lento
                    SET 
                        active_task=%s
                    WHERE id = %s;
                '''
            dane = (0, lento_id)
            
            if msq.insert_to_database(zapytanie_sql, dane):
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Odswiez':
            flash(f'Oferta została odświeżona pomyślnie!', 'success')

        if task_kind == 'Usun':
            zapytanie_sql = '''
                UPDATE ogloszenia_lento
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, 6, lento_id)
            
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie wysłana do usunięcia z lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta wynajmu nie została wysłana do usunięcia z lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')
        
        if task_kind == 'Ponow_zadanie':
            oldStatus = takeLentoResumeStatus(lento_id)
            zapytanie_sql = '''
                UPDATE ogloszenia_lento
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, oldStatus, lento_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie wysłana do ponowienia na lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do ponowienia na lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Anuluj_zadanie':
            oldStatus = takeLentoResumeStatus(lento_id)
            if oldStatus == 4:
                zapytanie_sql = '''
                    DELETE FROM ogloszenia_lento
                        
                    WHERE id = %s;
                    '''
                dane = (lento_id,)
            
            if oldStatus == 5 or oldStatus == 6 or oldStatus == 7:
                zapytanie_sql = '''
                    UPDATE ogloszenia_lento
                        SET 
                            active_task=%s,
                            status=%s
                        WHERE id = %s;
                    '''
                dane = (0, 1, lento_id)


            if oldStatus == 8:
                zapytanie_sql = '''
                    UPDATE ogloszenia_lento
                        SET 
                            active_task=%s,
                            status=%s
                        WHERE id = %s;
                    '''
                dane = (0, 0, lento_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Zadanie zostało anulowane w lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Zadanie zostało anulowane!', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Zadanie nie zostało anulowane w lento.pl przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Zadanie nie zostało anulowane!', 'danger')

        return redirect(url_for(redirectGoal))
    return redirect(url_for('index')) 

@app.route('/public-on-facebook', methods=['POST'])
def public_on_facebook():

    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /public-on-facebook bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /public-on-facebook bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        facebook_id = request.form.get('facebook_id')
        id_ogloszenia = request.form.get('PostID')
        task_kind = request.form.get('task_kind')
        redirectGoal = request.form.get('redirectGoal')
        
        
        rodzaj_ogloszenia = None
        if redirectGoal == 'estateAdsRent':
            rodzaj_ogloszenia = 'r'
        if redirectGoal == 'estateAdsSell':
            rodzaj_ogloszenia = 's'

        if task_kind == 'Publikuj':
            picked_offer = {}
            if rodzaj_ogloszenia == 'r':
                for rentOffer in generator_rentOffert():
                    if str(rentOffer['ID']) == str(id_ogloszenia):
                        picked_offer = rentOffer
            elif rodzaj_ogloszenia == 's':
                for sellOffer in generator_sellOffert():
                    if str(sellOffer['ID']) == str(id_ogloszenia):
                        picked_offer = sellOffer

            tytul_ogloszenia = picked_offer['Tytul']
            cena = picked_offer['Cena']
            lokalizacja = picked_offer['Lokalizacja'] 
            osoba_kontaktowa = session['user_data']['name']
            nr_telefonu = picked_offer['TelefonKontaktowy']


            if 'stan_nowy' in request.form: stan = 1
            elif 'stan_uzywany_jak_nowy' in request.form: stan = 2
            elif 'stan_uzywany_dobry' in request.form: stan = 3
            elif 'stan_uzywany_przecietny' in request.form: stan = 4
            else: stan = 1


            zdjecia_string = ''
            for foto_link in picked_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_offer['Metraz'] != '':
                extra_opis += f"Powierzchnia:\n{picked_offer['Metraz']} m²\n\n"
            if picked_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_offer['RodzajZabudowy']}\n\n"
            if picked_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_offer['TechBudowy']}\n\n"
            if picked_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_offer['StanWykonczenia']}\n\n"
            if picked_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_offer['RokBudowy']} r.\n\n"
            if picked_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_offer['NumerKW']}\n\n"
            if rodzaj_ogloszenia == 'r':
                if picked_offer['Czynsz'] != 0:
                    extra_opis += f"Czynsz:\n{picked_offer['Czynsz']} zł.\n\n"
                if picked_offer['Umeblowanie'] != "":
                    extra_opis += f"Umeblowanie:\n{picked_offer['Umeblowanie']}\n\n"

            extra_opis += f"Skontaktuj się telefonicznie!\n{osoba_kontaktowa}\n{nr_telefonu}\n\n"

            extra_opis = extra_opis[:-2]
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""

            znaczniki_list = ['Nieruchomości', 'Bez pośredników']
            allowed_znaczniki = [
                'Kaucja', 'Metraz', 'Czynsz', 'Umeblowanie', 
                'PowierzchniaDzialki', 'TechBudowy', 'FormaKuchni', 
                'TypDomu', 'StanWykonczenia', 'Rynek', 
                'LiczbaPieter', 'PrzeznaczenieLokalu'
            ]
            if rodzaj_ogloszenia == 'r':
                add_znacznik = f"Wynajem"
                znaczniki_list.append(add_znacznik)
            elif rodzaj_ogloszenia == 's':
                add_znacznik = f"Sprzedaż"
                znaczniki_list.append(add_znacznik)

            for znacznik in picked_offer.keys():
                if znacznik in allowed_znaczniki:
                    if znacznik == 'Kaucja' and picked_offer['Kaucja'] !=0:
                        add_znacznik = f"Kaucja {picked_offer['Kaucja']} zł"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'Metraz' and picked_offer['Metraz'] !=0:
                        add_znacznik = f"{picked_offer['Metraz']} m²"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'Czynsz' and picked_offer['Czynsz'] !=0:
                        add_znacznik = f"Czynsz {picked_offer['Czynsz']} zł"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'Umeblowanie' and picked_offer['Umeblowanie'] !='':
                        add_znacznik = f"{picked_offer['Umeblowanie']}"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'PowierzchniaDzialki' and picked_offer['PowierzchniaDzialki'] !=0:
                        add_znacznik = f"Działka {picked_offer['PowierzchniaDzialki']} m²"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'TechBudowy' and picked_offer['TechBudowy'] !='':
                        add_znacznik = f"Technologia {picked_offer['TechBudowy']}"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'FormaKuchni' and picked_offer['FormaKuchni'] !='':
                        add_znacznik = f"Kuchnia {picked_offer['FormaKuchni']}"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'TypDomu' and picked_offer['TypDomu'] !='':
                        add_znacznik = f"{picked_offer['TypDomu']}"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'StanWykonczenia' and picked_offer['StanWykonczenia'] !='':
                        add_znacznik = f"{picked_offer['StanWykonczenia']}"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'Rynek' and picked_offer['Rynek'] !='':
                        add_znacznik = f"Rynek {picked_offer['Rynek']}"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'LiczbaPieter' and picked_offer['LiczbaPieter'] !=0:
                        add_znacznik = f"Pięter {picked_offer['LiczbaPieter']}"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'PrzeznaczenieLokalu' and picked_offer['PrzeznaczenieLokalu'] !='':
                        add_znacznik = f"Przeznaczenie na {picked_offer['PrzeznaczenieLokalu']}"
                        znaczniki_list.append(add_znacznik)

            znaczniki_string = ''
            for znacznik_item in znaczniki_list:
                znaczniki_string += f'{znacznik_item}-@-'
            if znaczniki_string != '':znaczniki_string = znaczniki_string[:-3]   
            znaczniki = znaczniki_string

            if 'promuj_po_opublikowaniu' in request.form: promuj_po_opublikowaniu = 1
            else: promuj_po_opublikowaniu = 0

            time_truck = int(int(str(int(time.time()))[:6]) / 6)
            id_ogloszenia_na_facebook = int(f'{time_truck}{id_ogloszenia}')

            zapytanie_sql = '''
                    INSERT INTO ogloszenia_facebook 
                        (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia,
                        opis_ogloszenia, cena, stan, lokalizacja, znaczniki,
                        promuj_po_opublikowaniu, zdjecia_string, id_ogloszenia_na_facebook,
                        osoba_kontaktowa, nr_telefonu,
                        status)
                    VALUES 
                        (%s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s);
                '''
            dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia,
                    opis_ogloszenia, cena, stan, lokalizacja, znaczniki,
                    promuj_po_opublikowaniu, zdjecia_string, id_ogloszenia_na_facebook,
                    osoba_kontaktowa, nr_telefonu,
                    4)
            # print(dane)
            # flash(f'{dane}', 'success')

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do realizacji na facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Aktualizuj':
            picked_offer = {}
            if rodzaj_ogloszenia == 'r':
                for rentOffer in generator_rentOffert():
                    if str(rentOffer['ID']) == str(id_ogloszenia):
                        picked_offer = rentOffer
            elif rodzaj_ogloszenia == 's':
                for sellOffer in generator_sellOffert():
                    if str(sellOffer['ID']) == str(id_ogloszenia):
                        picked_offer = sellOffer

            tytul_ogloszenia = picked_offer['Tytul']
            cena = picked_offer['Cena']
            lokalizacja = picked_offer['Lokalizacja'] 
            osoba_kontaktowa = session['user_data']['name']
            nr_telefonu = picked_offer['TelefonKontaktowy']


            zdjecia_string = ''
            for foto_link in picked_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_offer['Metraz'] != '':
                extra_opis += f"Powierzchnia:\n{picked_offer['Metraz']} m²\n\n"
            if picked_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_offer['RodzajZabudowy']}\n\n"
            if picked_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_offer['TechBudowy']}\n\n"
            if picked_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_offer['StanWykonczenia']}\n\n"
            if picked_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_offer['RokBudowy']} r.\n\n"
            if picked_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_offer['NumerKW']}\n\n"
            if rodzaj_ogloszenia == 'r':
                if picked_offer['Czynsz'] != 0:
                    extra_opis += f"Czynsz:\n{picked_offer['Czynsz']} zł.\n\n"
                if picked_offer['Umeblowanie'] != "":
                    extra_opis += f"Umeblowanie:\n{picked_offer['Umeblowanie']}\n\n"

            extra_opis += f"Skontaktuj się telefonicznie!\n{osoba_kontaktowa}\n{nr_telefonu}\n\n"
            
            extra_opis = extra_opis[:-2]
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""

            znaczniki_list = ['Nieruchomości', 'Bez pośredników']
            allowed_znaczniki = [
                'Kaucja', 'Metraz', 'Czynsz', 'Umeblowanie', 
                'PowierzchniaDzialki', 'TechBudowy', 'FormaKuchni', 
                'TypDomu', 'StanWykonczenia', 'Rynek', 
                'LiczbaPieter', 'PrzeznaczenieLokalu'
            ]
            if rodzaj_ogloszenia == 'r':
                add_znacznik = f"Wynajem"
                znaczniki_list.append(add_znacznik)
            elif rodzaj_ogloszenia == 's':
                add_znacznik = f"Sprzedaż"
                znaczniki_list.append(add_znacznik)

            for znacznik in picked_offer.keys():
                if znacznik in allowed_znaczniki:
                    if znacznik == 'Kaucja' and picked_offer['Kaucja'] !=0:
                        add_znacznik = f"Kaucja {picked_offer['Kaucja']} zł"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'Metraz' and picked_offer['Metraz'] !=0:
                        add_znacznik = f"{picked_offer['Metraz']} m²"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'Czynsz' and picked_offer['Czynsz'] !=0:
                        add_znacznik = f"Czynsz {picked_offer['Czynsz']} zł"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'Umeblowanie' and picked_offer['Umeblowanie'] !='':
                        add_znacznik = f"{picked_offer['Umeblowanie']}"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'PowierzchniaDzialki' and picked_offer['PowierzchniaDzialki'] !=0:
                        add_znacznik = f"Działka {picked_offer['PowierzchniaDzialki']} m²"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'TechBudowy' and picked_offer['TechBudowy'] !='':
                        add_znacznik = f"Technologia {picked_offer['TechBudowy']}"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'FormaKuchni' and picked_offer['FormaKuchni'] !='':
                        add_znacznik = f"Kuchnia {picked_offer['FormaKuchni']}"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'TypDomu' and picked_offer['TypDomu'] !='':
                        add_znacznik = f"{picked_offer['TypDomu']}"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'StanWykonczenia' and picked_offer['StanWykonczenia'] !='':
                        add_znacznik = f"{picked_offer['StanWykonczenia']}"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'Rynek' and picked_offer['Rynek'] !='':
                        add_znacznik = f"Rynek {picked_offer['Rynek']}"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'LiczbaPieter' and picked_offer['LiczbaPieter'] !=0:
                        add_znacznik = f"Pięter {picked_offer['LiczbaPieter']}"
                        znaczniki_list.append(add_znacznik)
                    if znacznik == 'PrzeznaczenieLokalu' and picked_offer['PrzeznaczenieLokalu'] !='':
                        add_znacznik = f"Przeznaczenie na {picked_offer['PrzeznaczenieLokalu']}"
                        znaczniki_list.append(add_znacznik)

            znaczniki_string = ''
            for znacznik_item in znaczniki_list:
                znaczniki_string += f'{znacznik_item}-@-'
            if znaczniki_string != '':znaczniki_string = znaczniki_string[:-3]   
            znaczniki = znaczniki_string


            zapytanie_sql = '''
                UPDATE ogloszenia_facebook
                SET 
                    tytul_ogloszenia = %s, 
                    opis_ogloszenia = %s,
                    cena = %s,
                    lokalizacja = %s,
                    znaczniki = %s,
                    zdjecia_string = %s,

                    status = %s,
                    active_task=%s
                WHERE id = %s;
            '''
            dane = (tytul_ogloszenia, opis_ogloszenia, cena, lokalizacja, znaczniki, zdjecia_string,
                    5, 0, facebook_id)
            # print(dane)
            # flash(f'{dane}', 'success')

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do aktualizacji na facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Wstrzymaj':
            zapytanie_sql = '''
                UPDATE ogloszenia_facebook
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, 7, facebook_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie wysłana do wstrzymania na facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do wstrzymania na facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Wznow':
            zapytanie_sql = '''
                UPDATE ogloszenia_facebook
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, 8, facebook_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie wysłana do wznowienia na facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do wznowienia na facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Usun':
            zapytanie_sql = '''
                UPDATE ogloszenia_facebook
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, 6, facebook_id)
            
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie wysłana do usunięcia z facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do usunięcia z facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Promuj':
            pass

        if task_kind == 'Ponow_zadanie':
            oldStatus = takeFacebookResumeStatus(facebook_id)
            zapytanie_sql = '''
                UPDATE ogloszenia_facebook
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, oldStatus, facebook_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie ponowiona na facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została ponowiona na facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')
        
        if task_kind == 'Anuluj_zadanie':
            oldStatus = takeFacebookResumeStatus(facebook_id)
            if oldStatus == 4:
                zapytanie_sql = '''
                    DELETE FROM ogloszenia_facebook
                        
                    WHERE id = %s;
                    '''
                dane = (facebook_id,)
            
            if oldStatus == 5 or oldStatus == 6 or oldStatus == 7:
                zapytanie_sql = '''
                    UPDATE ogloszenia_facebook
                        SET 
                            active_task=%s,
                            status=%s
                        WHERE id = %s;
                    '''
                dane = (0, 1, facebook_id)


            if oldStatus == 8:
                zapytanie_sql = '''
                    UPDATE ogloszenia_facebook
                        SET 
                            active_task=%s,
                            status=%s
                        WHERE id = %s;
                    '''
                dane = (0, 0, facebook_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Zadanie zostało anulowane pomyślnie na facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Zadanie zostało anulowane!', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Zadanie nie zostało anulowane na facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Zadanie nie zostało anulowane!', 'danger')
        
        if task_kind == 'Odswiez':
             flash(f'Oferta została odświeżona pomyślnie!', 'success')

        if task_kind == 'Ponow':
            zapytanie_sql = '''
                UPDATE ogloszenia_facebook
                    SET 
                        active_task=%s
                    WHERE id = %s;
                '''
            dane = (0, facebook_id)
            
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie ponowiona na facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została ponowiona na facebook przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')
        
        return redirect(url_for(redirectGoal))
    return redirect(url_for('index')) 

@app.route('/get-region-data', methods=['GET'])
def get_region_data():
    level = request.args.get('level')
    wojewodztwo = request.args.get('wojewodztwo')
    powiat = request.args.get('powiat')
    gmina = request.args.get('gmina')
    miejscowosc = request.args.get('miejscowosc')
    dzielnica = request.args.get('dzielnica')

    # print(f"Level: {level}, Wojewodztwo: {wojewodztwo}, Powiat: {powiat}, Gmina: {gmina}, Miejscowosc: {miejscowosc}, Dzielnica: {dzielnica}")

    response = regions.getRegionData(wojewodztwo=wojewodztwo, powiat=powiat, gmina=gmina, miejscowosc=miejscowosc, dzielnica=dzielnica)
    # print(response)
    return jsonify(response)

@app.route('/public-on-adresowo', methods=['POST'])
def public_on_adresowo():

    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /public-on-adresowo bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /public-on-adresowo bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        adresowo_id = request.form.get('adresowo_id')
        id_ogloszenia = request.form.get('PostID')
        task_kind = request.form.get('task_kind')
        redirectGoal = request.form.get('redirectGoal')
        extra_descript = request.form.get('extra_descript')
        if 'region' in request.form:
            get_region = request.form.get('region')
            if get_region!='' and get_region.count('/')>4:
                region = get_region
            else:
                region = None  
        else:
            region = None

        if 'ulica' in request.form:
            get_ulica = request.form.get('ulica')
            if get_ulica!='':
                ulica = get_ulica
            else:
                ulica = 'Nieokreślona' 
        else:
            ulica = 'Nieokreślona'
        
        
        rodzaj_ogloszenia = None
        if redirectGoal == 'estateAdsRent':
            rodzaj_ogloszenia = 'r'
        if redirectGoal == 'estateAdsSell':
            rodzaj_ogloszenia = 's'

        if task_kind == 'Publikuj' and rodzaj_ogloszenia == 'r':
            if not region:
                msq.handle_error(f'UWAGA! Błąd braku regionu przez {session["username"]}!', log_path=logFileName)
                flash('Wybierz region!', 'danger')
                return redirect(url_for(redirectGoal))

            picked_offer = {}            
            for offer in generator_rentOffert():
                if str(offer['ID']) == str(id_ogloszenia):
                    picked_offer = offer
            
            tytul_ogloszenia = picked_offer['Tytul']
            powierzchnia = picked_offer['Metraz']
            cena = picked_offer['Cena']
            osoba_kontaktowa = session['user_data']['name']
            nr_telefonu = picked_offer['TelefonKontaktowy']

            zdjecia_string = ''
            for foto_link in picked_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_offer['RodzajZabudowy']}\n\n"
            if picked_offer['Czynsz'] != 0:
                extra_opis += f"Czynsz:\n{picked_offer['Czynsz']} zł.\n\n"
            if picked_offer['Umeblowanie'] != "":
                extra_opis += f"Umeblowanie:\n{picked_offer['Umeblowanie']}\n\n"
            if picked_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_offer['TechBudowy']}\n\n"
            if picked_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_offer['StanWykonczenia']}\n\n"
            if picked_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_offer['RokBudowy']} r.\n\n"
            if picked_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]
            if prepared_opis != '':
                if extra_descript:
                    prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_offer['InformacjeDodatkowe']

            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""

            if str(picked_offer['TypDomu']).lower().count('dom') > 0\
                or str(picked_offer['TypDomu']).lower().count('willa') > 0\
                    or str(picked_offer['TypDomu']).lower().count('bliźniak') > 0\
                or str(picked_offer['TypDomu']).lower().count('segment') > 0:
                # kategoria na adresowo dla dom
                kategoria_ogloszenia = 'dom'

            elif str(picked_offer['TypDomu']).lower().count('mieszkanie') > 0\
                or str(picked_offer['TypDomu']).lower().count('kawalerka') > 0\
                    or str(picked_offer['TypDomu']).lower().count('apartament') > 0\
                        or str(picked_offer['TypDomu']).lower().count('blok') > 0\
                    or str(picked_offer['TypDomu']).lower().count('kamienica') > 0\
                or str(picked_offer['TypDomu']).lower().count('loft') > 0:
                # kategoria na adresowo dla mieszkanie
                kategoria_ogloszenia = 'mieszkanie'
            
            elif str(picked_offer['TypDomu']).lower().count('działka') > 0\
                or str(picked_offer['TypDomu']).lower().count('plac') > 0\
                    or str(picked_offer['TypDomu']).lower().count('teren') > 0:
                # kategoria na adresowo dla dzialka
                kategoria_ogloszenia = 'dzialka'

            elif str(picked_offer['TypDomu']).lower().count('biur') > 0\
                or str(picked_offer['TypDomu']).lower().count('hal') > 0\
                    or str(picked_offer['TypDomu']).lower().count('usługi') > 0\
                    or str(picked_offer['TypDomu']).lower().count('lokal') > 0\
                    or str(picked_offer['TypDomu']).lower().count('magazyn') > 0\
                or str(picked_offer['TypDomu']).lower().count('produkcja') > 0:
                # kategoria na adresowo dla komercyjne
                kategoria_ogloszenia = 'komercyjne'

            else:
                msq.handle_error(f'UWAGA! Nie rozpoznano typu nieruchomości, dane wysłane przez {session["username"]} są niejednoznaczne!', log_path=logFileName)
                flash('Nie rozpoznano typu nieruchomości, dane są niejednoznaczne!', 'danger')
                return redirect(url_for(redirectGoal))
            
            if kategoria_ogloszenia == 'dom':
                powierzchnia = picked_offer['Metraz']
                pow_dzialki = picked_offer['PowierzchniaDzialki']
                rok_budowy = picked_offer['RokBudowy']
                

                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_offer['LiczbaPokoi'] > 20:liczba_pokoi = 20
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                if picked_offer['LiczbaPieter'] == 0:liczba_pieter = 1
                elif picked_offer['LiczbaPieter'] > 40:liczba_pieter = 40
                else:liczba_pieter = picked_offer['LiczbaPieter']
                

                if str(picked_offer['Umeblowanie']).lower().count('w całości') > 0: umeblowanie = 'W pełni'
                elif str(picked_offer['Umeblowanie']).lower().count('częściowo') > 0: umeblowanie = 'Częściowo'
                else: umeblowanie = 'Nieumeblowane'

                if str(picked_offer['StanWykonczenia']).lower().count('pod Klucz') > 0: stan = 'Do zamieszkania'
                elif str(picked_offer['StanWykonczenia']).lower().count('wysoki standard') > 0: stan = 'Wysoki standard'
                else: stan = 'Do odświeżenia'

                if str(picked_offer['RodzajZabudowy']).lower().count('bliźniacza') > 0: typ_budynku = 'Bliźniak'
                elif str(picked_offer['RodzajZabudowy']).lower().count('dworek') > 0: typ_budynku = 'Dworek'
                elif str(picked_offer['RodzajZabudowy']).lower().count('kamienica') > 0: typ_budynku = 'Kamienica'
                elif str(picked_offer['RodzajZabudowy']).lower().count('gospodarstwo') > 0: typ_budynku = 'Gospodarstwo'
                elif str(picked_offer['RodzajZabudowy']).lower().count('letniskowa') > 0: typ_budynku = 'Dom letniskowy'
                elif str(picked_offer['RodzajZabudowy']).lower().count('szeregowa') > 0: typ_budynku = 'Dom szeregowy'
                elif str(picked_offer['RodzajZabudowy']).lower().count('wolnostojąca') > 0: typ_budynku = 'Dom wolnostojący'
                elif str(picked_offer['RodzajZabudowy']).lower().count('wielorodzinna') > 0: typ_budynku = 'Budynek wielorodzinny'
                elif str(picked_offer['RodzajZabudowy']).lower().count('siedlisko') > 0: typ_budynku = 'Siedlisko'
                else: typ_budynku = 'Inny'

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_adresowo
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            umeblowanie, opis_ogloszenia, liczba_pokoi, liczba_pieter, pow_dzialki, ulica, powierzchnia, 
                            rok_budowy, stan, typ_budynku, zdjecia_string, osoba_kontaktowa, nr_telefonu, 
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, 
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        umeblowanie, opis_ogloszenia, liczba_pokoi, liczba_pieter, pow_dzialki, ulica, powierzchnia, 
                        rok_budowy, stan, typ_budynku, zdjecia_string, osoba_kontaktowa, nr_telefonu,
                        4)
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')
                
            if kategoria_ogloszenia == 'mieszkanie':
                powierzchnia = picked_offer['Metraz']
                rok_budowy = picked_offer['RokBudowy']
                
                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_offer['LiczbaPokoi'] > 20:liczba_pokoi = 20
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                poziom = 'parter'
                 
                if picked_offer['LiczbaPieter'] == 0:liczba_pieter = 1
                elif picked_offer['LiczbaPieter'] > 40:liczba_pieter = 40
                else:liczba_pieter = picked_offer['LiczbaPieter']
                
                if str(picked_offer['InformacjeDodatkowe']).lower().count('winda') > 0: winda = 'Z windą'
                else: winda = 'Bez windy'

                if str(picked_offer['Umeblowanie']).lower().count('w całości') > 0: umeblowanie = 'W pełni'
                elif str(picked_offer['Umeblowanie']).lower().count('częściowo') > 0: umeblowanie = 'Częściowo'
                else: umeblowanie = 'Nieumeblowane'

                if str(picked_offer['StanWykonczenia']).lower().count('pod Klucz') > 0: stan = 'Do zamieszkania'
                elif str(picked_offer['StanWykonczenia']).lower().count('wysoki standard') > 0: stan = 'Wysoki standard'
                else: stan = 'Do odświeżenia'

                if str(picked_offer['RodzajZabudowy']).lower().count('blok') > 0: typ_budynku = 'Blok'
                elif str(picked_offer['RodzajZabudowy']).lower().count('płyta') > 0: typ_budynku = 'Blok z płyty'
                elif str(picked_offer['RodzajZabudowy']).lower().count('kamienica') > 0: typ_budynku = 'Kamienica'
                elif str(picked_offer['RodzajZabudowy']).lower().count('apartamentowiec') > 0: typ_budynku = 'Apartamentowiec'
                else: typ_budynku = 'Dom wielorodzinny'


                # region, ulica, cena, powierzchnia, rok_budowy, l_poki, l_pieter, winda, umeblowanie, typ_budynku, stan
                zapytanie_sql = '''
                        INSERT INTO ogloszenia_adresowo
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            umeblowanie, opis_ogloszenia, liczba_pieter, liczba_pokoi, poziom, ulica,
                            winda, powierzchnia, rok_budowy, stan, typ_budynku, zdjecia_string, 
                            osoba_kontaktowa, nr_telefonu, 
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s,
                            %s, %s, %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        umeblowanie, opis_ogloszenia, liczba_pieter, liczba_pokoi, poziom, ulica,
                        winda, powierzchnia, rok_budowy, stan, typ_budynku, zdjecia_string, 
                        osoba_kontaktowa, nr_telefonu, 
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'dzialka':
                # region, ulica, typ_budynku, powierzchnia
                if str(picked_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: rodzaj_dzialki = 'Budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('inwestycyjna') > 0: rodzaj_dzialki = 'Inwestycyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolna') > 0: rodzaj_dzialki = 'Rolna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolno-budowlana') > 0: rodzaj_dzialki = 'Rolno-budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: rodzaj_dzialki = 'Rekreacyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: rodzaj_dzialki = 'Siedliskowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: rodzaj_dzialki = 'Usługowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: rodzaj_dzialki = 'Leśna'
                else: rodzaj_dzialki = 'Inna'

                powierzchnia = picked_offer['Metraz']

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_adresowo
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, ulica, powierzchnia, rodzaj_dzialki, zdjecia_string, osoba_kontaktowa, 
                            nr_telefonu, 
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s,
                            %s,
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, ulica, powierzchnia, rodzaj_dzialki, zdjecia_string, osoba_kontaktowa, 
                        nr_telefonu, 
                        4)
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'komercyjne':
                # region, ulica, typ_budynku, powierzchnia
                if str(picked_offer['InformacjeDodatkowe']).lower().count('biurowe') > 0: przeznaczenie_lokalu = 'Biuro'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('handel i usługi') > 0: przeznaczenie_lokalu = 'Lokal'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('produkcja i przemysł') > 0: przeznaczenie_lokalu = 'Hala'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('hala') > 0\
                      or str(picked_offer['InformacjeDodatkowe']).lower().count('magazyn') > 0: przeznaczenie_lokalu = 'Hala'
                else: przeznaczenie_lokalu = 'Pozostała nieruchomość'

                powierzchnia = picked_offer['Metraz']

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_adresowo
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, ulica, powierzchnia, przeznaczenie_lokalu, zdjecia_string, osoba_kontaktowa, 
                            nr_telefonu, 
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s,
                            %s,
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, ulica, powierzchnia, przeznaczenie_lokalu, zdjecia_string, osoba_kontaktowa, 
                        nr_telefonu, 
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Publikuj' and rodzaj_ogloszenia == 's':
            if not region:
                msq.handle_error(f'UWAGA! Błąd braku regionu przez {session["username"]}!', log_path=logFileName)
                flash('Wybierz region!', 'danger')
                return redirect(url_for(redirectGoal))

            picked_offer = {}            
            for offer in generator_sellOffert():
                if str(offer['ID']) == str(id_ogloszenia):
                    picked_offer = offer
            
            tytul_ogloszenia = picked_offer['Tytul']
            powierzchnia = picked_offer['Metraz']
            cena = picked_offer['Cena']
            rynek = picked_offer.get('Rynek') or 'wtórny'

            osoba_kontaktowa = session['user_data']['name']
            nr_telefonu = picked_offer['TelefonKontaktowy']

            zdjecia_string = ''
            for foto_link in picked_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':
                if extra_descript:
                    prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_offer['RodzajZabudowy']}\n\n"
            
            
            if picked_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_offer['TechBudowy']}\n\n"
            if picked_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_offer['StanWykonczenia']}\n\n"
            if picked_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_offer['RokBudowy']} r.\n\n"
            if picked_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]
            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""

            if str(picked_offer['TypNieruchomosci']).lower().count('dom') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('willa') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('bliźniak') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('segment') > 0:
                # kategoria na adresowo dla dom
                kategoria_ogloszenia = 'dom'

            elif str(picked_offer['TypNieruchomosci']).lower().count('mieszkanie') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('kawalerka') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('apartament') > 0\
                        or str(picked_offer['TypNieruchomosci']).lower().count('blok') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('kamienica') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('loft') > 0:
                # kategoria na adresowo dla mieszkanie
                kategoria_ogloszenia = 'mieszkanie'
            
            elif str(picked_offer['TypNieruchomosci']).lower().count('działka') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('plac') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('teren') > 0:
                # kategoria na adresowo dla dzialka
                kategoria_ogloszenia = 'dzialka'

            elif str(picked_offer['TypNieruchomosci']).lower().count('biur') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('hal') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('usługi') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('lokal') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('magazyn') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('produkcja') > 0:
                # kategoria na adresowo dla komercyjne
                kategoria_ogloszenia = 'komercyjne'

            else:
                msq.handle_error(f'UWAGA! Nie rozpoznano typu nieruchomości, dane wysłane przez {session["username"]} są niejednoznaczne!', log_path=logFileName)
                flash('Nie rozpoznano typu nieruchomości, dane są niejednoznaczne!', 'danger')
                return redirect(url_for(redirectGoal))

            if kategoria_ogloszenia == 'dom':
                # region, ulica, powierzchnia, pow_dzialki, rok_budowy, l_pieter, typ_budynku, stan
                powierzchnia = picked_offer['Metraz']
                pow_dzialki = powierzchnia * 4
                rok_budowy = picked_offer['RokBudowy']

                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_offer['LiczbaPokoi'] > 20:liczba_pokoi = 20
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                if picked_offer['LiczbaPieter'] == 0:liczba_pieter = 'parterowy'
                elif picked_offer['LiczbaPieter'] > 4:liczba_pieter = 'powyżej 4'
                else:liczba_pieter = picked_offer['LiczbaPieter']

                if str(picked_offer['StanWykonczenia']).lower().count('pod Klucz') > 0: stan = 'Do zamieszkania'
                elif str(picked_offer['StanWykonczenia']).lower().count('do remontu') > 0: stan = 'Do remontu'
                elif str(picked_offer['StanWykonczenia']).lower().count('do częściowego remontu') > 0: stan = 'Do częściowego remontu'
                elif str(picked_offer['StanWykonczenia']).lower().count('do wykończenia') > 0: stan = 'Do wykończenia'
                elif str(picked_offer['StanWykonczenia']).lower().count('surowy otwarty') > 0: stan = 'Surowy otwarty'
                elif str(picked_offer['StanWykonczenia']).lower().count('surowy zaknięty') > 0: stan = 'Surowy zaknięty'
                elif str(picked_offer['StanWykonczenia']).lower().count('wysoki standard') > 0: stan = 'Wysoki standard'
                else: stan = 'Do odświeżenia'

                if str(picked_offer['Rodzaj']).lower().count('bliźniacza') > 0: typ_budynku = 'Bliźniak'
                elif str(picked_offer['Rodzaj']).lower().count('dworek') > 0: typ_budynku = 'Dworek'
                elif str(picked_offer['Rodzaj']).lower().count('kamienica') > 0: typ_budynku = 'Kamienica'
                elif str(picked_offer['Rodzaj']).lower().count('gospodarstwo') > 0: typ_budynku = 'Gospodarstwo'
                elif str(picked_offer['Rodzaj']).lower().count('letniskowa') > 0: typ_budynku = 'Dom letniskowy'
                elif str(picked_offer['Rodzaj']).lower().count('szeregowa') > 0: typ_budynku = 'Dom szeregowy'
                elif str(picked_offer['Rodzaj']).lower().count('wolnostojąca') > 0: typ_budynku = 'Dom wolnostojący'
                elif str(picked_offer['Rodzaj']).lower().count('wielorodzinna') > 0: typ_budynku = 'Budynek wielorodzinny'
                elif str(picked_offer['Rodzaj']).lower().count('siedlisko') > 0: typ_budynku = 'Siedlisko'
                else: typ_budynku = 'Inny'

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_adresowo
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, liczba_pieter, pow_dzialki, ulica, powierzchnia, rok_budowy, 
                            stan, typ_budynku, zdjecia_string, osoba_kontaktowa, nr_telefonu, rynek,
                            status)
                        VALUES 
                            (
                            %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, 
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, liczba_pieter, pow_dzialki, ulica, powierzchnia, rok_budowy, 
                        stan, typ_budynku, zdjecia_string, osoba_kontaktowa, nr_telefonu, rynek,
                        4)
                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')
                
            if kategoria_ogloszenia == 'mieszkanie':
                # region, ulica, cena, powierzchnia, rok_budowy, l_poki, l_pieter, winda, umenlowanie, typ_budynku, stan
                powierzchnia = picked_offer['Metraz']
                rok_budowy = picked_offer['RokBudowy']

                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_offer['LiczbaPokoi'] > 20:liczba_pokoi = 20
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                poziom_int = picked_offer['Poziom']
                try:int(poziom_int)
                except:poziom_int=0
                if poziom_int == 0:poziom = 'parter'
                elif poziom_int > 40:poziom = 20
                else:poziom = poziom_int

                if picked_offer['LiczbaPieter'] == 0:liczba_pieter = 1
                elif picked_offer['LiczbaPieter'] > 40:liczba_pieter = 40
                else:liczba_pieter = picked_offer['LiczbaPieter']

                if str(picked_offer['InformacjeDodatkowe']).lower().count('winda') > 0: winda = 'Z windą'
                else: winda = 'Bez windy'

                if str(picked_offer['StanWykonczenia']).lower().count('pod Klucz') > 0: stan = 'Deweloperski'
                elif str(picked_offer['StanWykonczenia']).lower().count('dobry') > 0: stan = 'Dobry'
                elif str(picked_offer['StanWykonczenia']).lower().count('do remontu') > 0: stan = 'Do remontu'
                elif str(picked_offer['StanWykonczenia']).lower().count('do częściowego remontu') > 0: stan = 'Do częściowego remontu'
                elif str(picked_offer['StanWykonczenia']).lower().count('do wykończenia') > 0: stan = 'Do wykończenia'
                elif str(picked_offer['StanWykonczenia']).lower().count('wysoki standard') > 0: stan = 'Wysoki standard'
                else: stan = 'Do odświeżenia'

                if str(picked_offer['RodzajZabudowy']).lower().count('blok') > 0: typ_budynku = 'Blok'
                elif str(picked_offer['RodzajZabudowy']).lower().count('płyta') > 0: typ_budynku = 'Blok z płyty'
                elif str(picked_offer['RodzajZabudowy']).lower().count('kamienica') > 0: typ_budynku = 'Kamienica'
                elif str(picked_offer['RodzajZabudowy']).lower().count('apartamentowiec') > 0: typ_budynku = 'Apartamentowiec'
                else: typ_budynku = 'Dom wielorodzinny'

                if str(picked_offer['InformacjeDodatkowe']).lower().count('spółdzielcze własnościowe') > 0: forma_wlasnosci = 'Spółdzielcze własnościowe'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('pełna własność') > 0: forma_wlasnosci = 'Pełna własność'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('udział') > 0: forma_wlasnosci = 'Udział'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('tbs') > 0: forma_wlasnosci = 'TBS'
                else: 
                    msq.handle_error(f'UWAGA! Nie rozpoznano formy własności przez {session["username"]}, która jest wymagana w kategorii mieszkanie na sprzedaż! Wpisz formę własności (spółdzielcze własnościowe, pełna własność, udział, tbs) w polu informacje dodatkowe!!', log_path=logFileName)
                    flash('Nie rozpoznano formy własności, która jest wymagana w kategorii mieszkanie na sprzedaż! Wpisz formę własności (spółdzielcze własnościowe, pełna własność, udział, tbs) w polu informacje dodatkowe!', 'danger')
                    return redirect(url_for(redirectGoal))
                
                zapytanie_sql = '''
                        INSERT INTO ogloszenia_adresowo
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, liczba_pokoi, poziom, liczba_pieter, ulica, powierzchnia, 
                            rok_budowy, winda, stan, typ_budynku, forma_wlasnosci, zdjecia_string, 
                            osoba_kontaktowa, nr_telefonu, rynek,
                            status)
                        VALUES 
                            (
                            %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, 
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, liczba_pokoi, poziom, liczba_pieter, ulica, powierzchnia, 
                        rok_budowy, winda, stan, typ_budynku, forma_wlasnosci, zdjecia_string, 
                        osoba_kontaktowa, nr_telefonu, rynek,
                        4)
                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'dzialka':
                # region, ulica, typ_budynku, powierzchnia
                if str(picked_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: rodzaj_dzialki = 'Budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('inwestycyjna') > 0: rodzaj_dzialki = 'Inwestycyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolna') > 0: rodzaj_dzialki = 'Rolna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolno-budowlana') > 0: rodzaj_dzialki = 'Rolno-budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: rodzaj_dzialki = 'Rekreacyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: rodzaj_dzialki = 'Siedliskowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: rodzaj_dzialki = 'Usługowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: rodzaj_dzialki = 'Leśna'
                else: rodzaj_dzialki = 'Inna'

                powierzchnia = picked_offer['Metraz']

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_adresowo
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, ulica, powierzchnia, rodzaj_dzialki, zdjecia_string, osoba_kontaktowa, 
                            nr_telefonu, 
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s,
                            %s,
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, ulica, powierzchnia, rodzaj_dzialki, zdjecia_string, osoba_kontaktowa, 
                        nr_telefonu, 
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'komercyjne':
                # region, ulica, typ_budynku, powierzchnia
                if str(picked_offer['InformacjeDodatkowe']).lower().count('biurowe') > 0: przeznaczenie_lokalu = 'Biuro'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('handel i usługi') > 0: przeznaczenie_lokalu = 'Lokal'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('produkcja i przemysł') > 0: przeznaczenie_lokalu = 'Hala'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('hala') > 0\
                      or str(picked_offer['InformacjeDodatkowe']).lower().count('magazyn') > 0: przeznaczenie_lokalu = 'Hala'
                else: przeznaczenie_lokalu = 'Pozostała nieruchomość'

                powierzchnia = picked_offer['Metraz']

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_adresowo
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, ulica, powierzchnia, przeznaczenie_lokalu, zdjecia_string, osoba_kontaktowa, 
                            nr_telefonu, 
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s,
                            %s,
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, ulica, powierzchnia, przeznaczenie_lokalu, zdjecia_string, osoba_kontaktowa, 
                        nr_telefonu, 
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do realizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Aktualizuj' and rodzaj_ogloszenia == 'r':
            picked_offer = {}            
            for offer in generator_rentOffert():
                if str(offer['ID']) == str(id_ogloszenia):
                    picked_offer = offer
            
            tytul_ogloszenia = picked_offer['Tytul']
            powierzchnia = picked_offer['Metraz']
            cena = picked_offer['Cena']
            osoba_kontaktowa = session['user_data']['name']
            nr_telefonu = picked_offer['TelefonKontaktowy']

            zdjecia_string = ''
            for foto_link in picked_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':
                if extra_descript:
                    prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_offer['RodzajZabudowy']}\n\n"
            if picked_offer['Czynsz'] != 0:
                extra_opis += f"Czynsz:\n{picked_offer['Czynsz']} zł.\n\n"
            if picked_offer['Umeblowanie'] != "":
                extra_opis += f"Umeblowanie:\n{picked_offer['Umeblowanie']}\n\n"
            if picked_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_offer['TechBudowy']}\n\n"
            if picked_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_offer['StanWykonczenia']}\n\n"
            if picked_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_offer['RokBudowy']} r.\n\n"
            if picked_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]
            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""

            if str(picked_offer['TypDomu']).lower().count('dom') > 0\
                or str(picked_offer['TypDomu']).lower().count('willa') > 0\
                    or str(picked_offer['TypDomu']).lower().count('bliźniak') > 0\
                or str(picked_offer['TypDomu']).lower().count('segment') > 0:
                # kategoria na adresowo dla dom
                kategoria_ogloszenia = 'dom'

            elif str(picked_offer['TypDomu']).lower().count('mieszkanie') > 0\
                or str(picked_offer['TypDomu']).lower().count('kawalerka') > 0\
                    or str(picked_offer['TypDomu']).lower().count('apartament') > 0\
                        or str(picked_offer['TypDomu']).lower().count('blok') > 0\
                    or str(picked_offer['TypDomu']).lower().count('kamienica') > 0\
                or str(picked_offer['TypDomu']).lower().count('loft') > 0:
                # kategoria na adresowo dla mieszkanie
                kategoria_ogloszenia = 'mieszkanie'
            
            elif str(picked_offer['TypDomu']).lower().count('działka') > 0\
                or str(picked_offer['TypDomu']).lower().count('plac') > 0\
                    or str(picked_offer['TypDomu']).lower().count('teren') > 0:
                # kategoria na adresowo dla dzialka
                kategoria_ogloszenia = 'dzialka'

            elif str(picked_offer['TypDomu']).lower().count('biur') > 0\
                or str(picked_offer['TypDomu']).lower().count('hal') > 0\
                    or str(picked_offer['TypDomu']).lower().count('usługi') > 0\
                    or str(picked_offer['TypDomu']).lower().count('lokal') > 0\
                    or str(picked_offer['TypDomu']).lower().count('magazyn') > 0\
                or str(picked_offer['TypDomu']).lower().count('produkcja') > 0:
                # kategoria na adresowo dla komercyjne
                kategoria_ogloszenia = 'komercyjne'

            else:
                msq.handle_error(f'UWAGA! Nie rozpoznano typu nieruchomości, dane wysłane przez {session["username"]} są niejednoznaczne!', log_path=logFileName)
                flash('Nie rozpoznano typu nieruchomości, dane są niejednoznaczne!', 'danger')
                return redirect(url_for(redirectGoal))
            
            if kategoria_ogloszenia == 'dom':
                powierzchnia = picked_offer['Metraz']
                pow_dzialki = picked_offer['PowierzchniaDzialki']
                rok_budowy = picked_offer['RokBudowy']
                

                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_offer['LiczbaPokoi'] > 20:liczba_pokoi = 20
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                if picked_offer['LiczbaPieter'] == 0:liczba_pieter = 1
                elif picked_offer['LiczbaPieter'] > 40:liczba_pieter = 40
                else:liczba_pieter = picked_offer['LiczbaPieter']
                

                if str(picked_offer['Umeblowanie']).lower().count('w całości') > 0: umeblowanie = 'W pełni'
                elif str(picked_offer['Umeblowanie']).lower().count('częściowo') > 0: umeblowanie = 'Częściowo'
                else: umeblowanie = 'Nieumeblowane'

                if str(picked_offer['StanWykonczenia']).lower().count('pod Klucz') > 0: stan = 'Do zamieszkania'
                elif str(picked_offer['StanWykonczenia']).lower().count('wysoki standard') > 0: stan = 'Wysoki standard'
                else: stan = 'Do odświeżenia'

                if str(picked_offer['RodzajZabudowy']).lower().count('bliźniacza') > 0: typ_budynku = 'Bliźniak'
                elif str(picked_offer['RodzajZabudowy']).lower().count('dworek') > 0: typ_budynku = 'Dworek'
                elif str(picked_offer['RodzajZabudowy']).lower().count('kamienica') > 0: typ_budynku = 'Kamienica'
                elif str(picked_offer['RodzajZabudowy']).lower().count('gospodarstwo') > 0: typ_budynku = 'Gospodarstwo'
                elif str(picked_offer['RodzajZabudowy']).lower().count('letniskowa') > 0: typ_budynku = 'Dom letniskowy'
                elif str(picked_offer['RodzajZabudowy']).lower().count('szeregowa') > 0: typ_budynku = 'Dom szeregowy'
                elif str(picked_offer['RodzajZabudowy']).lower().count('wolnostojąca') > 0: typ_budynku = 'Dom wolnostojący'
                elif str(picked_offer['RodzajZabudowy']).lower().count('wielorodzinna') > 0: typ_budynku = 'Budynek wielorodzinny'
                elif str(picked_offer['RodzajZabudowy']).lower().count('siedlisko') > 0: typ_budynku = 'Siedlisko'
                else: typ_budynku = 'Inny'

                # tytul_ogloszenia powierzchnia cena nr_telefonu zdjecia_string opis_ogloszenia
                # pow_dzialki rok_budowy liczba_pokoi liczba_pieter umeblowanie stan typ_budynku
                if region:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            region = %s,
                            ulica = %s,
                            umeblowanie = %s,
                            liczba_pokoi = %s,
                            liczba_pieter = %s,
                            pow_dzialki = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            rok_budowy = %s, 
                            stan = %s, 
                            typ_budynku = %s,
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (region, ulica, umeblowanie, liczba_pokoi, liczba_pieter, pow_dzialki, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, rok_budowy, stan, typ_budynku,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)
                else:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            ulica = %s,
                            umeblowanie = %s,
                            liczba_pokoi = %s,
                            liczba_pieter = %s,
                            pow_dzialki = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            rok_budowy = %s, 
                            stan = %s, 
                            typ_budynku = %s,
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (ulica, umeblowanie, liczba_pokoi, liczba_pieter, pow_dzialki, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, rok_budowy, stan, typ_budynku,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')
                
            if kategoria_ogloszenia == 'mieszkanie':
                powierzchnia = picked_offer['Metraz']
                rok_budowy = picked_offer['RokBudowy']
                
                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_offer['LiczbaPokoi'] > 20:liczba_pokoi = 20
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                poziom = 'parter'
                 
                if picked_offer['LiczbaPieter'] == 0:liczba_pieter = 1
                elif picked_offer['LiczbaPieter'] > 40:liczba_pieter = 40
                else:liczba_pieter = picked_offer['LiczbaPieter']
                
                if str(picked_offer['InformacjeDodatkowe']).lower().count('winda') > 0: winda = 'Z windą'
                else: winda = 'Bez windy'

                if str(picked_offer['Umeblowanie']).lower().count('w całości') > 0: umeblowanie = 'W pełni'
                elif str(picked_offer['Umeblowanie']).lower().count('częściowo') > 0: umeblowanie = 'Częściowo'
                else: umeblowanie = 'Nieumeblowane'

                if str(picked_offer['StanWykonczenia']).lower().count('pod Klucz') > 0: stan = 'Do zamieszkania'
                elif str(picked_offer['StanWykonczenia']).lower().count('wysoki standard') > 0: stan = 'Wysoki standard'
                else: stan = 'Do odświeżenia'

                if str(picked_offer['RodzajZabudowy']).lower().count('blok') > 0: typ_budynku = 'Blok'
                elif str(picked_offer['RodzajZabudowy']).lower().count('płyta') > 0: typ_budynku = 'Blok z płyty'
                elif str(picked_offer['RodzajZabudowy']).lower().count('kamienica') > 0: typ_budynku = 'Kamienica'
                elif str(picked_offer['RodzajZabudowy']).lower().count('apartamentowiec') > 0: typ_budynku = 'Apartamentowiec'
                else: typ_budynku = 'Dom wielorodzinny'


                # region, ulica, cena, powierzchnia, rok_budowy, l_poki, l_pieter, winda, umeblowanie, typ_budynku, stan

                # tytul_ogloszenia powierzchnia cena nr_telefonu zdjecia_string opis_ogloszenia
                # rok_budowy liczba_pokoi poziom liczba_pieter winda umeblowanie stan typ_budynku
                if region:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            region = %s,
                            ulica = %s,
                            umeblowanie = %s,
                            liczba_pokoi = %s,
                            liczba_pieter = %s,
                            poziom = %s,
                            winda = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            rok_budowy = %s, 
                            stan = %s, 
                            typ_budynku = %s,
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (region, ulica, umeblowanie, liczba_pokoi, liczba_pieter, poziom, winda, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, rok_budowy, stan, typ_budynku,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)
                else:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            ulica = %s,
                            umeblowanie = %s,
                            liczba_pokoi = %s,
                            liczba_pieter = %s,
                            poziom = %s,
                            winda = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            rok_budowy = %s, 
                            stan = %s, 
                            typ_budynku = %s,
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (ulica, umeblowanie, liczba_pokoi, liczba_pieter, poziom, winda, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, rok_budowy, stan, typ_budynku,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'dzialka':
                # region, ulica, typ_budynku, powierzchnia
                if str(picked_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: rodzaj_dzialki = 'Budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('inwestycyjna') > 0: rodzaj_dzialki = 'Inwestycyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolna') > 0: rodzaj_dzialki = 'Rolna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolno-budowlana') > 0: rodzaj_dzialki = 'Rolno-budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: rodzaj_dzialki = 'Rekreacyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: rodzaj_dzialki = 'Siedliskowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: rodzaj_dzialki = 'Usługowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: rodzaj_dzialki = 'Leśna'
                else: rodzaj_dzialki = 'Inna'

                powierzchnia = picked_offer['Metraz']

                # tytul_ogloszenia powierzchnia cena nr_telefonu zdjecia_string opis_ogloszenia
                # powierzchnia rodzaj_dzialki
                if region:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            region = %s,
                            ulica = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            rodzaj_dzialki = %s,
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (region, ulica, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, 
                            rodzaj_dzialki,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)
                else:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            ulica = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            rodzaj_dzialki = %s,
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (ulica, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, 
                            rodzaj_dzialki,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'komercyjne':
                # region, ulica, typ_budynku, powierzchnia
                if str(picked_offer['InformacjeDodatkowe']).lower().count('biurowe') > 0: przeznaczenie_lokalu = 'Biuro'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('handel i usługi') > 0: przeznaczenie_lokalu = 'Lokal'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('produkcja i przemysł') > 0: przeznaczenie_lokalu = 'Hala'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('hala') > 0\
                      or str(picked_offer['InformacjeDodatkowe']).lower().count('magazyn') > 0: przeznaczenie_lokalu = 'Hala'
                else: przeznaczenie_lokalu = 'Pozostała nieruchomość'

                powierzchnia = picked_offer['Metraz']

                # tytul_ogloszenia powierzchnia cena nr_telefonu zdjecia_string opis_ogloszenia
                # przeznaczenie_lokalu
                if region:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            region = %s,
                            ulica = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            przeznaczenie_lokalu = %s,
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (region, ulica, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, 
                            przeznaczenie_lokalu,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)
                else:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            ulica = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            przeznaczenie_lokalu = %s,
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (ulica, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, 
                            przeznaczenie_lokalu,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Aktualizuj' and rodzaj_ogloszenia == 's':
            picked_offer = {}            
            for offer in generator_sellOffert():
                if str(offer['ID']) == str(id_ogloszenia):
                    picked_offer = offer
            
            tytul_ogloszenia = picked_offer['Tytul']
            powierzchnia = picked_offer['Metraz']
            cena = picked_offer['Cena']

            osoba_kontaktowa = session['user_data']['name']
            nr_telefonu = picked_offer['TelefonKontaktowy']

            zdjecia_string = ''
            for foto_link in picked_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':
                if extra_descript:
                    prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_offer['RodzajZabudowy']}\n\n"
           
            if picked_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_offer['TechBudowy']}\n\n"
            if picked_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_offer['StanWykonczenia']}\n\n"
            if picked_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_offer['RokBudowy']} r.\n\n"
            if picked_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]
            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""

            if str(picked_offer['TypNieruchomosci']).lower().count('dom') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('willa') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('bliźniak') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('segment') > 0:
                # kategoria na adresowo dla dom
                kategoria_ogloszenia = 'dom'

            elif str(picked_offer['TypNieruchomosci']).lower().count('mieszkanie') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('kawalerka') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('apartament') > 0\
                        or str(picked_offer['TypNieruchomosci']).lower().count('blok') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('kamienica') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('loft') > 0:
                # kategoria na adresowo dla mieszkanie
                kategoria_ogloszenia = 'mieszkanie'
            
            elif str(picked_offer['TypNieruchomosci']).lower().count('działka') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('plac') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('teren') > 0:
                # kategoria na adresowo dla dzialka
                kategoria_ogloszenia = 'dzialka'

            elif str(picked_offer['TypNieruchomosci']).lower().count('biur') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('hal') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('usługi') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('lokal') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('magazyn') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('produkcja') > 0:
                # kategoria na adresowo dla komercyjne
                kategoria_ogloszenia = 'komercyjne'

            else:
                msq.handle_error(f'UWAGA! Nie rozpoznano typu nieruchomości, dane wysłane przez {session["username"]} są niejednoznaczne!', log_path=logFileName)
                flash('Nie rozpoznano typu nieruchomości, dane są niejednoznaczne!', 'danger')
                return redirect(url_for(redirectGoal))

            if kategoria_ogloszenia == 'dom':
                # region, ulica, powierzchnia, pow_dzialki, rok_budowy, l_pieter, typ_budynku, stan
                powierzchnia = picked_offer['Metraz']
                pow_dzialki = powierzchnia * 4
                rok_budowy = picked_offer['RokBudowy']

                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_offer['LiczbaPokoi'] > 20:liczba_pokoi = 20
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                if picked_offer['LiczbaPieter'] == 0:liczba_pieter = 'parterowy'
                elif picked_offer['LiczbaPieter'] > 4:liczba_pieter = 'powyżej 4'
                else:liczba_pieter = picked_offer['LiczbaPieter']

                if str(picked_offer['StanWykonczenia']).lower().count('pod Klucz') > 0: stan = 'Do zamieszkania'
                elif str(picked_offer['StanWykonczenia']).lower().count('do remontu') > 0: stan = 'Do remontu'
                elif str(picked_offer['StanWykonczenia']).lower().count('do częściowego remontu') > 0: stan = 'Do częściowego remontu'
                elif str(picked_offer['StanWykonczenia']).lower().count('do wykończenia') > 0: stan = 'Do wykończenia'
                elif str(picked_offer['StanWykonczenia']).lower().count('surowy otwarty') > 0: stan = 'Surowy otwarty'
                elif str(picked_offer['StanWykonczenia']).lower().count('surowy zaknięty') > 0: stan = 'Surowy zaknięty'
                elif str(picked_offer['StanWykonczenia']).lower().count('wysoki standard') > 0: stan = 'Wysoki standard'
                else: stan = 'Do odświeżenia'

                if str(picked_offer['Rodzaj']).lower().count('bliźniacza') > 0: typ_budynku = 'Bliźniak'
                elif str(picked_offer['Rodzaj']).lower().count('dworek') > 0: typ_budynku = 'Dworek'
                elif str(picked_offer['Rodzaj']).lower().count('kamienica') > 0: typ_budynku = 'Kamienica'
                elif str(picked_offer['Rodzaj']).lower().count('gospodarstwo') > 0: typ_budynku = 'Gospodarstwo'
                elif str(picked_offer['Rodzaj']).lower().count('letniskowa') > 0: typ_budynku = 'Dom letniskowy'
                elif str(picked_offer['Rodzaj']).lower().count('szeregowa') > 0: typ_budynku = 'Dom szeregowy'
                elif str(picked_offer['Rodzaj']).lower().count('wolnostojąca') > 0: typ_budynku = 'Dom wolnostojący'
                elif str(picked_offer['Rodzaj']).lower().count('wielorodzinna') > 0: typ_budynku = 'Budynek wielorodzinny'
                elif str(picked_offer['Rodzaj']).lower().count('siedlisko') > 0: typ_budynku = 'Siedlisko'
                else: typ_budynku = 'Inny'

                # tytul_ogloszenia powierzchnia cena nr_telefonu zdjecia_string opis_ogloszenia
                # pow_dzialki rok_budowy liczba_pokoi liczba_pieter stan typ_budynku
                if region:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            region = %s,
                            ulica = %s,
                            liczba_pokoi = %s,
                            liczba_pieter = %s,
                            pow_dzialki = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            rok_budowy = %s, 
                            stan = %s, 
                            typ_budynku = %s,
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (region, ulica, liczba_pokoi, liczba_pieter, pow_dzialki, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, rok_budowy, stan, typ_budynku,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)
                else:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            ulica = %s,
                            liczba_pokoi = %s,
                            liczba_pieter = %s,
                            pow_dzialki = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            rok_budowy = %s, 
                            stan = %s, 
                            typ_budynku = %s,
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (ulica, liczba_pokoi, liczba_pieter, pow_dzialki, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, rok_budowy, stan, typ_budynku,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')
                
            if kategoria_ogloszenia == 'mieszkanie':
                # region, ulica, cena, powierzchnia, rok_budowy, l_poki, l_pieter, winda, umenlowanie, typ_budynku, stan
                powierzchnia = picked_offer['Metraz']
                rok_budowy = picked_offer['RokBudowy']

                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = 1
                elif picked_offer['LiczbaPokoi'] > 20:liczba_pokoi = 20
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                poziom_int = picked_offer['Poziom']
                try:int(poziom_int)
                except:poziom_int=0
                if poziom_int == 0:poziom = 'parter'
                elif poziom_int > 40:poziom = 20
                else:poziom = poziom_int

                if picked_offer['LiczbaPieter'] == 0:liczba_pieter = 1
                elif picked_offer['LiczbaPieter'] > 40:liczba_pieter = 40
                else:liczba_pieter = picked_offer['LiczbaPieter']

                if str(picked_offer['InformacjeDodatkowe']).lower().count('winda') > 0: winda = 'Z windą'
                else: winda = 'Bez windy'

                if str(picked_offer['StanWykonczenia']).lower().count('pod Klucz') > 0: stan = 'Deweloperski'
                elif str(picked_offer['StanWykonczenia']).lower().count('dobry') > 0: stan = 'Dobry'
                elif str(picked_offer['StanWykonczenia']).lower().count('do remontu') > 0: stan = 'Do remontu'
                elif str(picked_offer['StanWykonczenia']).lower().count('do częściowego remontu') > 0: stan = 'Do częściowego remontu'
                elif str(picked_offer['StanWykonczenia']).lower().count('do wykończenia') > 0: stan = 'Do wykończenia'
                elif str(picked_offer['StanWykonczenia']).lower().count('wysoki standard') > 0: stan = 'Wysoki standard'
                else: stan = 'Do odświeżenia'

                if str(picked_offer['RodzajZabudowy']).lower().count('blok') > 0: typ_budynku = 'Blok'
                elif str(picked_offer['RodzajZabudowy']).lower().count('płyta') > 0: typ_budynku = 'Blok z płyty'
                elif str(picked_offer['RodzajZabudowy']).lower().count('kamienica') > 0: typ_budynku = 'Kamienica'
                elif str(picked_offer['RodzajZabudowy']).lower().count('apartamentowiec') > 0: typ_budynku = 'Apartamentowiec'
                else: typ_budynku = 'Dom wielorodzinny'

                if str(picked_offer['InformacjeDodatkowe']).lower().count('spółdzielcze własnościowe') > 0: forma_wlasnosci = 'Spółdzielcze własnościowe'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('pełna własność') > 0: forma_wlasnosci = 'Pełna własność'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('udział') > 0: forma_wlasnosci = 'Udział'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('tbs') > 0: forma_wlasnosci = 'TBS'
                else: 
                    msq.handle_error(f'UWAGA! Nie rozpoznano formy własności, która jest wymagana w kategorii mieszkanie na sprzedaż, wysłanej przez {session["username"]}! Wpisz formę własności (spółdzielcze własnościowe, pełna własność, udział, tbs) w polu informacje dodatkowe!', log_path=logFileName)
                    flash('Nie rozpoznano formy własności, która jest wymagana w kategorii mieszkanie na sprzedaż! Wpisz formę własności (spółdzielcze własnościowe, pełna własność, udział, tbs) w polu informacje dodatkowe!', 'danger')
                    return redirect(url_for(redirectGoal))
                
                # tytul_ogloszenia powierzchnia cena nr_telefonu zdjecia_string opis_ogloszenia
                # rok_budowy liczba_pokoi poziom liczba_pieter winda stan typ_budynku forma_wlasnosci

                if region:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            region = %s,
                            ulica = %s,
                            liczba_pokoi = %s,
                            poziom = %s,
                            liczba_pieter = %s,
                            winda = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            rok_budowy = %s, 
                            stan = %s, 
                            typ_budynku = %s,
                            forma_wlasnosci = %s,
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (region, ulica, liczba_pokoi, poziom, liczba_pieter, winda, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, rok_budowy, stan, typ_budynku, forma_wlasnosci,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)
                else:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            ulica = %s,
                            liczba_pokoi = %s,
                            poziom = %s,
                            liczba_pieter = %s,
                            winda = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            rok_budowy = %s, 
                            stan = %s, 
                            typ_budynku = %s,
                            forma_wlasnosci = %s,
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (ulica, liczba_pokoi, poziom, liczba_pieter, winda, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, rok_budowy, stan, typ_budynku, forma_wlasnosci,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)
                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'dzialka':
                if str(picked_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: rodzaj_dzialki = 'Budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('inwestycyjna') > 0: rodzaj_dzialki = 'Inwestycyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolna') > 0: rodzaj_dzialki = 'Rolna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolno-budowlana') > 0: rodzaj_dzialki = 'Rolno-budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: rodzaj_dzialki = 'Rekreacyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: rodzaj_dzialki = 'Siedliskowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: rodzaj_dzialki = 'Usługowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: rodzaj_dzialki = 'Leśna'
                else: rodzaj_dzialki = 'Inna'

                powierzchnia = picked_offer['Metraz']

                # tytul_ogloszenia powierzchnia cena nr_telefonu zdjecia_string opis_ogloszenia
                # rodzaj_dzialki
                if region:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            region = %s,
                            ulica = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            rodzaj_dzialki = %s, 
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (region, ulica, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, rodzaj_dzialki,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)
                else:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            ulica = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            rodzaj_dzialki = %s, 
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (ulica, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, rodzaj_dzialki,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'komercyjne':
                # region, ulica, typ_budynku, powierzchnia
                if str(picked_offer['InformacjeDodatkowe']).lower().count('biurowe') > 0: przeznaczenie_lokalu = 'Biuro'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('handel i usługi') > 0: przeznaczenie_lokalu = 'Lokal'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('produkcja i przemysł') > 0: przeznaczenie_lokalu = 'Hala'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('hala') > 0\
                      or str(picked_offer['InformacjeDodatkowe']).lower().count('magazyn') > 0: przeznaczenie_lokalu = 'Hala'
                else: przeznaczenie_lokalu = 'Pozostała nieruchomość'

                powierzchnia = picked_offer['Metraz']

                # tytul_ogloszenia powierzchnia cena nr_telefonu zdjecia_string opis_ogloszenia
                # przeznaczenie_lokalu
                if region:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            region = %s,
                            ulica = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            przeznaczenie_lokalu = %s, 
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (region, ulica, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, przeznaczenie_lokalu,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)
                else:
                    zapytanie_sql = '''
                        UPDATE ogloszenia_adresowo
                        SET 
                            ulica = %s,
                            tytul_ogloszenia = %s,   
                            powierzchnia = %s, 
                            opis_ogloszenia = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            przeznaczenie_lokalu = %s, 
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                    dane = (ulica, tytul_ogloszenia, powierzchnia, 
                            opis_ogloszenia, cena, zdjecia_string, przeznaczenie_lokalu,
                            osoba_kontaktowa, nr_telefonu,
                            5, 0,
                        adresowo_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do aktualizacji na adresowo przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Wstrzymaj':
            zapytanie_sql = '''
                UPDATE ogloszenia_adresowo
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, 7, adresowo_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie wysłana do wstrzymania na adresowo przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do wstrzymania na adresowo przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')


        if task_kind == 'Wznow':
            zapytanie_sql = '''
                UPDATE ogloszenia_adresowo
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, 8, adresowo_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie wysłana do wznowienia na adresowo przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do wznowienia na adresowo przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')


        if task_kind == 'Usun':
            zapytanie_sql = '''
                UPDATE ogloszenia_adresowo
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, 6, adresowo_id)
            
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie wysłana do usunięcia na adresowo przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do usunięcia na adresowo przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')


        if task_kind == 'Promuj':
            pass


        if task_kind == 'Ponow_zadanie':
            oldStatus = takeAdresowoResumeStatus(adresowo_id)
            zapytanie_sql = '''
                UPDATE ogloszenia_adresowo
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, oldStatus, adresowo_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Zadanie zostało pomyślnie ponowione dla adresowo przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                msq.handle_error(f'UWAGA!Zadanie nie zostało ponowione dla adresowo przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')
        
        if task_kind == 'Anuluj_zadanie':
            oldStatus = takeAdresowoResumeStatus(adresowo_id)
            if oldStatus == 4:
                zapytanie_sql = '''
                    DELETE FROM ogloszenia_adresowo
                        
                    WHERE id = %s;
                    '''
                dane = (adresowo_id,)
            
            if oldStatus == 5 or oldStatus == 6 or oldStatus == 7:
                zapytanie_sql = '''
                    UPDATE ogloszenia_adresowo
                        SET 
                            active_task=%s,
                            status=%s
                        WHERE id = %s;
                    '''
                dane = (0, 1, adresowo_id)


            if oldStatus == 8:
                zapytanie_sql = '''
                    UPDATE ogloszenia_adresowo
                        SET 
                            active_task=%s,
                            status=%s
                        WHERE id = %s;
                    '''
                dane = (0, 0, adresowo_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Zadanie zostało pomyślnie anulowane dla adresowo przez {session["username"]}!', log_path=logFileName)
                flash(f'Zadanie zostało anulowane!', 'success')
            else:
                msq.handle_error(f'UWAGA!Zadanie nie zostało anulowane dla adresowo przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Zadanie nie zostało anulowane!', 'danger')
        

        if task_kind == 'Odswiez':
            flash(f'Oferta została odświeżona pomyślnie!', 'success')


        if task_kind == 'Ponow':
            zapytanie_sql = '''
                UPDATE ogloszenia_adresowo
                    SET 
                        active_task=%s
                    WHERE id = %s;
                '''
            dane = (0, adresowo_id)
            
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie wysłana do ponowienia na adresowo przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do ponowienia na adresowo przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')
        
        return redirect(url_for(redirectGoal))
    return redirect(url_for('index')) 

@app.route('/public-on-allegro', methods=['POST'])
def public_on_allegro():
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /public-on-allegro bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /public-on-allegro bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        allegro_id = request.form.get('allegro_id')
        id_ogloszenia = request.form.get('PostID')
        task_kind = request.form.get('task_kind')
        redirectGoal = request.form.get('redirectGoal')
        extra_descript = request.form.get('extra_descript')
        if 'region' in request.form:
            get_region = request.form.get('region')
            if get_region!='' and get_region.count('/')>4:
                region = get_region
            else:
                region = None  
        else:
            region = None

        if 'ulica' in request.form:
            get_ulica = request.form.get('ulica')
            if get_ulica!='':
                ulica = get_ulica
            else:
                ulica = 'Nieokreślona' 
        else:
            ulica = 'Nieokreślona'
        
        if 'kodpocztowy' in request.form:
            get_kod_pocztowy = request.form.get('kodpocztowy')
            if get_kod_pocztowy!='':
                kod_pocztowy = get_kod_pocztowy
            else:
                kod_pocztowy = None  
        else:
            kod_pocztowy = None
        
        if 'pakiet_premium' in request.form:
            pakiet = 3
        elif 'pakiet_optymalny' in request.form:
            pakiet = 2
        else:
            pakiet = 1

        if 'wyroznij' in request.form:
            extra_wyroznienie = 1
        else:
            extra_wyroznienie = 0

        if 'wznawiaj' in request.form:
            extra_wznawianie = 1
        else:
            extra_wznawianie = 0

        rodzaj_ogloszenia = None
        if redirectGoal == 'estateAdsRent':
            rodzaj_ogloszenia = 'r'
        if redirectGoal == 'estateAdsSell':
            rodzaj_ogloszenia = 's'

        if task_kind == 'Publikuj' and rodzaj_ogloszenia == 'r':
            if not region:
                msq.handle_error(f'UWAGA! Błąd wyboru regionu dla allegro przez {session["username"]}!', log_path=logFileName)
                flash('Wybierz region!', 'danger')
                return redirect(url_for(redirectGoal))

            picked_offer = {}            
            for offer in generator_rentOffert():
                if str(offer['ID']) == str(id_ogloszenia):
                    picked_offer = offer
            
            tytul_ogloszenia = picked_offer['Tytul']
            powierzchnia = picked_offer['Metraz']
            cena = picked_offer['Cena']
            osoba_kontaktowa = session['user_data']['name']
            adres_email = session['user_data']['email']            
            nr_telefonu = picked_offer['TelefonKontaktowy']

            zdjecia_string = ''
            for foto_link in picked_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':
                if extra_descript:
                    prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_offer['RodzajZabudowy']}\n\n"
            if picked_offer['Czynsz'] != 0:
                extra_opis += f"Czynsz:\n{picked_offer['Czynsz']} zł.\n\n"
            if picked_offer['Umeblowanie'] != "":
                extra_opis += f"Umeblowanie:\n{picked_offer['Umeblowanie']}\n\n"
            if picked_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_offer['TechBudowy']}\n\n"
            if picked_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_offer['StanWykonczenia']}\n\n"
            if picked_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_offer['RokBudowy']} r.\n\n"
            if picked_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]
            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""

            if str(picked_offer['TypDomu']).lower().count('dom') > 0\
                or str(picked_offer['TypDomu']).lower().count('willa') > 0\
                    or str(picked_offer['TypDomu']).lower().count('bliźniak') > 0\
                or str(picked_offer['TypDomu']).lower().count('segment') > 0:
                # kategoria na adresowo dla dom
                kategoria_ogloszenia = 'dom'

            elif str(picked_offer['TypDomu']).lower().count('mieszkanie') > 0\
                or str(picked_offer['TypDomu']).lower().count('kawalerka') > 0\
                    or str(picked_offer['TypDomu']).lower().count('apartament') > 0\
                        or str(picked_offer['TypDomu']).lower().count('blok') > 0\
                    or str(picked_offer['TypDomu']).lower().count('kamienica') > 0\
                or str(picked_offer['TypDomu']).lower().count('loft') > 0:
                # kategoria na adresowo dla mieszkanie
                kategoria_ogloszenia = 'mieszkanie'
            
            elif str(picked_offer['TypDomu']).lower().count('działka') > 0\
                or str(picked_offer['TypDomu']).lower().count('plac') > 0\
                    or str(picked_offer['TypDomu']).lower().count('teren') > 0:
                # kategoria na adresowo dla dzialka
                kategoria_ogloszenia = 'dzialka'

            elif str(picked_offer['TypDomu']).lower().count('biur') > 0\
                    or str(picked_offer['TypDomu']).lower().count('usługi') > 0\
                    or str(picked_offer['TypDomu']).lower().count('lokal') > 0\
                or str(picked_offer['TypDomu']).lower().count('produkcja') > 0:
                # kategoria na adresowo dla lokal
                kategoria_ogloszenia = 'lokal'

            elif str(picked_offer['TypDomu']).lower().count('magazyn') > 0\
                or str(picked_offer['TypDomu']).lower().count('hal') > 0:
                # kategoria na adresowo dla magazyn
                kategoria_ogloszenia = 'magazyn'
            else:
                msq.handle_error(f'UWAGA! Nie rozpoznano typu nieruchomości, dane wysłane przez {session["username"]} są niejednoznaczne!', log_path=logFileName)
                flash('Nie rozpoznano typu nieruchomości, dane są niejednoznaczne!', 'danger')
                return redirect(url_for(redirectGoal))
            
            time_truck = int(int(str(int(time.time()))[:6]) / 6)
            id_ogloszenia_na_allegro = int(f'{time_truck}{id_ogloszenia}')

            if kategoria_ogloszenia == 'dom': 
                pow_dzialki = picked_offer['PowierzchniaDzialki']

                liczba_pokoi = picked_offer['LiczbaPokoi']

                if str(picked_offer['RodzajZabudowy']).lower().count('bliźniacza') > 0: typ_budynku = 'Bliźniak'
                elif str(picked_offer['RodzajZabudowy']).lower().count('dworek') > 0: typ_budynku = 'Pałac lub dworek'
                elif str(picked_offer['RodzajZabudowy']).lower().count('pałac') > 0: typ_budynku = 'Pałac lub dworek'
                elif str(picked_offer['RodzajZabudowy']).lower().count('kamienica') > 0: typ_budynku = 'Kamienica'
                elif str(picked_offer['RodzajZabudowy']).lower().count('gospodarstwo') > 0: typ_budynku = 'Gospodarstwo'
                elif str(picked_offer['RodzajZabudowy']).lower().count('letniskowa') > 0: typ_budynku = 'Letniskowy'
                elif str(picked_offer['RodzajZabudowy']).lower().count('szeregowa') > 0: typ_budynku = 'Szeregowiec'
                elif str(picked_offer['RodzajZabudowy']).lower().count('wolnostojąca') > 0: typ_budynku = 'Wolnostojący'
                elif str(picked_offer['RodzajZabudowy']).lower().count('atrialny') > 0: typ_budynku = 'Atrialny'
                else: typ_budynku = 'Inny'

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_allegrolokalnie
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, liczba_pokoi, pow_dzialki, ulica, powierzchnia, kod_pocztowy,
                            typ_budynku, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, pakiet,
                            extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s,
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, liczba_pokoi, pow_dzialki, ulica, powierzchnia, kod_pocztowy,
                        typ_budynku, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, pakiet,
                        extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')


            if kategoria_ogloszenia == 'mieszkanie': 

                liczba_pokoi = picked_offer['LiczbaPokoi']
                liczba_pieter = picked_offer['LiczbaPieter']
                poziom = 0


                zapytanie_sql = '''
                        INSERT INTO ogloszenia_allegrolokalnie
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, liczba_pokoi, liczba_pieter, poziom, ulica, powierzchnia, 
                            kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                            pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, 
                             %s, %s, %s, %s,
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, liczba_pokoi, liczba_pieter, poziom, ulica, powierzchnia, 
                        kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                        pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                        4)
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'dzialka': 

                if str(picked_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: typ_dzialki = 'Budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolna') > 0: typ_dzialki = 'Rolna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolno-budowlana') > 0: typ_dzialki = 'Rolno-budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: typ_dzialki = 'Rekreacyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: typ_dzialki = 'Siedliskowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: typ_dzialki = 'Handlowo-Usługowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('handlowa') > 0: typ_dzialki = 'Handlowo-Usługowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: typ_dzialki = 'Leśna'
                else: typ_dzialki = 'Inna'

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_allegrolokalnie
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, ulica, powierzchnia, typ_dzialki, 
                            kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                            pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, 
                             %s, %s, %s, %s,
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, ulica, powierzchnia, typ_dzialki, 
                        kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                        pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'lokal': 
                if str(picked_offer['InformacjeDodatkowe']).lower().count('biurowe') > 0: typ_komercyjny = 'Biuro'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('handel i usługi') > 0: typ_komercyjny = 'Lokal usługowy'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('produkcja i przemysł') > 0: typ_komercyjny = 'Fabryka'
                else: typ_komercyjny = 'Inny obiekt'

                liczba_pokoi = picked_offer['LiczbaPokoi']

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_allegrolokalnie
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, ulica, powierzchnia, typ_komercyjny, liczba_pokoi,
                            kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                            pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, 
                             %s, %s, %s, %s,
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, ulica, powierzchnia, typ_komercyjny, liczba_pokoi,
                        kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                        pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                        4)
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'magazyn':
                if str(picked_offer['InformacjeDodatkowe']).lower().count('dystrybucja') > 0: typ_komercyjny = 'Centrum dystrybucyjne'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('logistyk') > 0: typ_komercyjny = 'Centrum dystrybucyjne'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('hal') > 0: typ_komercyjny = 'Hala'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('magazyn') > 0: typ_komercyjny = 'Magazyn'
                else: typ_komercyjny = 'Magazyn'


                zapytanie_sql = '''
                        INSERT INTO ogloszenia_allegrolokalnie
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, ulica, powierzchnia, typ_komercyjny, 
                            kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                            pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, 
                            %s, %s, %s, %s, %s, 
                            %s, %s, %s, %s,
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, ulica, powierzchnia, typ_komercyjny, 
                        kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                        pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')   

        if task_kind == 'Publikuj' and rodzaj_ogloszenia == 's':
            if not region:
                msq.handle_error(f'UWAGA! Błąd wyboru regionu dla allegro przez {session["username"]}!', log_path=logFileName)
                flash('Wybierz region!', 'danger')
                return redirect(url_for(redirectGoal))

            picked_offer = {}            
            for offer in generator_sellOffert():
                if str(offer['ID']) == str(id_ogloszenia):
                    picked_offer = offer
            
            tytul_ogloszenia = picked_offer['Tytul']
            powierzchnia = picked_offer['Metraz']
            cena = picked_offer['Cena']
            rynek = picked_offer['Rynek']
            osoba_kontaktowa = session['user_data']['name']
            adres_email = session['user_data']['email']            
            nr_telefonu = picked_offer['TelefonKontaktowy']

            zdjecia_string = ''
            for foto_link in picked_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':
                if extra_descript:
                    prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_offer['RodzajZabudowy']}\n\n"

            if picked_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_offer['TechBudowy']}\n\n"
            if picked_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_offer['StanWykonczenia']}\n\n"
            if picked_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_offer['RokBudowy']} r.\n\n"
            if picked_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]
            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""

            if str(picked_offer['TypNieruchomosci']).lower().count('dom') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('willa') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('bliźniak') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('segment') > 0:
                # kategoria na adresowo dla dom
                kategoria_ogloszenia = 'dom'

            elif str(picked_offer['TypNieruchomosci']).lower().count('mieszkanie') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('kawalerka') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('apartament') > 0\
                        or str(picked_offer['TypNieruchomosci']).lower().count('blok') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('kamienica') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('loft') > 0:
                # kategoria na adresowo dla mieszkanie
                kategoria_ogloszenia = 'mieszkanie'
            
            elif str(picked_offer['TypNieruchomosci']).lower().count('działka') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('plac') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('teren') > 0:
                # kategoria na adresowo dla dzialka
                kategoria_ogloszenia = 'dzialka'

            elif str(picked_offer['TypNieruchomosci']).lower().count('biur') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('usługi') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('lokal') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('produkcja') > 0:
                # kategoria na adresowo dla lokal
                kategoria_ogloszenia = 'lokal'

            elif str(picked_offer['TypNieruchomosci']).lower().count('magazyn') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('hal') > 0:
                # kategoria na adresowo dla magazyn
                kategoria_ogloszenia = 'magazyn'
            else:
                msq.handle_error(f'UWAGA! Nie rozpoznano typu nieruchomości, dane wysłane przez {session["username"]} są niejednoznaczne!', log_path=logFileName)
                flash('Nie rozpoznano typu nieruchomości, dane są niejednoznaczne!', 'danger')
                return redirect(url_for(redirectGoal))
            
            time_truck = int(int(str(int(time.time()))[:6]) / 6)
            id_ogloszenia_na_allegro = int(f'{time_truck}{id_ogloszenia}')

            if kategoria_ogloszenia == 'dom': 
                pow_dzialki = int(powierzchnia) * 5

                liczba_pokoi = picked_offer['LiczbaPokoi']

                if str(picked_offer['RodzajZabudowy']).lower().count('bliźniacza') > 0: typ_budynku = 'Bliźniak'
                elif str(picked_offer['RodzajZabudowy']).lower().count('dworek') > 0: typ_budynku = 'Pałac lub dworek'
                elif str(picked_offer['RodzajZabudowy']).lower().count('pałac') > 0: typ_budynku = 'Pałac lub dworek'
                elif str(picked_offer['RodzajZabudowy']).lower().count('kamienica') > 0: typ_budynku = 'Kamienica'
                elif str(picked_offer['RodzajZabudowy']).lower().count('gospodarstwo') > 0: typ_budynku = 'Gospodarstwo'
                elif str(picked_offer['RodzajZabudowy']).lower().count('letniskowa') > 0: typ_budynku = 'Letniskowy'
                elif str(picked_offer['RodzajZabudowy']).lower().count('szeregowa') > 0: typ_budynku = 'Szeregowiec'
                elif str(picked_offer['RodzajZabudowy']).lower().count('wolnostojąca') > 0: typ_budynku = 'Wolnostojący'
                elif str(picked_offer['RodzajZabudowy']).lower().count('atrialny') > 0: typ_budynku = 'Atrialny'
                else: typ_budynku = 'Inny'

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_allegrolokalnie
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, liczba_pokoi, pow_dzialki, ulica, powierzchnia, kod_pocztowy,
                            typ_budynku, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, pakiet,
                            extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro, rynek,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s,
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, liczba_pokoi, pow_dzialki, ulica, powierzchnia, kod_pocztowy,
                        typ_budynku, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, pakiet,
                        extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro, rynek,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')


            if kategoria_ogloszenia == 'mieszkanie': 

                liczba_pokoi = picked_offer['LiczbaPokoi']
                liczba_pieter = picked_offer['LiczbaPieter']
                poziom = 0 if picked_offer['LiczbaPieter'] == 'None' else picked_offer['LiczbaPieter']


                zapytanie_sql = '''
                        INSERT INTO ogloszenia_allegrolokalnie
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, liczba_pokoi, liczba_pieter, poziom, ulica, powierzchnia, 
                            kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                            pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, 
                             %s, %s, %s, %s,
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, liczba_pokoi, liczba_pieter, poziom, ulica, powierzchnia, 
                        kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                        pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'dzialka': 

                if str(picked_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: typ_dzialki = 'Budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolna') > 0: typ_dzialki = 'Rolna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolno-budowlana') > 0: typ_dzialki = 'Rolno-budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: typ_dzialki = 'Rekreacyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: typ_dzialki = 'Siedliskowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: typ_dzialki = 'Handlowo-Usługowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('handlowa') > 0: typ_dzialki = 'Handlowo-Usługowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: typ_dzialki = 'Leśna'
                else: typ_dzialki = 'Inna'

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_allegrolokalnie
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, ulica, powierzchnia, typ_dzialki, 
                            kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                            pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, 
                             %s, %s, %s, %s,
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, ulica, powierzchnia, typ_dzialki, 
                        kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                        pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'lokal': 
                if str(picked_offer['InformacjeDodatkowe']).lower().count('biurowe') > 0: typ_komercyjny = 'Biuro'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('handel i usługi') > 0: typ_komercyjny = 'Lokal usługowy'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('produkcja i przemysł') > 0: typ_komercyjny = 'Fabryka'
                else: typ_komercyjny = 'Inny obiekt'

                liczba_pokoi = picked_offer['LiczbaPokoi']

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_allegrolokalnie
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, ulica, powierzchnia, typ_komercyjny, liczba_pokoi,
                            kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                            pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, 
                             %s, %s, %s, %s,
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, ulica, powierzchnia, typ_komercyjny, liczba_pokoi,
                        kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                        pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'magazyn':
                if str(picked_offer['InformacjeDodatkowe']).lower().count('dystrybucja') > 0: typ_komercyjny = 'Centrum dystrybucyjne'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('logistyk') > 0: typ_komercyjny = 'Centrum dystrybucyjne'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('hal') > 0: typ_komercyjny = 'Hala'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('magazyn') > 0: typ_komercyjny = 'Magazyn'
                else: typ_komercyjny = 'Magazyn'


                zapytanie_sql = '''
                        INSERT INTO ogloszenia_allegrolokalnie
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, ulica, powierzchnia, typ_komercyjny, 
                            kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                            pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, 
                             %s, %s, %s, %s, %s, 
                             %s, %s, %s, %s,
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, ulica, powierzchnia, typ_komercyjny, 
                        kod_pocztowy, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email, 
                        pakiet, extra_wyroznienie, extra_wznawianie, id_ogloszenia_na_allegro,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Aktualizuj' and rodzaj_ogloszenia == 'r': 

            picked_offer = {}            
            for offer in generator_rentOffert():
                if str(offer['ID']) == str(id_ogloszenia):
                    picked_offer = offer
            
            tytul_ogloszenia = picked_offer['Tytul']
            powierzchnia = picked_offer['Metraz']
            cena = picked_offer['Cena']
            osoba_kontaktowa = session['user_data']['name']
            adres_email = session['user_data']['email']            
            nr_telefonu = picked_offer['TelefonKontaktowy']

            zdjecia_string = ''
            for foto_link in picked_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
                if prepared_opis != '':
                    if extra_descript:
                        prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
                else: prepared_opis = picked_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_offer['RodzajZabudowy']}\n\n"
            if picked_offer['Czynsz'] != 0:
                extra_opis += f"Czynsz:\n{picked_offer['Czynsz']} zł.\n\n"
            if picked_offer['Umeblowanie'] != "":
                extra_opis += f"Umeblowanie:\n{picked_offer['Umeblowanie']}\n\n"
            if picked_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_offer['TechBudowy']}\n\n"
            if picked_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_offer['StanWykonczenia']}\n\n"
            if picked_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_offer['RokBudowy']} r.\n\n"
            if picked_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]
            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""


            kategoria_ogloszenia = checkAllegroStatus('r', id_ogloszenia)[8]
            # print(kategoria_ogloszenia)
            if kategoria_ogloszenia == None:
                msq.handle_error(f'UWAGA! Bład kategorii! Oferta nie została wysłana do aktualizacji przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład kategorii! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'dom': 
                pow_dzialki = picked_offer['PowierzchniaDzialki']

                liczba_pokoi = picked_offer['LiczbaPokoi']

                if str(picked_offer['RodzajZabudowy']).lower().count('bliźniacza') > 0: typ_budynku = 'Bliźniak'
                elif str(picked_offer['RodzajZabudowy']).lower().count('dworek') > 0: typ_budynku = 'Pałac lub dworek'
                elif str(picked_offer['RodzajZabudowy']).lower().count('pałac') > 0: typ_budynku = 'Pałac lub dworek'
                elif str(picked_offer['RodzajZabudowy']).lower().count('kamienica') > 0: typ_budynku = 'Kamienica'
                elif str(picked_offer['RodzajZabudowy']).lower().count('gospodarstwo') > 0: typ_budynku = 'Gospodarstwo'
                elif str(picked_offer['RodzajZabudowy']).lower().count('letniskowa') > 0: typ_budynku = 'Letniskowy'
                elif str(picked_offer['RodzajZabudowy']).lower().count('szeregowa') > 0: typ_budynku = 'Szeregowiec'
                elif str(picked_offer['RodzajZabudowy']).lower().count('wolnostojąca') > 0: typ_budynku = 'Wolnostojący'
                elif str(picked_offer['RodzajZabudowy']).lower().count('atrialny') > 0: typ_budynku = 'Atrialny'
                else: typ_budynku = 'Inny'


                zapytanie_sql = '''
                        UPDATE ogloszenia_allegrolokalnie
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            liczba_pokoi = %s,
                            pow_dzialki = %s,
                            powierzchnia = %s,   
                            typ_budynku = %s, 
                            zdjecia_string = %s, 
                            cena = %s, 
                            zdjecia_string = %s, 
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            adres_email = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia, liczba_pokoi, pow_dzialki, powierzchnia,
                        typ_budynku, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email,
                        5, 0,
                    allegro_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')


            if kategoria_ogloszenia == 'mieszkanie': 

                liczba_pokoi = picked_offer['LiczbaPokoi']
                liczba_pieter = picked_offer['LiczbaPieter']
                poziom = 0

                zapytanie_sql = '''
                        UPDATE ogloszenia_allegrolokalnie
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            liczba_pokoi = %s,
                            liczba_pieter = %s,
                            poziom = %s,
                            powierzchnia = %s,   
                            zdjecia_string = %s, 
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            adres_email = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia, liczba_pokoi, liczba_pieter, poziom,
                        powierzchnia, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email,
                        5, 0,
                    allegro_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'dzialka': 

                if str(picked_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: typ_dzialki = 'Budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolna') > 0: typ_dzialki = 'Rolna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolno-budowlana') > 0: typ_dzialki = 'Rolno-budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: typ_dzialki = 'Rekreacyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: typ_dzialki = 'Siedliskowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: typ_dzialki = 'Handlowo-Usługowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('handlowa') > 0: typ_dzialki = 'Handlowo-Usługowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: typ_dzialki = 'Leśna'
                else: typ_dzialki = 'Inna'

                zapytanie_sql = '''
                        UPDATE ogloszenia_allegrolokalnie
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            typ_dzialki = %s,
                            zdjecia_string = %s, 
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            adres_email = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, typ_dzialki, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email,
                        5, 0,
                    allegro_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'lokal': 
                if str(picked_offer['InformacjeDodatkowe']).lower().count('biurowe') > 0: typ_komercyjny = 'Biuro'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('handel i usługi') > 0: typ_komercyjny = 'Lokal usługowy'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('produkcja i przemysł') > 0: typ_komercyjny = 'Fabryka'
                else: typ_komercyjny = 'Inny obiekt'

                liczba_pokoi = picked_offer['LiczbaPokoi']

                zapytanie_sql = '''
                        UPDATE ogloszenia_allegrolokalnie
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            typ_komercyjny = %s,
                            liczba_pokoi = %s,
                            zdjecia_string = %s, 
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            adres_email = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, typ_komercyjny, liczba_pokoi, 
                        zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email,
                        5, 0,
                    allegro_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'magazyn':
                if str(picked_offer['InformacjeDodatkowe']).lower().count('dystrybucja') > 0: typ_komercyjny = 'Centrum dystrybucyjne'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('logistyk') > 0: typ_komercyjny = 'Centrum dystrybucyjne'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('hal') > 0: typ_komercyjny = 'Hala'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('magazyn') > 0: typ_komercyjny = 'Magazyn'
                else: typ_komercyjny = 'Magazyn'

                zapytanie_sql = '''
                        UPDATE ogloszenia_allegrolokalnie
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            typ_komercyjny = %s,
                            zdjecia_string = %s, 
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            adres_email = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, typ_komercyjny,  
                        zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email,
                        5, 0,
                    allegro_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Aktualizuj' and rodzaj_ogloszenia == 's': 
            picked_offer = {}            
            for offer in generator_sellOffert():
                if str(offer['ID']) == str(id_ogloszenia):
                    picked_offer = offer
            
            tytul_ogloszenia = picked_offer['Tytul']
            powierzchnia = picked_offer['Metraz']
            cena = picked_offer['Cena']
            rynek = picked_offer['Rynek']
            osoba_kontaktowa = session['user_data']['name']
            adres_email = session['user_data']['email']            
            nr_telefonu = picked_offer['TelefonKontaktowy']

            zdjecia_string = ''
            for foto_link in picked_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':
                if extra_descript:
                    prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_offer['RodzajZabudowy']}\n\n"
           
            if picked_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_offer['TechBudowy']}\n\n"
            if picked_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_offer['StanWykonczenia']}\n\n"
            if picked_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_offer['RokBudowy']} r.\n\n"
            if picked_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]
            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""



            kategoria_ogloszenia = checkAllegroStatus('s', id_ogloszenia)[8]
            # print(kategoria_ogloszenia)
            if kategoria_ogloszenia == None:
                msq.handle_error(f'UWAGA! Bład kategorii allegro! Oferta nie została wysłana przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład kategorii! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'dom': 
                pow_dzialki = int(powierzchnia) * 5

                liczba_pokoi = picked_offer['LiczbaPokoi']

                if str(picked_offer['RodzajZabudowy']).lower().count('bliźniacza') > 0: typ_budynku = 'Bliźniak'
                elif str(picked_offer['RodzajZabudowy']).lower().count('dworek') > 0: typ_budynku = 'Pałac lub dworek'
                elif str(picked_offer['RodzajZabudowy']).lower().count('pałac') > 0: typ_budynku = 'Pałac lub dworek'
                elif str(picked_offer['RodzajZabudowy']).lower().count('kamienica') > 0: typ_budynku = 'Kamienica'
                elif str(picked_offer['RodzajZabudowy']).lower().count('gospodarstwo') > 0: typ_budynku = 'Gospodarstwo'
                elif str(picked_offer['RodzajZabudowy']).lower().count('letniskowa') > 0: typ_budynku = 'Letniskowy'
                elif str(picked_offer['RodzajZabudowy']).lower().count('szeregowa') > 0: typ_budynku = 'Szeregowiec'
                elif str(picked_offer['RodzajZabudowy']).lower().count('wolnostojąca') > 0: typ_budynku = 'Wolnostojący'
                elif str(picked_offer['RodzajZabudowy']).lower().count('atrialny') > 0: typ_budynku = 'Atrialny'
                else: typ_budynku = 'Inny'


                zapytanie_sql = '''
                        UPDATE ogloszenia_allegrolokalnie
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            liczba_pokoi = %s,
                            pow_dzialki = %s,
                            powierzchnia = %s,   
                            rynek = %s,   
                            typ_budynku = %s, 
                            zdjecia_string = %s, 
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            adres_email = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia, liczba_pokoi, pow_dzialki, powierzchnia, rynek,
                        typ_budynku, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email,
                        5, 0,
                    allegro_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')


            if kategoria_ogloszenia == 'mieszkanie': 

                liczba_pokoi = picked_offer['LiczbaPokoi']
                liczba_pieter = picked_offer['LiczbaPieter']
                poziom = 0 if picked_offer['LiczbaPieter'] == 'None' else picked_offer['LiczbaPieter']


                zapytanie_sql = '''
                        UPDATE ogloszenia_allegrolokalnie
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            liczba_pokoi = %s,
                            liczba_pieter = %s,
                            poziom = %s,
                            powierzchnia = %s,   
                            zdjecia_string = %s, 
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            adres_email = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia, liczba_pokoi, liczba_pieter, poziom,
                        powierzchnia, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email,
                        5, 0,
                    allegro_id)
                
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'dzialka': 

                if str(picked_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: typ_dzialki = 'Budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolna') > 0: typ_dzialki = 'Rolna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolno-budowlana') > 0: typ_dzialki = 'Rolno-budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: typ_dzialki = 'Rekreacyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: typ_dzialki = 'Siedliskowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: typ_dzialki = 'Handlowo-Usługowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('handlowa') > 0: typ_dzialki = 'Handlowo-Usługowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: typ_dzialki = 'Leśna'
                else: typ_dzialki = 'Inna'

                zapytanie_sql = '''
                        UPDATE ogloszenia_allegrolokalnie
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            typ_dzialki = %s,
                            zdjecia_string = %s, 
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            adres_email = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, typ_dzialki, zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email,
                        5, 0,
                    allegro_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'lokal': 
                if str(picked_offer['InformacjeDodatkowe']).lower().count('biurowe') > 0: typ_komercyjny = 'Biuro'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('handel i usługi') > 0: typ_komercyjny = 'Lokal usługowy'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('produkcja i przemysł') > 0: typ_komercyjny = 'Fabryka'
                else: typ_komercyjny = 'Inny obiekt'

                liczba_pokoi = picked_offer['LiczbaPokoi']

                zapytanie_sql = '''
                        UPDATE ogloszenia_allegrolokalnie
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            typ_komercyjny = %s,
                            liczba_pokoi = %s,
                            zdjecia_string = %s, 
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            adres_email = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, typ_komercyjny, liczba_pokoi, 
                        zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email,
                        5, 0,
                    allegro_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'magazyn':
                if str(picked_offer['InformacjeDodatkowe']).lower().count('dystrybucja') > 0: typ_komercyjny = 'Centrum dystrybucyjne'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('logistyk') > 0: typ_komercyjny = 'Centrum dystrybucyjne'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('hal') > 0: typ_komercyjny = 'Hala'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('magazyn') > 0: typ_komercyjny = 'Magazyn'
                else: typ_komercyjny = 'Magazyn'

                zapytanie_sql = '''
                        UPDATE ogloszenia_allegrolokalnie
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            typ_komercyjny = %s,
                            zdjecia_string = %s, 
                            osoba_kontaktowa = %s, 
                            nr_telefonu = %s,
                            adres_email = %s,
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, typ_komercyjny,  
                        zdjecia_string, osoba_kontaktowa, nr_telefonu, adres_email,
                        5, 0,
                    allegro_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na allgero przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Usun': 
            zapytanie_sql = '''
                UPDATE ogloszenia_allegrolokalnie
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, 6, allegro_id)
            
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie wysłana do usunięcia na allgero przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana usunięcia na allgero przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Ponow_zadanie':
            oldStatus = takeAllegroResumeStatus(allegro_id)
            zapytanie_sql = '''
                UPDATE ogloszenia_allegrolokalnie
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, oldStatus, allegro_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została ponowiona dla allgero przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została ponowiona dla allgero przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')
        
        if task_kind == 'Anuluj_zadanie':
            oldStatus = takeAllegroResumeStatus(allegro_id)
            if oldStatus == 4:
                zapytanie_sql = '''
                    DELETE FROM ogloszenia_allegrolokalnie
                        
                    WHERE id = %s;
                    '''
                dane = (allegro_id,)
            
            if oldStatus == 5 or oldStatus == 6 or oldStatus == 7:
                zapytanie_sql = '''
                    UPDATE ogloszenia_allegrolokalnie
                        SET 
                            active_task=%s,
                            status=%s
                        WHERE id = %s;
                    '''
                dane = (0, 1, allegro_id)


            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Zadanie zostało anulowane przez {session["username"]}!', log_path=logFileName)
                flash(f'Zadanie zostało anulowane!', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Zadanie nie zostało anulowane przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Zadanie nie zostało anulowane!', 'danger')
        
        if task_kind == 'Odswiez':
            flash(f'Oferta została odświeżona pomyślnie!', 'success')

        if task_kind == 'Ponow': 
            zapytanie_sql = '''
                UPDATE ogloszenia_allegrolokalnie
                    SET 
                        active_task=%s
                    WHERE id = %s;
                '''
            dane = (0, allegro_id)
            
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została ponowiona dla allgero przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została ponowiona dla allgero przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')


        return redirect(url_for(redirectGoal))
    return redirect(url_for('index')) 

@app.route('/public-on-otodom', methods=['POST'])
def public_on_otodom():
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /public-on-otodom bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /public-on-otodom bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        otodom_id = request.form.get('otodom_id')
        id_ogloszenia = request.form.get('PostID')
        task_kind = request.form.get('task_kind')
        redirectGoal = request.form.get('redirectGoal')
        extra_descript = request.form.get('extra_descript')
        if 'region' in request.form:
            get_region = request.form.get('region')
            if get_region!='' and get_region.count('/')>4:
                region = get_region
            else:
                region = None  
        else:
            region = None

        if 'bez_promowania' in request.form:
            promo = 0
            auto_refresh = 0
            extra_top = 0
            extra_home = 0
            export_olx = 0
            extra_raise = 0
            mega_raise = 0
            pakiet_olx_mini = 0
            pakiet_olx_midi = 0
            pakiet_olx_maxi = 0
            pick_olx = 0
            auto_refresh_olx = 0
        else:
            promo = 1
            if 'wznawiaj' in request.form:
                auto_refresh = 1
            else:
                auto_refresh = 0

            if 'top_14_dni_otodom' in request.form:
                extra_top = 14
            elif 'top_30_dni_otodom' in request.form:
                extra_top = 30
            else:
                extra_top = 0

            if 'wyswietlanie_na_stronie_glownej_7_dni_otodom' in request.form:
                extra_home = 7
            elif 'wyswietlanie_na_stronie_glownej_14_dni_otodom' in request.form:
                extra_home = 14
            else:
                extra_home = 0

            if 'export_do_olx_otodom' in request.form:
                export_olx = 1
            else:
                export_olx = 0


            if 'pakiet_olxmini_otodom' in request.form:
                pakiet_olx_mini = 1
            else:
                pakiet_olx_mini = 0

            if 'pakiet_olxmidi_otodom' in request.form:
                pakiet_olx_midi = 1
            else:
                pakiet_olx_midi = 0
            
            if 'pakiet_olxmaxi_otodom' in request.form:
                pakiet_olx_maxi = 1
            else:
                pakiet_olx_maxi = 0

            if 'wyroznij_na_olx_otodom' in request.form:
                pick_olx = 1
            else:
                pick_olx = 0

            if 'odswiezaj_na_olx_otodom' in request.form:
                auto_refresh_olx = 1
            else:
                auto_refresh_olx = 0

            extra_raise = 1
            mega_raise = 1

        rodzaj_ogloszenia = None
        if redirectGoal == 'estateAdsRent':
            rodzaj_ogloszenia = 'r'
        if redirectGoal == 'estateAdsSell':
            rodzaj_ogloszenia = 's'

        if task_kind == 'Publikuj' and rodzaj_ogloszenia == 'r': 
            if not region:
                msq.handle_error(f'UWAGA! Błąd wyboru regionu dla otodom przez {session["username"]}!', log_path=logFileName)
                flash('Wybierz region!', 'danger')
                return redirect(url_for(redirectGoal))

            picked_offer = {}            
            for offer in generator_rentOffert():
                if str(offer['ID']) == str(id_ogloszenia):
                    picked_offer = offer
            
            tytul_ogloszenia = picked_offer['Tytul']
            powierzchnia = picked_offer['Metraz']
            cena = picked_offer['Cena']

            zdjecia_string = ''
            for foto_link in picked_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':
                if extra_descript:
                    prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_offer['RodzajZabudowy']}\n\n"
            if picked_offer['Czynsz'] != 0:
                extra_opis += f"Czynsz:\n{picked_offer['Czynsz']} zł.\n\n"
            if picked_offer['Umeblowanie'] != "":
                extra_opis += f"Umeblowanie:\n{picked_offer['Umeblowanie']}\n\n"
            if picked_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_offer['TechBudowy']}\n\n"
            if picked_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_offer['StanWykonczenia']}\n\n"
            if picked_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_offer['RokBudowy']} r.\n\n"
            if picked_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]
            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""

            if str(picked_offer['TypDomu']).lower().count('dom') > 0\
                or str(picked_offer['TypDomu']).lower().count('willa') > 0\
                    or str(picked_offer['TypDomu']).lower().count('bliźniak') > 0\
                or str(picked_offer['TypDomu']).lower().count('segment') > 0:
                # kategoria na adresowo dla dom
                kategoria_ogloszenia = 'dom'

            elif str(picked_offer['TypDomu']).lower().count('mieszkanie') > 0\
                or str(picked_offer['TypDomu']).lower().count('kawalerka') > 0\
                    or str(picked_offer['TypDomu']).lower().count('apartament') > 0\
                        or str(picked_offer['TypDomu']).lower().count('blok') > 0\
                    or str(picked_offer['TypDomu']).lower().count('kamienica') > 0\
                or str(picked_offer['TypDomu']).lower().count('loft') > 0:
                # kategoria na adresowo dla mieszkanie
                kategoria_ogloszenia = 'mieszkanie'
            
            elif str(picked_offer['TypDomu']).lower().count('działka') > 0\
                or str(picked_offer['TypDomu']).lower().count('plac') > 0\
                    or str(picked_offer['TypDomu']).lower().count('teren') > 0:
                # kategoria na adresowo dla dzialka
                kategoria_ogloszenia = 'dzialka'

            elif str(picked_offer['TypDomu']).lower().count('biur') > 0\
                    or str(picked_offer['TypDomu']).lower().count('usługi') > 0\
                    or str(picked_offer['TypDomu']).lower().count('lokal') > 0\
                or str(picked_offer['TypDomu']).lower().count('produkcja') > 0:
                # kategoria na adresowo dla lokal
                kategoria_ogloszenia = 'lokal'

            elif str(picked_offer['TypDomu']).lower().count('magazyn') > 0\
                or str(picked_offer['TypDomu']).lower().count('hal') > 0:
                # kategoria na adresowo dla magazyn
                kategoria_ogloszenia = 'magazyn'
            else:
                msq.handle_error(f'UWAGA! Nie rozpoznano typu nieruchomości, dane wysłane przez {session["username"]} są niejednoznaczne!', log_path=logFileName)
                flash('Nie rozpoznano typu nieruchomości, dane są niejednoznaczne!', 'danger')
                return redirect(url_for(redirectGoal))
            

            if kategoria_ogloszenia == 'dom':
                pow_dzialki = picked_offer['PowierzchniaDzialki']

                if picked_offer['LiczbaPieter'] == 0:liczba_pieter = 'parterowy'
                elif picked_offer['LiczbaPieter'] > 3:liczba_pieter = '3 pietra i więcej'
                else:liczba_pieter = f'{picked_offer["LiczbaPieter"]} piętr'

                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = '1'
                elif picked_offer['LiczbaPokoi'] > 10:liczba_pokoi = 'więcej niż 10'
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                if str(picked_offer['RodzajZabudowy']).lower().count('bliźniacza') > 0: rodzaj_zabudowy = 'Bliźniak'
                elif str(picked_offer['RodzajZabudowy']).lower().count('wolnostojąca') > 0: rodzaj_zabudowy = 'Wolnostojący'
                elif str(picked_offer['RodzajZabudowy']).lower().count('szeregowa') > 0: rodzaj_zabudowy = 'Szeregowiec'
                elif str(picked_offer['RodzajZabudowy']).lower().count('kamienica') > 0: rodzaj_zabudowy = 'Kamienica'
                elif str(picked_offer['RodzajZabudowy']).lower().count('dworek') > 0: rodzaj_zabudowy = 'dworek/pałac'
                elif str(picked_offer['RodzajZabudowy']).lower().count('pałac') > 0: rodzaj_zabudowy = 'dworek/pałac'
                elif str(picked_offer['RodzajZabudowy']).lower().count('gospodarstwo') > 0: rodzaj_zabudowy = 'Gospodarstwo'
                else: rodzaj_zabudowy = 'Wolnostojący'

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_otodom
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, liczba_pieter, liczba_pokoi, pow_dzialki, powierzchnia, rodzaj_zabudowy, 
                            zdjecia_string, 
                            promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                            mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, 
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, liczba_pieter, liczba_pokoi, pow_dzialki, powierzchnia, rodzaj_zabudowy, 
                        zdjecia_string, 
                        promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                        mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'mieszkanie': 
                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = '1'
                elif picked_offer['LiczbaPokoi'] > 10:liczba_pokoi = 'więcej niż 10'
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_otodom
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, liczba_pokoi, powierzchnia, zdjecia_string, 
                            promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                            mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, liczba_pokoi, powierzchnia, zdjecia_string,  
                        promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                        mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'dzialka': 
                if str(picked_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: typ_dzialki = 'budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolna') > 0: typ_dzialki = 'rolna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: typ_dzialki = 'rekreacyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('inwestycyjna') > 0: typ_dzialki = 'pod inwestycję'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: typ_dzialki = 'leśna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: typ_dzialki = 'siedliskowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: typ_dzialki = 'usługowa'
                else: typ_dzialki = 'inna'

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_otodom
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, powierzchnia, typ_dzialki, zdjecia_string, 
                            promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                            mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, powierzchnia, typ_dzialki, zdjecia_string, 
                        promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                        mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'lokal': 
                zapytanie_sql = '''
                        INSERT INTO ogloszenia_otodom
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, powierzchnia, zdjecia_string, 
                            promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                            mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, powierzchnia, zdjecia_string, 
                        promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                        mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'magazyn': 
                if str(picked_offer['TechBudowy']).lower().count('stalowa') > 0: konstrukcja = 'stalowa'
                elif str(picked_offer['TechBudowy']).lower().count('murowana') > 0: konstrukcja = 'murowana'
                elif str(picked_offer['TechBudowy']).lower().count('wiata') > 0: konstrukcja = 'wiata'
                elif str(picked_offer['TechBudowy']).lower().count('drewniana') > 0: konstrukcja = 'drewniana'
                elif str(picked_offer['TechBudowy']).lower().count('szklana') > 0: konstrukcja = 'szklana'
                else: konstrukcja = 'wybierz'

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_otodom
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, powierzchnia, konstrukcja, zdjecia_string, 
                            promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                            mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, powierzchnia, konstrukcja, zdjecia_string, 
                        promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                        mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Publikuj' and rodzaj_ogloszenia == 's': 
            if not region:
                msq.handle_error(f'UWAGA! Błąd wyboru regionu dla otodom przez {session["username"]}!', log_path=logFileName)
                flash('Wybierz region!', 'danger')
                return redirect(url_for(redirectGoal))

            picked_offer = {}            
            for offer in generator_sellOffert():
                if str(offer['ID']) == str(id_ogloszenia):
                    picked_offer = offer
            
            tytul_ogloszenia = picked_offer['Tytul']
            powierzchnia = picked_offer['Metraz']
            cena = picked_offer['Cena']
            rynek = picked_offer['Rynek']

            zdjecia_string = ''
            for foto_link in picked_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':
                if extra_descript:
                    prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_offer['RodzajZabudowy']}\n\n"
            
            if picked_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_offer['TechBudowy']}\n\n"
            if picked_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_offer['StanWykonczenia']}\n\n"
            if picked_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_offer['RokBudowy']} r.\n\n"
            if picked_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]
            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""

            if str(picked_offer['TypNieruchomosci']).lower().count('dom') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('willa') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('bliźniak') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('segment') > 0:
                # kategoria na adresowo dla dom
                kategoria_ogloszenia = 'dom'

            elif str(picked_offer['TypNieruchomosci']).lower().count('mieszkanie') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('kawalerka') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('apartament') > 0\
                        or str(picked_offer['TypNieruchomosci']).lower().count('blok') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('kamienica') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('loft') > 0:
                # kategoria na adresowo dla mieszkanie
                kategoria_ogloszenia = 'mieszkanie'
            
            elif str(picked_offer['TypNieruchomosci']).lower().count('działka') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('plac') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('teren') > 0:
                # kategoria na adresowo dla dzialka
                kategoria_ogloszenia = 'dzialka'

            elif str(picked_offer['TypNieruchomosci']).lower().count('biur') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('usługi') > 0\
                    or str(picked_offer['TypNieruchomosci']).lower().count('lokal') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('produkcja') > 0:
                # kategoria na adresowo dla lokal
                kategoria_ogloszenia = 'lokal'

            elif str(picked_offer['TypNieruchomosci']).lower().count('magazyn') > 0\
                or str(picked_offer['TypNieruchomosci']).lower().count('hal') > 0:
                # kategoria na adresowo dla magazyn
                kategoria_ogloszenia = 'magazyn'
            else:
                msq.handle_error(f'UWAGA! Nie rozpoznano typu nieruchomości, dane wysłane przez {session["username"]} są niejednoznaczne!', log_path=logFileName)
                flash('Nie rozpoznano typu nieruchomości, dane są niejednoznaczne!', 'danger')
                return redirect(url_for(redirectGoal))
            

            if kategoria_ogloszenia == 'dom':
                pow_dzialki = picked_offer['Metraz'] * 5

                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = '1'
                elif picked_offer['LiczbaPokoi'] > 10:liczba_pokoi = 'więcej niż 10'
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                rok_budowy = picked_offer['RokBudowy']

                if str(picked_offer['RodzajZabudowy']).lower().count('bliźniacza') > 0: rodzaj_zabudowy = 'Bliźniak'
                elif str(picked_offer['RodzajZabudowy']).lower().count('wolnostojąca') > 0: rodzaj_zabudowy = 'Wolnostojący'
                elif str(picked_offer['RodzajZabudowy']).lower().count('szeregowa') > 0: rodzaj_zabudowy = 'Szeregowiec'
                elif str(picked_offer['RodzajZabudowy']).lower().count('kamienica') > 0: rodzaj_zabudowy = 'Kamienica'
                elif str(picked_offer['RodzajZabudowy']).lower().count('dworek') > 0: rodzaj_zabudowy = 'dworek/pałac'
                elif str(picked_offer['RodzajZabudowy']).lower().count('pałac') > 0: rodzaj_zabudowy = 'dworek/pałac'
                elif str(picked_offer['RodzajZabudowy']).lower().count('gospodarstwo') > 0: rodzaj_zabudowy = 'Gospodarstwo'
                else: rodzaj_zabudowy = 'Wolnostojący'

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_otodom
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, liczba_pokoi, pow_dzialki, powierzchnia, rodzaj_zabudowy, 
                            zdjecia_string, rynek, rok_budowy, 
                            promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                            mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, 
                             %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, liczba_pokoi, pow_dzialki, powierzchnia, rodzaj_zabudowy, 
                        zdjecia_string, rynek, rok_budowy, 
                        promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                        mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'mieszkanie': 
                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = '1'
                elif picked_offer['LiczbaPokoi'] > 10:liczba_pokoi = 'więcej niż 10'
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_otodom
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, liczba_pokoi, powierzchnia, zdjecia_string, rynek,
                            promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                            mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, liczba_pokoi, powierzchnia, zdjecia_string, rynek,
                        promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                        mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'dzialka': 
                if str(picked_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: typ_dzialki = 'budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolna') > 0: typ_dzialki = 'rolna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: typ_dzialki = 'rekreacyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('inwestycyjna') > 0: typ_dzialki = 'pod inwestycję'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: typ_dzialki = 'leśna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: typ_dzialki = 'siedliskowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: typ_dzialki = 'usługowa'
                else: typ_dzialki = 'inna'

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_otodom
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, powierzchnia, typ_dzialki, zdjecia_string, 
                            promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                            mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, powierzchnia, typ_dzialki, zdjecia_string, 
                        promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                        mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'lokal': 
                zapytanie_sql = '''
                        INSERT INTO ogloszenia_otodom
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, powierzchnia, zdjecia_string, rynek,
                            promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                            mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, powierzchnia, zdjecia_string, rynek,
                        promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                        mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'magazyn': 
                if str(picked_offer['TechBudowy']).lower().count('stalowa') > 0: konstrukcja = 'stalowa'
                elif str(picked_offer['TechBudowy']).lower().count('murowana') > 0: konstrukcja = 'murowana'
                elif str(picked_offer['TechBudowy']).lower().count('wiata') > 0: konstrukcja = 'wiata'
                elif str(picked_offer['TechBudowy']).lower().count('drewniana') > 0: konstrukcja = 'drewniana'
                elif str(picked_offer['TechBudowy']).lower().count('szklana') > 0: konstrukcja = 'szklana'
                else: konstrukcja = 'wybierz'

                zapytanie_sql = '''
                        INSERT INTO ogloszenia_otodom
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, powierzchnia, konstrukcja, zdjecia_string, rynek,
                            promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                            mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s,
                             %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, powierzchnia, konstrukcja, zdjecia_string, rynek,
                        promo, auto_refresh, extra_top, extra_home, export_olx, extra_raise, 
                        mega_raise, pakiet_olx_mini, pakiet_olx_midi, pakiet_olx_maxi, pick_olx, auto_refresh_olx,
                        4)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana realizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Aktualizuj' and rodzaj_ogloszenia == 'r': 
            picked_offer = {}            
            for offer in generator_rentOffert():
                if str(offer['ID']) == str(id_ogloszenia):
                    picked_offer = offer
            
            tytul_ogloszenia = picked_offer['Tytul']
            powierzchnia = picked_offer['Metraz']
            cena = picked_offer['Cena']

            zdjecia_string = ''
            for foto_link in picked_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':
                if extra_descript:
                    prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_offer['RodzajZabudowy']}\n\n"
            if picked_offer['Czynsz'] != 0:
                extra_opis += f"Czynsz:\n{picked_offer['Czynsz']} zł.\n\n"
            if picked_offer['Umeblowanie'] != "":
                extra_opis += f"Umeblowanie:\n{picked_offer['Umeblowanie']}\n\n"
            if picked_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_offer['TechBudowy']}\n\n"
            if picked_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_offer['StanWykonczenia']}\n\n"
            if picked_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_offer['RokBudowy']} r.\n\n"
            if picked_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]
            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""

            kategoria_ogloszenia = checkOtodomStatus('r', id_ogloszenia)[6]

            if kategoria_ogloszenia == 'dom': 
                pow_dzialki = picked_offer['PowierzchniaDzialki']

                if picked_offer['LiczbaPieter'] == 0:liczba_pieter = 'parterowy'
                elif picked_offer['LiczbaPieter'] > 3:liczba_pieter = '3 pietra i więcej'
                else:liczba_pieter = f'{picked_offer["LiczbaPieter"]} piętr'

                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = '1'
                elif picked_offer['LiczbaPokoi'] > 10:liczba_pokoi = 'więcej niż 10'
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                if str(picked_offer['RodzajZabudowy']).lower().count('bliźniacza') > 0: rodzaj_zabudowy = 'Bliźniak'
                elif str(picked_offer['RodzajZabudowy']).lower().count('wolnostojąca') > 0: rodzaj_zabudowy = 'Wolnostojący'
                elif str(picked_offer['RodzajZabudowy']).lower().count('szeregowa') > 0: rodzaj_zabudowy = 'Szeregowiec'
                elif str(picked_offer['RodzajZabudowy']).lower().count('kamienica') > 0: rodzaj_zabudowy = 'Kamienica'
                elif str(picked_offer['RodzajZabudowy']).lower().count('dworek') > 0: rodzaj_zabudowy = 'dworek/pałac'
                elif str(picked_offer['RodzajZabudowy']).lower().count('pałac') > 0: rodzaj_zabudowy = 'dworek/pałac'
                elif str(picked_offer['RodzajZabudowy']).lower().count('gospodarstwo') > 0: rodzaj_zabudowy = 'Gospodarstwo'
                else: rodzaj_zabudowy = 'Wolnostojący'

                zapytanie_sql = '''
                        UPDATE ogloszenia_otodom
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            rodzaj_zabudowy = %s,
                            liczba_pieter = %s,
                            liczba_pokoi = %s,
                            region = %s,
                            zdjecia_string = %s, 
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, rodzaj_zabudowy, liczba_pieter, liczba_pokoi,
                        region, zdjecia_string,
                        5, 0,
                    otodom_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'mieszkanie': 
                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = '1'
                elif picked_offer['LiczbaPokoi'] > 10:liczba_pokoi = 'więcej niż 10'
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                zapytanie_sql = '''
                        UPDATE ogloszenia_otodom
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            rodzaj_zabudowy = %s,
                            liczba_pokoi = %s,
                            region = %s,
                            zdjecia_string = %s, 
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, rodzaj_zabudowy, liczba_pokoi,
                        region, zdjecia_string,
                        5, 0,
                    otodom_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'dzialka': 
                if str(picked_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: typ_dzialki = 'budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolna') > 0: typ_dzialki = 'rolna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: typ_dzialki = 'rekreacyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('inwestycyjna') > 0: typ_dzialki = 'pod inwestycję'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: typ_dzialki = 'leśna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: typ_dzialki = 'siedliskowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: typ_dzialki = 'usługowa'
                else: typ_dzialki = 'inna'

                zapytanie_sql = '''
                        UPDATE ogloszenia_otodom
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            typ_dzialki = %s,
                            region = %s,
                            zdjecia_string = %s, 
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, typ_dzialki, 
                        region, zdjecia_string,
                        5, 0,
                    otodom_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'lokal': 
                zapytanie_sql = '''
                        UPDATE ogloszenia_otodom
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            region = %s,
                            zdjecia_string = %s, 
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, 
                        region, zdjecia_string,
                        5, 0,
                    otodom_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'magazyn': 
                if str(picked_offer['TechBudowy']).lower().count('stalowa') > 0: konstrukcja = 'stalowa'
                elif str(picked_offer['TechBudowy']).lower().count('murowana') > 0: konstrukcja = 'murowana'
                elif str(picked_offer['TechBudowy']).lower().count('wiata') > 0: konstrukcja = 'wiata'
                elif str(picked_offer['TechBudowy']).lower().count('drewniana') > 0: konstrukcja = 'drewniana'
                elif str(picked_offer['TechBudowy']).lower().count('szklana') > 0: konstrukcja = 'szklana'
                else: konstrukcja = 'wybierz'

                zapytanie_sql = '''
                        UPDATE ogloszenia_otodom
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            konstrukcja = %s,
                            region = %s,
                            zdjecia_string = %s, 
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, konstrukcja, 
                        region, zdjecia_string,
                        5, 0,
                    otodom_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Aktualizuj' and rodzaj_ogloszenia == 's': 
            picked_offer = {}            
            for offer in generator_sellOffert():
                if str(offer['ID']) == str(id_ogloszenia):
                    picked_offer = offer
            
            tytul_ogloszenia = picked_offer['Tytul']
            powierzchnia = picked_offer['Metraz']
            cena = picked_offer['Cena']
            rynek = picked_offer['Rynek']

            zdjecia_string = ''
            for foto_link in picked_offer['Zdjecia']:
                zdjecia_string += f'{foto_link}-@-'
            if zdjecia_string != '':zdjecia_string = zdjecia_string[:-3]

            prepared_opis = ''
            for item in picked_offer['Opis']:
                for val in item.values():
                    if isinstance(val, str):
                        prepared_opis += f'{val}\n'
                    if isinstance(val, list):
                        for v_val in val:
                            prepared_opis += f'{v_val}\n'
            if prepared_opis != '':
                if extra_descript:
                    prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
            else: prepared_opis = picked_offer['InformacjeDodatkowe']

            extra_opis = ''
            if picked_offer['RodzajZabudowy'] != '':
                extra_opis += f"Rodzaj Zabudowy:\n{picked_offer['RodzajZabudowy']}\n\n"
            
            if picked_offer['TechBudowy'] != "":
                extra_opis += f"Technologia Budowy:\n{picked_offer['TechBudowy']}\n\n"
            if picked_offer['StanWykonczenia'] != "":
                extra_opis += f"Stan Wykończenia:\n{picked_offer['StanWykonczenia']}\n\n"
            if picked_offer['RokBudowy'] != 0:
                extra_opis += f"Rok Budowy:\n{picked_offer['RokBudowy']} r.\n\n"
            if picked_offer['NumerKW'] != "":
                extra_opis += f"Numer KW:\n{picked_offer['NumerKW']}\n\n"
            extra_opis = extra_opis[:-2]
            if extra_descript:
                opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            else:
                opis_ogloszenia = f"""{prepared_opis}"""

            kategoria_ogloszenia = checkOtodomStatus('s', id_ogloszenia)[6]

            if kategoria_ogloszenia == 'dom': 
                pow_dzialki = picked_offer['Metraz'] * 5

                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = '1'
                elif picked_offer['LiczbaPokoi'] > 10:liczba_pokoi = 'więcej niż 10'
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                rok_budowy = picked_offer['RokBudowy']

                if str(picked_offer['RodzajZabudowy']).lower().count('bliźniacza') > 0: rodzaj_zabudowy = 'Bliźniak'
                elif str(picked_offer['RodzajZabudowy']).lower().count('wolnostojąca') > 0: rodzaj_zabudowy = 'Wolnostojący'
                elif str(picked_offer['RodzajZabudowy']).lower().count('szeregowa') > 0: rodzaj_zabudowy = 'Szeregowiec'
                elif str(picked_offer['RodzajZabudowy']).lower().count('kamienica') > 0: rodzaj_zabudowy = 'Kamienica'
                elif str(picked_offer['RodzajZabudowy']).lower().count('dworek') > 0: rodzaj_zabudowy = 'dworek/pałac'
                elif str(picked_offer['RodzajZabudowy']).lower().count('pałac') > 0: rodzaj_zabudowy = 'dworek/pałac'
                elif str(picked_offer['RodzajZabudowy']).lower().count('gospodarstwo') > 0: rodzaj_zabudowy = 'Gospodarstwo'
                else: rodzaj_zabudowy = 'Wolnostojący'

                zapytanie_sql = '''
                        UPDATE ogloszenia_otodom
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            pow_dzialki = %s,
                            rok_budowy = %s,
                            rynek = %s,
                            rodzaj_zabudowy = %s,
                            region = %s,
                            zdjecia_string = %s, 
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, pow_dzialki, rok_budowy, rynek, rodzaj_zabudowy,
                        region, zdjecia_string,
                        5, 0,
                    otodom_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'mieszkanie': 
                if picked_offer['LiczbaPokoi'] == 0:liczba_pokoi = '1'
                elif picked_offer['LiczbaPokoi'] > 10:liczba_pokoi = 'więcej niż 10'
                else:liczba_pokoi = picked_offer['LiczbaPokoi']

                zapytanie_sql = '''
                        UPDATE ogloszenia_otodom
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            liczba_pokoi = %s,
                            rynek = %s,
                            region = %s,
                            zdjecia_string = %s, 
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, liczba_pokoi, rynek,
                        region, zdjecia_string,
                        5, 0,
                    otodom_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'dzialka': 
                if str(picked_offer['InformacjeDodatkowe']).lower().count('budowlana') > 0: typ_dzialki = 'budowlana'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rolna') > 0: typ_dzialki = 'rolna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('rekreacyjna') > 0: typ_dzialki = 'rekreacyjna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('inwestycyjna') > 0: typ_dzialki = 'pod inwestycję'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('leśna') > 0: typ_dzialki = 'leśna'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('siedliskowa') > 0: typ_dzialki = 'siedliskowa'
                elif str(picked_offer['InformacjeDodatkowe']).lower().count('usługowa') > 0: typ_dzialki = 'usługowa'
                else: typ_dzialki = 'inna'

                zapytanie_sql = '''
                        UPDATE ogloszenia_otodom
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            typ_dzialki = %s,
                            region = %s,
                            zdjecia_string = %s, 
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, typ_dzialki,
                        region, zdjecia_string,
                        5, 0,
                    otodom_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'lokal': 
                zapytanie_sql = '''
                        UPDATE ogloszenia_otodom
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            rynek = %s,
                            region = %s,
                            zdjecia_string = %s, 
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, rynek,
                        region, zdjecia_string,
                        5, 0,
                    otodom_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

            if kategoria_ogloszenia == 'magazyn': 
                if str(picked_offer['TechBudowy']).lower().count('stalowa') > 0: konstrukcja = 'stalowa'
                elif str(picked_offer['TechBudowy']).lower().count('murowana') > 0: konstrukcja = 'murowana'
                elif str(picked_offer['TechBudowy']).lower().count('wiata') > 0: konstrukcja = 'wiata'
                elif str(picked_offer['TechBudowy']).lower().count('drewniana') > 0: konstrukcja = 'drewniana'
                elif str(picked_offer['TechBudowy']).lower().count('szklana') > 0: konstrukcja = 'szklana'
                else: konstrukcja = 'wybierz'

                zapytanie_sql = '''
                        UPDATE ogloszenia_otodom
                        SET 
                            tytul_ogloszenia = %s,
                            cena = %s,
                            opis_ogloszenia = %s,
                            powierzchnia = %s,
                            rynek = %s,
                            konstrukcja = %s,
                            region = %s,
                            zdjecia_string = %s, 
                            status = %s,
                            active_task=%s
                        WHERE id = %s;
                    '''
                dane = (tytul_ogloszenia, cena, opis_ogloszenia,
                        powierzchnia, rynek, konstrukcja,
                        region, zdjecia_string,
                        5, 0,
                    otodom_id)

                if msq.insert_to_database(zapytanie_sql, dane):
                    msq.handle_error(f'Oferta została pomyślnie wysłana do aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana aktualizacji na otodom przez {session["username"]}!', log_path=logFileName)
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Usun': 
            zapytanie_sql = '''
                UPDATE ogloszenia_otodom
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, 6, otodom_id)
            
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie wysłana do usunięcia na otodom przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do usunięcia na otodom przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Ponow_zadanie': 
            oldStatus = takeOtodomResumeStatus(otodom_id)
            zapytanie_sql = '''
                UPDATE ogloszenia_otodom
                    SET 
                        active_task=%s,
                        status=%s
                    WHERE id = %s;
                '''
            dane = (0, oldStatus, otodom_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Oferta została pomyślnie wysłana do ponowienia na otodom przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Oferta nie została wysłana do ponowienia na otodom przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Anuluj_zadanie': 
            oldStatus = takeOtodomResumeStatus(otodom_id)
            if oldStatus == 4:
                zapytanie_sql = '''
                    DELETE FROM ogloszenia_otodom
                        
                    WHERE id = %s;
                    '''
                dane = (otodom_id,)
            
            if oldStatus == 5 or oldStatus == 6 or oldStatus == 7:
                zapytanie_sql = '''
                    UPDATE ogloszenia_otodom
                        SET 
                            active_task=%s,
                            status=%s
                        WHERE id = %s;
                    '''
                dane = (0, 1, otodom_id)


            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Zadanie zostało anulowane przez {session["username"]}!', log_path=logFileName)
                flash(f'Zadanie zostało anulowane!', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Zadanie nie zostało anulowane przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Zadanie nie zostało anulowane!', 'danger')

        if task_kind == 'Odswiez': 
            flash(f'Oferta została odświeżona pomyślnie!', 'success')

        if task_kind == 'Ponow': 
            zapytanie_sql = '''
                UPDATE ogloszenia_otodom
                    SET 
                        active_task=%s
                    WHERE id = %s;
                '''
            dane = (0, otodom_id)
            
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Ponowiono zadanie dla otodom przez {session["username"]}!', log_path=logFileName)
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                msq.handle_error(f'UWAGA! Nie ponowiono zadania dla otodom przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        return redirect(url_for(redirectGoal))
    return redirect(url_for('index')) 

@app.route("/publikuj-na-socialsync", methods=['POST'])
def public_on_socialsync():
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /public-on-socialsync bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))

    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /public-on-socialsync bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj się z administratorem!', 'danger')
        return redirect(url_for('index'))

    # Pobranie danych z formularza
    socialSync_id = request.form.get('socialSync_id')
    id_ogloszenia = request.form.get('PostID')
    task_kind = request.form.get('task_kind')
    generuj_opis = request.form.get('generuj_opis') == "1"  # Konwersja na bool
    uzyj_aktualnego_opisu = request.form.get('uzyj_aktualnego_opisu') == "1"  # Konwersja na bool
    redirectGoal = request.form.get('redirectGoal')

    # Pobranie polecenia dla AI (jeśli generowanie opisu jest zaznaczone)
    polecenie_ai = request.form.get('polecenie_ai', "").strip() if generuj_opis else None

    # Ustalenie rodzaju ogłoszenia
    rodzaj_ogloszenia = 'r' if redirectGoal == 'estateAdsRent' else 's' if redirectGoal == 'estateAdsSell' else None

    if task_kind == 'Publikuj' and rodzaj_ogloszenia:
        # Pobranie oferty
        picked_offer = get_offer(id_ogloszenia, rodzaj_ogloszenia)

        if not picked_offer:
            flash('Nie znaleziono ogłoszenia!', 'danger')
            return redirect(url_for(redirectGoal))

        # Generowanie opisu ogłoszenia
        if uzyj_aktualnego_opisu:
            generator = False
        else:
            generator = True
        opis_ogloszenia, zdjecia_string, kategoria_ogloszenia = generate_offer_description(picked_offer, rodzaj_ogloszenia, generator)
        status = 4
        if uzyj_aktualnego_opisu:
            styl_ogloszenia = 0
            
            polecenie_ai = None  # Nie generujemy opisu, więc polecenie nie jest potrzebne
        elif generuj_opis:
            styl_ogloszenia = 1
            
            polecenie_ai = polecenie_ai.strip() if polecenie_ai else None  # Pobieramy polecenie tylko jeśli zostało wpisane
            mgr = MistralChatManager(MISTRAL_API_KEY)
            sys_prompt = (
                "Jesteś copywriterem sprzedażowym social media dla ofert nieruchomości.\n"
                "Twoim JEDYNYM zadaniem jest napisanie gotowego posta sprzedażowego.\n\n"

                "ZAKAZANE (BEZWZGLĘDNIE):\n"
                "- NIE analizujesz treści.\n"
                "- NIE oceniasz ogłoszenia.\n"
                "- NIE wypisujesz sugestii, rekomendacji ani list porad.\n"
                "- NIE informujesz, że czegoś brakuje w danych.\n"
                "- NIE tworzysz sekcji typu: analiza, propozycje, działania marketingowe.\n\n"

                "DOZWOLONE I WYMAGANE:\n"
                "- Zwracasz WYŁĄCZNIE gotową treść posta na social media.\n"
                "- Styl: sprzedażowy, emocjonalny, konkretny.\n"
                "- Używasz emotek/ikonek.\n"
                "- ZERO markdown (brak #, **, list markdown, nagłówków technicznych).\n"
                "- Krótkie zdania, dobra czytelność.\n\n"

                "ZASADA FAKTÓW (KRYTYCZNA):\n"
                "- Korzystasz WYŁĄCZNIE z informacji zawartych w danych źródłowych.\n"
                "- NIE zmieniasz i NIE dopisujesz: ceny, lokalizacji, metrażu, terminów, parametrów.\n"
                "- Jeśli jakaś informacja NIE występuje w danych źródłowych: pomijasz ją bez komentarza.\n\n"

                "ELEMENTY OBOWIĄZKOWE POSTA:\n"
                "- Cena (jeśli występuje w danych źródłowych).\n"
                "- Lokalizacja (jeśli występuje w danych źródłowych).\n"
                "- Informacja kontaktowa lub wyraźne CTA do kontaktu (jeśli występuje w danych źródłowych).\n\n"

                "STRUKTURA POSTA:\n"
                "1) Mocne otwarcie (emocje, wizja, 1–2 linie)\n"
                "2) Konkretne atuty oferty w punktach (myślniki + emotki)\n"
                "3) Krótka wizja życia / użytkowania\n"
                "4) Cena, lokalizacja i kontakt – JEŚLI SĄ W DANYCH\n"
                "5) CTA – zachęta do kontaktu\n\n"

                "Odpowiadasz WYŁĄCZNIE treścią posta. Nic więcej."
            )


            content = (
                "DANE ŹRÓDŁOWE (NIE ZMIENIAJ FAKTÓW):\n"
                f"{opis_ogloszenia}\n\n"
                "KONTEKST OFERTY:\n"
                f"- Kategoria: {kategoria_ogloszenia}\n"
                f"- Rodzaj oferty: {rodzaj_ogloszenia}\n"
                f"- Styl: {styl_ogloszenia}\n\n"
                "ZADANIE:\n"
                "- Napisz GOTOWY POST SPRZEDAŻOWY na social media.\n"
                "- Zawsze uwzględnij cenę, lokalizację i kontakt, JEŚLI występują w danych źródłowych.\n"
                "- Jeśli którejś z tych informacji nie ma: pomiń ją bez komentarza.\n"
                "- Nie analizuj, nie oceniaj, nie sugeruj zmian.\n"
                "- Używaj emotek, bez markdown.\n"
                "- Tekst ma zachęcać do zakupu i kontaktu.\n"


                "WYTYCZNE ADMINISTRATORA (jeśli są):\n"
                f"{polecenie_ai or 'brak'}"
            )

            hist = [
                {"role": "user", "content": content}
            ]

            answering = mgr.continue_conversation_with_system(hist, sys_prompt, max_tokens=800)
            if answering and len(str(answering).strip()) > 30:
                opis_ogloszenia = answering
            else:
                status = 7 # → PENDING_AI_OLLAMA / TRYB_AWARYJNY
                flash("Post generuje się w tle (tryb awaryjny).", "warning")

        else:
            styl_ogloszenia = 0
            polecenie_ai = None  # Domyślnie brak polecenia

        # Wstawienie rekordu do bazy danych
        zapytanie_sql = '''
            INSERT INTO ogloszenia_socialsync
                (rodzaj_ogloszenia, id_ogloszenia, kategoria_ogloszenia, tresc_ogloszenia,
                styl_ogloszenia, polecenie_ai, zdjecia_string, status, created_by)
            VALUES 
                (%s, %s, %s, %s, %s, %s, %s, %s, %s);
        '''
        dane = (rodzaj_ogloszenia, id_ogloszenia, kategoria_ogloszenia, opis_ogloszenia, 
                styl_ogloszenia, polecenie_ai, zdjecia_string, status, 'dmdinwestycje')

        if msq.insert_to_database(zapytanie_sql, dane):
            msq.handle_error(f'Oferta została pomyślnie wysłana do realizacji na profilu FB przez {session["username"]}!', log_path=logFileName)
            flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
        else:
            msq.handle_error(f'UWAGA! Błąd zapisu! Oferta nie została wysłana do realizacji na profilu FB przez {session["username"]}!', log_path=logFileName)
            flash('Błąd zapisu! Oferta nie została wysłana do realizacji!', 'danger')

    elif task_kind == 'Anuluj_zadanie':
        zapytanie_sql = "DELETE FROM ogloszenia_socialsync WHERE id = %s;"
        dane = (socialSync_id,)
    
        if msq.insert_to_database(zapytanie_sql, dane):
            msq.handle_error(f'Zadanie zostało anulowane przez {session["username"]}!', log_path=logFileName)
            flash('Zadanie zostało anulowane!', 'success')
        else:
            msq.handle_error(f'UWAGA! Błąd zapisu! Zadanie nie zostało anulowane przez {session["username"]}!', log_path=logFileName)
            flash('Błąd zapisu! Zadanie nie zostało anulowane!', 'danger')


    elif task_kind == 'Odswiez':
        flash('Oferta została odświeżona pomyślnie!', 'success')

    elif task_kind == 'Ponow':
        zapytanie_sql = '''
            UPDATE ogloszenia_socialsync
                SET active_task=%s
                WHERE id = %s;
        '''
        dane = (0, socialSync_id)

        if msq.insert_to_database(zapytanie_sql, dane):
            msq.handle_error(f'Ponowiono zadanie dla FB przez {session["username"]}!', log_path=logFileName)
            flash('Oferta została ponownie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
        else:
            msq.handle_error(f'UWAGA! Nie ponowiono zadania dla FB przez {session["username"]}!', log_path=logFileName)
            flash('Błąd zapisu! Oferta nie została ponownie wysłana do realizacji!', 'danger')

    return redirect(url_for(redirectGoal))

@app.route('/estate-ads-special')
def estateAdsspecial():
    """Strona zawierająca listę z ogłoszeniami nieruchomości."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /estate-ads-special bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /estate-ads-special bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Wczytanie listy wszystkich postów z bazy danych i przypisanie jej do zmiennej posts
    all_spec = generator_specialOffert(status='aktywna') + generator_specialOffert(status='nieaktywna') # status='aktywna', 'nieaktywna', 'wszystkie'

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(all_spec)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    ads_spec = all_spec[offset: offset + per_page]

    return render_template(
            "estate_management_special.html",
            ads_spec=ads_spec,
            userperm=session['userperm'],
            username=session['username'],
            pagination=pagination
            )

@app.route("/estate-development")
def estate_development():
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /estate-development bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))

    if session['userperm']['estate'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /estate-development bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj się z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    lokale = generator_wisniowa_lokale()

    return render_template(
            "estate_development.html",
            userperm=session['userperm'],
            username=session['username'],
            lokale=lokale
            )

@app.route('/zarezerwuj-lokal', methods=['POST'])
def zarezerwuj_lokal():
    try:
        imie_nazwisko = request.form.get('imie_nazwisko_rezerwujacego')
        adres = request.form.get('adres_rezerwujacego')
        telefon = request.form.get('nr_telefonu_rezerwujacego')
        email = request.form.get('email_rezerwujacego')
        data_rezerwacji = request.form.get('data_rezerwacji')
        nr_umowy = request.form.get('nr_umowy_rezerwacyjnej')
        data_wplaty = request.form.get('data_wplaty_zadatku')
        status_platnosci = request.form.get('status_platnosci')
        post_id = request.form.get('post_id')  # zakładam, że id_lokalu to właśnie post_id (można zmienić nazwę)

        kto_aktualizowal = session['user_data']['name']  # lub np. session["user"] jeśli masz logowanie
        data_aktualizacji = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        db = get_db()
        query = """
            UPDATE Lokale_wisniowa SET 
                status_lokalu='rezerwacja',
                imie_nazwisko_rezerwujacego=%s,
                adres_rezerwujacego=%s,
                nr_telefonu_rezerwujacego=%s,
                email_rezerwujacego=%s,
                data_rezerwacji=%s,
                nr_umowy_rezerwacyjnej=%s,
                data_wplaty_zadatku=%s,
                status_platnosci=%s,
                kto_aktualizowal=%s,
                data_aktualizacji=%s
            WHERE id = %s
        """

        params = (
            imie_nazwisko,
            adres,
            telefon,
            email,
            data_rezerwacji,
            nr_umowy,
            data_wplaty,
            status_platnosci,
            kto_aktualizowal,
            data_aktualizacji,
            post_id
        )

        success = db.executeTo(query, params)

        if success:
            return jsonify({"message": "Formularz został pomyślnie przesłany!"})
        else:
            return jsonify({"message": "Nie udało się zaktualizować danych."}), 500

    except Exception as e:
        return jsonify({"message": f"Wystąpił błąd: {str(e)}"}), 500

@app.route('/status-platnosci', methods=['POST'])
def zmien_status_platnosci():
    try:
        data_wplaty = request.form.get('data_wplaty_zadatku')
        status = request.form.get('status_platnosci')
        post_id = request.form.get('post_id')

        kto_aktualizowal = session['user_data']['name']  # Możesz tu użyć session["user"] jeśli masz logowanie
        data_aktualizacji = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        db = get_db()
        query = """
            UPDATE Lokale_wisniowa SET 
                data_wplaty_zadatku=%s,
                status_platnosci=%s,
                kto_aktualizowal=%s,
                data_aktualizacji=%s
            WHERE id = %s
        """

        params = (
            data_wplaty,
            status,
            kto_aktualizowal,
            data_aktualizacji,
            post_id
        )

        success = db.executeTo(query, params)

        if success:
            return jsonify({"message": "Status płatności został zaktualizowany."})
        else:
            return jsonify({"message": "Nie udało się zaktualizować statusu."}), 500

    except Exception as e:
        return jsonify({"message": f"Błąd: {str(e)}"}), 500

@app.route('/anuluj-rezerwacje', methods=['POST'])
def anuluj_rezerwacje():
    try:
        post_id = request.form.get('post_id')
        powod = request.form.get('powod_anulowania')

        kto_aktualizowal = session['user_data']['name']  # lub np. session["user"]
        data_aktualizacji = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        db = get_db()
        query = """
            UPDATE Lokale_wisniowa SET
                status_lokalu='dostepny',
                imie_nazwisko_rezerwujacego=NULL,
                adres_rezerwujacego=NULL,
                nr_telefonu_rezerwujacego=NULL,
                email_rezerwujacego=NULL,
                data_rezerwacji=NULL,
                nr_umowy_rezerwacyjnej=NULL,
                data_wplaty_zadatku=NULL,
                status_platnosci='oczekuje',
                powod_wycofania=%s,
                kto_aktualizowal=%s,
                data_aktualizacji=%s
            WHERE id = %s
        """

        params = (
            powod,
            kto_aktualizowal,
            data_aktualizacji,
            post_id
        )

        success = db.executeTo(query, params)

        if success:
            return jsonify({"message": f"Rezerwacja została anulowana (ID: {post_id})."})
        else:
            return jsonify({"message": "Nie udało się anulować rezerwacji."}), 500

    except Exception as e:
        return jsonify({"message": f"Błąd: {str(e)}"}), 500

@app.route('/wymow-sprzedaz', methods=['POST'])
def wymow_sprzedaz():
    try:
        post_id = request.form.get('post_id')
        powod = request.form.get('powod_wymowienia')

        kto_aktualizowal = session['user_data']['name']  # lub session["user"]
        data_aktualizacji = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        db = get_db()
        query = """
            UPDATE Lokale_wisniowa SET
                status_lokalu='dostepny',
                imie_nazwisko_nowego_wlasciciela=NULL,
                adres_nowego_wlasciciela=NULL,
                nr_telefonu_nowego_wlasciciela=NULL,
                email_nowego_wlasciciela=NULL,
                data_sprzedazy=NULL,
                nr_umowy_sprzedazy=NULL,
                data_podpisania_umowy=NULL,
                notariusz=NULL,
                cena_po_negocjacji=NULL,
                cena_sprzedazy=NULL,
                forma_platnosci=NULL,
                powod_wycofania=%s,
                kto_aktualizowal=%s,
                data_aktualizacji=%s
            WHERE id = %s
        """

        params = (
            powod,
            kto_aktualizowal,
            data_aktualizacji,
            post_id
        )

        success = db.executeTo(query, params)

        if success:
            return jsonify({"message": f"Sprzedaż lokalu została wymówiona (ID: {post_id})."})
        else:
            return jsonify({"message": "Nie udało się wymówić sprzedaży."}), 500

    except Exception as e:
        return jsonify({"message": f"Błąd: {str(e)}"}), 500

@app.route('/sprzedaj-lokal', methods=['POST'])
def sprzedaj_lokal():
    try:
        dane = {
            "imie_nazwisko": request.form.get('imie_nazwisko_nowego_wlasciciela'),
            "adres": request.form.get('adres_nowego_wlasciciela'),
            "telefon": request.form.get('nr_telefonu_nowego_wlasciciela'),
            "email": request.form.get('email_nowego_wlasciciela'),
            "data_sprzedazy": request.form.get('data_sprzedazy'),
            "nr_umowy": request.form.get('nr_umowy_sprzedazy'),
            "data_podpisania": request.form.get('data_podpisania_umowy'),
            "notariusz": request.form.get('notariusz'),
            "cena_po_negocjacji": request.form.get('cena_po_negocjacji'),
            "cena_sprzedazy": request.form.get('cena_sprzedazy'),
            "forma_platnosci": request.form.get('forma_platnosci'),
        }

        post_id = request.form.get("post_id")
        kto_aktualizowal = session['user_data']['name']
        data_aktualizacji = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        db = get_db()
        query = """
            UPDATE Lokale_wisniowa SET
                status_lokalu='sprzedane',
                imie_nazwisko_nowego_wlasciciela=%s,
                adres_nowego_wlasciciela=%s,
                nr_telefonu_nowego_wlasciciela=%s,
                email_nowego_wlasciciela=%s,
                data_sprzedazy=%s,
                nr_umowy_sprzedazy=%s,
                data_podpisania_umowy=%s,
                notariusz=%s,
                cena_po_negocjacji=%s,
                cena_sprzedazy=%s,
                forma_platnosci=%s,
                kto_aktualizowal=%s,
                data_aktualizacji=%s
            WHERE id = %s
        """

        params = (
            dane["imie_nazwisko"],
            dane["adres"],
            dane["telefon"],
            dane["email"],
            dane["data_sprzedazy"],
            dane["nr_umowy"],
            dane["data_podpisania"],
            dane["notariusz"],
            dane["cena_po_negocjacji"],
            dane["cena_sprzedazy"],
            dane["forma_platnosci"],
            kto_aktualizowal,
            data_aktualizacji,
            post_id
        )

        success = db.executeTo(query, params)

        if success:
            return jsonify({"message": f"Lokal (ID: {post_id}) został oznaczony jako sprzedany."})
        else:
            return jsonify({"message": "Nie udało się oznaczyć lokalu jako sprzedanego."}), 500

    except Exception as e:
        return jsonify({"message": f"Błąd: {str(e)}"}), 500

@app.route('/lokale-wisniowa-messages-control', methods=['POST'])
def messages_control():
    try:
        data = request.get_json()
        action = data.get('action')
        post_id = data.get('post_id')
        message_id = data.get('message_id')
        status = data.get('status', None)

        db = get_db()

        if action == 'change_status':
            if not status:
                return jsonify({"success": False, "message": "Brak statusu do ustawienia"}), 400

            query = "UPDATE Messages_wisniowa SET status_wiadomosci = %s WHERE id = %s"
            db.executeTo(query, (status, message_id))
            print(f"[STATUS] Zmieniono status wiadomości {message_id} na '{status}'")

            return jsonify({"success": True, "message": "Status zmieniony"})

        elif action == 'remove':
            # Możesz zamiast DELETE zrobić UPDATE z oznaczeniem 'usunieta', jeśli chcesz zachować historię
            query = "DELETE FROM Messages_wisniowa WHERE id = %s LIMIT 1"
            db.executeTo(query, (message_id,))
            print(f"[USUNIĘCIE] Wiadomość {message_id} została oznaczona jako usunięta")

            return jsonify({"success": True, "message": "Wiadomość usunięta"})

        return jsonify({"success": False, "message": "Nieznana akcja"}), 400

    except Exception as e:
        return jsonify({"success": False, "message": f"Błąd: {str(e)}"}), 500

@app.route('/subscriber')
def subscribers(router=True):
    """Strona zawierająca listę subskrybentów Newslettera."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /subscriber bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['subscribers'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /subscriber bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    subscribers_all = generator_subsDataDB()

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(subscribers_all)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    subs = subscribers_all[offset: offset + per_page]
    
    if router:
        
        return render_template(
                "subscriber_management.html", 
                subs=subs, 
                username=session['username'], 
                userperm=session['userperm'], 
                pagination=pagination
                )
    else:
        return subs, session['username'], pagination

@app.route('/restart', methods=['POST'])
def restart():
    try:
        if restart_pm2_tasks_signal(logFileName):
            zapytanie_sql = f'''
                    UPDATE admin_settings 
                    SET 
                        last_restart = %s
                    WHERE ID = %s;'''
            dane = (datetime.datetime.now(), 1)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Aplikacja została zrestartowana przez {session["username"]}', log_path=logFileName)
                flash("Aplikacja została zrestartowana", 'success')
                addDataLogs(f"Aplikacja została zrestartowana", 'success')
                return jsonify({"message": "Aplikacja została zrestartowana"}), 200
            else:
                msq.handle_error(f'UWAGA! Błąd podczas restartu aplikacji przez {session["username"]}!', log_path=logFileName)
                flash("Błąd podczas restartu aplikacji!", 'danger')
                addDataLogs("Błąd podczas restartu aplikacji!", 'danger')
                return jsonify({"message": f"Błąd podczas restartu aplikacji!"}), 500
        else:
            flash("Błąd podczas restartu aplikacji!", 'danger')
            return jsonify({"message": f"Błąd podczas restartu aplikacji!"}), 500
    except Exception as e:
        msq.handle_error(f'UWAGA! Błąd podczas restartu aplikacji: {e}', log_path=logFileName)
        flash(f"Błąd podczas restartu aplikacji: {e}", 'danger')
        return jsonify({"message": f"Błąd podczas restartu aplikacji: {e}"}), 500

@app.route('/setting')
def settings():
    """Strona z ustawieniami."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /setting bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['settings'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /setting bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    settingsDB = generator_settingsDB()
    onPages = settingsDB['pagination']
    domain = settingsDB['main-domain']
    blog = settingsDB['blog-pic-path']
    avatar = settingsDB['avatar-pic-path']
    real_loc_on_server = settingsDB['real-location-on-server']
    estate_pic_path = settingsDB['estate-pic-offer']
    etate_logo_png = settingsDB['main-domain']+estate_pic_path+'logo.png'
    presentations_path = settingsDB['presentation-files']
    
    restart = settingsDB['last-restart']
    
    smtpAdmin = settingsDB['smtp_admin']

    # last_logs = get_last_logs('logs/errors.log', 10250)

    return render_template(
            "setting_management.html", 
            username=session['username'],
            userperm=session['userperm'], 
            onPages=onPages, 
            domain=domain,
            blog=blog,
            avatar=avatar,
            real_loc_on_server=real_loc_on_server,
            estate_pic_path=estate_pic_path,
            presentations_path=presentations_path,
            restart=restart,
            smtpAdmin=smtpAdmin,
            etate_logo_png=etate_logo_png,
            # last_logs=last_logs
            )

@app.route('/fetch-logs')
def fetch_logs():
    """Strona z ustawieniami."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /fetch-logs bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['settings'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /fetch-logs bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    last_logs = get_last_logs('logs/errors.log', 10250)
    return jsonify(last_logs)

@app.route('/fetch-noisy-system')
def fetch_noisy_system():
    db = get_db()

    # 1. Logi z ostatnich 2h
    query_recent = """
        SELECT module, message, status, update_date
        FROM noisy_system
        WHERE update_date >= NOW() - INTERVAL 2 HOUR
        ORDER BY update_date DESC
        LIMIT 4;
    """
    recent_logs = db.getFrom(query_recent, as_dict=True)

    if recent_logs:
        # Formatowanie klasyczne
        formatted_logs = [
            f"{log['update_date']} {log['status']} {log['module']} {log['message']}"
            for log in recent_logs
        ]
        return jsonify(formatted_logs)

    # 2. Brak logów → szukamy ostatniego wpisu w ogóle
    query_last = """
        SELECT module, message, status, update_date
        FROM noisy_system
        ORDER BY update_date DESC
        LIMIT 1;
    """
    last_log = db.getFrom(query_last, as_dict=True)

    if last_log:
        log = last_log[0]
        last_line = f"{log['update_date']} {log['status']} {log['module']} {log['message']}"
    else:
        last_line = "Brak danych w bazie"

    # 3. Generujemy log systemowy
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    synthetic_log = [
        f"{now} INFO SYSTEM",
        f"Oczekiwanie na aktywność automatu...",
        f"Ostatni wpis w systemie:",
        f"{last_line}"
    ]

    return jsonify(synthetic_log)


@app.route('/fb-groups')
def fbGroups():
    """Zarządzanie grupami FB"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /fb-groups bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['settings'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /fb-groups bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    all_groups = generator_facebookGroups()

    sort_by = request.args.get('sort', 'id')  # Domyślnie sortowanie po nazwie
    sort_type = request.args.get('type', 'up')  # Domyślnie sortowanie rosnące
    
    if sort_by == 'name':
        items_sorted = sorted(all_groups, key=lambda x: x['name'], reverse=(sort_type == 'down'))
    elif sort_by == 'category':
        items_sorted = sorted(all_groups, key=lambda x: x['category'], reverse=(sort_type == 'down'))
    elif sort_by == 'id':
        items_sorted = sorted(all_groups, key=lambda x: x['id'], reverse=(sort_type == 'down'))
    elif sort_by == 'created_by':
        items_sorted = sorted(all_groups, key=lambda x: x['created_by'], reverse=(sort_type == 'down'))

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(items_sorted)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    groups = items_sorted[offset: offset + per_page]

    return render_template(
            "fb-groups_management.html", 
            username=session['username'],
            userperm=session['userperm'], 
            groups=groups,
            pagination=pagination,
            sort_by=sort_by, 
            sort_type=sort_type
            )

@app.route('/add-fb-group', methods=["POST"])
def add_fb_group():
    """Usuwanie ofertę najmu"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /add-fb-group bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['settings'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /add-fb-group bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()
        try: form_data['PostID']
        except KeyError: return redirect(url_for('index'))
        set_post_id = int(form_data['PostID'])

        if not form_data['name'] or form_data['name'] == '':
            flash("Musisz podać nazwę grupy!", "danger")
            return redirect(url_for('fbGroups'))
        else:
            name = form_data['name']

        if not form_data['kategoria'] or form_data['kategoria'] == '':
            flash("Musisz wybrać kategorię grupy!", "danger")
            return redirect(url_for('fbGroups'))
        else:
            category = form_data['kategoria']

        if not form_data['link'] or form_data['link'] == '':
            flash("Podaj LINK! Link jest niezbedny do prawidłowego wykorzystywania grup w modułach!", "danger")
            return redirect(url_for('fbGroups'))
        
        if not form_data['link'].startswith('https://www.facebook.com/groups/'):
            flash("Możliwy jest tylko link do grup Facebooka", "danger")
            return redirect(url_for('fbGroups'))
        else:
            link = form_data['link']
        
        if not form_data['created_by']or form_data['created_by'] == '':
            flash("Musisz wybrać profil posiadacza grupy FB", "danger")
            return redirect(url_for('fbGroups'))
        else:
            created_by = form_data['created_by']

        if set_post_id == 9999999:
            zapytanie_sql = '''
                        INSERT INTO facebook_gropus
                            (name, category, link, created_by)
                        VALUES 
                            (%s, %s, %s, %s);
                    '''
            dane = (name, category, link, created_by)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Dodano grupę FB {name} do kategorii {category} przez {session["username"]}!', log_path=logFileName)
                flash(f'Grupa została dodana!', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Grupa FB {name} z kategorii {category} nie została dodana przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Grupa nie została dodana!', 'danger')

        else:
            zapytanie_sql = '''
                    UPDATE facebook_gropus
                    SET 
                        name = %s,
                        category = %s,
                        link = %s,
                        created_by = %s
                    WHERE id = %s;
                '''
            dane = (name, category, link, created_by, set_post_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Zaktualizowano grupę FB {name} do kategorii {category} przez {session["username"]}!', log_path=logFileName)
                flash(f'Zmiany zostały zapisane!', 'success')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu! Grupa nie została zaktualizowana przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu! Grupa FB {name} z kategorii {category} nie została zmodyfikowana!', 'danger')

        return redirect(url_for('fbGroups'))
    
    return redirect(url_for('index'))

@app.route('/remove-fbgroup', methods=['POST'])
def remove_fbgroup():
    """Usuwanie bloga"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /remove-fbgroup bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['settings'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /remove-fbgroup bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()
        try: form_data['PostID']
        except KeyError: return redirect(url_for('index'))
        set_post_id = int(form_data['PostID'])
        if msq.delete_row_from_database(
                """
                    DELETE FROM facebook_gropus WHERE ID = %s;
                """,
                (set_post_id,)
            ):
            msq.handle_error(f'Grupa została usunięta przez {session["username"]}!', log_path=logFileName)
            flash("Grupa została usunięta.", "success")
        else:
            msq.handle_error(f'UWAGA! Błąd usunięcia grupy przez {session["username"]}!', log_path=logFileName)
            flash("Błąd usunięcia grupy.", "danger")
        return redirect(url_for('fbGroups'))
    
    return redirect(url_for('index'))

@app.route('/fb-groups-sender', methods=['POST'])
def fb_groups_sender():
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /fb-groups-sender bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))

    data = request.json  # Odbieramy dane JSON

    # Pobieranie harmonogramu
    schedule = data.get('schedule', [])
    wznawiaj = data.get('wznawiaj', False)
    repeats_dict = data.get('repeats', {})
    content = data.get('content')
    color_choice = data.get('color_choice')
    post_id = data.get('post_id')

    # Flagi konfigruracyjne deamona
    category = data.get('category')
    section = data.get('section')
    get_id_gallery = data.get('id_gallery')
    created_by = data.get('created_by')
    msq.handle_error(f"created_by {created_by} category {category}  section {section}, id:{post_id}", log_path=logFileName)
    if get_id_gallery == "None":
        id_gallery = None
    else:
        try: int(get_id_gallery)
        except ValueError: return jsonify({'success': False, 'message': 'Błąd w przekształcaniu na int id_gallery!'}), 400
        id_gallery = int(get_id_gallery)

    # Przekształcanie każdej daty w harmonogramie na standardowy format
    formatted_schedule_org = [format_date_pl(date_str) for date_str in schedule]

    # Sprawdzamy, czy wszystkie daty są poprawnie sformatowane
    if None in formatted_schedule_org:
        msq.handle_error(f"Błąd w przekształcaniu dat.", log_path=logFileName)
        return jsonify({'success': False, 'message': 'Błąd w przekształcaniu dat'}), 400
    
    def get_actions_dates():
        existing_campaigns_query = '''
            SELECT schedule_0_datetime, schedule_1_datetime, 
                schedule_2_datetime, schedule_3_datetime, 
                schedule_4_datetime, schedule_5_datetime, 
                schedule_6_datetime, schedule_7_datetime, 
                schedule_8_datetime, schedule_9_datetime, 
                schedule_10_datetime
            FROM waitinglist_fbgroups
        '''
        return msq.connect_to_database(existing_campaigns_query)
    

    existing_campaigns = get_actions_dates()
    formatted_schedule = znajdz_wolny_termin(formatted_schedule_org, existing_campaigns)

    # Przygotowywanie list jednej długości
    less_index = []
    repeater = 0
    if not wznawiaj: 
        less_index  = [None for _ in range(10)]
        repeater = 0
    else:
        if 'ponow2razy' in repeats_dict and 'ponow5razy' in repeats_dict\
            and 'ponow8razy' in repeats_dict and 'ponow10razy' in repeats_dict\
                and wznawiaj:
            if repeats_dict['ponow2razy']: 
                less_index = [None for _ in range(8)]
                repeater = 2
            elif repeats_dict['ponow5razy']: 
                less_index = [None for _ in range(5)]
                repeater = 5
            elif repeats_dict['ponow8razy']: 
                less_index = [None for _ in range(2)]
                repeater = 8
            elif repeats_dict['ponow10razy']: 
                less_index = []
                repeater = 10
        else:
            msq.handle_error(f"Błąd w przygotowywaniu list hramonogramów.", log_path=logFileName)
            return jsonify({'success': False, 'message': 'Błąd w przygotowywaniu list hramonogramów'}), 400
        
    repeats_left = repeater + 1
    repeats_last = None
    repeats = repeater + 1

    # Gotowa lista prepareded_schedule
    prepareded_schedule = formatted_schedule + less_index

    # Przyporzadkowuję daty do zmiennych exportowych
    schedule_0_datetime, schedule_1_datetime, schedule_2_datetime, \
        schedule_3_datetime, schedule_4_datetime, schedule_5_datetime, \
            schedule_6_datetime, schedule_7_datetime, schedule_8_datetime, \
                schedule_9_datetime, schedule_10_datetime = prepareded_schedule


    zapytanie_sql = '''
                INSERT INTO waitinglist_fbgroups
                    (post_id, content, color_choice,
                    repeats, repeats_left, repeats_last, 
                    schedule_0_datetime, schedule_1_datetime, 
                    schedule_2_datetime, schedule_3_datetime, 
                    schedule_4_datetime, schedule_5_datetime, 
                    schedule_6_datetime, schedule_7_datetime, 
                    schedule_8_datetime, schedule_9_datetime, 
                    schedule_10_datetime, 
                    category, section, id_gallery, created_by)
                VALUES 
                    (%s, %s, %s, 
                    %s, %s, %s, 
                    %s, %s,  
                    %s, %s,  
                    %s, %s,  
                    %s, %s,  
                    %s, %s,  
                    %s, 
                    %s, %s, %s, %s);
            '''
    dane = (post_id, content, color_choice,
            repeats, repeats_left, repeats_last, 
            schedule_0_datetime, schedule_1_datetime, 
            schedule_2_datetime, schedule_3_datetime, 
            schedule_4_datetime, schedule_5_datetime, 
            schedule_6_datetime, schedule_7_datetime, 
            schedule_8_datetime, schedule_9_datetime, 
            schedule_10_datetime, 
            category, section, id_gallery, created_by)

    if msq.insert_to_database(zapytanie_sql, dane):
        msq.handle_error(f'Harmonogram kampanii dla {section}, id:{post_id} zsotał poprawnie zapisany przez {session["username"]}.', log_path=logFileName)
        
        return jsonify({'success': True, 'message': f'Zmiany zostały zapisane!'})
    else:
        msq.handle_error(f"Błąd zapisu bazy danych dla {created_by} {section}, id:{post_id}", log_path=logFileName)
        return jsonify({'success': False, 'message': 'Błąd zapisu bazy danych'}), 400

@app.route('/remove-career-fbgroups', methods=["POST"])
def remove_career_fbgroups():
    """Usuwanie kampanii fbgroups career"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /remove-career-fbgroups bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    # if session['userperm']['career'] == 0:
    #     flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
    #     return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()
        schedule_0_id = form_data.get('schedule_0_id', None)
        schedule_1_id = form_data.get('schedule_1_id', None)
        schedule_2_id = form_data.get('schedule_2_id', None)
        schedule_3_id = form_data.get('schedule_3_id', None)
        schedule_4_id = form_data.get('schedule_4_id', None)
        schedule_5_id = form_data.get('schedule_5_id', None)
        schedule_6_id = form_data.get('schedule_6_id', None)
        schedule_7_id = form_data.get('schedule_7_id', None)
        schedule_8_id = form_data.get('schedule_8_id', None)
        schedule_9_id = form_data.get('schedule_9_id', None)
        schedule_10_id = form_data.get('schedule_10_id', None)
        section = form_data.get('section', 'career')


        schedule_id_list = [x for x in [
                                schedule_0_id, 
                                schedule_1_id, 
                                schedule_2_id, 
                                schedule_3_id, 
                                schedule_4_id, 
                                schedule_5_id, 
                                schedule_6_id, 
                                schedule_7_id, 
                                schedule_8_id, 
                                schedule_9_id, 
                                schedule_10_id
                                ] if x is not None]
        
        for deleter_id in schedule_id_list:
            zapytanie_sql = """
                DELETE FROM ogloszenia_fbgroups WHERE id_zadania = %s;
            """
            data = (deleter_id,)
            try: msq.insert_to_database(zapytanie_sql, data)
            except Exception as e: 
                msq.handle_error(f'UWAGA! Błąd w usunięciu kampanii: {e}!', log_path=logFileName)
                print(f"Błąd w usunięciu kampanii: {e}")

        try: form_data['waitnig_list_id']
        except KeyError: return redirect(url_for(f'{section}'))
        set_wl_id = int(form_data['waitnig_list_id'])
        
        msq.delete_row_from_database(
                """
                    DELETE FROM waitinglist_fbgroups WHERE id = %s;
                """,
                (set_wl_id,)
            )
        msq.handle_error(f'Kampania została usunięta przez {session["username"]}!', log_path=logFileName)
        flash("Kampania została usunięta.", "success")
        return redirect(url_for(f'{section}'))
    
    return redirect(url_for('index'))

@app.route('/hidden-campaigns')
def hiddeCampaigns():
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /hidden-campaigns bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['fbhidden'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /hidden-campaigns bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    ads_hidden_got = generator_hidden_campaigns()
    categoryStats = generator_FbGroupsStats()

    new_all_hidden = []
    for item in ads_hidden_got:
        if 'fbgroups' not in item:
            item['fbgroups'] = {}
        fbgroupsIDstatus = checkFbGroupstatus(section="hiddeCampaigns", post_id=item['id'])
        item['fbgroups']['id'] = fbgroupsIDstatus[0]
        item['fbgroups']['post_id'] = fbgroupsIDstatus[1]
        item['fbgroups']['content'] = fbgroupsIDstatus[2]
        item['fbgroups']['color_choice'] = fbgroupsIDstatus[3]
        item['fbgroups']['repeats'] = fbgroupsIDstatus[4]
        item['fbgroups']['repeats_left'] = fbgroupsIDstatus[5]
        item['fbgroups']['repeats_last'] = fbgroupsIDstatus[6]

        item['fbgroups']['schedule_0_id'] = fbgroupsIDstatus[7]
        item['fbgroups']['schedule_0_datetime'] = fbgroupsIDstatus[8]
        item['fbgroups']['schedule_0_status'] = fbgroupsIDstatus[9]
        item['fbgroups']['schedule_0_errors'] = fbgroupsIDstatus[10]

        item['fbgroups']['schedule_1_id'] = fbgroupsIDstatus[11]
        item['fbgroups']['schedule_1_datetime'] = fbgroupsIDstatus[12]
        item['fbgroups']['schedule_1_status'] = fbgroupsIDstatus[13]
        item['fbgroups']['schedule_1_errors'] = fbgroupsIDstatus[14]

        item['fbgroups']['schedule_2_id'] = fbgroupsIDstatus[15]
        item['fbgroups']['schedule_2_datetime'] = fbgroupsIDstatus[16]
        item['fbgroups']['schedule_2_status'] = fbgroupsIDstatus[17]
        item['fbgroups']['schedule_2_errors'] = fbgroupsIDstatus[18]

        item['fbgroups']['schedule_3_id'] = fbgroupsIDstatus[19]
        item['fbgroups']['schedule_3_datetime'] = fbgroupsIDstatus[20]
        item['fbgroups']['schedule_3_status'] = fbgroupsIDstatus[21]
        item['fbgroups']['schedule_3_errors'] = fbgroupsIDstatus[22]

        item['fbgroups']['schedule_4_id'] = fbgroupsIDstatus[23]
        item['fbgroups']['schedule_4_datetime'] = fbgroupsIDstatus[24]
        item['fbgroups']['schedule_4_status'] = fbgroupsIDstatus[25]
        item['fbgroups']['schedule_4_errors'] = fbgroupsIDstatus[26]

        item['fbgroups']['schedule_5_id'] = fbgroupsIDstatus[27]
        item['fbgroups']['schedule_5_datetime'] = fbgroupsIDstatus[28]
        item['fbgroups']['schedule_5_status'] = fbgroupsIDstatus[29]
        item['fbgroups']['schedule_5_errors'] = fbgroupsIDstatus[30]

        item['fbgroups']['schedule_6_id'] = fbgroupsIDstatus[31]
        item['fbgroups']['schedule_6_datetime'] = fbgroupsIDstatus[32]
        item['fbgroups']['schedule_6_status'] = fbgroupsIDstatus[33]
        item['fbgroups']['schedule_6_errors'] = fbgroupsIDstatus[34]

        item['fbgroups']['schedule_7_id'] = fbgroupsIDstatus[35]
        item['fbgroups']['schedule_7_datetime'] = fbgroupsIDstatus[36]
        item['fbgroups']['schedule_7_status'] = fbgroupsIDstatus[37]
        item['fbgroups']['schedule_7_errors'] = fbgroupsIDstatus[38]

        item['fbgroups']['schedule_8_id'] = fbgroupsIDstatus[39]
        item['fbgroups']['schedule_8_datetime'] = fbgroupsIDstatus[40]
        item['fbgroups']['schedule_8_status'] = fbgroupsIDstatus[41]
        item['fbgroups']['schedule_8_errors'] = fbgroupsIDstatus[42]

        item['fbgroups']['schedule_9_id'] = fbgroupsIDstatus[43]
        item['fbgroups']['schedule_9_datetime'] = fbgroupsIDstatus[44]
        item['fbgroups']['schedule_9_status'] = fbgroupsIDstatus[45]
        item['fbgroups']['schedule_9_errors'] = fbgroupsIDstatus[46]

        item['fbgroups']['schedule_10_id'] = fbgroupsIDstatus[47]
        item['fbgroups']['schedule_10_datetime'] = fbgroupsIDstatus[48]
        item['fbgroups']['schedule_10_status'] = fbgroupsIDstatus[49]
        item['fbgroups']['schedule_10_errors'] = fbgroupsIDstatus[50]

        item['fbgroups']['category'] = fbgroupsIDstatus[51]
        item['fbgroups']['created_by'] = fbgroupsIDstatus[52]
        item['fbgroups']['section'] = fbgroupsIDstatus[53]
        item['fbgroups']['id_gallery'] = fbgroupsIDstatus[54]
        item['fbgroups']['data_aktualizacji'] = fbgroupsIDstatus[55]

        new_all_hidden.append(item)

    all_hidden = new_all_hidden

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(all_hidden)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    ads_hidden_campaigns = all_hidden[offset: offset + per_page]
    
    return render_template(
            "hidden_management.html", 
            username=session['username'],
            useremail=session['user_data']['email'],
            userperm=session['userperm'], 
            user_brands=session['brands'], 
            ads_hidden_campaigns=ads_hidden_campaigns,
            categoryStats=categoryStats,
            pagination=pagination
            )

@app.route('/save-hidden-campaigns', methods=['POST'])
def save_hidden_campaigns():
    # Sprawdzenie czy użytkownik jest zalogowany i ma uprawnienia
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /save-career-offer bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['fbhidden'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /save-career-offer bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj się z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # print(request.form)
    # print(request.files.getlist('photos[]'))
    # Odczytanie danych z formularza
    title = request.form.get('title')
    description = request.form.get('description')
    category = request.form.get('category')
    offerID = request.form.get('offerID')
    created_by = request.form.get('created_by')
    author = request.form.get('author')
    target = request.form.get('target')


    # msq.handle_error(f'UWAGA! created_by {created_by} category {category}!', log_path=logFileName)


    try: offerID_int = int(offerID)
    except ValueError:
        msq.handle_error(f'UWAGA! Błąd z id kampanii {title} wywołany przez {session["username"]}!', log_path=logFileName)
        flash('Błąd z id kampanii. Skontaktuj się z administratorem!', 'danger')
        return jsonify({'error': 'Błąd z id kampanii. Skontaktuj się z administratorem!'}), 400

    # Sprawdzenie czy wszystkie wymagane dane zostały przekazane
    if not all([title, description, category]):
        msq.handle_error(f'UWAGA! Nie wszystkie wymagane dane zostały przekazane przez {session["username"]}!', log_path=logFileName)
        return jsonify({'error': 'Nie wszystkie wymagane dane zostały przekazane'}), 400

    if offerID_int == 9999999:
        oldPhotos = []
        allPhotos = []
    else:
        oldPhotos = request.form.getlist('oldPhotos[]')
        allPhotos = request.form.getlist('allPhotos[]')

    settingsDB = generator_settingsDB()
    real_loc_on_server = settingsDB['real-location-on-server']
    domain = settingsDB['main-domain']
    estate_pic_path = settingsDB['estate-pic-offer']

    upload_path = f'{real_loc_on_server}{estate_pic_path}'
    mainDomain_URL = f'{domain}{estate_pic_path}'

    # Przetwarzanie przesłanych zdjęć
    photos = request.files.getlist('photos[]')

    saved_photos =[]
    if photos:
        for photo in photos:
            if photo:
                filename = f"{int(time.time())}_{secure_filename(photo.filename)}"
                full_path = os.path.join(upload_path, filename)
                complete_URL_PIC = f'{mainDomain_URL}{filename}'

                try:
                    photo.save(full_path)
                    saved_photos.append(complete_URL_PIC)

                    # Normalizujemy nazwy plików w allPhotos, aby uniknąć problemów z porównaniem
                    normalized_allPhotos = [secure_filename(p.split('/')[-1]) for p in allPhotos]

                    # Sprawdzenie, czy nazwa zdjęcia istnieje w allPhotos
                    original_name = secure_filename(photo.filename)
                    if original_name in normalized_allPhotos:
                        pobrany_index = normalized_allPhotos.index(original_name)
                        allPhotos[pobrany_index] = filename  # Zastępujemy starą nazwę nową

                except Exception as e:
                    msq.handle_error(
                        f'UWAGA! Nie udało się zapisać pliku {filename}: {str(e)}. Adres {complete_URL_PIC} nie jest dostępny!!', 
                        log_path=logFileName
                    )
                    print(f"Nie udało się zapisać pliku {filename}: {str(e)}. UWAGA: Adres {complete_URL_PIC} nie jest dostępny!")


    # print(allPhotos)
    if offerID_int == 9999999:
        gallery_id = None
        # Obsługa zdjęć 
        if len(saved_photos)>=1:
            # dodaj zdjęcia do bazy i pobierz id galerii
            dynamic_col_name = ''
            dynamic_amount = ''
            for i in range(len(saved_photos)):
                dynamic_col_name += f'Zdjecie_{i + 1}, '
                dynamic_amount += '%s, '
            dynamic_col_name = dynamic_col_name[:-2]
            dynamic_amount = dynamic_amount[:-2]

            zapytanie_sql = f'''INSERT INTO ZdjeciaOfert ({dynamic_col_name}) VALUES ({dynamic_amount});'''
            dane = tuple(a for a in saved_photos)

            if msq.insert_to_database(zapytanie_sql, dane):
                # Przykładowe dane
                try:
                    gallery_id = msq.connect_to_database(
                        '''
                            SELECT * FROM ZdjeciaOfert ORDER BY ID DESC;
                        ''')[0][0]
                except Exception as err:
                    msq.handle_error(f'Błąd podczas tworzenia galerii przez {session["username"]}! {err}.', log_path=logFileName)
                    flash(f'Błąd podczas tworzenia galerii! {err}.', 'danger')
                    return jsonify({
                        'message': f'Błąd podczas tworzenia galerii! \n {err}',
                        'success': True
                        }), 200
            else:
                msq.handle_error(f'UWAGA! Błąd podczas zapisywania galerii w bazie przez {session["username"]}!', log_path=logFileName)
                flash(f'Błąd podczas zapisywania galerii w bazie!', 'danger')
                return jsonify({
                    'message': 'Błąd podczas zapisywania galerii w bazie!',
                    'success': True
                    }), 200
        

    else:
        try: gallery_id = take_data_where_ID('id_gallery', 'hidden_campaigns', 'id', offerID_int)[0][0]
        except IndexError: 
            msq.handle_error(f'UWAGA! Nie udało się pobrać ID galerii!', log_path=logFileName)
            flash(f"Nie udało się pobrać ID galerii!", "danger")
            return jsonify({
                    'message': 'Nie udało się pobrać ID galerii!',
                    'success': False
                    }), 200
        
        if gallery_id is not None:
            try: 
                current_gallery = take_data_where_ID('*', 'ZdjeciaOfert', 'ID', gallery_id)[0]
                current_gallery_list = [p for p in current_gallery[1:-1] if p is not None]
            except IndexError: 
                msq.handle_error(f'UWAGA! Nie udało się pobrać galerii!', log_path=logFileName)
                flash(f"Nie udało się pobrać galerii!", "danger")
                return jsonify({
                        'message': 'Nie udało się pobrać galerii!',
                        'success': False
                        }), 200
        else:
            current_gallery = ()
            current_gallery_list = []

        aktualne_linkURL_set = set()
        for linkUrl in current_gallery:
            nazwaZdjecia = str(linkUrl).split('/')[-1]
            aktualne_linkURL_set.add(nazwaZdjecia)

        przeslane_nazwyZdjec_set = set()
        for nazwaZdjecia in oldPhotos:
            przeslane_nazwyZdjec_set.add(nazwaZdjecia)

        zdjeciaDoUsuniecia = aktualne_linkURL_set.difference(przeslane_nazwyZdjec_set)
        for delIt in zdjeciaDoUsuniecia:
            complete_URL_PIC = f'{mainDomain_URL}{delIt}'
            if complete_URL_PIC in current_gallery_list:
                current_gallery_list.remove(complete_URL_PIC)
                try:
                    file_path = upload_path + delIt
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    else:
                        print(f"File {file_path} not found.")
                except Exception as e:
                    msq.handle_error(f'UWAGA! Error removing file {upload_path + delIt}: {e}', log_path=logFileName)
                    print(f"Error removing file {upload_path + delIt}: {e}")

        oldPhotos_plus_saved_photos = current_gallery_list + saved_photos

        index_map = {nazwa: index for index, nazwa in enumerate(allPhotos)}

        # Sortowanie oldPhotos_plus_saved_photos na podstawie pozycji w allPhotos
        oldPhotos_plus_saved_photos_sorted = sorted(oldPhotos_plus_saved_photos, key=lambda x: index_map[x.split('/')[-1]])
        
        if len(oldPhotos_plus_saved_photos_sorted)>=1 and len(oldPhotos_plus_saved_photos_sorted) <=10:
            # dodaj zdjęcia do bazy i pobierz id galerii
            dynamic_col_name = ''
            
            for i in range(10):
                dynamic_col_name += f'Zdjecie_{i + 1} = %s, '

            dynamic_col_name = dynamic_col_name[:-2]

            if gallery_id is not None:
                zapytanie_sql = f'''
                    UPDATE ZdjeciaOfert
                    SET {dynamic_col_name} 
                    WHERE ID = %s;
                    '''
            else:
                # dodaj zdjęcia do bazy i pobierz id galerii
                dynamic_col_name_with_none = ''
                dynamic_amount_with_none = ''
                for i in range(len(saved_photos)):
                    dynamic_col_name_with_none += f'Zdjecie_{i + 1}, '
                    dynamic_amount_with_none += '%s, '
                dynamic_col_name_with_none = dynamic_col_name_with_none[:-2]
                dynamic_amount_with_none = dynamic_amount_with_none[:-2]

                zapytanie_sql_with_none = f'''INSERT INTO ZdjeciaOfert ({dynamic_col_name_with_none}) VALUES ({dynamic_amount_with_none});'''
                dane_with_none = tuple(a for a in saved_photos)

                if msq.insert_to_database(zapytanie_sql_with_none, dane_with_none):
                    # Przykładowe dane
                    try:
                        gallery_id = msq.connect_to_database(
                            '''
                                SELECT * FROM ZdjeciaOfert ORDER BY ID DESC;
                            ''')[0][0]
                    except Exception as err:
                        msq.handle_error(f'Błąd podczas tworzenia galerii przez {session["username"]}! {err}.', log_path=logFileName)
                        flash(f'Błąd podczas tworzenia galerii! {err}.', 'danger')
                        return jsonify({
                            'message': f'Błąd podczas tworzenia galerii! \n {err}',
                            'success': True
                            }), 200
                else:
                    msq.handle_error(f'UWAGA! Błąd podczas zapisywania galerii w bazie przez {session["username"]}!', log_path=logFileName)
                    flash(f'Błąd podczas zapisywania galerii w bazie!', 'danger')
                    return jsonify({
                        'message': 'Błąd podczas zapisywania galerii w bazie!',
                        'success': True
                        }), 200

                zapytanie_sql = f'''
                    UPDATE ZdjeciaOfert
                    SET {dynamic_col_name} 
                    WHERE ID = %s;
                    '''

            len_oldPhotos_plus_saved_photos = len(oldPhotos_plus_saved_photos_sorted)
            if 10 - len_oldPhotos_plus_saved_photos == 0:
                dane = tuple(a for a in oldPhotos_plus_saved_photos_sorted + [gallery_id])
            else:
                oldPhotos_plus_saved_photos_plus_empyts = oldPhotos_plus_saved_photos_sorted
                for _ in  range(10 - len_oldPhotos_plus_saved_photos):
                    oldPhotos_plus_saved_photos_plus_empyts += [None]
                dane = tuple(a for a in oldPhotos_plus_saved_photos_plus_empyts + [gallery_id])

            msq.handle_error(f'UWAGA! zapytanie_sql : {gallery_id} dane: {dane}!', log_path=logFileName)

            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Galeria została pomyslnie zaktualizowana przez {session["username"]}!', log_path=logFileName)
                print('update_galerii_udany')
            else:
                msq.handle_error(f'UWAGA! Bład zapisu galerii! Oferta wynajmu nie została zapisana przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu galerii! Oferta wynajmu nie została zapisana!', 'danger')
                return jsonify({
                        'message': 'xxx',
                        'success': True
                        }), 200
        else:
            # Usuwam galerię jeżeli nie ma zdjęć
            zapytanie_sql = f'''
                DELETE FROM ZdjeciaOfert WHERE ID = %s;
                '''
            dane = (gallery_id, )

            # print(zapytanie_sql, dane)
            if msq.insert_to_database(zapytanie_sql, dane):
                msq.handle_error(f'Galeria została pomyslnie usunięta z powodu braku zdjęć przez {session["username"]}!', log_path=logFileName)
                gallery_id = None
            else:
                msq.handle_error(f'UWAGA! Bład zapisu galerii! Oferta wynajmu nie została zapisana przez {session["username"]}!', log_path=logFileName)
                flash(f'Bład zapisu galerii! Oferta wynajmu nie została zapisana!', 'danger')
                return jsonify({
                        'message': 'xxx',
                        'success': True
                        }), 200


    id_gallery = gallery_id
    # Przygotowanie zapytania SQL w zależności od tego, czy jest to nowy wpis, czy aktualizacja
    if offerID_int == 9999999:
        # Nowe ogłoszenie
        
        
        zapytanie_sql = '''
            INSERT INTO hidden_campaigns (title, description, target, category, author, id_gallery, created_by, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
        '''
        dane = (title, description, target, category, author, id_gallery, created_by, 1)
    else:
        # Aktualizacja istniejącego ogłoszenia
        zapytanie_sql = '''
            UPDATE hidden_campaigns 
            SET 
                title=%s, 
                description=%s, 
                target=%s, 
                category=%s, 
                created_by=%s,
                author=%s,
                id_gallery=%s
            WHERE ID=%s;
        '''
        dane = (title, description, target, category, created_by, author, id_gallery, offerID_int)

    # Wykonanie zapytania
    if msq.insert_to_database(zapytanie_sql, dane):
        msq.handle_error(f'Kampania została pomyślnie zapisana przez {session["username"]}!', log_path=logFileName)
        flash(f'Kampania została zapisana pomyślnie!', 'success')
        return jsonify({
            'message': 'Kampania została zapisana pomyślnie!',
            'success': True
        }), 200
    else:
        msq.handle_error(f'UWAGA! Błąd zapisu! Kampania nie została zapisana przez {session["username"]}!', log_path=logFileName)
        flash(f'Błąd zapisu! Kampania nie została zapisana!', 'danger')
        return jsonify({
            'message': 'Błąd zapisu! Kampania nie została zapisana!',
            'success': False
        }), 500

@app.route('/remove-hidden-campaigns', methods=["POST"])
def remove_hidden_campaigns():
    """Usuwanie ofertę najmu"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /remove-sell-offer bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['fbhidden'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /remove-sell-offer bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()

        
        msq.handle_error(f'form_data {form_data}!', log_path=logFileName)
        try: form_data['PostID']
        except KeyError: return redirect(url_for('index'))
        set_post_id = int(form_data['PostID'])
        # pobieram id galerii
        try: id_galerry = take_data_where_ID('id_gallery', 'hidden_campaigns', 'id', set_post_id )[0][0]
        except IndexError: 
            msq.handle_error(f'UWAGA! Wpis nie został usunięty przez {session["username"]}! Wystąpił błąd struktury danych galerii!', log_path=logFileName)
            flash("Wpis nie został usunięty. Wystąpił błąd struktury danych galerii", "danger")
            return redirect(url_for('hiddeCampaigns'))
        
        if id_galerry is not None:
            try: current_gallery = take_data_where_ID('*', 'ZdjeciaOfert', 'ID', id_galerry)[0]
            except IndexError: 
                msq.handle_error(f'UWAGA! Wpis nie został usunięty przez {session["username"]}! Wystąpił błąd struktury danych galerii!', log_path=logFileName)
                flash("Wpis nie został usunięty. Wystąpił błąd struktury danych galerii", "danger")
                return redirect(url_for('hiddeCampaigns'))

            msq.delete_row_from_database(
                    """
                        DELETE FROM ZdjeciaOfert WHERE ID = %s;
                    """,
                    (id_galerry,)
                )
        # Usuwam wpis z tabeli kampani anonimowych
        msq.delete_row_from_database(
                """
                    DELETE FROM hidden_campaigns WHERE ID = %s;
                """,
                (set_post_id,)
            )
        
        if id_galerry is not None:
            real_loc_on_server = settingsDB['real-location-on-server']
            domain = settingsDB['main-domain']
            estate_pic_path = settingsDB['estate-pic-offer']
            upload_path = f'{real_loc_on_server}{estate_pic_path}'
            mainDomain_URL = f'{domain}{estate_pic_path}'

            
            current_gallery_list = [p for p in current_gallery[1:-1] if p is not None]
            # print(current_gallery_list)
            for delIt in current_gallery_list:
                delIt_clear = str(delIt).replace(mainDomain_URL, '')
                # print(delIt)
                # print(delIt_clear)
                if delIt in current_gallery_list:
                    try:
                        file_path = upload_path + delIt_clear
                        # print(file_path)
                        if os.path.exists(file_path):
                            os.remove(file_path)
                        else:
                            print(f"File {file_path} not found.")
                    except Exception as e:
                        msq.handle_error(f'UWAGA! Error removing file {file_path}: {e}', log_path=logFileName)
                        print(f"Error removing file {file_path}: {e}")

        msq.handle_error(f'Wpis został usunięty przez {session["username"]}!', log_path=logFileName)
        flash("Wpis został usunięty.", "success")
        return redirect(url_for('hiddeCampaigns'))
    
    return redirect(url_for('index'))

@app.route('/update-hidden-campaigns-status', methods=['POST'])
def update_hidden_campaigns_status():
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /update-career-offer-status bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm']['fbhidden'] == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /update-career-offer-status bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()
        try: 
            form_data['PostID']
            form_data['Status']
        except KeyError: return redirect(url_for('index'))
        set_post_id = int(form_data['PostID'])
        set_post_status = int(form_data['Status'])

        statusHidden = checkFbGroupstatus(section="hidden", post_id=set_post_id)
        if statusHidden[0] != None:
            msq.handle_error(f'UWAGA! Status kampanii nie został zmieniony przez {session["username"]}!', log_path=logFileName)
            flash("Status kampanii nie został zmieniony. Przewij kampanię na grupach Facebooka", "danger")
            return redirect(url_for('hiddeCampaigns'))

        zapytanie_sql = f'''
                UPDATE hidden_campaigns
                SET status = %s
                WHERE ID = %s;
                '''
        dane = (set_post_status, set_post_id)
        if msq.insert_to_database(zapytanie_sql, dane):
            msq.handle_error(f'Status oferty został zmieniony przez {session["username"]}!', log_path=logFileName)
            flash("Status oferty został zmieniony.", "success")
            return redirect(url_for('hiddeCampaigns'))
    
    return redirect(url_for('index'))

@app.route('/presentation-view')
def presentation_view():
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        msq.handle_error(f'UWAGA! Wywołanie adresu endpointa /presentation-view bez autoryzacji!', log_path=logFileName)
        return redirect(url_for('index'))
    
    if session['userperm'].get('presentation', 0) == 0:
        msq.handle_error(f'UWAGA! Próba zarządzania /presentation-view bez uprawnień przez {session["username"]}!', log_path=logFileName)
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    db = get_db()
    query = """SELECT * FROM presentations;"""
    presentations_items_all = db.getFrom(query=query, as_dict=True)

    total_bytes = sum(p['video_size_bytes'] or 0 for p in presentations_items_all)
    total_mb = round(total_bytes / (1024*1024), 2)
    # quota_mb = PRESENTATION_QUOTA_MB
    used_percent = int(total_mb / PRESENTATION_QUOTA_MB * 100) if PRESENTATION_QUOTA_MB else 0

    presentations_items = []
    for item in presentations_items_all:
        if item.get("slot", None) == "green":
            presentations_items.append(item)
        elif item.get("slot", None) == "silver" \
            and session['userperm'].get('presentation-silver', 0) == 1 \
                and item.get("author", None) == session["username"]:
            presentations_items.append(item)
        elif item.get("slot", None) == "silver" \
            and session['userperm'].get('presentation-gold', 0) == 1:
            presentations_items.append(item)
        elif item.get("slot", None) == "gold" \
            and (session['userperm'].get('presentation-gold', 0) == 1 or session['userperm'].get('presentation-silver', 0) == 1) \
                and item.get("author", None) == session["username"]:
            presentations_items.append(item)
    
    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(presentations_items)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    presentations_list = presentations_items[offset: offset + per_page]
    
    return render_template(
            "presentation_view.html", 
            username=session['username'],
            useremail=session['user_data']['email'],
            userperm=session['userperm'], 
            user_brands=session['brands'], 
            presentations_list=presentations_list,
            pagination=pagination,
            total_mb=total_mb,
            quota_mb=PRESENTATION_QUOTA_MB,
            used_percent=used_percent
        )


@app.route('/presentation-sync-status', methods=['GET'])
def presentation_sync_status():
    # --- autoryzacja ---
    if 'username' not in session:
        msq.handle_error(
            f'UWAGA! Wywołanie endpointa /presentation-sync-status bez autoryzacji!',
            log_path=logFileName
        )
        return jsonify({
            'success': False,
            'message': 'Brak autoryzacji – zaloguj się ponownie.'
        }), 401

    if session['userperm'].get('presentation', 0) == 0:
        msq.handle_error(
            f'UWAGA! Próba zarządzania /presentation-sync-status bez uprawnień przez {session["username"]}!',
            log_path=logFileName
        )
        return jsonify({
            'success': False,
            'message': 'Nie masz uprawnień do zarządzania prezentacjami.'
        }), 403

    post_id = request.args.get('PostID')

    if not post_id:
        return jsonify({
            'success': False,
            'message': 'Brak parametru PostID.'
        }), 400

    try:
        post_id_int = int(post_id)
    except ValueError:
        return jsonify({
            'success': False,
            'message': 'Nieprawidłowy identyfikator prezentacji.'
        }), 400

    db = get_db()

    query = """
        SELECT id, slot, status, sync,
               published_at, last_sync_at,
               last_sync_status, last_sync_error
        FROM presentations
        WHERE id = %s
        LIMIT 1
    """
    rows = db.getFrom(query=query, params=(post_id_int,), as_dict=True)

    if not rows:
        return jsonify({
            'success': False,
            'message': 'Nie znaleziono prezentacji o podanym ID.'
        }), 404

    row = rows[0]

    return jsonify({
        'success': True,
        'data': {
            'id': row.get('id'),
            'slot': row.get('slot'),
            'status': row.get('status'),
            'sync': row.get('sync'),
            'published_at': row.get('published_at'),
            'last_sync_at': row.get('last_sync_at'),
            'last_sync_status': row.get('last_sync_status'),
            'last_sync_error': row.get('last_sync_error'),
        }
    }), 200


@app.route('/presentation-save', methods=['POST'])
def presentation_save():
    # --- autoryzacja ---
    if 'username' not in session:
        msq.handle_error(
            f'UWAGA! Wywołanie adresu endpointa /presentation-save bez autoryzacji!',
            log_path=logFileName
        )
        return redirect(url_for('index'))
    
    if session['userperm'].get('presentation', 0) == 0:
        msq.handle_error(
            f'UWAGA! Próba zarządzania /presentation-save bez uprawnień przez {session["username"]}!',
            log_path=logFileName
        )
        flash(
            'Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!',
            'danger'
        )
        return redirect(url_for('index'))

    # --- dane z formularza ---
    offer_id        = request.form.get('offer_id') or request.form.get('OfferID')
    is_edit         = request.form.get('is_edit') == '1'
    title           = (request.form.get('title') or '').strip()
    description     = (request.form.get('description') or '').strip()
    slot            = (request.form.get('slot') or '').strip().lower()
    author          = (request.form.get('author') or session.get('username'))
    target          = request.form.get('target') or 'presentation'
    duration        = request.form.get('video_duration_sec', '0 min 0 s')
    v_width         = request.form.get('video_width', '0') 
    v_height        = request.form.get('video_height', '0')
    v_size_bytes    = request.form.get('video_size_bytes', '0')

    video_file  = request.files.get('video_file')  # może być None przy edycji bez zmiany wideo

    # --- walidacja podstawowa ---
    errors = []

    if not title:
        errors.append('Brak tytułu prezentacji.')
    if slot not in ('green', 'silver', 'gold'):
        errors.append('Nieprawidłowy slot prezentacji.')

    if not is_edit and video_file is None:
        errors.append('Dla nowej prezentacji wymagany jest plik wideo.')

    if errors:
        msg = ' '.join(errors)
        msq.handle_error(
            f'Błąd zapisu prezentacji (użytkownik {session["username"]}): {msg}',
            log_path=logFileName
        )
        return jsonify({
            'success': False,
            'message': msg
        }), 400
    # --- ZAPIS DO BAZY ---
    db = get_db()

    userperm  = session.get('userperm', {}) or {}
    username  = session.get('username')
    has_gold  = True if userperm.get('presentation-gold', 0) == 1 else False

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # jeśli edycja → aktualizujemy istniejący rekord
    if is_edit and offer_id:

        db.fetch_one(
            """
            SELECT author, created_by, slot
            FROM presentations
            WHERE id = %s;
            """,
            (offer_id,)
        )

        db_author     = getattr(db, "author", None)
        db_created_by = getattr(db, "created_by", None)
        # db.slot też jest dostępny, jakbyś kiedyś chciał logikę per slot

        # brak danych – rekord nie istnieje / nie został załadowany
        if db_author is None and db_created_by is None:
            msg = f"Prezentacja o id:{offer_id} nie istnieje."
            msq.handle_error(
                f'Błąd zapisu prezentacji (użytkownik {username}): {msg}',
                log_path=logFileName
            )
            return jsonify({
                'success': False,
                'message': msg
            }), 404

        # BLOKADA: użytkownik NIE jest autorem i NIE jest created_by i NIE ma gold
        if (db_author != username and db_created_by != username) and not has_gold:
            msg = (
                f"Brak uprawnień do zarządzania prezentacją o id:{offer_id} "
                f"użytkownika {db_author} (zalogowany: {username})"
            )
            msq.handle_error(
                f'Błąd zapisu prezentacji (użytkownik {username}): {msg}',
                log_path=logFileName
            )
            return jsonify({
                'success': False,
                'message': msg
            }), 403

        # jeśli dotarliśmy tutaj:
        # - jesteś autorem LUB
        # - jesteś created_by LUB
        # - masz presentation-gold

        query = """
            UPDATE presentations SET
                title = %s,
                description = %s,
                slot = %s,
                author = %s,
                target = %s,
                updated_by = %s,
                updated_at = %s,                
                sync = 0
            WHERE id = %s
        """
        params = (
            title,
            description,
            slot,
            author,
            target,
            session['username'],        # NEW
            now,                        # updated_at
            offer_id
        )
    else:
        # jeśli dodawanie → tworzymy nowy rekord
        query = """
            INSERT INTO presentations
                (title, description, slot, author, target, created_by, updated_by, created_at, updated_at)
            VALUES
                (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        params = (
            title,
            description,
            slot,
            author,
            target,
            session['username'],   # created_by
            session['username'],   # updated_by (przy tworzeniu takie samo)
            now,
            now
        )


    success = db.executeTo(query, params)

    if not success:
        msq.handle_error(
            f'BŁĄD zapisu prezentacji (slot={slot}, title={title}) przez {session["username"]}',
            log_path=logFileName
        )
        return jsonify({
            'success': False,
            'message': 'Błąd bazy danych — nie udało się zapisać prezentacji.'
        }), 500

    # przy INSERT pobierz ID nowego rekordu
    if not is_edit:
        checkingIDparams = (
            now,
            now,
            title,
            description,
            slot,
            author,
            target
        )
        db.fetch_one(
            """
            SELECT id 
            FROM presentations 
            WHERE created_at=%s 
            AND updated_at=%s 
            AND title=%s 
            AND description=%s 
            AND slot=%s 
            AND author=%s 
            AND target=%s
            """, 
            checkingIDparams
        )
        offer_id = getattr(db, 'id', None)
        if offer_id is None:
            msq.handle_error(
                f'UWAGA! Nie udało się pobrać ID nowej prezentacji (slot={slot}, title={title})',
                log_path=logFileName
            )

    # --- ZAPIS PLIKU WIDEO (jeśli plik dostarczony) ---
    if video_file and offer_id:
        settingsDB = generator_settingsDB()

        # fizyczny root katalogu (np. /var/www/dmd-panel/)
        base_root = (settingsDB.get('real-location-on-server', '') or '').rstrip('/')
        base_root = Path(base_root)

        # relatywny katalog na prezentacje, np. "presentations" albo "static/presentations"
        pre_rel = (settingsDB.get('presentation-files', 'images/presentations/') or '').strip('/')
        rel_root = Path(pre_rel)  # np. "presentations"

        # katalog dla danego slotu: /var/www/.../presentations/green
        slot_dir = base_root / rel_root / slot
        slot_dir.mkdir(parents=True, exist_ok=True)

        # nazwa pliku powiązana z ID prezentacji, np. 42.mp4
        filename = f"{offer_id}.mp4"

        tmp_path  = slot_dir / f"{filename}.tmp"
        final_path = slot_dir / filename
        prev_path  = slot_dir / f"{filename}.bak"

        # zapisz tmp
        video_file.save(str(tmp_path))

        # rotacja poprzedniej wersji (zachowaj backup)
        if final_path.exists():
            try:
                final_path.replace(prev_path)
            except Exception as e:
                msq.handle_error(
                    f'UWAGA! Nie udało się zrobić backupu pliku wideo {final_path}: {e}',
                    log_path=logFileName
                )

        # atomowe przeniesienie tmp → final
        tmp_path.replace(final_path)

        # video_hash
        video_hash = generate_file_hash(final_path)

        # zbuduj PUBLICZNY URL pod którym RPi i TV zobaczą plik
        # np. main-domain = "https://panel.dmd.pl", presentation-files = "/presentations"
        main_domain = (settingsDB.get('main-domain', '') or '').rstrip('/')
        pres_rel_for_url = settingsDB.get('presentation-files', 'images/presentations/').strip('/')  # np. "presentations"

        rel_url_path = f"{pres_rel_for_url}/{slot}/{filename}".replace('\\', '/')
        video_url = f"{main_domain}/{rel_url_path}"

        
        # zapisz ścieżkę / URL pliku do bazy
        upd_q = """
            UPDATE presentations SET 
                video_path = %s, 
                video_hash=%s,
                video_duration_sec = %s,
                video_width = %s,
                video_width = %s,
                video_size_bytes = %s
            WHERE id = %s
        """
        upd_params = (video_url, video_hash, duration, v_width, v_height, v_size_bytes, offer_id)
        ok_video = db.executeTo(upd_q, upd_params)

        if not ok_video:
            msq.handle_error(
                f'BŁĄD: zapisano plik wideo na dysk, ale nie udało się zaktualizować video_path, video_hash, video_duration, video_width, video_height w bazie (ID={offer_id})',
                log_path=logFileName
            )

        # log techniczny
        msq.handle_error(
            f'Plik wideo dla prezentacji ID={offer_id} slot={slot} został zapisany w {final_path} (URL: {video_url}).',
            log_path=logFileName
        )



    msq.handle_error(
        f'Prezentacja {offer_id or "(nowa)"} slot={slot} zapisana przez {session["username"]} (author={author}, target={target}).',
        log_path=logFileName
    )

    flash('Prezentacja została zapisana pomyślnie!', 'success')
    return jsonify({
        'message': 'Prezentacja została zapisana pomyślnie!',
        'success': True
    }), 200

@app.route('/presentation-download/<int:presentation_id>', methods=["GET"])
def presentation_download(presentation_id):
    """
    Pobranie pliku wideo powiązanego z prezentacją.
    Wymaga zalogowania + uprawnienia 'presentation'.
    """

    # --- autoryzacja podstawowa ---
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(
            f'UWAGA! Wywołanie endpointa /presentation-download bez autoryzacji!',
            log_path=logFileName
        )
        return redirect(url_for('index'))

    if session['userperm'].get('presentation', 0) == 0:
        msq.handle_error(
            f'UWAGA! Próba użycia /presentation-download bez uprawnień przez {session.get("username")}',
            log_path=logFileName
        )
        flash('Nie masz uprawnień do pobierania prezentacji.', 'danger')
        return redirect(url_for('presentation_view'))

    db = get_db()

    # --- pobierz dane prezentacji: ścieżka do pliku + coś do nazwy ---
    db.fetch_one(
        """
        SELECT title, video_path
        FROM presentations
        WHERE id = %s;
        """,
        (presentation_id,)
    )

    title          = getattr(db, "title", None)
    video_path_db  = getattr(db, "video_path", None)

    if video_path_db is None:
        msg = f"Brak przypisanego pliku wideo dla prezentacji ID={presentation_id}."
        msq.handle_error(
            f'/presentation-download: {msg} (użytkownik {session.get("username")})',
            log_path=logFileName
        )
        flash("Brak pliku wideo dla tej prezentacji.", "warning")
        return redirect(url_for('presentation_view'))

    # --- zbuduj pełną ścieżkę na serwerze ---
    try:
        real_loc_on_server = settingsDB['real-location-on-server']  # np. "/var/www/app"
    except KeyError:
        # awaryjnie: katalog bieżący
        real_loc_on_server = "."

    # jeżeli w bazie jest pełny URL, odcinamy domenę
    if video_path_db.startswith('http://') or video_path_db.startswith('https://'):
        domain = settingsDB.get('main-domain', '')
        video_rel_path = video_path_db.replace(domain, '').lstrip('/')
    else:
        # jeśli ścieżka jest względna względem root-a aplikacji
        video_rel_path = video_path_db.lstrip('/')

    file_path = os.path.join(real_loc_on_server, video_rel_path)

    if not os.path.exists(file_path):
        msg = f"Plik wideo {file_path} dla prezentacji ID={presentation_id} nie istnieje na dysku."
        msq.handle_error(
            f'/presentation-download: {msg} (użytkownik {session.get("username")})',
            log_path=logFileName
        )
        flash("Plik wideo nie został znaleziony na serwerze.", "danger")
        return redirect(url_for('presentation_view'))

    # nazwa pliku przy pobieraniu – użyjemy fizycznej nazwy
    download_name = os.path.basename(file_path)
    # można by ewentualnie zrobić slug z title, ale nie ma takiej potrzeby na start

    msq.handle_error(
        f'Użytkownik {session.get("username")} pobiera prezentację ID={presentation_id} (plik: {file_path})',
        log_path=logFileName
    )

    # Flask 2.x: download_name; przy starszym Flasku użyj attachment_filename
    return send_file(
        file_path,
        as_attachment=True,
        download_name=download_name
    )

@app.route('/download-dev-script/<slot>/<platform>', methods=["GET"])
def download_dev_script(slot, platform):
    """
    Generowanie skryptów DEV do wywoływania trigera:
    /trigger/<slot>
    Skrypty działają tylko w sieci lokalnej.
    Uprawnienia: presentation-silver lub presentation-gold
    """

    # --- autoryzacja ---
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(
            f'UWAGA! Wywołanie /download-dev-script bez autoryzacji!',
            log_path=logFileName
        )
        return redirect(url_for('index'))

    userperm = session.get('userperm', {})
    username = session.get('username')

    can_dev = (
        userperm.get('presentation-silver', 0) == 1 or
        userperm.get('presentation-gold', 0) == 1
    )

    if not can_dev:
        msq.handle_error(
            f'UWAGA! {username} próbował pobrać DEV SCRIPT bez uprawnień.',
            log_path=logFileName
        )
        flash("Nie masz uprawnień do pobierania narzędzi DEV.", "danger")
        return redirect(url_for('presentation_view'))

    # --- walidacja slotu ---
    slot = slot.lower()
    if slot not in ("gold", "silver", "green"):
        return "Invalid slot", 400

    # --- walidacja platformy ---
    platform = platform.lower()
    if platform not in ("windows", "macos", "android", "ios"):
        return "Invalid platform", 400

    # --- adres Huba ---
    # HUB_URL = http://raspberrypi-tv:5000 lub to, co masz w settings
    settingsDB = generator_settingsDB()
    HUB_URL = settingsDB.get('rpi-api-addr', 'http://localhost:3000')
    AMPIO_TOKEN = settingsDB.get('rpi-api-token', 'bad-token')

    # --- sprawdź, czy mamy token ---
    if not AMPIO_TOKEN:
        # możesz zalogować ostrzeżenie, że token nie jest skonfigurowany
        msq.handle_error(
            "Brak skonfigurowanego AMPIO_TOKEN dla skryptów DEV!",
            log_path=logFileName
        )

    if platform == "windows":
        filename = f"dmd_trigger_{slot}.bat"
        content = f"""@echo off
echo Wywolywanie trigera dla slota: {slot}
echo Pamietaj: Ten skrypt dziala tylko w sieci lokalnej DMD.
curl "{HUB_URL}/trigger/{slot}/{AMPIO_TOKEN}"
pause
"""

    elif platform == "macos":
        filename = f"dmd_trigger_{slot}.command"
        content = f"""#!/bin/bash
echo "Wywolywanie trigera dla slota: {slot}"
echo "Pamietaj: Ten skrypt dziala tylko w sieci lokalnej DMD."
curl "{HUB_URL}/trigger/{slot}/{AMPIO_TOKEN}"
"""

    elif platform == "android":
        filename = f"dmd_trigger_{slot}.sh"
        content = f"""#!/data/data/com.termux/files/usr/bin/bash
echo "Wywolywanie trigera dla slota: {slot}"
echo "Uruchom w Termuxie w sieci DMD."
curl "{HUB_URL}/trigger/{slot}/{AMPIO_TOKEN}"
"""

    elif platform == "ios":
        filename = f"dmd_trigger_{slot}.sh"
        content = f"""#!/bin/bash
echo "Wywolywanie trigera dla slota: {slot}"
echo "UWAGA: iOS wymaga uruchomienia skryptu przez aplikacje typu iSH/Shell."
curl "{HUB_URL}/trigger/{slot}/{AMPIO_TOKEN}"
"""
    # --- log ---
    msq.handle_error(
        f'User {username} pobral DEV SCRIPT: {filename}',
        log_path=logFileName
    )

    # --- wysyłamy skrypt jako plik do pobrania ---
    return Response(
        content,
        mimetype="text/plain",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


@app.route('/update-presentation-status', methods=['POST'])
def update_presentation_status():
    # --- autoryzacja ---
    if 'username' not in session:
        msq.handle_error(
            f'UWAGA! Wywołanie endpointa /update-presentation-status bez autoryzacji!',
            log_path=logFileName
        )
        return redirect(url_for('index'))
    
    if session['userperm'].get('presentation', 0) == 0:
        msq.handle_error(
            f'UWAGA! Próba zarządzania /update-presentation-status bez uprawnień przez {session["username"]}!',
            log_path=logFileName
        )
        flash(
            'Nie masz uprawnień do zarządzania prezentacjami. Skontaktuj się z administratorem!',
            'danger'
        )
        return redirect(url_for('index'))

    # --- dane z formularza ---
    post_id    = request.form.get('PostID')
    new_status = request.form.get('Status')
    slot       = (request.form.get('slot') or '').strip().lower()

    if not post_id or not new_status:
        return jsonify({
            'success': False,
            'message': 'Brak wymaganych danych (PostID / Status).'
        }), 400

    try:
        post_id_int = int(post_id)
    except ValueError:
        return jsonify({
            'success': False,
            'message': 'Nieprawidłowy identyfikator prezentacji.'
        }), 400

    # w tej logice obsługujemy tylko aktywację (Status = 1)
    if new_status != '1':
        return jsonify({
            'success': False,
            'message': 'Nieobsługiwany status – prezentację można tylko aktywować.'
        }), 400

    if slot not in ('green', 'silver', 'gold'):
        return jsonify({
            'success': False,
            'message': 'Nieprawidłowy slot prezentacji.'
        }), 400

    # --- ZAPIS DO BAZY ---
    db = get_db()

    # 1) dezaktywuj wszystkie prezentacje w tym slocie
    query_reset = """
        UPDATE presentations
        SET status = 0, sync = 0
        WHERE slot = %s
    """
    params_reset = (slot,)
    success_reset = db.executeTo(query_reset, params_reset)

    if not success_reset:
        msq.handle_error(
            f'BŁĄD przy dezaktywowaniu prezentacji w slocie {slot} (użytkownik {session["username"]})',
            log_path=logFileName
        )
        return jsonify({
            'success': False,
            'message': 'Błąd bazy danych — nie udało się dezaktywować pozostałych prezentacji dla tego slotu.'
        }), 500

    # 2) aktywuj wskazaną prezentację
    query_set = """
        UPDATE presentations
        SET status = 1
        WHERE id = %s
    """
    params_set = (post_id_int,)
    success_set = db.executeTo(query_set, params_set)

    if not success_set:
        msq.handle_error(
            f'BŁĄD przy aktywowaniu prezentacji ID={post_id_int} (slot={slot}) przez {session["username"]}',
            log_path=logFileName
        )
        return jsonify({
            'success': False,
            'message': 'Błąd bazy danych — nie udało się aktywować wybranej prezentacji.'
        }), 500

    msq.handle_error(
        f'Aktywowano prezentację ID={post_id_int} w slocie {slot} przez {session["username"]}',
        log_path=logFileName
    )

    flash('Prezentacja została aktywowana dla wybranego slotu.', 'success')

    # jeśli używasz klasycznego formularza (bez fetch), to lepiej przekierować:
    return redirect(request.referrer or url_for('presentation_view'))
    # jeśli wolisz wersję JSON pod fetch(), zamień powyższą linię na:
    # return jsonify({
    #     'success': True,
    #     'message': 'Prezentacja została aktywowana.'
    # }), 200

@app.route('/force-resync', methods=['POST'])
def force_resync():
    # --- autoryzacja ---
    if 'username' not in session:
        msq.handle_error(
            f'UWAGA! Wywołanie endpointa /force-resync bez autoryzacji!',
            log_path=logFileName
        )
        return jsonify({
            'success': False,
            'message': 'Brak autoryzacji – zaloguj się ponownie.'
        }), 401

    if session['userperm'].get('presentation', 0) == 0:
        msq.handle_error(
            f'UWAGA! Próba zarządzania /force-resync bez uprawnień przez {session["username"]}!',
            log_path=logFileName
        )
        return jsonify({
            'success': False,
            'message': 'Nie masz uprawnień do zarządzania prezentacjami.'
        }), 403

    # --- dane z formularza ---
    post_id = request.form.get('PostID')
    slot    = (request.form.get('slot') or '').strip().lower()

    if not post_id or not slot:
        return jsonify({
            'success': False,
            'message': 'Brak wymaganych danych (PostID / slot).'
        }), 400

    try:
        post_id_int = int(post_id)
    except ValueError:
        return jsonify({
            'success': False,
            'message': 'Nieprawidłowy identyfikator prezentacji.'
        }), 400

    if slot not in ('green', 'silver', 'gold'):
        return jsonify({
            'success': False,
            'message': 'Nieprawidłowy slot prezentacji.'
        }), 400

    db = get_db()

    # Opcjonalnie – upewniamy się, że prezentacja istnieje i jest aktywna
    query_check = """
        SELECT id, status, sync, slot
        FROM presentations
        WHERE id = %s AND slot = %s
        LIMIT 1
    """
    row_list = db.getFrom(query=query_check, params=(post_id_int, slot), as_dict=True)
    if not row_list:
        return jsonify({
            'success': False,
            'message': 'Nie znaleziono prezentacji o podanym ID/slot.'
        }), 404

    row = row_list[0]
    if row.get('status') != 1:
        # Możesz to dopuścić, ale lepiej jasno komunikować:
        return jsonify({
            'success': False,
            'message': 'Wymusić synchronizację można tylko dla aktywnej prezentacji.'
        }), 400

    # --- ustawiamy flagi force_resync ---
    query_update = """
        UPDATE presentations
        SET
            sync             = 0,
            video_hash       = %s,
            last_sync_status = %s,
            last_sync_error  = NULL
        WHERE id = %s AND slot = %s
    """
    params_update = (
        'FORCE_RESYNC',
        'manual_force_resync',
        post_id_int,
        slot
    )

    success_update = db.executeTo(query_update, params_update)

    if not success_update:
        msq.handle_error(
            f'BŁĄD przy force-resync prezentacji ID={post_id_int} (slot={slot}) przez {session["username"]}',
            log_path=logFileName
        )
        return jsonify({
            'success': False,
            'message': 'Błąd bazy danych – nie udało się ustawić flagi wymuszonej synchronizacji.'
        }), 500

    msq.handle_error(
        f'Wymuszono ponowną synchronizację prezentacji ID={post_id_int} w slocie {slot} przez {session["username"]}',
        log_path=logFileName
    )

    return jsonify({
        'success': True,
        'message': 'Wymuszono ponowną synchronizację – RPi pobierze plik przy najbliższym cyklu.'
    }), 200


@app.route('/remove-presentation', methods=["POST"])
def remove_presentation():
    """Usuwanie prezentacji (rekord + plik wideo)."""

    # --- autoryzacja ---
    if 'username' not in session or 'userperm' not in session:
        msq.handle_error(
            f'UWAGA! Wywołanie endpointa /remove-presentation bez autoryzacji!',
            log_path=logFileName
        )
        return redirect(url_for('index'))
    
    if session['userperm'].get('presentation', 0) == 0:
        msq.handle_error(
            f'UWAGA! Próba zarządzania /remove-presentation bez uprawnień przez {session["username"]}!',
            log_path=logFileName
        )
        flash('Nie masz uprawnień do zarządzania prezentacjami. Skontaktuj się z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # --- Obsługa formularza POST ---
    if request.method == 'POST':
        form_data = request.form.to_dict()
        msq.handle_error(f'/remove-presentation form_data: {form_data}!', log_path=logFileName)

        # Walidacja PostID
        if 'PostID' not in form_data:
            flash("Brak identyfikatora prezentacji.", "danger")
            return redirect(url_for('presentation_view'))  # widok listy prezentacji

        try:
            set_post_id = int(form_data['PostID'])
        except ValueError:
            flash("Nieprawidłowy identyfikator prezentacji.", "danger")
            return redirect(url_for('presentation_view'))

        db = get_db()

        userperm = session.get('userperm', {}) or {}
        username = session.get('username')
        has_gold = True if userperm.get('presentation-gold', 0) == 1 else False

        # --- Pobranie danych prezentacji (autor, created_by, slot, ścieżka pliku) ---
        db.fetch_one(
            """
            SELECT author, created_by, slot, video_path
            FROM presentations
            WHERE id = %s;
            """,
            (set_post_id,)
        )

        db_author     = getattr(db, "author", None)
        db_created_by = getattr(db, "created_by", None)
        slot          = getattr(db, "slot", None)
        video_path_db = getattr(db, "video_path", None)

        # brak danych – rekord nie istnieje / nie został załadowany
        if db_author is None and db_created_by is None:
            msg = f"Prezentacja o id:{set_post_id} nie istnieje."
            msq.handle_error(
                f'Błąd usuwania prezentacji (użytkownik {username}): {msg}',
                log_path=logFileName
            )
            flash("Prezentacja nie została znaleziona.", "danger")
            return redirect(url_for('presentation_view'))

        # BLOKADA: użytkownik NIE jest autorem i NIE jest created_by i NIE ma gold
        if (db_author != username and db_created_by != username) and not has_gold:
            msg = (
                f"Brak uprawnień do usunięcia prezentacji o id:{set_post_id} "
                f"użytkownika {db_author} (zalogowany: {username})"
            )
            msq.handle_error(
                f'Błąd usuwania prezentacji (użytkownik {username}): {msg}',
                log_path=logFileName
            )
            flash("Nie masz uprawnień do usunięcia tej prezentacji.", "danger")
            return redirect(url_for('presentation_view'))

        # jeśli dotarliśmy tutaj:
        # - jesteś autorem LUB
        # - jesteś created_by LUB
        # - masz presentation-gold

        # --- Usunięcie rekordu z tabeli presentations ---
        if not db.executeTo(
            """
            DELETE FROM presentations
            WHERE id = %s;
            """,
            (set_post_id,)
        ):
            msq.handle_error(
                f'UWAGA! Prezentacja ID={set_post_id} nie została usunięta z bazy przez {username}!',
                log_path=logFileName
            )
            flash("Prezentacja nie została usunięta z bazy!", "danger")
            return redirect(url_for('presentation_view'))

        # --- Usunięcie pliku MP4 z serwera (jeśli jest zdefiniowany) ---
        if video_path_db:
            try:
                # Przykładowa konfiguracja – DOSTOSUJ klucze do swoich settings
                real_loc_on_server = settingsDB['real-location-on-server']  # np. "/var/www/app"

                # jeżeli video_path_db jest ścieżką URL (z domeną), czyścimy domenę
                if video_path_db.startswith('http://') or video_path_db.startswith('https://'):
                    domain = settingsDB.get('main-domain', '')
                    video_rel_path = video_path_db.replace(domain, '').lstrip('/')
                else:
                    video_rel_path = video_path_db.lstrip('/')

                file_path = os.path.join(real_loc_on_server, video_rel_path)

                if os.path.exists(file_path):
                    os.remove(file_path)
                    msq.handle_error(
                        f'Plik wideo {file_path} powiązany z prezentacją ID={set_post_id} został usunięty przez {username}.',
                        log_path=logFileName
                    )
                else:
                    msq.handle_error(
                        f'Plik wideo {file_path} powiązany z prezentacją ID={set_post_id} nie został znaleziony na dysku.',
                        log_path=logFileName
                    )
            except Exception as e:
                msq.handle_error(
                    f'UWAGA! Error removing presentation video file ({video_path_db}) dla ID={set_post_id}: {e}',
                    log_path=logFileName
                )

        msq.handle_error(
            f'Prezentacja ID={set_post_id} została usunięta przez {username}!',
            log_path=logFileName
        )
        flash("Prezentacja została usunięta.", "success")
        return redirect(url_for('presentation_view'))

    return redirect(url_for('index'))


if __name__ == '__main__':
    # app.run(debug=True, port=8000)
    app.run(debug=True, host='0.0.0.0', port=8000)
    # app.run(debug=False, host='0.0.0.0', port=8000)