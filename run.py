from flask import Flask, render_template, redirect, url_for, flash, jsonify, session, request
from flask_wtf import FlaskForm
from flask_paginate import Pagination, get_page_args
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename
import secrets
import app.utils.passwordSalt as hash
import mysqlDB as msq
import time
import datetime
import os
import random
import string
import adminSmtpSender as mails
from googletrans import Translator
import json
import html
from markupsafe import Markup
import subprocess
import regions
from flask_session import Session
from PIL import Image


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
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=10)  # Czas wygaśnięcia sesji (10 minut)

Session(app)

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
        'last-restart': take_data_settingsDB('last_restart'),
        'domy': take_data_settingsDB('domy'),
        'budownictwo': take_data_settingsDB('budownictwo'),
        'development': take_data_settingsDB('development'),
        'elitehome': take_data_settingsDB('elitehome'),
        'inwestycje': take_data_settingsDB('inwestycje'),
        'instalacje': take_data_settingsDB('instalacje'),
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

def generator_userDataDB():
    took_usrD = take_data_table('*', 'admins')
    userData = []
    for data in took_usrD:
        theme = {
            'id': data[0], 
            'username': data[2],
            'password': data[3], 
            'salt' : data[4], 
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
                'career': data[32] # kolejne uprawnienie wzz. dmd budownictwo kariera
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
            'link': data[3]
            }
        groupsData.append(theme)
    return groupsData

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

def getLangText(text):
    """Funkcja do tłumaczenia tekstu z polskiego na angielski"""
    translator = Translator()
    translation = translator.translate(str(text), dest='en')
    return translation.text

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
                    category, section, id_gallery, data_aktualizacji
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
            None, None, None, None
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

def takeOtodomResumeStatus(otodom_id):
    try:
        return msq.connect_to_database(f'SELECT action_before_errors FROM ogloszenia_otodom WHERE id="{otodom_id}";')[0][0]
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
def restart_pm2_tasks_signal():
    try:
        # Utworzenie pliku sygnału
        with open('/tmp/restart_pm2.signal', 'w') as f:
            f.write('restart')
        return True
    except Exception as e:
        print(f"Błąd podczas restartu tasków PM2: {e}")
        return False

def apply_logo_to_image(image_path, logo_path, output_path, scale_factor=1):
    # Otwórz obraz główny i logo
    image = Image.open(image_path)
    logo = Image.open(logo_path)

    # Skalowanie logo
    image_width, image_height = image.size
    logo_width, logo_height = logo.size

    # Obliczenie nowych rozmiarów logo proporcjonalnie do rozmiaru zdjęcia
    new_logo_width = int(image_width * scale_factor)
    new_logo_height = int(logo_height * (new_logo_width / logo_width))
    logo = logo.resize((new_logo_width, new_logo_height), Image.LANCZOS)

    # Ustawienie przezroczystości logo
    logo = logo.convert("RGBA")

    # Ustawienie przezroczystości obrazu głównego
    image = image.convert("RGBA")

    # Pozycja logo w prawym dolnym rogu
    position = (image_width - new_logo_width, image_height - new_logo_height)

    # Nałożenie logo na obraz
    image.paste(logo, position, logo)

    # Sprawdzenie formatu wyjściowego
    if str(output_path).lower().endswith('.png')\
        or str(output_path).lower().endswith('.webp'):
        final_image = image  # Zostawiamy przezroczystość
    else:
        final_image = image.convert("RGB")  # Konwersja do RGB dla JPEG i innych formatów bez przezroczystości
    
    # Konwersja z powrotem do formatu RGB, aby zapisać jako JPG
    final_image.save(output_path, format='JPEG')

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

def get_last_20_lines(file_path: str) -> list:
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
            return lines[-20:][::-1]   # Zwraca ostatnie 20 niepustych linii
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

settingsDB = generator_settingsDB()
app.config['PER_PAGE'] = settingsDB['pagination']  # Określa liczbę elementów na stronie
newsletterSettingDB = generator_newsletterSettingDB()
userDataDB = generator_userDataDB()
teamDB = generator_teamDB()
subsDataDB = generator_subsDataDB()
daneDBList = generator_daneDBList()

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

            return redirect(url_for('index'))
        elif int(users_data[username]['status']) == 0:
            flash('Konto nie aktywne!', 'danger')
        else:
            flash('Błędne nazwa użytkownika lub hasło', 'danger')

    return render_template('gateway.html', form=form)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('userperm', None)
    session.pop('user_data', None)

    return redirect(url_for('index'))

@app.route('/home')
def home():
    """Strona główna."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej    
    if 'username' not in session:
        return redirect(url_for('index'))
    
    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']
    
    return render_template(
                            "home.html", 
                            userperm=session['userperm'], 
                            username=session['username'], 
                            users_data=session['user_data'],
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje
                            )

@app.route('/fetch-messages')
def fetch_messages():
    messages = get_messages('last')
    return jsonify(messages)

@app.route('/send-chat-message', methods=['POST'])
def send_chat_message():
    """Strona z zarządzaniem czatem."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    data = request.get_json()
    
    new_message = save_chat_message(user_name=session['username'], content=data['content'], status=0)
    if new_message:
        return jsonify({"status": "success"}), 201
    else:
        return jsonify({"status": "error"}), 500

@app.route('/blog')
def blog(router=True):
    """Strona z zarządzaniem blogiem."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['blog'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
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
        # Renderowanie szablonu blog-managment.html z danymi o postach (wszystkimi lub po jednym)
        settingsDB = generator_settingsDB()
        domy = settingsDB['domy']
        budownictwo = settingsDB['budownictwo']
        development = settingsDB['development']
        elitehome = settingsDB['elitehome']
        inwestycje = settingsDB['inwestycje']
        instalacje = settingsDB['instalacje']

        return render_template(
                            "blog_management.html", 
                            posts=posts, 
                            username=session['username'], 
                            userperm=session['userperm'], 
                            pagination=pagination,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje
                            )
    else:
        return posts, session['username'], session['userperm'], pagination

@app.route('/update-password-user', methods=['GET', 'POST'])
def update_password_user():
    """Aktualizacja awatara usera"""

    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
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
                    flash('Nieprawidłowe stare hasło', 'danger')
                    return redirect(url_for('index'))
                
            if PAGE == 'users':
                if session['userperm']['users'] == 0:
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
                userDataDB = generator_userDataDB()
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
                return redirect(url_for('home'))
            
        if form_data['page'] == 'users':
            if session['userperm']['users'] == 0:
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
                flash('Dane zostały pomyślnie zaktualizowane.', 'success')
            return redirect(url_for('users'))
    return redirect(url_for('index'))

@app.route('/update-avatar', methods=['GET', 'POST'])
def update_avatar():
    """Aktualizacja awatara usera"""

    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
        
    # Pobierz id usera z formularza
    if request.method == 'POST':
        form_data = request.form.to_dict()

        set_ava_id = form_data['user_id'].split('_')[0]
        set_page = form_data['user_id'].split('_')[1]

        if set_page == 'users':
            if session['userperm']['users'] == 0:
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
            userDataDB = generator_userDataDB()
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
            flash('Avatar został zmieniony ','success')
        else:
            flash('Nieprawidłowy format pliku! ','danger')
    else:
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
        return redirect(url_for('index'))
    
    if session['userperm']['users'] == 0:
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
        print(f'Usunieto użytkownika {ADMIN_NAME} o loginie {LOGIN} z bazy admins.')
        # Usuwanie danych z workers_team
        msq.delete_row_from_database(
            """
            DELETE FROM workers_team WHERE EMPLOYEE_NAME = %s AND EMAIL = %s;
            """,
            (ADMIN_NAME, EMAIL)
        )
        print(f'Usunieto użytkownika {ADMIN_NAME} o emailu {EMAIL} z bazy workers_team.')
        flash(f'Pomyślnie usunięto użytkownika {ADMIN_NAME}.', 'success')
        return redirect(url_for('users'))
    
    return redirect(url_for('index'))

@app.route('/update-permission', methods=['POST'])
def update_permission():
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['users'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    data = request.json
    perm_id = int(data.get('perm_id'))
    user_id = int(data.get('user_id'))
    perm_type= int(data.get('permissionType'))
    permission = data.get('permission')
    print([perm_id], [user_id], [perm_type], [permission])

    perm_name = None
    if perm_id == 1: perm_name = 'Zarządzanie Użytkownikami'
    if perm_id == 2: perm_name = 'Zarządzanie Brendami'
    if perm_id == 3: perm_name = 'Zarządzanie Blogiem'
    if perm_id == 4: perm_name = 'Zarządzanie Subskrybentami'
    if perm_id == 5: perm_name = 'Zarządzanie Komentarzami'
    if perm_id == 6: perm_name = 'Zarządzanie Personelem'
    if perm_id == 7: perm_name = 'Zarządzanie Uprawnieniami'
    if perm_id == 8: perm_name = 'Zarządzanie Newsletterem'
    if perm_id == 9: perm_name = 'Zarządzanie Ustawieniami'

    if perm_id == 16: perm_name = 'Zarządzanie Ogłoszeniami'
    if perm_id == 17: perm_name = 'Zarządzanie Karierą'

    if perm_id == 10: perm_name = 'Przynależność do DMD Domy'
    if perm_id == 11: perm_name = 'Przynależność do DMD Budownictwo'
    if perm_id == 12: perm_name = 'Przynależność do DMD EliteHome'
    if perm_id == 13: perm_name = 'Przynależność do DMD Inwestycje'
    if perm_id == 14: perm_name = 'Przynależność do DMD Instalacje'
    if perm_id == 15: perm_name = 'Przynależność do DMD Development'

    if perm_id in [1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 9, 16, 17]:
        if session['userperm']['permissions'] == 0:
            flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
            return redirect(url_for('users'))
        #Aktualizacja uprawnienia
        if perm_id == 1: 
            'Zarządzanie Użytkownikami'
            zapytanie_sql = '''UPDATE admins SET PERM_USERS = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})

        if perm_id == 2:
            'Zarządzanie Brendami'
            zapytanie_sql = '''UPDATE admins SET PERM_BRANDS = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})
        if perm_id == 3: 
            'Zarządzanie Blogiem'
            zapytanie_sql = '''UPDATE admins SET PERM_BLOG = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})
        if perm_id == 4: 
            'Zarządzanie Subskrybentami'
            zapytanie_sql = '''UPDATE admins SET PERM_SUBS = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})
        if perm_id == 5: 
            'Zarządzanie Komentarzami'
            zapytanie_sql = '''UPDATE admins SET PERM_COMMENTS = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})
        if perm_id == 6: 
            'Zarządzanie Personelem'
            zapytanie_sql = '''UPDATE admins SET PERM_TEAM = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})
        if perm_id == 7: 
            'Zarządzanie Uprawnieniami'
            zapytanie_sql = '''UPDATE admins SET PERM_PERMISSIONS = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})
        if perm_id == 8: 
            'Zarządzanie Newsletterem'
            zapytanie_sql = '''UPDATE admins SET PERM_NEWSLETTER = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})
        if perm_id == 9: 
            'Zarządzanie Ustawieniami'
            zapytanie_sql = '''UPDATE admins SET PERM_SETTINGS = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})
        
        if perm_id == 16: 
            'Zarządzanie Ogłoszeniami'
            zapytanie_sql = '''UPDATE admins SET PERM_ESTATE = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})
        
        if perm_id == 17: 
            'Zarządzanie Karierą'
            zapytanie_sql = '''UPDATE admins SET PERM_CAREER = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})
    
    if perm_id in [10, 11, 12, 13, 14, 15]:
        if session['userperm']['brands'] == 0:
            flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
            return redirect(url_for('users'))
        #Aktualizacja przynależności
        if perm_id == 10: 
            'Przynależność do DMD Domy'
            zapytanie_sql = '''UPDATE admins SET BRANDS_DOMY = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})
        if perm_id == 11: 
            'Przynależność do DMD Budownictwo'
            zapytanie_sql = '''UPDATE admins SET BRANDS_BUDOWNICTWO = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})
        if perm_id == 12: 
            'Przynależność do DMD EliteHome'
            zapytanie_sql = '''UPDATE admins SET BRANDS_ELITEHOME = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})
        if perm_id == 13: 
            'Przynależność do DMD Inwestycje'
            zapytanie_sql = '''UPDATE admins SET BRANDS_INWESTYCJE = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})
        if perm_id == 14: 
            'Przynależność do DMD Instalacje'
            zapytanie_sql = '''UPDATE admins SET BRANDS_INSTALACJE = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})
        if perm_id == 15: 
            'Przynależność do DMD Development'
            zapytanie_sql = '''UPDATE admins SET BRANDS_DEVELOPMENT = %s WHERE ID = %s;'''
            if permission: onOff = 1
            else: onOff = 0
            dane = (onOff, user_id)
            if msq.insert_to_database(zapytanie_sql, dane):
                return jsonify({'success': True, 'message': f'{perm_name} zostało zaktualizowane.', 'user_id': user_id})

    return jsonify({'success': False, 'message': 'Coś poszło nie tak, zgłoś to Administratorowi', 'user_id': user_id})

@app.route('/update-user-status', methods=['GET', 'POST'])
def update_user_status():
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['users'] == 0:
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
            return redirect(url_for('users'))
    flash('Zmiana statusu nie powiodła się, skontaktuj się z Administratorem Systemu!', 'danger')
    return redirect(url_for('users'))

@app.route('/add-new-user', methods=['GET', 'POST'])
def save_new_user():
    """Strona zapisywania edytowanego posta."""
    
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['users'] == 0:
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
                        <h1>Szanowny {NAME}, witamy w firmie DMD!</h1>
                        <p>Ta wiadomość została wygenerowana automatycznie i zawiera ważne informacje dotyczące Twojego dostępu do systemów informatycznych firmy DMD.</p>
                        <p>Jesteśmy przekonani, że Twoje doświadczenie i zaangażowanie wniosą znaczący wkład w nasz zespół. Poniżej znajdziesz dane dostępowe, które umożliwią Ci logowanie do naszego systemu.</p>
                        <p><strong>Dane do logowania:</strong></p>
                        <ul>
                            <li>Login: {LOGIN}</li>
                            <li>Hasło: {TEXT_PASSWORD}</li>
                        </ul>
                        <p>Zachęcamy do zmiany hasła przy pierwszym logowaniu w celu zapewnienia bezpieczeństwa danych. Jeśli nie planujesz w najbliższym czasie korzystać z systemu, możesz zignorować tę wiadomość.</p>
                        <p>W razie pytań lub potrzeby wsparcia, nasz zespół IT jest do Twojej dyspozycji. Skontaktuj się z nami wysyłając wiadomość na adres: support@dmd.com</p>
                        <p>Życzymy Ci owocnej współpracy i sukcesów w realizacji powierzonych zadań.</p>
                        <p>Z wyrazami szacunku,<br/>Zespół DMD</p>
                        </body></html>
                        """
                to_email = EMAIL
                mails.send_html_email(subject, html_body, to_email)
                flash('Administrator został dodany', 'success')
                return redirect(url_for('users'))
            else:
                flash('Nie udało się dodać administratora', 'danger')
                return redirect(url_for('users'))
    return redirect(url_for('users'))

@app.route('/save-blog-post', methods=['GET', 'POST'])
def save_post():
    """Strona zapisywania edytowanego posta."""
       
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['blog'] == 0:
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
            
            users_data = generator_userDataDB()
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
                    flash(f'Błąd podczas tworzenia nowego posta! \n {err}', 'danger')
                    return redirect(url_for('blog'))
            else:
                flash(f'Błąd podczas tworzenia nowego posta', 'danger')
                return redirect(url_for('blog'))
            if msq.insert_to_database(
                    '''
                        INSERT INTO blog_posts (CONTENT_ID, AUTHOR_ID) VALUES(%s, %s);
                    ''', 
                    (ID_NEW_POST_CONTENT, ID_AUTHOR)):
                flash('Dane zostały zapisane poprawnie!', 'success')
                return redirect(url_for('blog'))
            else:
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
                flash('Dane zostały zapisane poprawnie!', 'success')
                return redirect(url_for('blog'))
        
            flash('Dane zostały zapisane poprawnie!', 'success')
            print('Dane zostały zapisane poprawnie!')
            
            return redirect(url_for('blog'))
    flash('Błąd!', 'danger')
    return redirect(url_for('index'))

@app.route('/remove-post', methods=['POST'])
def remove_post():
    """Usuwanie bloga"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['blog'] == 0:
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
        flash("Wpis został usunięty.", "success")
        return redirect(url_for('blog'))
    
    return redirect(url_for('index'))

@app.route('/remove-comment', methods=['POST'])
def remove_comment():
    """Usuwanie komentarza"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['commnets'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        form_data = request.form.to_dict()

        try: form_data['comment_id']
        except KeyError: return redirect(url_for('index'))
        set_comm_id = int(form_data['comment_id'])

        print(set_comm_id)
        msq.delete_row_from_database(
                """
                    DELETE FROM comments WHERE ID = %s;
                """,
                (set_comm_id,)
            )

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
        return redirect(url_for('index'))
    
    if session['userperm']['subscribers'] == 0:
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
            flash('Subskryber został usunięty!', 'success')
            return redirect(url_for('subscribers'))
    flash('Błąd usuwania Subskrybenta!', 'danger')
    return redirect(url_for('subscribers'))

@app.route('/set-newsletter-plan', methods=['POST'])
def set_plan():
    """Usuwanie planu"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['newsletter'] == 0:
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
            flash('Plan został aktywowany!', 'success')
            return redirect(url_for('newsletter'))

    return redirect(url_for('newsletter'))

@app.route('/set-newsletter-sender', methods=['POST'])
def set_sender():
    """Usuwanie planu"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['newsletter'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        form_data = request.form.to_dict()
        print(form_data)
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
            flash('Nadawca został ustawiony!', 'success')
            return redirect(url_for('newsletter'))
        
    flash('Błąd! Nadawca nie został ustawiony!', 'danger')
    return redirect(url_for('newsletter'))

@app.route('/set-settings', methods=['POST'])
def set_settings():
    """settings"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['settings'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        form_data = request.form.to_dict()

        upload_path = '/var/www/html/appdmddomy/public/'+settingsDB['estate-pic-offer']
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
        if ADMIN_PASSWORD == '':
            
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
                        estate_pic_offer = %s
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
                        ADMIN_ESTATE, 1)
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
                        estate_pic_offer = %s
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
                    ADMIN_ESTATE, 1)
        if msq.insert_to_database(zapytanie_sql, dane):
            flash('Ustawienia zapisane!', 'success')
            return redirect(url_for('settings'))
        
    flash('Błąd podczas zapisu ustawień!', 'danger')
    return redirect(url_for('settings'))

@app.route('/user')
def users(router=True):
    """Strona z zarządzaniem użytkownikami."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['users'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    userDataDB = generator_userDataDB()
    all_users = userDataDB

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(all_users)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    users = all_users[offset: offset + per_page]
    if router:
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
                            instalacje=instalacje
            )
    else:
        return users, session['username'], session['userperm'], pagination
    

@app.route('/newsletter')
def newsletter():
    """Strona Newslettera."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['newsletter'] == 0:
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

    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']

    return render_template(
                            "newsletter_management.html", 
                            username=session['username'],
                            userperm=session['userperm'], 
                            newsletterPlan=newsletterPlan, 
                            smtpSettingsDict=smtpSettingsDict,
                            sortedListSubs=sortedListSubs,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje
                            )

@app.route('/team-domy', methods=['GET', 'POST'])
def team_domy():
    """Strona zespołu domy."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['team'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    

    users_atributes = {}
    assigned_dmddomy = []
    
    for usr_d in generator_userDataDB():
        u_name = usr_d['name']
        u_login = usr_d['username']
        users_atributes[u_name] = usr_d
        if usr_d['brands']['domy'] == 1:
            assigned_dmddomy.append(u_login)

    collections = {
            'domy': {
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
        
        if i_domy < 5 and department == "domy":
            collections[department]['home'].append(employee_login)
        elif i_domy >= 5 and department == "domy":
            collections[department]['team'].append(employee_login)
        if department == 'domy':
            i_domy += 1
        
    for assign in assigned_dmddomy:
        if assign not in collections['domy']['home'] + collections['domy']['team']:
            collections['domy']['available'].append(assign)

            for row in generator_userDataDB():
                if row['username'] == assign:
                    employee_photo = row['avatar']
                    try: employee_photo_dict[assign]
                    except KeyError: employee_photo_dict[assign] = employee_photo

    # Tutaj złapane dane
    if request.method == 'POST':
        data = request.get_json()
        sequence_data = data.get('sequence', [])
        sequence = []
        for s in sequence_data:
            clear_data = s.strip()
            sequence.append(clear_data)

        users_atributesByLogin = {}
        for usr_d in generator_userDataDB():
            u_login = usr_d['username']
            users_atributesByLogin[u_login] = usr_d
        
        ready_exportDB = []
        for u_login in sequence:
            set_row = {
                'EMPLOYEE_PHOTO': users_atributesByLogin[u_login]['avatar'],
                'EMPLOYEE_NAME': users_atributesByLogin[u_login]['name'],
                'EMPLOYEE_ROLE': users_atributesByLogin[u_login]['stanowisko'],
                'EMPLOYEE_DEPARTMENT': 'dmd domy',
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
                ('dmd domy', )
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
                    flash(f'Ustwiono {row["EMPLOYEE_NAME"]}.', 'success')

        else:
            flash('Błąd! Zespół nie został zmieniony.', 'danger')
            return redirect(url_for('team_domy'))
        print('dane:', ready_exportDB)
        flash('Zespół został pomyślnie zmieniony.', 'success')


    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']

    # update sesji userperm brands
    permTempDict = {}
    brands_data = {}
    for un in generator_userDataDB(): 
        permTempDict[un['username']] = un['uprawnienia']
        brands_data[un['username']] = un['brands']

    session['userperm'] = permTempDict[session['username']]
    session['brands'] = brands_data[session['username']]

    return render_template(
                            "team_management_domy.html", 
                            username=session['username'],
                            userperm=session['userperm'], 
                            user_brands=session['brands'], 
                            members=collections['domy'], 
                            photos_dict=employee_photo_dict,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje
                            )

@app.route('/team-elitehome', methods=['GET', 'POST'])
def team_elitehome():
    """Strona zespołu elitehome."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['team'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    

    users_atributes = {}
    assigned_dmdelitehome = []
    
    for usr_d in generator_userDataDB():
        u_name = usr_d['name']
        u_login = usr_d['username']
        users_atributes[u_name] = usr_d
        if usr_d['brands']['elitehome'] == 1:
            assigned_dmdelitehome.append(u_login)

    collections = {
            'elitehome': {
                'home': [],
                'team': [],
                'available': []
            }
        }

    employee_photo_dict = {}

    i_elitehome = 1 
    for employees in generator_teamDB():
        group = employees['EMPLOYEE_DEPARTMENT']
        department = str(group).replace('dmd ', '')
        employee = employees['EMPLOYEE_NAME']
        employee_login = users_atributes[employee]['username']

        employee_photo = users_atributes[employee]['avatar']
        try: employee_photo_dict[employee_login]
        except KeyError: employee_photo_dict[employee_login] = employee_photo
        
        if i_elitehome < 5 and department == "elitehome":
            collections[department]['home'].append(employee_login)
        elif i_elitehome >= 5 and department == "elitehome":
            collections[department]['team'].append(employee_login)
        if department == 'elitehome':
            i_elitehome += 1
        
    for assign in assigned_dmdelitehome:
        if assign not in collections['elitehome']['home'] + collections['elitehome']['team']:
            collections['elitehome']['available'].append(assign)

            for row in generator_userDataDB():
                if row['username'] == assign:
                    employee_photo = row['avatar']
                    try: employee_photo_dict[assign]
                    except KeyError: employee_photo_dict[assign] = employee_photo

    # Tutaj złapane dane
    if request.method == 'POST':
        data = request.get_json()
        sequence_data = data.get('sequence', [])
        sequence = []
        for s in sequence_data:
            clear_data = s.strip()
            sequence.append(clear_data)

        users_atributesByLogin = {}
        for usr_d in generator_userDataDB():
            u_login = usr_d['username']
            users_atributesByLogin[u_login] = usr_d
        
        ready_exportDB = []
        for u_login in sequence:
            set_row = {
                'EMPLOYEE_PHOTO': users_atributesByLogin[u_login]['avatar'],
                'EMPLOYEE_NAME': users_atributesByLogin[u_login]['name'],
                'EMPLOYEE_ROLE': users_atributesByLogin[u_login]['stanowisko'],
                'EMPLOYEE_DEPARTMENT': 'dmd elitehome',
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
                ('dmd elitehome', )
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
                    flash(f'Ustwiono {row["EMPLOYEE_NAME"]}.', 'success')

        else:
            flash('Błąd! Zespół nie został zmieniony.', 'danger')
            return redirect(url_for('team_elitehome'))
        print('dane:', ready_exportDB)
        flash('Zespół został pomyślnie zmieniony.', 'success')


    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']

    # update sesji userperm brands
    permTempDict = {}
    brands_data = {}
    for un in generator_userDataDB(): 
        permTempDict[un['username']] = un['uprawnienia']
        brands_data[un['username']] = un['brands']

    session['userperm'] = permTempDict[session['username']]
    session['brands'] = brands_data[session['username']]

    return render_template(
                            "team_management_elitehome.html", 
                            username=session['username'],
                            userperm=session['userperm'], 
                            user_brands=session['brands'], 
                            members=collections['elitehome'], 
                            photos_dict=employee_photo_dict,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje
                            )

@app.route('/team-budownictwo', methods=['GET', 'POST'])
def team_budownictwo():
    """Strona zespołu budownictwo."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['team'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    

    users_atributes = {}
    assigned_dmdbudownictwo = []
    
    for usr_d in generator_userDataDB():
        u_name = usr_d['name']
        u_login = usr_d['username']
        users_atributes[u_name] = usr_d
        if usr_d['brands']['budownictwo'] == 1:
            assigned_dmdbudownictwo.append(u_login)

    collections = {
            'budownictwo': {
                'home': [],
                'team': [],
                'available': []
            }
        }

    employee_photo_dict = {}

    i_budownictwo = 1 
    for employees in generator_teamDB():
        group = employees['EMPLOYEE_DEPARTMENT']
        department = str(group).replace('dmd ', '')
        employee = employees['EMPLOYEE_NAME']
        employee_login = users_atributes[employee]['username']

        employee_photo = users_atributes[employee]['avatar']
        try: employee_photo_dict[employee_login]
        except KeyError: employee_photo_dict[employee_login] = employee_photo
        
        if i_budownictwo < 5 and department == "budownictwo":
            collections[department]['home'].append(employee_login)
        elif i_budownictwo >= 5 and department == "budownictwo":
            collections[department]['team'].append(employee_login)
        if department == 'budownictwo':
            i_budownictwo += 1
        
    for assign in assigned_dmdbudownictwo:
        if assign not in collections['budownictwo']['home'] + collections['budownictwo']['team']:
            collections['budownictwo']['available'].append(assign)

            for row in generator_userDataDB():
                if row['username'] == assign:
                    employee_photo = row['avatar']
                    try: employee_photo_dict[assign]
                    except KeyError: employee_photo_dict[assign] = employee_photo

    # Tutaj złapane dane
    if request.method == 'POST':
        data = request.get_json()
        sequence_data = data.get('sequence', [])
        sequence = []
        for s in sequence_data:
            clear_data = s.strip()
            sequence.append(clear_data)

        users_atributesByLogin = {}
        for usr_d in generator_userDataDB():
            u_login = usr_d['username']
            users_atributesByLogin[u_login] = usr_d
        
        ready_exportDB = []
        for u_login in sequence:
            set_row = {
                'EMPLOYEE_PHOTO': users_atributesByLogin[u_login]['avatar'],
                'EMPLOYEE_NAME': users_atributesByLogin[u_login]['name'],
                'EMPLOYEE_ROLE': users_atributesByLogin[u_login]['stanowisko'],
                'EMPLOYEE_DEPARTMENT': 'dmd budownictwo',
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
                ('dmd budownictwo', )
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
                    flash(f'Ustwiono {row["EMPLOYEE_NAME"]}.', 'success')

        else:
            flash('Błąd! Zespół nie został zmieniony.', 'danger')
            return redirect(url_for('team_budownictwo'))
        print('dane:', ready_exportDB)
        flash('Zespół został pomyślnie zmieniony.', 'success')


    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']

    # update sesji userperm brands
    permTempDict = {}
    brands_data = {}
    for un in generator_userDataDB(): 
        permTempDict[un['username']] = un['uprawnienia']
        brands_data[un['username']] = un['brands']

    session['userperm'] = permTempDict[session['username']]
    session['brands'] = brands_data[session['username']]

    return render_template(
                            "team_management_budownictwo.html", 
                            username=session['username'],
                            userperm=session['userperm'], 
                            user_brands=session['brands'], 
                            members=collections['budownictwo'], 
                            photos_dict=employee_photo_dict,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje
                            )

@app.route('/team-development', methods=['GET', 'POST'])
def team_development():
    """Strona zespołu development."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['team'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    

    users_atributes = {}
    assigned_dmddevelopment = []
    
    for usr_d in generator_userDataDB():
        u_name = usr_d['name']
        u_login = usr_d['username']
        users_atributes[u_name] = usr_d
        if usr_d['brands']['development'] == 1:
            assigned_dmddevelopment.append(u_login)

    collections = {
            'development': {
                'home': [],
                'team': [],
                'available': []
            }
        }

    employee_photo_dict = {}

    i_development = 1 
    for employees in generator_teamDB():
        group = employees['EMPLOYEE_DEPARTMENT']
        department = str(group).replace('dmd ', '')
        employee = employees['EMPLOYEE_NAME']
        employee_login = users_atributes[employee]['username']

        employee_photo = users_atributes[employee]['avatar']
        try: employee_photo_dict[employee_login]
        except KeyError: employee_photo_dict[employee_login] = employee_photo
        
        if i_development < 5 and department == "development":
            collections[department]['home'].append(employee_login)
        elif i_development >= 5 and department == "development":
            collections[department]['team'].append(employee_login)
        if department == 'development':
            i_development += 1
        
    for assign in assigned_dmddevelopment:
        if assign not in collections['development']['home'] + collections['development']['team']:
            collections['development']['available'].append(assign)

            for row in generator_userDataDB():
                if row['username'] == assign:
                    employee_photo = row['avatar']
                    try: employee_photo_dict[assign]
                    except KeyError: employee_photo_dict[assign] = employee_photo

    # Tutaj złapane dane
    if request.method == 'POST':
        data = request.get_json()
        sequence_data = data.get('sequence', [])
        sequence = []
        for s in sequence_data:
            clear_data = s.strip()
            sequence.append(clear_data)

        users_atributesByLogin = {}
        for usr_d in generator_userDataDB():
            u_login = usr_d['username']
            users_atributesByLogin[u_login] = usr_d
        
        ready_exportDB = []
        for u_login in sequence:
            set_row = {
                'EMPLOYEE_PHOTO': users_atributesByLogin[u_login]['avatar'],
                'EMPLOYEE_NAME': users_atributesByLogin[u_login]['name'],
                'EMPLOYEE_ROLE': users_atributesByLogin[u_login]['stanowisko'],
                'EMPLOYEE_DEPARTMENT': 'dmd development',
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
                ('dmd development', )
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
                    flash(f'Ustwiono {row["EMPLOYEE_NAME"]}.', 'success')

        else:
            flash('Błąd! Zespół nie został zmieniony.', 'danger')
            return redirect(url_for('team_development'))
        print('dane:', ready_exportDB)
        flash('Zespół został pomyślnie zmieniony.', 'success')


    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']

    # update sesji userperm brands
    permTempDict = {}
    brands_data = {}
    for un in generator_userDataDB(): 
        permTempDict[un['username']] = un['uprawnienia']
        brands_data[un['username']] = un['brands']

    session['userperm'] = permTempDict[session['username']]
    session['brands'] = brands_data[session['username']]

    return render_template(
                            "team_management_development.html", 
                            username=session['username'],
                            userperm=session['userperm'], 
                            user_brands=session['brands'], 
                            members=collections['development'], 
                            photos_dict=employee_photo_dict,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje
                            )


@app.route('/team-inwestycje', methods=['GET', 'POST'])
def team_inwestycje():
    """Strona zespołu inwestycje."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['team'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    

    users_atributes = {}
    assigned_dmdinwestycje = []
    
    for usr_d in generator_userDataDB():
        u_name = usr_d['name']
        u_login = usr_d['username']
        users_atributes[u_name] = usr_d
        if usr_d['brands']['inwestycje'] == 1:
            assigned_dmdinwestycje.append(u_login)

    collections = {
            'inwestycje': {
                'home': [],
                'team': [],
                'available': []
            }
        }

    employee_photo_dict = {}

    i_inwestycje = 1 
    for employees in generator_teamDB():
        group = employees['EMPLOYEE_DEPARTMENT']
        department = str(group).replace('dmd ', '')
        employee = employees['EMPLOYEE_NAME']
        employee_login = users_atributes[employee]['username']

        employee_photo = users_atributes[employee]['avatar']
        try: employee_photo_dict[employee_login]
        except KeyError: employee_photo_dict[employee_login] = employee_photo
        
        if i_inwestycje < 5 and department == "inwestycje":
            collections[department]['home'].append(employee_login)
        elif i_inwestycje >= 5 and department == "inwestycje":
            collections[department]['team'].append(employee_login)
        if department == 'inwestycje':
            i_inwestycje += 1
        
    for assign in assigned_dmdinwestycje:
        if assign not in collections['inwestycje']['home'] + collections['inwestycje']['team']:
            collections['inwestycje']['available'].append(assign)

            for row in generator_userDataDB():
                if row['username'] == assign:
                    employee_photo = row['avatar']
                    try: employee_photo_dict[assign]
                    except KeyError: employee_photo_dict[assign] = employee_photo

    # Tutaj złapane dane
    if request.method == 'POST':
        data = request.get_json()
        sequence_data = data.get('sequence', [])
        sequence = []
        for s in sequence_data:
            clear_data = s.strip()
            sequence.append(clear_data)

        users_atributesByLogin = {}
        for usr_d in generator_userDataDB():
            u_login = usr_d['username']
            users_atributesByLogin[u_login] = usr_d
        
        ready_exportDB = []
        for u_login in sequence:
            set_row = {
                'EMPLOYEE_PHOTO': users_atributesByLogin[u_login]['avatar'],
                'EMPLOYEE_NAME': users_atributesByLogin[u_login]['name'],
                'EMPLOYEE_ROLE': users_atributesByLogin[u_login]['stanowisko'],
                'EMPLOYEE_DEPARTMENT': 'dmd inwestycje',
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
                ('dmd inwestycje', )
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
                    flash(f'Ustwiono {row["EMPLOYEE_NAME"]}.', 'success')

        else:
            flash('Błąd! Zespół nie został zmieniony.', 'danger')
            return redirect(url_for('team_inwestycje'))
        print('dane:', ready_exportDB)
        flash('Zespół został pomyślnie zmieniony.', 'success')


    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']

    # update sesji userperm brands
    permTempDict = {}
    brands_data = {}
    for un in generator_userDataDB(): 
        permTempDict[un['username']] = un['uprawnienia']
        brands_data[un['username']] = un['brands']

    session['userperm'] = permTempDict[session['username']]
    session['brands'] = brands_data[session['username']]

    return render_template(
                            "team_management_inwestycje.html", 
                            username=session['username'],
                            userperm=session['userperm'], 
                            user_brands=session['brands'], 
                            members=collections['inwestycje'], 
                            photos_dict=employee_photo_dict,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje
                            )

@app.route('/team-instalacje', methods=['GET', 'POST'])
def team_instalacje():
    """Strona zespołu instalacje."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['team'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    users_atributes = {}
    assigned_dmdinstalacje = []
    
    for usr_d in generator_userDataDB():
        u_name = usr_d['name']
        u_login = usr_d['username']
        users_atributes[u_name] = usr_d
        if usr_d['brands']['instalacje'] == 1:
            assigned_dmdinstalacje.append(u_login)

    collections = {
            'instalacje': {
                'home': [],
                'team': [],
                'available': []
            }
        }

    employee_photo_dict = {}

    i_instalacje = 1 
    for employees in generator_teamDB():
        group = employees['EMPLOYEE_DEPARTMENT']
        department = str(group).replace('dmd ', '')
        employee = employees['EMPLOYEE_NAME']
        employee_login = users_atributes[employee]['username']

        employee_photo = users_atributes[employee]['avatar']
        try: employee_photo_dict[employee_login]
        except KeyError: employee_photo_dict[employee_login] = employee_photo
        
        if i_instalacje < 5 and department == "instalacje":
            collections[department]['home'].append(employee_login)
        elif i_instalacje >= 5 and department == "instalacje":
            collections[department]['team'].append(employee_login)
        if department == 'instalacje':
            i_instalacje += 1
        
    for assign in assigned_dmdinstalacje:
        if assign not in collections['instalacje']['home'] + collections['instalacje']['team']:
            collections['instalacje']['available'].append(assign)

            for row in generator_userDataDB():
                if row['username'] == assign:
                    employee_photo = row['avatar']
                    try: employee_photo_dict[assign]
                    except KeyError: employee_photo_dict[assign] = employee_photo

    # Tutaj złapane dane
    if request.method == 'POST':
        data = request.get_json()
        sequence_data = data.get('sequence', [])
        sequence = []
        for s in sequence_data:
            clear_data = s.strip()
            sequence.append(clear_data)

        users_atributesByLogin = {}
        for usr_d in generator_userDataDB():
            u_login = usr_d['username']
            users_atributesByLogin[u_login] = usr_d
        
        ready_exportDB = []
        for u_login in sequence:
            set_row = {
                'EMPLOYEE_PHOTO': users_atributesByLogin[u_login]['avatar'],
                'EMPLOYEE_NAME': users_atributesByLogin[u_login]['name'],
                'EMPLOYEE_ROLE': users_atributesByLogin[u_login]['stanowisko'],
                'EMPLOYEE_DEPARTMENT': 'dmd instalacje',
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
                ('dmd instalacje', )
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
                    flash(f'Ustwiono {row["EMPLOYEE_NAME"]}.', 'success')

        else:
            flash('Błąd! Zespół nie został zmieniony.', 'danger')
            return redirect(url_for('team_instalacje'))
        print('dane:', ready_exportDB)
        flash('Zespół został pomyślnie zmieniony.', 'success')


    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']

    # update sesji userperm brands
    permTempDict = {}
    brands_data = {}
    for un in generator_userDataDB(): 
        permTempDict[un['username']] = un['uprawnienia']
        brands_data[un['username']] = un['brands']

    session['userperm'] = permTempDict[session['username']]
    session['brands'] = brands_data[session['username']]

    return render_template(
                            "team_management_instalacje.html", 
                            username=session['username'],
                            userperm=session['userperm'], 
                            user_brands=session['brands'], 
                            members=collections['instalacje'], 
                            photos_dict=employee_photo_dict,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje
                            )

@app.route('/career', methods=['GET', 'POST'])
def career():
    """Strona zespołu instalacje."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['career'] == 0:
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
        item['fbgroups']['section'] = fbgroupsIDstatus[52]
        item['fbgroups']['id_gallery'] = fbgroupsIDstatus[53]
        item['fbgroups']['data_aktualizacji'] = fbgroupsIDstatus[54]

        new_all_career.append(item)

    all_career = new_all_career

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(all_career)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    ads_career = all_career[offset: offset + per_page]
    
    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']

    return render_template(
                            "career_management.html", 
                            username=session['username'],
                            useremail=session['user_data']['email'],
                            userperm=session['userperm'], 
                            user_brands=session['brands'], 
                            ads_career=ads_career,
                            pagination=pagination,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje
                            )

@app.route('/save-career-offer', methods=["POST"])
def save_career_offer():
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
        flash('Błąd z id oferty. Skontaktuj się z administratorem!', 'danger')
        return redirect(url_for('index'))

    # print(f'title: {title} | start_date: {start_date} | salary: {salary} | employment_type: {employment_type} | location: {location} | brand: {brand} | contact_email: {contact_email} | description: {description} | requirements_description: {requirements_description} | requirements: {requirements} | benefits: {benefits} | offerID: {offerID} |')

    # Sprawdzenie czy użytkownik jest zalogowany i ma uprawnienia
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['career'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj się z administratorem!', 'danger')
        return redirect(url_for('index'))

    # Sprawdzenie czy wszystkie wymagane dane zostały przekazane
    if not all([title, start_date, salary, employment_type, location, contact_email]):
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
        flash(f'Oferta pracy została zapisana pomyślnie!', 'success')
        return jsonify({
            'message': 'Oferta pracy została zapisana pomyślnie!',
            'success': True
        }), 200
    else:
        flash(f'Błąd zapisu! Oferta pracy nie została zapisana!', 'danger')
        return jsonify({
            'message': 'Błąd zapisu! Oferta pracy nie została zapisana!',
            'success': False
        }), 500


@app.route('/remove-career-offer', methods=["POST"])
def remove_career_offer():
    """Usuwanie ofertę najmu"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['career'] == 0:
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

        flash("Oferta pracy została usunięta.", "success")
        return redirect(url_for('career'))
    
    return redirect(url_for('index'))


@app.route('/update-career-offer-status', methods=['POST'])
def update_career_offer_status():
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['career'] == 0:
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
            flash("Status oferty nie został zmieniony. Przewij kampanię na grupach Facebooka", "danger")
            return redirect(url_for('career'))

        zapytanie_sql = f'''
                UPDATE job_offers
                SET status = %s
                WHERE ID = %s;
                '''
        dane = (set_post_status, set_post_id)
        if msq.insert_to_database(zapytanie_sql, dane):
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
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
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
        item['fbgroups']['section'] = fbgroupsIDstatus[52]
        item['fbgroups']['id_gallery'] = fbgroupsIDstatus[53]
        item['fbgroups']['data_aktualizacji'] = fbgroupsIDstatus[54]

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

    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']

    lentoOffer = 1

    # flash(f"{str(len(ads_rent))}", 'dnager')

    return render_template(
                            "estate_management_rent.html",
                            ads_rent=ads_rent,
                            specOfferID=specOfferID,
                            userperm=session['userperm'],
                            username=session['username'],
                            pagination=pagination,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje,
                            lentoOffer=lentoOffer
                            )     

@app.route('/remove-rent-offer', methods=['POST'])
def remove_rent_offer():
    """Usuwanie ofertę najmu"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
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
            flash("Wpis nie został usunięty. Wystąpił błąd struktury danych galerii", "danger")
            return redirect(url_for('estateAdsRent'))
        
        try: current_gallery = take_data_where_ID('*', 'ZdjeciaOfert', 'ID', id_galerry)[0]
        except IndexError: 
            flash("Wpis nie został usunięty. Wystąpił błąd struktury danych galerii", "danger")
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

        flash("Wpis został usunięty.", "success")
        return redirect(url_for('estateAdsRent'))
    
    return redirect(url_for('index'))

@app.route('/update-rent-offer-status', methods=['POST'])
def update_rent_offer_status():
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
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
            flash("Status oferty nie został zmieniony. Usuń na zawsze ogłoszenie z Lento.pl", "danger")
            return redirect(url_for('estateAdsRent'))
        
        statusNaFacebooku = checkFacebookStatus('r', set_post_id)
        if statusNaFacebooku[0] != None:
            flash("Status oferty nie został zmieniony. Usuń na zawsze ogłoszenie z Facebooka", "danger")
            return redirect(url_for('estateAdsRent'))
        
        statusNaAdresowo = checkAdresowoStatus('r', set_post_id)
        if statusNaAdresowo[0] != None:
            flash("Status oferty nie został zmieniony. Usuń na zawsze ogłoszenie z Adresowo", "danger")
            return redirect(url_for('estateAdsRent'))
        
        statusNaAllegro = checkAllegroStatus('r', set_post_id)
        if statusNaAllegro[0] != None:
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
            flash("Status oferty został zmieniony.", "success")
            return redirect(url_for('estateAdsRent'))
    
    return redirect(url_for('index'))

@app.route('/save-rent-offer', methods=["POST"])
def save_rent_offer():
    # Odczytanie danych formularza
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
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
            # print(filename)
            full_path = os.path.join(upload_path, filename)
            complete_URL_PIC = f'{mainDomain_URL}{filename}'
            try:
                photo.save(full_path)
                
                # if not first_photo_processed:
                #     logo_path = upload_path+'logo.png'  # Ścieżka do pliku logo
                #     output_path = full_path  # Zapisujemy z nałożonym logo pod tym samym adresem
                #     apply_logo_to_image(full_path, logo_path, output_path, scale_factor=1)
                #     first_photo_processed = True

                saved_photos.append(complete_URL_PIC)
                if secure_filename(photo.filename) in allPhotos:
                    pobrany_index = allPhotos.index(secure_filename(photo.filename))
                    allPhotos[pobrany_index] = filename
            except Exception as e:
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
                    flash(f'Błąd podczas tworzenia galerii! \n {err}', 'danger')
                    return jsonify({
                        'message': f'Błąd podczas tworzenia galerii! \n {err}',
                        'success': True
                        }), 200
            else:
                flash(f'Błąd podczas zapisywania galerii w bazie!', 'danger')
                return jsonify({
                    'message': 'Błąd podczas zapisywania galerii w bazie!',
                    'success': True
                    }), 200
        else:
            flash(f'BRAK ZDJĘĆ! Niemożliwe jest zapisywania galerii w bazie!', 'danger')
            return jsonify({
                    'message': 'BRAK ZDJĘĆ! Niemożliwe jest zapisywania galerii w bazie!',
                    'success': True
                    }), 200
        
        logo_path = upload_path+'logo.png'  # Ścieżka do pliku logo
        output_path = upload_path+saved_photos[0].split('/')[-1]
        full_path = output_path

        # print(full_path, logo_path, output_path)
        apply_logo_to_image(full_path, logo_path, output_path, scale_factor=1)

    else:
        try: gallery_id = take_data_where_ID('Zdjecia', 'OfertyNajmu', 'ID', offerID_int)[0][0]
        except IndexError: 
            flash(f"Nie udało się pobrać ID galerii!", "danger")
            return jsonify({
                    'message': 'Nie udało się pobrać ID galerii!',
                    'success': True
                    }), 200
            
        try: 
            current_gallery = take_data_where_ID('*', 'ZdjeciaOfert', 'ID', gallery_id)[0]
            current_gallery_list = [p for p in current_gallery[1:-1] if p is not None]
        except IndexError: 
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
                print('update_galerii_udany')
            else:
                flash(f'Bład zapisu galerii! Oferta wynajmu nie została zapisana!', 'danger')
                return jsonify({
                        'message': 'xxx',
                        'success': True
                        }), 200

    
        logo_path = upload_path+'logo.png'  # Ścieżka do pliku logo
        output_path = upload_path+oldPhotos_plus_saved_photos_sorted[0].split('/')[-1]
        full_path = output_path

        # print(full_path, logo_path, output_path)
        apply_logo_to_image(full_path, logo_path, output_path, scale_factor=1)


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
        flash(f'Oferta wynajmu została zapisana pomyślnie!', 'success')
        return jsonify({
            'message': 'Oferta wynajmu została zapisana pomyślnie!',
            'success': True
            }), 200
    else:
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
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
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
        item['fbgroups']['section'] = fbgroupsIDstatus[52]
        item['fbgroups']['id_gallery'] = fbgroupsIDstatus[53]
        item['fbgroups']['data_aktualizacji'] = fbgroupsIDstatus[54]

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


    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']
    return render_template(
                            "estate_management_sell.html",
                            ads_sell=ads_sell,
                            specOfferID=specOfferID,
                            userperm=session['userperm'],
                            username=session['username'],
                            pagination=pagination,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje
                            )     

@app.route('/remove-sell-offer', methods=['POST'])
def remove_sell_offer():
    """Usuwanie ofertę najmu"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
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
            flash("Wpis nie został usunięty. Wystąpił błąd struktury danych galerii", "danger")
            return redirect(url_for('estateAdsSell'))
        
        try: current_gallery = take_data_where_ID('*', 'ZdjeciaOfert', 'ID', id_galerry)[0]
        except IndexError: 
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
                    print(f"Error removing file {file_path}: {e}")

        flash("Wpis został usunięty.", "success")
        return redirect(url_for('estateAdsSell'))
    
    return redirect(url_for('index'))

@app.route('/update-sell-offer-status', methods=['POST'])
def update_sell_offer_status():
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
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
            flash("Status oferty nie został zmieniony. Usuń na zawsze ogłoszenie z Lento.pl", "danger")
            return redirect(url_for('estateAdsSell'))
        
        statusNaFacebooku = checkFacebookStatus('s', set_post_id)
        if statusNaFacebooku[0] != None:
            flash("Status oferty nie został zmieniony. Usuń na zawsze ogłoszenie z Facebooka", "danger")
            return redirect(url_for('estateAdsSell'))
        
        statusNaAdresowo = checkAdresowoStatus('s', set_post_id)
        if statusNaAdresowo[0] != None:
            flash("Status oferty nie został zmieniony. Usuń na zawsze ogłoszenie z Adresowo", "danger")
            return redirect(url_for('estateAdsSell'))
        
        statusNaAllegro = checkAllegroStatus('s', set_post_id)
        if statusNaAllegro[0] != None:
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
            flash("Status oferty został zmieniony.", "success")
            return redirect(url_for('estateAdsSell'))
    
    return redirect(url_for('index'))


@app.route('/save-sell-offer', methods=["POST"])
def save_sell_offer():
    # Odczytanie danych formularza
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
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
            # print(filename)
            full_path = os.path.join(upload_path, filename)
            complete_URL_PIC = f'{mainDomain_URL}{filename}'
            try:
                photo.save(full_path)
                saved_photos.append(complete_URL_PIC)
                if secure_filename(photo.filename) in allPhotos:
                    pobrany_index = allPhotos.index(secure_filename(photo.filename))
                    allPhotos[pobrany_index] = filename
            except Exception as e:
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
                    flash(f'Błąd podczas tworzenia galerii! \n {err}', 'danger')
                    return jsonify({
                        'message': f'Błąd podczas tworzenia galerii! \n {err}',
                        'success': True
                        }), 200
            else:
                flash(f'Błąd podczas zapisywania galerii w bazie!', 'danger')
                return jsonify({
                    'message': 'Błąd podczas zapisywania galerii w bazie!',
                    'success': True
                    }), 200
        else:
            flash(f'BRAK ZDJĘĆ! Niemożliwe jest zapisywania galerii w bazie!', 'danger')
            return jsonify({
                    'message': 'BRAK ZDJĘĆ! Niemożliwe jest zapisywania galerii w bazie!',
                    'success': True
                    }), 200
        
        logo_path = upload_path+'logo.png'  # Ścieżka do pliku logo
        output_path = upload_path+saved_photos[0].split('/')[-1]
        full_path = output_path

        # print(full_path, logo_path, output_path)
        apply_logo_to_image(full_path, logo_path, output_path, scale_factor=1)

    else:
        try: gallery_id = take_data_where_ID('Zdjecia', 'OfertySprzedazy', 'ID', offerID_int)[0][0]
        except IndexError: 
            flash(f"Nie udało się pobrać ID galerii!", "danger")
            return jsonify({
                    'message': 'Nie udało się pobrać ID galerii!',
                    'success': True
                    }), 200
            
        try: 
            current_gallery = take_data_where_ID('*', 'ZdjeciaOfert', 'ID', gallery_id)[0]
            current_gallery_list = [p for p in current_gallery[1:-1] if p is not None]
        except IndexError: 
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
                print('update_galerii_udany')
            else:
                flash(f'Bład zapisu galerii! Oferta wynajmu nie została zapisana!', 'danger')
                return jsonify({
                        'message': 'xxx',
                        'success': True
                        }), 200
            
        logo_path = upload_path+'logo.png'  # Ścieżka do pliku logo
        output_path = upload_path+oldPhotos_plus_saved_photos_sorted[0].split('/')[-1]
        full_path = output_path

        # print(full_path, logo_path, output_path)
        apply_logo_to_image(full_path, logo_path, output_path, scale_factor=1)


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
        flash(f'Oferta wynajmu została zapisana pomyślnie!', 'success')
        return jsonify({
            'message': 'Oferta wynajmu została zapisana pomyślnie!',
            'success': True
            }), 200
    else:
        flash(f'Bład zapisu! Oferta wynajmu nie została zapisana!', 'danger')
        return jsonify({
                'message': 'Bład zapisu! Oferta wynajmu nie została zapisana!',
                'success': True
                }), 200


@app.route('/set-as-specOffer', methods=['POST'])
def set_as_specOffer():
    """Strona zawierająca listę z ogłoszeniami nieruchomości."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
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
                flash('Zmiany zotały zastosowane z sukcesem!', 'success')
            else:
                flash('Błąd! Zmiany nie zotały zastosowane!', 'danger')
        
        if status == '1':
            if addSpecOffer(postID, parent):
                flash('Zmiany zotały zastosowane z sukcesem!', 'success')
            else:
                flash('Błąd! Zmiany nie zotały zastosowane!', 'danger')

        return redirect(url_for(redirectGoal))
    return redirect(url_for('index'))

@app.route('/public-on-lento', methods=['POST'])
def public_on_lento():
    """Strona zawierająca listę z ogłoszeniami nieruchomości."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        lento_id = request.form.get('lento_id')
        id_ogloszenia = request.form.get('PostID')
        task_kind = request.form.get('task_kind')
        redirectGoal = request.form.get('redirectGoal')
        
        
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
            if prepared_opis != '':prepared_opis = prepared_opis + '\n' + picked_rent_offer['InformacjeDodatkowe']
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            

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
                flash(f'Oferta wynajmu została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
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
            if prepared_opis != '':prepared_opis = prepared_opis + '\n' + picked_sell_offer['InformacjeDodatkowe']
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""
            
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
                flash(f'Oferta sprzedaży została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
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
            if prepared_opis != '':prepared_opis = prepared_opis + '\n' + picked_rent_offer['InformacjeDodatkowe']
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""

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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuta.', 'success')
            else:
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
            if prepared_opis != '':prepared_opis = prepared_opis + '\n' + picked_sell_offer['InformacjeDodatkowe']
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""

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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuta.', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuta.', 'success')
            else:
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
                flash(f'Zadanie zostało anulowane!', 'success')
            else:
                flash(f'Bład zapisu! Zadanie nie zostało anulowane!', 'danger')

        return redirect(url_for(redirectGoal))
    return redirect(url_for('index')) 

@app.route('/public-on-facebook', methods=['POST'])
def public_on_facebook():

    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
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
                flash(f'Zadanie zostało anulowane!', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
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
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        print(request.form)
        adresowo_id = request.form.get('adresowo_id')
        id_ogloszenia = request.form.get('PostID')
        task_kind = request.form.get('task_kind')
        redirectGoal = request.form.get('redirectGoal')
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""

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
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Publikuj' and rodzaj_ogloszenia == 's':
            if not region:
                flash('Wybierz region!', 'danger')
                return redirect(url_for(redirectGoal))

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
            if prepared_opis != '':prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""

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
                            stan, typ_budynku, zdjecia_string, osoba_kontaktowa, nr_telefonu, 
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, 
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, liczba_pieter, pow_dzialki, ulica, powierzchnia, rok_budowy, 
                        stan, typ_budynku, zdjecia_string, osoba_kontaktowa, nr_telefonu,
                        4)
                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                    flash('Nie rozpoznano formy własności, która jest wymagana w kategorii mieszkanie na sprzedaż! Wpisz formę własności (spółdzielcze własnościowe, pełna własność, udział, tbs) w polu informacje dodatkowe!', 'danger')
                    return redirect(url_for(redirectGoal))
                
                zapytanie_sql = '''
                        INSERT INTO ogloszenia_adresowo
                            (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                            opis_ogloszenia, liczba_pokoi, poziom, liczba_pieter, ulica, powierzchnia, 
                            rok_budowy, winda, stan, typ_budynku, forma_wlasnosci, zdjecia_string, 
                            osoba_kontaktowa, nr_telefonu, 
                            status)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s,
                            %s, %s,
                            %s);
                    '''
                dane = (rodzaj_ogloszenia, id_ogloszenia, tytul_ogloszenia, kategoria_ogloszenia, region, cena,
                        opis_ogloszenia, liczba_pokoi, poziom, liczba_pieter, ulica, powierzchnia, 
                        rok_budowy, winda, stan, typ_budynku, forma_wlasnosci, zdjecia_string, 
                        osoba_kontaktowa, nr_telefonu, 
                        4)
                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""

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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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

                print(zapytanie_sql, dane)

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
            if prepared_opis != '':prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""

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
                # print(dane)
                # flash(f'{dane}', 'success')
                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
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
                flash(f'Zadanie zostało anulowane!', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')
        
        return redirect(url_for(redirectGoal))
    return redirect(url_for('index')) 

@app.route('/public-on-allegro', methods=['POST'])
def public_on_allegro():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        print(request.form)
        allegro_id = request.form.get('allegro_id')
        id_ogloszenia = request.form.get('PostID')
        task_kind = request.form.get('task_kind')
        redirectGoal = request.form.get('redirectGoal')
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""

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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                    # print(dane)
                    # flash(f'{dane}', 'success')

                    if msq.insert_to_database(zapytanie_sql, dane):
                        flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                    else:
                        flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')   


        if task_kind == 'Publikuj' and rodzaj_ogloszenia == 's':
            if not region:
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
            if prepared_opis != '':prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""

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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""


            kategoria_ogloszenia = checkAllegroStatus('r', id_ogloszenia)[8]
            # print(kategoria_ogloszenia)
            if kategoria_ogloszenia == None:
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
                
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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

                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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


                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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


                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
            if prepared_opis != '':prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""


            kategoria_ogloszenia = checkAllegroStatus('s', id_ogloszenia)[8]
            # print(kategoria_ogloszenia)
            if kategoria_ogloszenia == None:
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
                
                # print(dane)
                flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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

                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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


                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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


                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
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
                flash(f'Zadanie zostało anulowane!', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')


        return redirect(url_for(redirectGoal))
    return redirect(url_for('index')) 

@app.route('/public-on-otodom', methods=['POST'])
def public_on_otodom():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        print(request.form)
        otodom_id = request.form.get('otodom_id')
        id_ogloszenia = request.form.get('PostID')
        task_kind = request.form.get('task_kind')
        redirectGoal = request.form.get('redirectGoal')
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""

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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
                    flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        if task_kind == 'Publikuj' and rodzaj_ogloszenia == 's': 
            if not region:
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
            if prepared_opis != '':prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""

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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""

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

                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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

                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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

                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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

                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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

                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
            if prepared_opis != '':prepared_opis = prepared_opis + '\n' + picked_offer['InformacjeDodatkowe']
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
            opis_ogloszenia = f"""{prepared_opis}\n\n{extra_opis}"""

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

                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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

                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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

                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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

                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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

                # print(dane)
                # flash(f'{dane}', 'success')

                if msq.insert_to_database(zapytanie_sql, dane):
                    flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
                else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 1 minuta.', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
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
                flash(f'Zadanie zostało anulowane!', 'success')
            else:
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
                flash(f'Oferta została pomyślnie wysłana do realizacji! Przewidywany czas realizacji 3 minuty.', 'success')
            else:
                flash(f'Bład zapisu! Oferta nie została wysłana do realizacji!', 'danger')

        return redirect(url_for(redirectGoal))
    return redirect(url_for('index')) 


@app.route('/estate-ads-special')
def estateAdsspecial():
    """Strona zawierająca listę z ogłoszeniami nieruchomości."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
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

    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']
    return render_template(
                            "estate_management_special.html",
                            ads_spec=ads_spec,
                            userperm=session['userperm'],
                            username=session['username'],
                            pagination=pagination,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje
                            )     

@app.route('/subscriber')
def subscribers(router=True):
    """Strona zawierająca listę subskrybentów Newslettera."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['subscribers'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    subscribers_all = generator_subsDataDB()

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(subscribers_all)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    subs = subscribers_all[offset: offset + per_page]
    
    if router:
        settingsDB = generator_settingsDB()
        domy = settingsDB['domy']
        budownictwo = settingsDB['budownictwo']
        development = settingsDB['development']
        elitehome = settingsDB['elitehome']
        inwestycje = settingsDB['inwestycje']
        instalacje = settingsDB['instalacje']
        # Renderowanie szablonu blog-managment.html z danymi o postach (wszystkimi lub po jednym)
        return render_template(
                                "subscriber_management.html", 
                                subs=subs, 
                                username=session['username'], 
                                userperm=session['userperm'], 
                                pagination=pagination,
                                domy=domy,
                                budownictwo=budownictwo,
                                development=development,
                                elitehome=elitehome,
                                inwestycje=inwestycje,
                                instalacje=instalacje)
    else:
        return subs, session['username'], pagination

@app.route('/restart', methods=['POST'])
def restart():
    try:
        if restart_pm2_tasks_signal():
            zapytanie_sql = f'''
                    UPDATE admin_settings 
                    SET 
                        last_restart = %s
                    WHERE ID = %s;'''
            dane = (datetime.datetime.now(), 1)

            if msq.insert_to_database(zapytanie_sql, dane):
                flash("Aplikacja została zrestartowana", 'success')
                return jsonify({"message": "Aplikacja została zrestartowana"}), 200
            else:
                flash("Błąd podczas restartu aplikacji!", 'danger')
                return jsonify({"message": f"Błąd podczas restartu aplikacji!"}), 500
        else:
            flash("Błąd podczas restartu aplikacji!", 'danger')
            return jsonify({"message": f"Błąd podczas restartu aplikacji!"}), 500
    except Exception as e:
        flash(f"Błąd podczas restartu aplikacji: {e}", 'danger')
        return jsonify({"message": f"Błąd podczas restartu aplikacji: {e}"}), 500

@app.route('/setting')
def settings():
    """Strona z ustawieniami."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['settings'] == 0:
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
    
    restart = settingsDB['last-restart']
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']
    smtpAdmin = settingsDB['smtp_admin']

    last_logs = get_last_20_lines('logs/errors.log')

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
                            restart=restart,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje,
                            smtpAdmin=smtpAdmin,
                            etate_logo_png=etate_logo_png,
                            last_logs=last_logs
                            )

@app.route('/fb-groups')
def fbGroups():
    """Zarządzanie grupami FB"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['settings'] == 0:
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

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(items_sorted)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    groups = items_sorted[offset: offset + per_page]

    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']


    return render_template(
                            "fb-groups_management.html", 
                            username=session['username'],
                            userperm=session['userperm'], 
                            groups=groups,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje,
                            pagination=pagination,
                            sort_by=sort_by, 
                            sort_type=sort_type
                            )



@app.route('/add-fb-group', methods=["POST"])
def add_fb_group():
    """Usuwanie ofertę najmu"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['settings'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()
        print(form_data)
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

        if set_post_id == 9999999:
            zapytanie_sql = '''
                        INSERT INTO facebook_gropus
                            (name, category, link)
                        VALUES 
                            (%s, %s, %s);
                    '''
            dane = (name, category, link)

            if msq.insert_to_database(zapytanie_sql, dane):
                flash(f'Grupa została dodana!', 'success')
            else:
                flash(f'Bład zapisu! Grupa nie została dodana!', 'danger')

        else:
            zapytanie_sql = '''
                    UPDATE facebook_gropus
                    SET 
                        name = %s,
                        category = %s,
                        link = %s
                    WHERE id = %s;
                '''
            dane = (name, category, link, set_post_id)

            if msq.insert_to_database(zapytanie_sql, dane):
                flash(f'Zmiany zostały zapisane!', 'success')
            else:
                flash(f'Bład zapisu! Grupa nie została zmodyfikowana!', 'danger')

        return redirect(url_for('fbGroups'))
    
    return redirect(url_for('index'))

@app.route('/remove-fbgroup', methods=['POST'])
def remove_fbgroup():
    """Usuwanie bloga"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['settings'] == 0:
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
            flash("Grupa została usunięta.", "success")
        else:
            flash("Błąd usunięcia grupy.", "danger")
        return redirect(url_for('fbGroups'))
    
    return redirect(url_for('index'))

@app.route('/fb-groups-sender', methods=['POST'])
def fb_groups_sender():
    data = request.json  # Odbieramy dane JSON

    # print(data)
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
    if get_id_gallery == "None":
        id_gallery = None
    else:
        try: int(get_id_gallery)
        except ValueError: return jsonify({'success': False, 'message': 'Błąd w przekształcaniu na int id_gallery!'}), 400
        id_gallery = int(get_id_gallery)

    # Przekształcanie każdej daty w harmonogramie na standardowy format
    formatted_schedule = [format_date_pl(date_str) for date_str in schedule]

    # Sprawdzamy, czy wszystkie daty są poprawnie sformatowane
    if None in formatted_schedule:
        return jsonify({'success': False, 'message': 'Błąd w przekształcaniu dat'}), 400

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

    # print(f'formatted_schedule: {formatted_schedule}')
    # print(f'less_index: {less_index}')
    # print(f'prepareded_schedule: {prepareded_schedule}', len(prepareded_schedule))

    # print(len(prepareded_schedule))

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
                    category, section, id_gallery)
                VALUES 
                    (%s, %s, %s, 
                    %s, %s, %s, 
                    %s, %s,  
                    %s, %s,  
                    %s, %s,  
                    %s, %s,  
                    %s, %s,  
                    %s, 
                    %s, %s, %s);
            '''
    dane = (post_id, content, color_choice,
            repeats, repeats_left, repeats_last, 
            schedule_0_datetime, schedule_1_datetime, 
            schedule_2_datetime, schedule_3_datetime, 
            schedule_4_datetime, schedule_5_datetime, 
            schedule_6_datetime, schedule_7_datetime, 
            schedule_8_datetime, schedule_9_datetime, 
            schedule_10_datetime, 
            category, section, id_gallery)

    # print(zapytanie_sql)
    # print(dane)
    if msq.insert_to_database(zapytanie_sql, dane):
        return jsonify({'success': True, 'message': f'Zmiany zostały zapisane!'})
    else:
        return jsonify({'success': False, 'message': 'Błąd zapisu bazy danych'}), 400

    # Zwracamy sukces
    

@app.route('/remove-career-fbgroups', methods=["POST"])
def remove_career_fbgroups():
    """Usuwanie kampanii fbgroups career"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['career'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))
    
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
            except Exception as e: print(f"Błąd w usunięciu kampanii: {e}")

        try: form_data['waitnig_list_id']
        except KeyError: return redirect(url_for(f'{section}'))
        set_wl_id = int(form_data['waitnig_list_id'])
        
        msq.delete_row_from_database(
                """
                    DELETE FROM waitinglist_fbgroups WHERE id = %s;
                """,
                (set_wl_id,)
            )

        flash("Kampania została usunięta.", "success")
        return redirect(url_for(f'{section}'))
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    # app.run(debug=True, port=8000)
    app.run(debug=False, host='0.0.0.0', port=8000)