from flask import Flask, render_template, redirect, url_for, flash, jsonify, session, request, current_app
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


class LoginForm(FlaskForm):
    username = StringField('Nazwa użytkownika', validators=[DataRequired()])
    password = PasswordField('Hasło', validators=[DataRequired()])
    submit = SubmitField('Zaloguj się')

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
                'estate': data[31] # kolejne uprawnienie wzz. dmd inwestycje
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
        except json.JSONDecodeError: print("Błąd: Podane dane nie są poprawnym JSON-em")
        except IndexError: print("Błąd: Próba dostępu do indeksu, który nie istnieje w liście")
        except TypeError as e: print(f"Błąd typu danych: {e}")
        except Exception as e: print(f"Nieoczekiwany błąd: {e}")
        
        opis_json = {}
        try:
            if data[2] is not None:
                opis_json = json.loads(data[2])
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
            'Kaucja': 0 if data[4] is None else data[4],
            'Lokalizacja': data[5],
            'LiczbaPokoi': 0 if data[6] is None else data[6],
            'Metraz': 0 if data[7] is None else data[7],
            'Zdjecia': [foto for foto in fotoList if foto is not None],
            'DataPublikacjiOlx': format_date(data[9]),
            'DataPublikacjiAllegro': format_date(data[10]),
            'DataPublikacjiOtoDom': format_date(data[11]),
            'DataPublikacjiMarketplace': format_date(data[12]),
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

    if perm_id == 10: perm_name = 'Przynależność do DMD Domy'
    if perm_id == 11: perm_name = 'Przynależność do DMD Budownictwo'
    if perm_id == 12: perm_name = 'Przynależność do DMD EliteHome'
    if perm_id == 13: perm_name = 'Przynależność do DMD Inwestycje'
    if perm_id == 14: perm_name = 'Przynależność do DMD Instalacje'
    if perm_id == 15: perm_name = 'Przynależność do DMD Development'

    if perm_id in [1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 9, 16]:
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

        

            # 'smtp_config': {
            #     'smtp_server': take_data_newsletterSettingDB('config_smtp_server'),
            #     'smtp_port': int(take_data_newsletterSettingDB('config_smtp_port')),
            #     'smtp_username': take_data_newsletterSettingDB('config_smtp_username'),
            #     'smtp_password': take_data_newsletterSettingDB('config_smtp_password')
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
        print(form_data)
        {
            'main-domain': 'https://dmddomy.pl/', 
            'blog-pic-path': 'images/blog/', 
            'avatar-pic-path': 'images/team/', 
            'item-on-page': '15', 
            'admin-smtp-username': 'informatyk@dmdbudownictwo.pl', 
            'admin-smtp-server': 'smtp.office365.com', 
            'admin-smtp-port': '587', 
            'admin-smtp-password': '', 
            'url-domy': 'https://dmddomy.pl/', 
            'url-budownictwo': 'https://dmddomy.pl/', 
            'url-development': 'https://dmddomy.pl/', 
            'url-elitehome': 'https://dmddomy.pl/', 
            'url-inwestycje': 'https://dmddomy.pl/', 
            'url-instalacje': 'https://dmddomy.pl/'
        }
        ADMIN_DOMAIN = form_data['main-domain']
        ADMIN_BLOG = form_data['blog-pic-path']
        ADMIN_AVATAR = form_data['avatar-pic-path']
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
            # admin_settings
            # pagination
            # admin_smtp_password
            # admin_smtp_usernam
            # admin_smtp_port
            # admin_smtp_server
            # instalacje
            # inwestycje
            # elitehome
            # development
            # budownictwo
            # domy
            # last_restart
            # avatar_pic_path
            # blog_pic_path
            # main_domain
            # ID
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
                        main_domain = %s
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
                        ADMIN_DOMAIN, 1)
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
                        main_domain = %s
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
                        ADMIN_DOMAIN, 1)
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

    # Ustawienia paginacji
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = len(all_rents)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    # Pobierz tylko odpowiednią ilość postów na aktualnej stronie
    ads_rent = all_rents[offset: offset + per_page]



    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']
    return render_template(
                            "estate_management_rent.html",
                            ads_rent=ads_rent,
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


@app.route('/update-rent-offer-status')
def update_rent_offer_status():
    return

@app.route('/save-rent-offer', methods=["POST"])
def save_rent_offer():
    # Odczytanie danych formularza
    if request.method == 'POST':
        form_data = request.form.to_dict()
        # print(form_data)

    # Pobierz JSON jako string z formularza
    opis_json_string = request.form['opis']
    
    # Przekonwertuj string JSON na słownik Pythona
    try:
        opis_data = json.loads(f'{opis_json_string}')
    except json.JSONDecodeError:
        return jsonify({'error': 'Nieprawidłowy format JSON'}), 400

    # Teraz opis_data jest słownikiem Pythona, który możesz używać w kodzie
    title = request.form.get('title')
    rodzaj_nieruchomosci = request.form.get('rodzajNieruchomosci')
    lokalizacja = request.form.get('lokalizacja')
    cena = request.form.get('cena')
    opis = opis_data

    lat = request.form.get('lat')
    lon = request.form.get('lon')
    rokBudowy = request.form.get('rokBudowy')
    stan = request.form.get('stan')
    nrKW = request.form.get('nrKW')
    czynsz = request.form.get('czynsz')
    kaucja = request.form.get('kaucja')
    metraz = request.form.get('metraz')
    powDzialki = request.form.get('powDzialki')
    liczbaPieter = request.form.get('liczbaPieter')
    liczbaPokoi = request.form.get('liczbaPokoi')
    techBudowy = request.form.get('techBudowy')
    rodzajZabudowy = request.form.get('rodzajZabudowy')
    umeblowanie = request.form.get('umeblowanie')
    kuchnia = request.form.get('kuchnia')
    dodatkoweInfo = request.form.get('dodatkoweInfo')


    validOpis = []
    for test in opis:
        for val in test.values():
            if isinstance(val, str) and val != "":
                validOpis.append(test)
            if isinstance(val, list) and len(val)!=0:
                clearLI = [a for a in val if a != ""]
                new_li = {"li": clearLI}
                validOpis.append(new_li)
    
    if len(validOpis)!=0: testOpisu = True
    else: testOpisu = False

    # Sprawdzenie czy wszystkie wymagane dane zostały przekazane
    if not all([title, rodzaj_nieruchomosci, lokalizacja, cena, testOpisu]):
        return jsonify({'error': 'Nie wszystkie wymagane dane zostały przekazane'}), 400

    settingsDB = generator_settingsDB()
    real_loc_on_server = settingsDB['real-location-on-server']
    domain = settingsDB['main-domain']
    estate_pic_path = settingsDB['estate-pic-offer']

    'https://dmddomy.pl/images/estate/1713336102750.jpg'

    upload_path = f'{real_loc_on_server}{estate_pic_path}'
    mainDomain_URL = f'{domain}{estate_pic_path}'


    # Przetwarzanie przesłanych zdjęć
    photos = request.files.getlist('photos[]')
    saved_photos =[]
    for photo in photos:
        if photo:
            filename = f"{int(time.time())}_{secure_filename(photo.filename)}"
            print(filename)
            full_path = os.path.join(upload_path, filename)
            complete_URL_PIC = f'{mainDomain_URL}{filename}'
            try:
                photo.save(full_path)
                saved_photos.append(complete_URL_PIC)
            except Exception as e:
                print(f"Nie udało się zapisać pliku {filename}: {str(e)}. UWAGA: Adres {complete_URL_PIC} nie jest dostępny!")

    # Obsługa zdjęć 
    if len(saved_photos)>=1:
        # dodaj zdjęcia do bazy i pobierz id galerii
        gallery_id = None
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
                return redirect(url_for('estateAdsRent'))
        else:
            flash(f'Błąd podczas tworzenia zapisywania galerii w bazie!', 'danger')
            return redirect(url_for('estateAdsRent'))
        print(gallery_id)

    # Odpowiedź dla klienta
    return jsonify({'message': 'Oferta wynajmu została zapisana pomyślnie!'}), 200


@app.route('/estate-ads-sell')
def estateAdsSell():
    """Strona zawierająca listę z ogłoszeniami nieruchomości."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))

    return render_template(
                            "estate_management_sell.html",
                            )     

@app.route('/estate-ads-special')
def estateAdsspecial():
    """Strona zawierająca listę z ogłoszeniami nieruchomości."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['estate'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!', 'danger')
        return redirect(url_for('index'))

    return render_template(
                            "estate_management_special.html",
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
    
    
    restart = settingsDB['last-restart']
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']
    smtpAdmin = settingsDB['smtp_admin']

    return render_template(
                            "setting_management.html", 
                            username=session['username'],
                            userperm=session['userperm'], 
                            onPages=onPages, 
                            domain=domain,
                            blog=blog,
                            avatar=avatar,
                            restart=restart,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje,
                            smtpAdmin=smtpAdmin
                            )



if __name__ == '__main__':
    # app.run(debug=True, port=8000)
    app.run(debug=False, host='0.0.0.0', port=8000)