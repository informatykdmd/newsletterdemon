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
import os

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
        'blog-pic-path': take_data_settingsDB('blog_pic_path'),
        'avatar-pic-path': take_data_settingsDB('avatar_pic_path'),
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
                'settings': data[30],
                'newsletter': data[23]
                },
            'brands': {
                'domy': data[24],
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
    took_allPost = take_data_table('*', 'blog_posts')
    for post in took_allPost:
        id = post[0]
        id_content = post[1]
        id_author = post[2]
        post_data = post[3]

        allPostComments = take_data_where_ID('*', 'comments', 'BLOG_POST_ID', id)
        comments_dict = {}
        for i, com in enumerate(allPostComments):
            comments_dict[i] = {}
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
                ) == usersTempDict[username]['hashed_password']:
            session['username'] = username
            session['userperm'] = permTempDict[username]
            session['user_data'] = users_data[username]
            session['brands'] = brands_data[username]

            return redirect(url_for('index'))
        else:
            flash('Błędne nazwa użytkownika lub hasło')

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
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
        return redirect(url_for('index'))
    
    # Wczytanie listy wszystkich postów z bazy danych i przypisanie jej do zmiennej posts
    all_posts = daneDBList

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
                    flash('Nieprawidłowe stare hasło')
                    return redirect(url_for('index'))
                
            if PAGE == 'users':
                if session['userperm']['users'] == 0:
                    flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
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
                                flash('Hasło zostało pomyślnie zmienione.')
                                if PAGE == 'users':
                                    return redirect(url_for('users'))
                                if PAGE=='home':
                                    return redirect(url_for('logout'))
                        else:
                            flash("Hasło musi zawierać co najmniej jeden znak specjalny.")
                            return redirect(url_for('index'))
                    else:
                        flash("Hasło musi zawierać co najmniej jedną wielką literę.")
                        return redirect(url_for('index'))
                else:
                    flash("Hasło musi mieć co najmniej 8 znaków.")
                    return redirect(url_for('index'))
            else:
                flash('Hasła muszą być identyczne!')
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
                flash('Dane zostały pomyślnie zaktualizowane.')
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
                flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
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
                flash('Dane zostały pomyślnie zaktualizowane.')
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
                flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
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
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
        return redirect(url_for('index'))
    # Pobierz id usera z formularza
    if request.method == 'POST':
        form_data = request.form.to_dict()
        
        ID=int(form_data['UserId'])
        take_user_data = take_data_where_ID('*', 'admins', 'ID', ID)[0]
        ADMIN_NAME = take_user_data[1]
        LOGIN = take_user_data[2]
        msq.delete_row_from_database(
            """
            DELETE FROM admins WHERE ID = %s AND ADMIN_NAME = %s AND LOGIN = %s;
            """,
            (ID, ADMIN_NAME, LOGIN)
        )
        print(take_user_data)
        print(ADMIN_NAME)
        print(LOGIN)
    
    return redirect(url_for('index'))

@app.route('/save-blog-post', methods=['GET', 'POST'])
def save_post():
    """Strona zapisywania edytowanego posta."""
    # print(blog(False))
    
    try:
        posts, username, userperm, pagination = blog(False)
    except Exception as e:
        flash(f"Błąd! {e}", "error")
        return redirect(url_for('blog'))
    
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['blog'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
        return redirect(url_for('index'))
    
    # Obsługa formularza POST
    if request.method == 'POST':
        form_data = request.form.to_dict()
        set_form_id = None
        print(form_data)
        # Znajdź id posta
        for key in form_data.keys():
            if '_' in key:
                set_form_id = key.split('_')[1]
                try: 
                    int(set_form_id)
                    break
                except ValueError:
                    set_form_id = None
        if set_form_id == '9999999':
            new_post = True
            set_form_id = None
            print(f"procedura dodawania nowego posta = {new_post}" )
            flash(f"procedura dodawania nowego posta = {new_post}" )

            return render_template("blog_management.html", posts=posts, username=username, userperm=userperm, pagination=pagination)

        # Sprawdzenie czy udało się ustalić id posta
        if not set_form_id:
            flash('Ustalenie id posta okazało się niemożliwe')
            return render_template("blog_management.html", posts=posts, username=username, userperm=userperm, pagination=pagination)
        
        # Przygotowanie ścieżki do zapisu plików
        upload_path = '../'

        # Obsługa Main Foto
        main_foto = request.files.get(f'mainFoto_{set_form_id}')
        if main_foto and allowed_file(main_foto.filename):
            filename = str(int(time.time())) + secure_filename(main_foto.filename)
            main_foto.save(upload_path + filename)

        # Obsługa Content Foto
        content_foto = request.files.get(f'contentFoto_{set_form_id}')
        if content_foto and allowed_file(content_foto.filename):
            filename = str(int(time.time())) + secure_filename(content_foto.filename)
            content_foto.save(upload_path + filename)

        flash('Dane zostały zapisane poprawnie!')
        print('Dane zostały zapisane poprawnie!')
        print(form_data)

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
                            username=username, 
                            userperm=userperm, 
                            pagination=pagination,
                            domy=domy,
                            budownictwo=budownictwo,
                            development=development,
                            elitehome=elitehome,
                            inwestycje=inwestycje,
                            instalacje=instalacje)
    
    return redirect(url_for('index'))

@app.route('/remove-post')
def remove_post():
    """Usuwanie bloga"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['blog'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
        return redirect(url_for('index'))
    
    return render_template("home.html", userperm=session['userperm'])

@app.route('/remove-comment')
def remove_comment():
    """Usuwanie komentarza"""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    return render_template("home.html", userperm=session['userperm'])

@app.route('/user')
def users(router=True):
    """Strona z zarządzaniem użytkownikami."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session or 'userperm' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['users'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
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
        
        settingsDB = generator_settingsDB()# Renderowanie szablonu blog-managment.html z danymi o postach (wszystkimi lub po jednym)
        domy = settingsDB['domy']
        budownictwo = settingsDB['budownictwo']
        development = settingsDB['development']
        elitehome = settingsDB['elitehome']
        inwestycje = settingsDB['inwestycje']
        instalacje = settingsDB['instalacje']

        return render_template(
                            "user_management.html", 
                            users=users, 
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
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
        return redirect(url_for('index'))
    
    newsletterSettingDB = generator_newsletterSettingDB()
    newsletterPlan = newsletterSettingDB['time_interval_minutes']
    smtpSettingsDict = newsletterSettingDB['smtp_config']
    # Sortuj subsDataDB według klucza 'id' w malejącej kolejności
    sorted_subs = sorted(subsDataDB, key=lambda x: x['id'], reverse=True)

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
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
        return redirect(url_for('index'))
    
    curent_settings_team = teamDB
    users_atributes = {}
    assigned_dmddomy = []
    
    for usr_d in userDataDB:
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
    for employees in curent_settings_team:
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

            for row in userDataDB:
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
        for usr_d in userDataDB:
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
        # 1. usuń wszystkie pozycje dla EMPLOYEE_DEPARTMENT
        # 2. wstaw nowe dane do bazy zachowując kolejność zapisu w bazie

        print('dane:', ready_exportDB)

    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']

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
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
        return redirect(url_for('index'))
    
    curent_settings_team = teamDB
    users_atributes = {}
    
    assigned_dmdelitehome = []
    for usr_d in userDataDB:
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
    for employees in curent_settings_team:
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

            for row in userDataDB:
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
        for usr_d in userDataDB:
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
        # 1. usuń wszystkie pozycje dla EMPLOYEE_DEPARTMENT
        # 2. wstaw nowe dane do bazy zachowując kolejność zapisu w bazie

        print('dane:', ready_exportDB)

    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']

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
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
        return redirect(url_for('index'))
    
    curent_settings_team = teamDB
    users_atributes = {}

    assigned_dmdbudownictwo = []

    for usr_d in userDataDB:
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
    for employees in curent_settings_team:
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

            for row in userDataDB:
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
        for usr_d in userDataDB:
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
        # 1. usuń wszystkie pozycje dla EMPLOYEE_DEPARTMENT
        # 2. wstaw nowe dane do bazy zachowując kolejność zapisu w bazie

        print('dane:', ready_exportDB)

    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']

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
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
        return redirect(url_for('index'))
    
    curent_settings_team = teamDB
    users_atributes = {}
    assigned_dmddevelopment = []
    for usr_d in userDataDB:
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
    for employees in curent_settings_team:
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

            for row in userDataDB:
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
        for usr_d in userDataDB:
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
        # 1. usuń wszystkie pozycje dla EMPLOYEE_DEPARTMENT
        # 2. wstaw nowe dane do bazy zachowując kolejność zapisu w bazie
        
        print('dane:', ready_exportDB)

    settingsDB = generator_settingsDB()
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']

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
def team_investment():
    """Strona zespołu."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['team'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
        return redirect(url_for('index'))
    
    curent_settings_team = teamDB
    users_atributes = {}
    
    assigned_dmdinvestment = []
    for usr_d in userDataDB:
        u_name = usr_d['name']
        u_login = usr_d['username']
        users_atributes[u_name] = usr_d
        
        if usr_d['brands']['inwestycje'] == 1:
            assigned_dmdinvestment.append(u_login)

    collections = {
        'inwestycje': {
            'home': [],
            'team': [],
            'available': []
        }
    }

    employee_photo_dict = {}
    i_investment = 1
    for employees in curent_settings_team:
        group = employees['EMPLOYEE_DEPARTMENT']
        department = str(group).replace('dmd ', '')
        employee = employees['EMPLOYEE_NAME']
        employee_login = users_atributes[employee]['username']

        employee_photo = users_atributes[employee]['avatar']
        try: employee_photo_dict[employee_login]
        except KeyError: employee_photo_dict[employee_login] = employee_photo

       
        if i_investment < 5 and department == "investment":
            collections[department]['home'].append(employee_login)
        elif i_investment >= 5 and department == "investment":
            collections[department]['team'].append(employee_login)
        if department == 'investment':
            i_investment += 1
    
    for assign in assigned_dmdinvestment:
        if assign not in collections['inwestycje']['home'] + collections['inwestycje']['team']:
            collections['inwestycje']['available'].append(assign)

            for row in userDataDB:
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
        for usr_d in userDataDB:
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
        # 1. usuń wszystkie pozycje dla EMPLOYEE_DEPARTMENT
        # 2. wstaw nowe dane do bazy zachowując kolejność zapisu w bazie
        print('dane:', ready_exportDB)

    settingsDB = generator_settingsDB()    
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']
    
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
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
        return redirect(url_for('index'))
    
    curent_settings_team = teamDB
    users_atributes = {}
    assigned_dmdinstalacje = []
    for usr_d in userDataDB:
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

    for employees in curent_settings_team:
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

            for row in userDataDB:
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
        for usr_d in userDataDB:
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
        # 1. usuń wszystkie pozycje dla EMPLOYEE_DEPARTMENT
        # 2. wstaw nowe dane do bazy zachowując kolejność zapisu w bazie
        print('dane:', ready_exportDB)

    settingsDB = generator_settingsDB()    
    domy = settingsDB['domy']
    budownictwo = settingsDB['budownictwo']
    development = settingsDB['development']
    elitehome = settingsDB['elitehome']
    inwestycje = settingsDB['inwestycje']
    instalacje = settingsDB['instalacje']
    
    return render_template(
                            "team_management_instalacje.html", 
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


@app.route('/subscriber')
def subscribers(router=True):
    """Strona zawierająca listę subskrybentów Newslettera."""
    # Sprawdzenie czy użytkownik jest zalogowany, jeśli nie - przekierowanie do strony głównej
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if session['userperm']['subscribers'] == 0:
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
        return redirect(url_for('index'))
    
    subscribers_all = subsDataDB

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
                                subs=subs, username=session['username'], 
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
        flash('Nie masz uprawnień do zarządzania tymi zasobami. Skontaktuj sie z administratorem!')
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