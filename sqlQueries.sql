-- zapytanie pobierające dane postów
SELECT * FROM posts 
-- zapytanie edytujące posta
UPDATE posts SET title='Nowy tytuł', content='Nowy treść' WHERE id=1;
-- zapytanie dodając nowy post do bazy danych
INSERT INTO posts (title, author_id, created_at) VALUES ('Tytuł postu', 2, '2021-09-30');
-- zapytanie usuwające post z bazy danych
DELETE FROM posts WHERE id = 4;


-- zapytanie pobierajace wszystkich użytkowników
SELECT * FROM users;
-- zapytanie dodawajace nowego uzytkownika do systemu
INSERT INTO users(username, email, password, created_at) VALUES('nowyUzyszk', 'email@test.pl', '$2b$10$QYdVh5786lHGj');
--zapytanie edytujące dane użytkownika
UPDATE users SET email='nowa@email.pl', password='hasło' WHERE id=5;
--zapytanie usuwające użytkownika z systemu
DELETE FROM users WHERE id=6;

-- zapytanie pobierające wszyskie komentarze
SELECT c.* FROM comments AS c JOIN posts AS p ON c.post_id = p.id;
-- zapytanie usuwające komentarze 
DELETE FROM comments WHERE id=4;

-- zapytanie pobierające wszystkich subskrybentów
SELECT * FROM subscriptions WHERE user_id=(SELECT id FROM users WHERE username="Janek");

-- zapytanie pobierajace team
SELECT t.* FROM teams AS t JOIN members AS m ON t.id = m.team_id WHERE m.user_id=(SELECT id FROM users WHERE username="Janek");
-- zapytanie aktualizujące team
INSERT  INTO teams(name) VALUES('Zespół A'),('Zespół B');

-- zapytanie pobierające autorów
SELECT u.* FROM users AS u JOIN posts AS p ON u.id=p.author_id GROUP BY u.id ORDER BY COUNT(*)

-- tabela lento.pl
CREATE TABLE ogloszenia_lento (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rodzaj_ogloszenia VARCHAR(255),
    typ_ogloszenia VARCHAR(255),
    tytul_ogloszenia VARCHAR(255),
    kategoria_ogloszenia VARCHAR(255),
    opis_ogloszenia TEXT,
    id_galerii INT,
    miejscowosc VARCHAR(255),
    osoba_kontaktowa VARCHAR(255),
    nr_telefonu VARCHAR(20),
    status INT,
    data_aktualizacji TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

ALTER TABLE ogloszenia_lento
ADD COLUMN bez_promowania INT DEFAULT 0 AFTER nr_telefonu,
ADD COLUMN promowanie_lokalne_14_dni INT DEFAULT 0 AFTER bez_promowania,
ADD COLUMN promowanie_lokalne_30_dni INT DEFAULT 0 AFTER promowanie_lokalne_14_dni,
ADD COLUMN promowanie_regionalne_14_dni INT DEFAULT 0 AFTER promowanie_lokalne_30_dni,
ADD COLUMN promowanie_regionalne_30_dni INT DEFAULT 0 AFTER promowanie_regionalne_14_dni,
ADD COLUMN promowanie_ogolnopolskie_14_dni INT DEFAULT 0 AFTER promowanie_regionalne_30_dni,
ADD COLUMN promowanie_ogolnopolskie_30_dni INT DEFAULT 0 AFTER promowanie_ogolnopolskie_14_dni,
ADD COLUMN top_ogloszenie_7_dni INT DEFAULT 0 AFTER promowanie_ogolnopolskie_30_dni,
ADD COLUMN top_ogloszenie_14_dni INT DEFAULT 0 AFTER top_ogloszenie_7_dni,
ADD COLUMN etykieta_pilne_7_dni INT DEFAULT 0 AFTER top_ogloszenie_14_dni,
ADD COLUMN etykieta_pilne_14_dni INT DEFAULT 0 AFTER etykieta_pilne_7_dni,
ADD COLUMN codzienne_odswiezenie_7_dni INT DEFAULT 0 AFTER etykieta_pilne_14_dni,
ADD COLUMN codzienne_odswiezenie_14_dni INT DEFAULT 0 AFTER codzienne_odswiezenie_7_dni,
ADD COLUMN wyswietlanie_na_stronie_glownej_14_dni INT DEFAULT 0 AFTER codzienne_odswiezenie_14_dni,
ADD COLUMN wyswietlanie_na_stronie_glownej_30_dni INT DEFAULT 0 AFTER wyswietlanie_na_stronie_glownej_14_dni,
ADD COLUMN super_oferta_7_dni INT DEFAULT 0 AFTER wyswietlanie_na_stronie_glownej_30_dni,
ADD COLUMN super_oferta_14_dni INT DEFAULT 0 AFTER super_oferta_7_dni;


-- tabela facebook
CREATE TABLE ogloszenia_facebook (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rodzaj_ogloszenia VARCHAR(255),
    id_ogloszenia INT,
    tytul_ogloszenia TEXT,
    opis_ogloszenia TEXT,
    cena INT,
    stan INT,
    promuj_po_opublikowaniu INT,
    zdjecia_string TEXT,
    osoba_kontaktowa VARCHAR(255),
    nr_telefonu VARCHAR(20),
    id_zadania INT,
    id_ogloszenia_na_facebook INT,
    status INT,
    active_task INT,
    errors TEXT,
    data_aktualizacji TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    action_before_errors INT
);

ALTER TABLE ogloszenia_facebook
ADD COLUMN lokalizacja TEXT AFTER stan,
ADD COLUMN znaczniki TEXT AFTER lokalizacja;

-- tabela adresowo
CREATE TABLE ogloszenia_adresowo (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rodzaj_ogloszenia VARCHAR(255),
    id_ogloszenia INT,
    tytul_ogloszenia TEXT,
    kategoria_ogloszenia TEXT,
    region TEXT,
    cena INT,
    umeblowanie TEXT,
    opis_ogloszenia TEXT,
    liczba_pieter INT,
    liczba_pokoi INT,
    poziom TEXT,
    ulica TEXT,
    winda TEXT,
    powierzchnia INT,
    pow_dzialki INT,
    rok_budowy INT,
    stan INT,
    typ_budynku TEXT,
    forma_wlasnosci TEXT,
    zdjecia_string TEXT,
    osoba_kontaktowa VARCHAR(255),
    nr_telefonu VARCHAR(20),
    id_zadania INT,
    id_ogloszenia_na_adresowo TEXT,
    status INT,
    active_task INT,
    errors TEXT,
    data_aktualizacji TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    action_before_errors INT
);

-- tabela allegrolokalnie
CREATE TABLE ogloszenia_allegrolokalnie (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rodzaj_ogloszenia VARCHAR(255),
    id_ogloszenia INT,
    tytul_ogloszenia TEXT,
    kategoria_ogloszenia TEXT,
    region TEXT,
    kod_pocztowy TEXT,
    ulica TEXT,
    cena INT,
    opis_ogloszenia TEXT,
    liczba_pieter INT,
    liczba_pokoi INT,
    poziom TEXT,
    powierzchnia INT,
    pow_dzialki INT,
    typ_budynku TEXT,
    typ_komercyjny TEXT,
    typ_dzialki TEXT,
    typ_kuchni TEXT,
    rodzaj_zabudowy TEXT,
    rynek TEXT,
    pakiet TEXT,
    extra_wyroznienie TEXT,
    extra_wznawianie TEXT,
    zdjecia_string TEXT,
    osoba_kontaktowa VARCHAR(255),
    nr_telefonu VARCHAR(20),
    adres_email VARCHAR(255),
    id_zadania INT,
    id_ogloszenia_na_allegro TEXT,
    status INT,
    active_task INT,
    errors TEXT,
    data_aktualizacji TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    action_before_errors INT
);