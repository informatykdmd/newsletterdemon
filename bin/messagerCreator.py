from connectAndQuery import connect_to_database
def create_html_message(postID, client_name):
    """
        Funkcja pobiera z bazy dane posta o podanym identyfikatorze i tworzy wiadomość HTML.
    """
    # Pobieranie z bazy danych
    dumpDB = connect_to_database(
                        f'SELECT * FROM contents WHERE ID = {postID};')
    formatDump = {}
    try:
        formatDump['title'] = dumpDB[0][1]
        formatDump['content_main'] = dumpDB[0][2]
        formatDump['highlights'] = dumpDB[0][3]
        formatDump['bullets'] = dumpDB[0][4]
        formatDump['header_foto'] = dumpDB[0][5]
        formatDump['content_foto'] = dumpDB[0][6]
        formatDump['tags'] = dumpDB[0][7]
        formatDump['category'] = dumpDB[0][8]
    except IndexError as e:
        print("Błąd w funkcji 'create_html_message': ",e)
        return ''

    readyHtmlBullets = ''
    for text in formatDump['bullets'].split('#splx#'):
        readyHtmlBullets +=  f'<li>{text}</li>\n'

    template = """<!DOCTYPE html>
    <html lang="pl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{{tytuł}}</title>
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
        <p>Witaj, {{imie klienta}}. Przygotowaliśmy dla Ciebie nasze najnowsze newsy!</p>
        <h1>{{tytuł}}</h1>
        <p>{{wprowadzenie}}</p>

        <!-- Główna treść -->
        <div>
            {{tresc glowna}}
        </div>

        <!-- Wypunktowania -->
        <ul>
            {{wypunktowania}}
        </ul>

        <!-- Główne zdjęcie -->
        <img src="https://dmddomy.pl/{{zdjecie glowne}}" alt="Główne zdjęcie">

        <!-- Dodatkowe zdjęcie -->
        <img src="https://dmddomy.pl/{{zdjecie dodatkowe}}" alt="Dodatkowe zdjęcie">

        <!-- Tagi i kategoria -->
        <p>Tagi: {{tagi}}</p>
        <p>Kategoria: {{kategoria}}</p>

        <!-- Stopka, dodaj więcej informacji, jeśli to konieczne -->
        <footer>
            <p>© 2024 Twoja Firma. Wszelkie prawa zastrzeżone.</p>
        </footer>
    </body>
    </html>"""

    ready_template = template.replace('{{imie klienta}}', str(client_name)).replace('{{tytuł}}', formatDump['title']).replace('{{tresc glowna}}', formatDump['content_main'])\
                                .replace('{{wprowadzenie}}', formatDump['highlights']).replace('{{wypunktowania}}', readyHtmlBullets)\
                                    .replace('{{zdjecie glowne}}', formatDump['header_foto']).replace('{{zdjecie dodatkowe}}', formatDump['content_foto'])\
                                        .replace('{{kategoria}}', formatDump['category']).replace('{{tagi}}', formatDump['tags'])
    return ready_template

if __name__ == "__main__":
    print(create_html_message(1, 'michał'))
