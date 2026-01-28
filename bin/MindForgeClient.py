import requests

def show_template(user_name, api_key, api_url="http://127.0.0.1:5000/api/get-template"):

    # Dane do wysłania w formacie JSON
    payload = {
        "user": user_name,
        "api_key": api_key,
        "api_url": api_url
    }
    export_dict = {}
    try:
        # Wysyłanie żądania POST z danymi JSON
        response = requests.post(api_url, json=payload)
        
        # Sprawdzenie odpowiedzi
        if response.status_code == 200:
            show_template_response = response.json()
            if "prompt" in show_template_response:
                export_dict["prompt"] = show_template_response["prompt"]
                # print(show_template_response.get("prompt"))
            if "data" in show_template_response:
                export_dict["data"] = show_template_response["data"]
                # print(show_template_response.get("data"))
            if "level" in show_template_response:
                export_dict["level"] = show_template_response["level"]
                # print(show_template_response.get("level"))
        else:
            export_dict["error"] = f"Błąd: {response.text}, status: {response.status_code}!"
            # print("Błąd:", response.status_code, response.text)
            
    except requests.exceptions.RequestException as e:
        export_dict["error"] = f"Wystąpił błąd w komunikacji z serwerem: {e}!"
        # print("Wystąpił błąd w komunikacji z serwerem:", e)
    return export_dict

def communicate_with_endpoint(json_commander, user_name, api_key, api_url="http://127.0.0.1:5000/api/handling-responses"):
    # Adres URL endpointu Flask
    # url = "http://127.0.0.1:5000/api/handling-responses"
    
    payload = {
        "primary_key": json_commander,
        "user": user_name,
        "api_key": api_key,
        "api_url": api_url
    }
    export_dict = {}
    try:
        # Wysyłanie żądania POST z danymi JSON
        response = requests.post(api_url, json=payload, timeout=60)
        
        return response.json()

    except requests.exceptions.RequestException as e:
        export_dict["error"] = f"Błąd: {e}!"
        print("Wystąpił błąd w komunikacji z serwerem:", e)
    return export_dict
        
    

# Wywołanie funkcji
if __name__ == "__main__":
    for _ in range(10):
        print(show_template("aifa", "klucz_api"))
        inp = input("json: ")
        print(communicate_with_endpoint(inp, "aifa", "klucz_api"))
        print()

    """
    {"AKTUALIZACJA_OGLOSZEN_NIERUCHOMOSCI_NA_WYNAJEM": false, "AKTUALIZACJA_OGLOSZEN_NIERUCHOMOSCI_NA_SPRZEDAZ": false, "AKTUALIZACJA_OGLOSZEN_NIERUCHOMOSCI_NA_SPRZEDAZ_I_NA_WYNAJEM": false, "ZARZADZANIE_KAMPANIAMI_NIERUCHOMOSCI": false, "KAMPANIE_FB": false, "ZARZADZANIE_SEKCJA_KARIERA": false, "KAMPANIE_ANONIMOWE_FB": false, "WYSYLANIE_EMAIL": false, "ZARZADZANIE_PRACOWNIKAMI": false, "ZARZADZANIE_BLOGIEM": false}
    {"AKTUALIZACJA_OGLOSZEN_NIERUCHOMOSCI_NA_WYNAJEM": true, "AKTUALIZACJA_OGLOSZEN_NIERUCHOMOSCI_NA_SPRZEDAZ": false, "AKTUALIZACJA_OGLOSZEN_NIERUCHOMOSCI_NA_SPRZEDAZ_I_NA_WYNAJEM": false, "ZARZADZANIE_KAMPANIAMI_NIERUCHOMOSCI": false, "KAMPANIE_FB": false, "ZARZADZANIE_SEKCJA_KARIERA": false, "KAMPANIE_ANONIMOWE_FB": false, "WYSYLANIE_EMAIL": false, "ZARZADZANIE_PRACOWNIKAMI": false, "ZARZADZANIE_BLOGIEM": false}
    {"AKTUALIZACJA_OGLOSZEN_NIERUCHOMOSCI_NA_WYNAJEM": true, "AKTUALIZACJA_OGLOSZEN_NIERUCHOMOSCI_NA_SPRZEDAZ": false, "AKTUALIZACJA_OGLOSZEN_NIERUCHOMOSCI_NA_SPRZEDAZ_I_NA_WYNAJEM": true, "ZARZADZANIE_KAMPANIAMI_NIERUCHOMOSCI": true, "KAMPANIE_FB": false, "ZARZADZANIE_SEKCJA_KARIERA": false, "KAMPANIE_ANONIMOWE_FB": false, "WYSYLANIE_EMAIL": false, "ZARZADZANIE_PRACOWNIKAMI": false, "ZARZADZANIE_BLOGIEM": false}
    {"[1]::[tytuł pozycji1]::[OfertyNajmu]": false, "[2]::[tytuł pozycji2]::[OfertyNajmu]": false, "[3]::[tytuł pozycji3]::[OfertyNajmu]": false}
    {"[1]::[tytuł pozycji1]::[OfertyNajmu]": true, "[2]::[tytuł pozycji2]::[OfertyNajmu]": false, "[3]::[tytuł pozycji3]::[OfertyNajmu]": false}
    {"[1]::[tytuł pozycji1]::[OfertyNajmu]": true, "[2]::[tytuł pozycji2]::[OfertyNajmu]": true, "[3]::[tytuł pozycji3]::[OfertyNajmu]": true}

    {"tytul": "tytuł","opis": "[{^p^:^paragraf^}, {^li^:[^dynamiczny^, ^stylowalny^]}]","cena": 651450,"metraz": 89}
    {"tytul": "tytuł","opis": "[{^p^:^paragraf^}, {^li^:[^dynamiczny^, ^stylowalny^]}]","cena": 651450,"metraz": 100}
    {"tytul": "tytuł pozycji 1","opis": "[{^p^:^paragraf 1^}, {^li^:[^dynamiczny 1^, ^stylowalny^]}]","cena": 1500,"metraz": 20}
    {"raport": ""}
    {"raport": "zrobione"}

    {"tytul": "tytuł", "opis": "[{^p^:^paragraf^}, {^li^:[^dynamiczny^, ^stylowalny^]}]", "cena": 651450, "metraz": 100}
    """