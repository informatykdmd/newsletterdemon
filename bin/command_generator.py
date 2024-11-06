import json

def tuple_to_string(tup, sep="|"):
    """Konwertuje tuplę na string za pomocą separatora."""
    return sep.join(tup)

def string_to_tuple(s, sep="|"):
    """Konwertuje string na tuplę, używając separatora do podziału."""
    return tuple(s.split(sep))

def getMorphy(morphy_JSON_file_name="/home/johndoe/app/newsletterdemon/logs/commandAifa.json"):
    """Odzyskuje tuplę z kluczy JSON i zwraca dane z poprawionymi kluczami."""
    with open(morphy_JSON_file_name, "r", encoding="utf-8") as f:
        dane_json = json.load(f)
    # Konwersja kluczy z formatu string na tuple
    dane_with_tuples = {string_to_tuple(k): v for k, v in dane_json.items()}
    return dane_with_tuples

def saveMorphy(dane_dict, file_name="/home/johndoe/app/newsletterdemon/logs/commandAifa.json"):
    # Konwersja tupli na string przy zapisie do JSON
    dane_json_ready = {tuple_to_string(k): v for k, v in dane_dict.items()}
    # Zapis do JSON z kodowaniem utf-8
    with open(file_name, "w", encoding="utf-8") as f:
        json.dump(dane_json_ready, f, ensure_ascii=False, indent=4)

def generator_polecen():
    """Dodaje nowe polecenia do istniejącego pliku JSON."""
    file_name = "/home/johndoe/app/newsletterdemon/logs/commandAifa.json"
    dane = getMorphy(file_name)

    while True:
        # Wprowadzanie kategorii polecenia
        kategoria = input("Podaj flagę polecenia (np. 'raport systemu' lub 'status kampanii') lub wpisz @koniec, aby zakończyć: ")
        if kategoria == "@koniec":
            print("Zakończono dodawanie poleceń.")
            break

        while True:
            # Wprowadzanie treści polecenia
            polecenie = input(f"Wpisz polecenie dla kategorii '{kategoria}' (lub wpisz @koniec, aby zakończyć dodawanie dla tej kategorii): ")
            if polecenie == "@koniec":
                print(f"Zakończono dodawanie poleceń dla kategorii '{kategoria}'.")
                break

            # Konwersja polecenia na tuplę
            polecenie_tuple = tuple(polecenie.split())
            
            # Dodanie polecenia do danych
            dane[polecenie_tuple] = kategoria
            print(f"Dodano polecenie: {polecenie_tuple} -> {kategoria}")

    # Zapis do pliku JSON
    saveMorphy(dane, file_name)
    print("Zapisano wszystkie nowe polecenia do pliku.")
    
if __name__ == "__main__":
    generator_polecen()