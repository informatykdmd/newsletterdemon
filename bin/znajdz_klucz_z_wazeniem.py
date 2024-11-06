import re
import difflib

def usun_polskie_znaki(tekst):
    zamienniki = {
        'ą': 'a', 'ć': 'c', 'ę': 'e', 'ł': 'l', 'ń': 'n', 'ó': 'o', 'ś': 's', 'ż': 'z', 'ź': 'z'
    }
    for znak, zamiennik in zamienniki.items():
        tekst = tekst.replace(znak, zamiennik)
    return tekst

def porownaj_slowa(slowo1, slowo2):
    """
    Porównuje podobieństwo między dwoma słowami, uwzględniając literówki i brak polskich znaków.
    Zwraca procentowe dopasowanie (od 0 do 1).
    """
    # Zamiana polskich znaków na ich odpowiedniki bez znaków diakrytycznych
    

    # Ujednolicenie liter i usunięcie polskich znaków
    slowo1 = usun_polskie_znaki(slowo1.lower())
    slowo2 = usun_polskie_znaki(slowo2.lower())
    
    # Porównanie podobieństwa słów
    podobienstwo = difflib.SequenceMatcher(None, slowo1, slowo2).ratio()
    return round(podobienstwo, 2)

def znajdz_klucz_z_wazeniem(dane_d, tekst_szukany: str):
    """
    Sprawdza dopasowanie słów kluczowych i fraz z tekst_szukany do tupli kluczy w słowniku dane_d.
    Przeszukuje tekst w oknach o długości klucza, porównując każde słowo z frazami klucza przy 
    tolerancji na literówki i polskie znaki. Zwraca wynik z oceną na podstawie liczby wystąpień 
    dopasowań, kolejności fraz oraz procentu dopasowania.
    
    Parametry:
    - dane_d (dict): Słownik, gdzie kluczami są tuplę fraz do wyszukania, a wartościami - 
      odpowiadające im informacje zwracane przy dopasowaniu.
    - tekst_szukany (str): Tekst, w którym będą wyszukiwane frazy z kluczy słownika.
    
    Zwraca:
    dict: Słownik z informacjami o dopasowaniach, zawierający:
        - "wystapienia" (int): Liczba pełnych wystąpień klucza w tekście.
        - "kolejnosc" (bool): Czy frazy wystąpiły w tej samej kolejności co w kluczu.
        - "wartosci" (list): Lista unikalnych wartości, które zostały dopasowane.
        - "sukces" (bool): True, jeśli znaleziono co najmniej jedno dopasowanie, inaczej False.
        - "procent" (float): Procent dopasowania klucza w stosunku do liczby jego elementów.
        - "najtrafniejsze" (any): Najlepiej dopasowana wartość na podstawie oceny dopasowania.
    """
    # Usunięcie polskich znaków z tekstu szukanego
    tekst_szukany = usun_polskie_znaki(re.sub(r'[^\w\s]', '', tekst_szukany.lower()))
    slowa_w_tekscie = tekst_szukany.split()
    wynik = {
        "wystapienia": 0,
        "kolejnosc": False,
        "wartosci": set(),
        "sukces": False,
        "procent": 0.0,
        "najtrafniejsze": None
    }

    max_ocena = 0
    prog_podobienstwa = 0.8

    for klucz, wartosc in dane_d.items():
        klucz_lower = tuple(usun_polskie_znaki(k.lower()) for k in klucz)
        wystapienia = 0
        kolejnosc = True
        procent_dopasowania = 0.0

        # Sprawdzamy każde przesuwające się okno w tekście o długości równej kluczowi lub większym o 1 słowo
        for i in range(len(slowa_w_tekscie) - len(klucz_lower) + 1):
            okno = slowa_w_tekscie[i:i+len(klucz_lower) + 1]  # Okno o długości klucza + 1 słowo

            # Pierwsza próba: sprawdzenie pełnego dopasowania
            if all(any(porownaj_slowa(fraza, czesc_okna) >= prog_podobienstwa 
                       for czesc_okna in okno) for fraza in klucz_lower):
                wystapienia += 1
                procent_dopasowania = 1.0  # Pełne dopasowanie, 100%
                break  # Przerywamy dalsze sprawdzanie w tym oknie

            # Druga próba: usuwamy jedno słowo i sprawdzamy dopasowanie pozostałych
            for j in range(len(okno)):
                okno_bez_slowa = okno[:j] + okno[j+1:]
                if all(any(porownaj_slowa(fraza, czesc_okna) >= prog_podobienstwa 
                           for czesc_okna in okno_bez_slowa) for fraza in klucz_lower):
                    wystapienia += 1
                    procent_dopasowania = len(okno_bez_slowa) / len(klucz_lower)  # Procent dla dopasowania bez jednego słowa
                    break

        # Obliczenie ostatecznej oceny dla aktualnego klucza
        ocena = (wystapienia * 0.4) + (procent_dopasowania * 0.4) + (kolejnosc * 0.2)

        if wystapienia > 0:
            wynik["wartosci"].add(wartosc)
            wynik["sukces"] = True
            if ocena > max_ocena:
                max_ocena = ocena
                wynik["najtrafniejsze"] = wartosc
                wynik["wystapienia"] = wystapienia
                wynik["kolejnosc"] = kolejnosc
                wynik["procent"] = procent_dopasowania

    wynik["wartosci"] = list(wynik["wartosci"])
    if wynik["najtrafniejsze"] in wynik["wartosci"]:
        wynik["wartosci"].remove(wynik["najtrafniejsze"])

    return wynik