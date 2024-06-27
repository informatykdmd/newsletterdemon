def wczytaj_dane(plik_csv, kolumna1, kolumna2):
    with open(plik_csv, 'r', encoding='utf-8') as file:
        next(file)  # Pomija nagłówek
        dane = [(row[kolumna1], row[kolumna2]) for row in (line.strip().split(';') for line in file)]
    return dane
def getRegionData(
        wojewodztwo=None,
        powiat=None,
        gmina=None,
        miejscowosc=None,
        dzielnica=None,
        csv_woj='csv/A01_Granice_wojewodztw.csv',
        csv_pow='csv/A02_Granice_powiatow.csv',
        csv_gmi='csv/A03_Granice_gmin.csv',
        csv_jed='csv/A05_Granice_jednostek_ewidencyjnych.csv',
        csv_obr='csv/A06_Granice_obrebow_ewidencyjnych.csv'
        ):
    granice_wojewodztw = wczytaj_dane(csv_woj, 2, 3)
    granice_powiatow = wczytaj_dane(csv_pow, 2, 3)
    granice_gmin = wczytaj_dane(csv_gmi, 2, 3)
    granice_jednostek_ewidencyjnych = wczytaj_dane(csv_jed, 2, 3)
    granice_obrebow_ewidencyjnych = wczytaj_dane(csv_obr, 2, 3)

    wojewodztwa_dict = {w1: w2 for w1, w2 in granice_wojewodztw}
    wojewodztwa_dict_reverse = {w2: w1 for w1, w2 in granice_wojewodztw}

    powiaty_dict = {w1: " ".join(w2.split()[1:]) for w1, w2 in granice_powiatow}
    powiaty_dict_reverse = {" ".join(w2.split()[1:]): w1 for w1, w2 in granice_powiatow}

    gminy_dict = {w1: w2 for w1, w2 in granice_gmin}
    gminy_dict_reverse = {w2: w1 for w1, w2 in granice_gmin}

    jednostki_ewidencyjne_dict = {w1: w2 for w1, w2 in granice_jednostek_ewidencyjnych}
    jednostki_ewidencyjne_dict_reverse = {w2: w1 for w1, w2 in granice_jednostek_ewidencyjnych}

    obreby_ewidencyjne_dict = {w1: w2 for w1, w2 in granice_obrebow_ewidencyjnych}
    obreby_ewidencyjne_dict_reverse = {w2: w1 for w1, w2 in granice_obrebow_ewidencyjnych}

    wojewodztwa_list = [x for x in wojewodztwa_dict.values()]
    powiaty_list = []
    gminy_list = []
    miejscowosci_list = []
    dzielnice_list = ['Nieokreślona']

    inp_wojewodztwo = str(wojewodztwo)
    
    if inp_wojewodztwo in wojewodztwa_dict_reverse:
        choice_wojewodztwo = wojewodztwa_dict_reverse[inp_wojewodztwo]
    else:
        return wojewodztwa_list

    for key, val in powiaty_dict.items():
        if key.startswith(choice_wojewodztwo):
            powiaty_list.append(val)

    inp_powiat = str(powiat)
    if inp_powiat in powiaty_list:
        choice_powiat = powiaty_dict_reverse[inp_powiat]
    else:
        return powiaty_list

    for key, val in gminy_dict.items():
        if key.startswith(choice_powiat):
            gminy_list.append(val)

    if len(gminy_list) > 1 and len(gminy_list) != 0:
        inp_gmina = str(gmina)
        if inp_gmina in gminy_list:
            choice_gmina = gminy_dict_reverse[inp_gmina][:-1]
        else:
            return gminy_list

        for key, val in obreby_ewidencyjne_dict.items():
            val_check = False
            try: int(val[0])
            except: val_check = True
            if key.startswith(choice_gmina) and val_check:
                miejscowosci_list.append(val.capitalize())
        
        if not str(miejscowosc) in miejscowosci_list:
            return miejscowosci_list
        
        dzielnica='Brak'
        return f'{wojewodztwo}/{powiat}/{gmina}/{miejscowosc}/{dzielnica}'
    
    elif len(gminy_list) == 0:
        return powiaty_list
    else:
        for key, val in jednostki_ewidencyjne_dict.items():
            if key.startswith(choice_powiat):
                if not val.count(' - gmina miejska'):
                    if val.count(' - '):
                        val=val.split(' - ')[0]
                    if val.count(f'{gminy_list[0]}-'):
                        val=val.replace(f'{gminy_list[0]}-', '')
                    if val.count(f'dzielnica'):
                        val=val.replace(f'dzielnica', '')
                    dzielnice_list.append(val)
        if len(dzielnice_list) == 1:
            gmina=f'{gminy_list[0]} miasto'
            miejscowosc=gminy_list[0]
            dzielnica='Nieokreślona'
            return f'{wojewodztwo}/{powiat}/{gmina}/{miejscowosc}/{dzielnica}'
        
        if not str(dzielnica) in dzielnice_list:
            return dzielnice_list

    gmina=f'{gminy_list[0]} miasto'
    miejscowosc=gminy_list[0]
    return f'{wojewodztwo}/{powiat}/{gmina}/{miejscowosc}/{dzielnica}'

print(
    getRegionData(
        wojewodztwo='mazowieckie',
        powiat='Warszawa',
        # gmina='Nowe Miasto',
        # miejscowosc='Karolinowo',
        # dzielnica='Śródmieście',
        )
    )