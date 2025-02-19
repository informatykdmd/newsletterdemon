from MySQLModel import MySQLModel  # Import klasy MySQLModel

# Tworzymy instancję bazy z połączeniem permanentnym
db = MySQLModel(permanent_connection=True)

# 1️⃣ Pobieramy dane do skopiowania
groups = db.getFrom(
    "SELECT * FROM facebook_gropus WHERE created_by = %s AND category = %s",
    params=("dmddomy", "nieruchomosci"),
    as_dict=True  # Pobieramy jako listę słowników
)

# 2️⃣ Sprawdzamy, czy są dane do skopiowania
if not groups:
    print("❌ Brak rekordów do skopiowania!")
else:
    print(f"✅ Znaleziono {len(groups)} rekordów do skopiowania.")

    # 3️⃣ Iterujemy przez każdy rekord i dodajemy go ponownie z nowym `created_by`
    for group in groups:
        # Usuwamy oryginalne ID (jeśli istnieje, aby baza utworzyła nowe)
        group.pop("id", None)  

        # Modyfikujemy wartość `created_by`
        group["created_by"] = "dmdinwestycje"

        # Tworzymy dynamiczne zapytanie INSERT
        columns = ", ".join(group.keys())
        values_placeholders = ", ".join(["%s"] * len(group))
        query = f"INSERT INTO facebook_gropus ({columns}) VALUES ({values_placeholders})"

        # Wykonujemy INSERT
        db.executeTo(query, tuple(group.values()))

    print("✅ Wszystkie rekordy zostały skopiowane!")

# 4️⃣ Zamykamy połączenie
db.close_connection()