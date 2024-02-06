import mysql.connector

def connect_to_database(userA, passwordA, hostA, databaseA, queryA):
    """Łączy się z bazą danych i zwraca List"""
    polaczenie_DB = mysql.connector.connect(
        user=userA,
        password=passwordA,
        host=hostA,
        database=databaseA
        )
    cursor = polaczenie_DB.cursor()
    query = queryA # 'SELECT id, user, haslo, created FROM users_main'
    cursor.execute(query)
    export_list = []
    for data in cursor:
        "Logika zapytania"
        export_list.append(data)

    polaczenie_DB.commit()
    polaczenie_DB.close()

    return export_list

if __name__ == "__main__":
    promis = connect_to_database(
                        'informatyk',
                        'NJKjkhdsbjk7sdt$D4d',
                        'localhost',
                        'dmd',
                        'SELECT * FROM blog_posts;')
    print(promis)