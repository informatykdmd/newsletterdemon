import mysql.connector
from config_utils import DBDATA as DB
def connect_to_database(queryA, userA=DB['user'], passwordA=DB['pass'], hostA=DB['host'], databaseA=DB['base']):
    """Łączy się z bazą danych i zwraca List"""
    polaczenie_DB = mysql.connector.connect(
        user=userA,
        password=passwordA,
        host=hostA,
        database=databaseA)
    cursor = polaczenie_DB.cursor()
    query = queryA # 'SELECT id, user, haslo, created FROM users_main'
    cursor.execute(query)
    export_list = []
    for data in cursor:
        export_list.append(data)

    polaczenie_DB.commit()
    polaczenie_DB.close()

    return export_list

