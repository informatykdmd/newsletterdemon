from datetime import datetime, timedelta
from connectAndQuery import connect_to_database, insert_to_database
def get_waitnigfblist():
    
    zrzut_z_bazy = connect_to_database(
        """
            SELECT * FROM waitinglist_fbgroups ORDER BY id DESC;
        """)
    export_list = []
    for data in zrzut_z_bazy:
        theme = {
            'id': data[0],
            'post_id': data[1],
            'content': data[2],
            'color_choice': data[3],
            'repeats': data[4],
            'repeats_left': data[5],
            'repeats_last': data[6],
            'shedules': {
                "0": {
                        'task_id': data[7],
                        'datetime': data[8],
                        'status': data[9],
                        'errors': data[10]
                    },
                "1": {
                        'task_id': data[11],
                        'datetime': data[12],
                        'status': data[13],
                        'errors': data[14]
                    },
                "2": {
                        'task_id': data[15],
                        'datetime': data[16],
                        'status': data[17],
                        'errors': data[18]
                    },
                "3": {
                        'task_id': data[19],
                        'datetime': data[20],
                        'status': data[21],
                        'errors': data[22]
                    },
                "4": {
                        'task_id': data[23],
                        'datetime': data[24],
                        'status': data[25],
                        'errors': data[26]
                    },
                "5": {
                        'task_id': data[27],
                        'datetime': data[28],
                        'status': data[29],
                        'errors': data[30]
                    },
                "6": {
                        'task_id': data[31],
                        'datetime': data[32],
                        'status': data[33],
                        'errors': data[34]
                    },
                "7": {
                        'task_id': data[35],
                        'datetime': data[36],
                        'status': data[37],
                        'errors': data[38]
                    },
                "8": {
                        'task_id': data[39],
                        'datetime': data[40],
                        'status': data[41],
                        'errors': data[42]
                    },
                "9": {
                        'task_id': data[43],
                        'datetime': data[44],
                        'status': data[45],
                        'errors': data[46]
                    },
                "10": {
                        'task_id': data[47],
                        'datetime': data[48],
                        'status': data[49],
                        'errors': data[50]
                    }
            },
            'category': data[51],
            'section': data[52],
            'id_gallery': data[53],
            'data_aktualizacji': data[54]
        }
        export_list.append(theme)

    return export_list

def give_me_curently_tasks():
    schedules_data = get_waitnigfblist()
    export_ids = []
    today = datetime.now()
    max_delay = timedelta(hours=8)
    for item in schedules_data:
        item['shedules']["0"]['datetime']
        if item['repeats_last'] is None:
            date_str = item['shedules']["0"]['datetime']
            repeats_last_int = -1
            
        elif item['repeats_last'] == item['repeats']:
            zapytanie_sql = """
                DELETE FROM waitinglist_fbgroups WHERE id = %s;
            """
            data = (item['id'],)
            insert_to_database(zapytanie_sql, data)
            print("procedura zakończenia kamanii")
            continue
        else:
            date_str = item['shedules'][str(int(item['repeats_last']) + 1)]['datetime']
            repeats_last_int = int(item['repeats_last'])

        repeats_left_int = item['repeats_left']

        new_repeats_left_int = repeats_left_int - 1
        new_repeats_last_int = repeats_last_int + 1 

        date_took = date_str# datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')

        # Weryfikacja czy już czas
        if today > date_took and (today - date_took) <= max_delay:
            exportDataDict = {
                'id': item['id'],
                'shedules_level': new_repeats_last_int,
                'post_id': item['post_id'],
                'content': item['content'],
                'color_choice': item['color_choice'],
                'category': item['category'],
                'section': item['section'],
                'id_gallery': item['id_gallery']
            }
            export_ids.append(exportDataDict)
            zapytanie_sql = """
                UPDATE waitinglist_fbgroups SET
                    repeats_left = %s,
                    repeats_last = %s
                WHERE id = %s;
            """
            data = (new_repeats_left_int, new_repeats_last_int, item['id'])
            insert_to_database(zapytanie_sql, data)
            print(data)
    return export_ids



