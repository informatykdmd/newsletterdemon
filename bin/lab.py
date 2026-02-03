from wrapper_mistral import MistralChatManager
from config_utils import MISTRAL_API_KEY, api_key, url, tempalate_endpoit, responder_endpoit
import prepare_shedule
"""
Kolumny LTM (dodnae):
ltm_status (new domyślnie)
👉 to jest kolejka robocza dla pamięci długoterminowej
ltm_processing_token
👉 identyfikator „kto aktualnie obrabia”
ltm_processing_at
👉 kiedy wiadomość została wzięta do pracy
ltm_processed_at
👉 kiedy zakończono (processed / skipped / error)
ltm_error
👉 dlaczego się nie udało (jeśli się nie udało)"""


def get_messages(flag='all'):
    # WHERE status != 1
    if flag == 'all':
        dump_key = prepare_shedule.connect_to_database(
            "SELECT id, user_name, content, timestamp, status FROM Messages WHERE status != 1 ORDER BY timestamp ASC;")

    if flag == 'today':
        dump_key = prepare_shedule.connect_to_database(
            "SELECT id, user_name, content, timestamp, status FROM Messages WHERE date(timestamp) = curdate() AND status != 1 ORDER BY timestamp ASC;")

    if flag == 'last':
        dump_key = prepare_shedule.connect_to_database(
            """SELECT id, user_name, content, timestamp, status FROM Messages WHERE timestamp >= NOW() - INTERVAL 1 HOUR AND status != 1 ORDER BY timestamp ASC;""")
    if flag == 'ltm_new':
        dump_key = prepare_shedule.connect_to_database(
            "SELECT id, user_name, content, timestamp, status, "
            "ltm_status, ltm_processing_token, ltm_processing_at, ltm_processed_at, ltm_error "
            "FROM Messages "
            "WHERE ltm_status = 'new' AND status != 1 "
            "ORDER BY timestamp ASC;"
        )

    return dump_key

rows_all = get_messages('all')
rows_last = get_messages('last')
rows_new = get_messages('ltm_new')

print("all:", len(rows_all))
print("last:", len(rows_last))
print("ltm_new:", len(rows_new))
print(rows_last[-1] if rows_last else None)