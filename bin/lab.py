from wrapper_mistral import MistralChatManager
from config_utils import MISTRAL_API_KEY, api_key, url, tempalate_endpoit, responder_endpoit
import connectAndQuery as cad
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


def get_ltm(flag='all'):
    
    if flag == 'ltm_new':
        dump_key = cad.connect_to_database(
            "SELECT id, user_name, content, timestamp, status, "
            "ltm_status, ltm_processing_token, ltm_processing_at, ltm_processed_at, ltm_error "
            "FROM Messages "
            "WHERE ltm_status = 'new' "
            "ORDER BY timestamp ASC;"
        )

    return dump_key

rows_new = get_ltm('ltm_new')


print("ltm_new:", len(rows_new))
print(rows_new[-1] if rows_new else None)