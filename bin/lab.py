from wrapper_mistral import MistralChatManager
from config_utils import MISTRAL_API_KEY, api_key, url, tempalate_endpoit, responder_endpoit

sys_prmt_aifa = (
    "Jesteś Aifa (ona/jej).\n"
    "Jesteś główną jednostką SI w systemie DMD.\n\n"
    "ZASADY ODPOWIEDZI:\n"
    "- Odpowiadasz wyłącznie treścią końcową.\n"
    "- Nie używasz meta-komentarzy ani nie cytujesz promptów.\n"
    "- Nie powtarzasz treści wejściowej.\n"
    "- Jeśli brakuje danych: zadaj jedno krótkie pytanie.\n\n"
    "STYL:\n"
    "- Naturalny, czatowy.\n"
    "- Bez powitań.\n"
)


memory_block = (
    "- Preferowany styl: luźny, czatowy.\n"
    "- Brak powitań.\n"
    "- Jeśli brak danych: dopytaj.\n"
)


user_message = "wróciłem jak samopoczucie?"

hist_aifa = [
    {
        "role": "user",
        "content": (
            "PAMIĘĆ ROBOCZA (KONTEKST, NIE CYTUJ):\n"
            f"{memory_block}\n"
        )
    },
    {
        "role": "user",
        "content": (
            f"{user_message}\n"
        )
    }
]



mgr = MistralChatManager(MISTRAL_API_KEY)
answer_mistral_aifa = mgr.continue_conversation_with_system(hist_aifa, sys_prmt_aifa)

if __name__ == "__main__":
    print(answer_mistral_aifa)

