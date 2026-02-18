import requests
import json
import time
from typing import Optional
from mistralai import Mistral
from mistralai.utils import BackoffStrategy, RetryConfig


# --- OLLAMA FALLBACK (local) ---
OLLAMA_BASE_URL = "http://127.0.0.1:11434"
OLLAMA_FALLBACK_MODEL = "llama3.1:8b"   # możesz zmienić np. na swój profil: llama3.1:8b-tech-pl
OLLAMA_TIMEOUT = (2, 120)              # connect, read

def _ollama_chat(
    messages,
    model: str = OLLAMA_FALLBACK_MODEL,
    max_tokens: int = 512,
    temperature: float = 0.7,
    total_timeout: float = 120.0,
    fail_silently: bool = True,
    logger=None,
) -> str:

    """
    Fallback: Ollama /api/chat
    messages: lista {"role","content"} — zgodna z Mistral/OpenAI
    """
    url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/chat"

    payload = {
        "model": model,
        "stream": False,
        "keep_alive": "10m",  # trzyma model “rozgrzany” w RAM, mniej timeoutów po 1. zapytaniu
        "messages": messages,
        "options": {
            "temperature": temperature,
            "num_predict": max_tokens,      # odpowiednik max_tokens
            "top_p": 0.9,
            "repeat_penalty": 1.1,
        },
    }


    try:
        try:
            r = requests.post(
                url,
                json=payload,
                timeout=(2, total_timeout),
            )
        except requests.exceptions.ReadTimeout:
            # typowo: cold start / dogrywanie modelu -> dajemy drugą szansę z większym limitem
            r = requests.post(
                url,
                json=payload,
                timeout=(2, min(total_timeout * 2, 600.0)),
            )
        r.raise_for_status()
        data = r.json() or {}
        msg = data.get("message") or {}
        return (msg.get("content") or "").strip()

    except Exception as e:
        if logger:
            logger.error(f"Ollama fallback error: {repr(e)}")
        else:
            print(f"[Ollama FALLBACK ERROR] {repr(e)}")

        if fail_silently:
            return ""
        raise


def _extract_status_code(err: Exception):
    """
    Próbuje wydobyć HTTP status z wyjątków SDK/requests.
    """
    sc = getattr(err, "status_code", None)
    if isinstance(sc, int):
        return sc
    resp = getattr(err, "response", None)
    if resp is not None:
        sc = getattr(resp, "status_code", None)
        if isinstance(sc, int):
            return sc
    return None

def _is_retryable(err: Exception) -> bool:
    """
    Kiedy robimy fallback (rate limit / chwilowe problemy).
    """
    sc = _extract_status_code(err)
    if sc in (408, 409, 425, 429):
        return True
    if sc is not None and 500 <= sc <= 599:
        return True

    msg = (repr(err) + " " + str(err)).lower()
    markers = (
        "rate limit",
        "too many requests",
        "429",
        "timeout",
        "timed out",
        "temporarily unavailable",
        "service unavailable",
        "connection reset",
        "connection aborted",
        "getaddrinfo failed",
    )
    return any(m in msg for m in markers)



def json_string_to_dict(response_text, return_type="json"):
    """Parsuje strukturę JSON zawartą w tekście odpowiedzi SI i zwraca pozostały tekst, jeśli istnieje."""
    
    json_str = ""
    remaining_text = ""
    brace_count = 0
    in_json = False
    json_blocks = []
    
    for char in str(response_text):
        if char == '{':
            in_json = True
            brace_count += 1
        elif char == '}':
            brace_count -= 1
            if brace_count == 0:
                in_json = False
                json_str += char
                json_blocks.append(json_str)
                json_str = ""
                continue
        if in_json:
            json_str += char
        elif not in_json and brace_count == 0:
            remaining_text += char  # Zapisuje tekst poza blokiem JSON
    
    if len(json_blocks) > 1:
        return {"error": "Więcej niż jedna struktura JSON.", "json": None, "remaining_text": remaining_text.strip(), "success": False}
    elif not json_blocks:
        return {"error": "Brak struktury JSON w tekście.", "json": None, "remaining_text": remaining_text.strip(), "success": False}

    try:
        parsed_json = json.loads(json_blocks[0])
        if return_type == "json":
            return {"error": None, "json": parsed_json, "remaining_text": None, "success": True}
        elif return_type == "string":
            return {"error": None, "json": None, "remaining_text": remaining_text.strip(), "success": True}
    except json.JSONDecodeError:
        return {"error": "Błąd parsowania JSON.", "json": None, "remaining_text": remaining_text.strip(), "success": False}


def validate_response_structure(template, response):
    """
    Sprawdza, czy struktura i typy danych w odpowiedzi są zgodne ze wzorem (template). 
    Funkcja zwraca szczegóły o zgodności struktury i różnicach w wartościach.

    Args:
        template (dict): Wzór JSON, do którego ma być porównywana odpowiedź.
        response (dict): Odpowiedź JSON, która ma być zweryfikowana względem wzoru.

    Returns:
        dict: Wynik zawierający:
            - 'zgodnosc_struktury' (bool): True, jeśli struktura jest zgodna, False w przeciwnym razie.
            - 'error' (str lub None): Informacja o błędzie, jeśli wystąpił, w przeciwnym razie None.
            - 'success' (bool): True, jeśli struktura i typy danych są zgodne, False w przeciwnym razie.
            - 'rozne_wartosci' (dict): Klucze i wartości z odpowiedzi, które różnią się od wzoru.
            - 'anuluj_zadanie' (bool): True, jeśli wszystkie dane są niezmienione, False w przeciwnym razie.
    """
    def check_structure_and_types(template, response, path=""):
        if isinstance(template, dict):
            if not isinstance(response, dict):
                return f"Klucz '{path}' powinien być typu dict, a jest typu {type(response).__name__}."
            for key, tmpl_value in template.items():
                if key not in response:
                    return f"Brak klucza '{path + '.' + key}' w odpowiedzi."
                error = check_structure_and_types(tmpl_value, response[key], path + "." + key)
                if error:
                    return error
        elif isinstance(template, list):
            if not isinstance(response, list):
                return f"Klucz '{path}' powinien być typu list, a jest typu {type(response).__name__}."
            if template:
                for idx, tmpl_value in enumerate(template):
                    if idx < len(response):
                        error = check_structure_and_types(tmpl_value, response[idx], f"{path}[{idx}]")
                        if error:
                            return error
                    else:
                        return f"Brak elementu na pozycji {idx} w odpowiedzi w ścieżce '{path}'."
        else:
            if type(template) != type(response):
                return f"Klucz '{path}' powinien być typu {type(template).__name__}, a jest typu {type(response).__name__}."
        return None

    def find_different_values(template, response, path=""):
        different_values = {}
        if isinstance(template, dict):
            for key, tmpl_value in template.items():
                if isinstance(tmpl_value, (dict, list)):
                    nested_diff = find_different_values(tmpl_value, response[key], path + "." + key)
                    if nested_diff:
                        different_values.update(nested_diff)
                else:
                    if response[key] != tmpl_value:
                        different_values[path + "." + key] = response[key]
        elif isinstance(template, list):
            if len(template) != len(response):  # Porównanie długości list
                different_values[path] = response
            else:
                for idx, tmpl_value in enumerate(template):
                    if idx < len(response):
                        if isinstance(tmpl_value, (dict, list)):
                            nested_diff = find_different_values(tmpl_value, response[idx], f"{path}[{idx}]")
                            if nested_diff:
                                different_values.update(nested_diff)
                        else:
                            if response[idx] != tmpl_value:
                                different_values[f"{path}[{idx}]"] = response[idx]
        return different_values

    # 1. Sprawdź strukturę i typy danych
    structure_error = check_structure_and_types(template, response)
    if structure_error:
        return {
            "zgodnosc_struktury": False,
            "error": structure_error,
            "success": False,
            "rozne_wartosci": None,
            "anuluj_zadanie": False
        }

    # 2. Znajdź różnice w wartościach
    different_values = find_different_values(template, response)
    if different_values:
        return {
            "zgodnosc_struktury": True,
            "error": None,
            "success": False,
            "rozne_wartosci": different_values,
            "anuluj_zadanie": False
        }

    # 3. Jeśli wszystkie dane są identyczne, anuluj zadanie
    return {
        "zgodnosc_struktury": True,
        "error": None,
        "success": True,
        "rozne_wartosci": None,
        "anuluj_zadanie": True
    }


def dict_to_json_string(data):
    """Konwertuje słownik Python na format JSON w postaci stringa."""
    try:
        # Używamy ensure_ascii=False, aby zachować polskie znaki
        json_string = json.dumps(data, ensure_ascii=False, indent=4)
        return {"success": True, "json_string": json_string}
    except TypeError as e:
        return {"success": False, "error": f"Błąd konwersji: {e}"}


class MistralChatManager:
    """
    message = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "role": role,
        "content": content,
        "message_id": "unique_id_123",
        "username": "JanKowalski",
        "type": "text",
        "status": "delivered",
        "metadata": {
            "location": "Warsaw",
            "device": "mobile"
        },
        "reactions": {
            "like": 5,
            "dislike": 0
        },
        "attachments": [
            {
                "type": "image",
                "url": "http://example.com/image.jpg"
            }
        ],
        "priority": "high"
    }

    """

    def __init__(
            self, api_key, 
            model="mistral-saba-2502", #mistral-small-latest  mistral-large-2402
            server="eu"
        ):
        self.api_key = api_key
        self.model = model
        self.server = server  # opcjonalnie: "eu" (albo ustaw server_url, jeśli wolisz)


    def _normalize_content_to_text(self, content) -> str:
        """
        Normalizuje Mistral 'message.content' do czystego tekstu.
        Mistral: content może być string albo listą chunków (np. [{"type":"text","text":"..."}]).

        """
        if content is None:
            return ""

        # 1) Najczęściej: zwykły string
        if isinstance(content, str):
            return content

        # 2) Nowy format: lista chunków (np. [{"type":"text","text":"..."}])
        if isinstance(content, list):
            parts = []
            for ch in content:
                if isinstance(ch, str):
                    # czasem ktoś zwróci sam tekst jako element listy
                    parts.append(ch)
                    continue

                if isinstance(ch, dict):
                    ctype = (ch.get("type") or ch.get("kind") or "").lower()

                    # najczęstszy przypadek: {"type":"text","text":"..."}
                    if ctype == "text" and isinstance(ch.get("text"), str):
                        parts.append(ch["text"])
                        continue

                    # fallbacki: czasem tekst bywa pod "content" albo "value"
                    for k in ("content", "value", "data"):
                        v = ch.get(k)
                        if isinstance(v, str):
                            parts.append(v)
                            break

            return "".join(parts).strip()

        # 3) Jakby SDK zwróciło obiekt/dict w dziwnym formacie
        if isinstance(content, dict):
            for k in ("text", "content", "value", "data"):
                v = content.get(k)
                if isinstance(v, str):
                    return v
            return str(content)

        # 4) Ostateczność
        return str(content)


    def _post(
        self,
        messages,
        max_tokens: int = 512,
        temperature: float = 0.7,
        retries: int = 8,              # zostawiamy dla kompatybilności sygnatury
        base_delay: float = 0.8,       # jw.
        max_delay: float = 60.0,       # jw.
        total_timeout: float = 120.0,  # jw.
        fail_silently: bool = True,
        logger=None,
        mistral: bool = True,
    ) -> Optional[str]:
        """
        Wywołanie przez oficjalny SDK (mistralai).
        Retry/backoff może obsłużyć SDK (RetryConfig), a my trzymamy:
        - fail_silently (zwraca "" zamiast wyjątku)
        - jeden spójny parsing odpowiedzi do stringa
        """
                # ŚCIEŻKA OLLAMA (osobna, bez mieszania w wyjątki Mistrala)
        if not mistral:
            try:
                txt = _ollama_chat(
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    total_timeout=total_timeout,
                    fail_silently=fail_silently,
                    logger=logger,
                )
                return self._normalize_content_to_text(txt)
            except Exception as e:
                if logger:
                    logger.error(f"Ollama error: {repr(e)}")
                else:
                    print(f"[Ollama ERROR] {repr(e)}")
                if fail_silently:
                    return ""
                raise

        try:
            # Retry/backoff w SDK (opcjonalne, ale mega wygodne)
            retry_cfg = RetryConfig(
                "backoff",
                BackoffStrategy(
                    base_delay,        # start
                    max_delay,         # max
                    1.6,               # mnożnik (tweak)
                    retries            # max_tries
                ),
                False                 # "fail_fast" (w przykładach jest False)
            )

            with Mistral(
                api_key=self.api_key,
                server=self.server,
                retry_config=retry_cfg,
            ) as mistral_client:
                res = mistral_client.chat.complete(
                    model=self.model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    stream=False,
                    response_format={"type": "text"},
                )

            # Parsing: res bywa obiektem SDK (nie dict z requests)
            # Cel: zawsze wyciągnąć finalny tekst.
            content = None
            try:
                # najczęstsze: res.choices[0].message.content
                content = res.choices[0].message.content
            except Exception as e:
                print(f"[Mistral ERROR 01] {repr(e)}")

            if content is None:
                try:
                    # fallback jakby res był dictopodobny
                    content = res["choices"][0]["message"]["content"]
                except Exception as e:
                    print(f"[Mistral ERROR 02] {repr(e)}")
                    content = None

            if content is None:
                # ostatnia deska ratunku: stringuj cały obiekt
                content = str(res) if res is not None else ""

            return self._normalize_content_to_text(content)


        except Exception as e:
            if logger:
                logger.error(f"Mistral SDK error: {repr(e)}")
            else:
                print(f"[Mistral SDK ERROR 00] {repr(e)}")

            if fail_silently:
                return ""
            raise


    def text_response(self, user_message, max_tokens=500, mistral: bool = True):
        messages = [
            {"role": "user", "content": user_message}
        ]
        return self._post(messages, max_tokens=max_tokens, mistral=mistral)

    def categorize_response(self, user_message, categories, max_tokens=100, mistral: bool = True):
        prompt = f"Wybierz jedną kategorię spośród: {', '.join(categories)}. Zwróć tylko nazwę kategorii."
        response = self._post([
            {"role": "system", "content": prompt},
            {"role": "user", "content": user_message}
        ], max_tokens=max_tokens, mistral=mistral)

        cleaned = response.strip().lower()
        categories_l = [c.lower() for c in categories]
        return cleaned if cleaned in categories_l else "nieznana"
    
    def spam_catcher(
        self,
        client_name: str,
        client_email: str,
        subject: str,
        message: str,
        dt: str | None = None,
        labels: tuple[str, str] = ("SPAM", "WIADOMOŚĆ"),
        max_tokens: int = 5,
        temperature: float = 0.0,
        system_prompt: str = None,
        user_prompt: str = None,
        total_timeout: float = 120.0,
        mistral: bool = True
    ) -> str:
        """
        Klasyfikuje treść z formularza kontaktowego jako 'SPAM' lub 'WIADOMOŚĆ'.
        Zwraca wyłącznie jeden z elementów `labels` (domyślnie: 'SPAM' lub 'WIADOMOŚĆ').

        :param client_name: Imię/nazwisko nadawcy
        :param client_email: E-mail nadawcy
        :param subject: Temat wiadomości
        :param message: Treść wiadomości
        :param dt: Data/czas (opcjonalnie, string)
        :param labels: Dwuelementowa krotka etykiet (('SPAM','WIADOMOŚĆ') lub np. ('SPAM','MESSAGE'))
        :param max_tokens: Limit tokenów odpowiedzi (wystarczy 1–5)
        :param temperature: 0.0 dla deterministycznych odpowiedzi
        :return: 'SPAM' albo 'WIADOMOŚĆ' (lub odpowiedniki z `labels`)
        """
        # Mapowanie do formy kanonicznej (zachowujemy oryginalne etykiety z `labels`)
        canonical = {l.upper().replace("Ś", "S").replace("Ć", "C").strip(): l for l in labels}

        if system_prompt is None:
            system_prompt = (
                "Jesteś klasyfikatorem wiadomości z formularza kontaktowego firmy budowlanej.\n"
                f"Zwróć DOKŁADNIE JEDNO SŁOWO z zestawu: {list(labels)}.\n\n"
                "Definicje:\n"
                "- 'SPAM' — niezamówione oferty masowe, phishing/oszustwa, erotyka/hazard/krypto, "
                "ogólne mailingi sprzedażowe bez odniesienia do naszej oferty, niepowiązane tematy, "
                "losowe linki/załączniki bez kontekstu, niska wiarygodność.\n"
                "- 'WIADOMOŚĆ' — realne zapytanie związane z naszą działalnością (budowa domów, wyceny, terminy, "
                "lokalizacja, metraż, budżet, projekt/architekt, formalności), sensowne pytania/dane kontaktowe, "
                "nawiązanie do konkretnej realizacji lub wcześniejszego kontaktu.\n\n"
                "Wskazówki:\n"
                "- Oceń tylko treść użytkową.\n"
                "- Jeśli nie masz pewności, wybierz 'WIADOMOŚĆ'.\n"
                "- Format odpowiedzi: bez cudzysłowów, bez kropek i komentarzy — tylko etykieta."
            )
        if user_prompt is None:
            user_prompt = (
                "Oceń, czy poniższa treść z formularza kontaktowego to SPAM czy WIADOMOŚĆ.\n"
                f"Imię/nazwisko: {client_name}\n"
                f"E-mail: {client_email}\n"
                f"Temat: {subject}\n"
                f"Treść:\n{message}\n"
            )
            
        if dt:
            user_prompt += f"Data: {dt}\n"

        response = self._post(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=max_tokens,
            temperature=temperature,
            total_timeout=total_timeout,
            mistral=mistral
        )

        raw = (response or "").strip()
        key = raw.upper().replace("Ś", "S").replace("Ć", "C").strip()

        # Jeśli model odda np. 'WIADOMOSC' zamiast 'WIADOMOŚĆ', mapujemy do oryginału z `labels`
        if key in canonical:
            return canonical[key]

        # Fallback: jeśli odpowiedź zawiera którąś etykietę „w środku”, spróbuj wyłuskać
        for k, original in canonical.items():
            if k in key:
                return original

        # Ostatecznie: domyślnie 'WIADOMOŚĆ' (zgodnie z polityką)
        return labels[1] if len(labels) > 1 else "WIADOMOŚĆ"

    def translate(self, text: str, target_lang: str = "pl", source_lang: str | None = None, max_tokens: int = 1200, mistral: bool = True) -> str:
        lang_info = f"z języka {source_lang} " if source_lang else "z wykryciem języka źródłowego "
        system_prompt = (
            f"Jesteś profesjonalnym tłumaczem. Przetłumacz poniższy tekst {lang_info}"
            f"na język {target_lang}.\n"
            "Zasady:\n"
            "- Zachowaj sens, ton i styl.\n"
            "- Nie streszczaj.\n"
            "- Zwróć wyłącznie przetłumaczony tekst."
        )
        return self._post(
            [{"role": "system", "content": system_prompt},
            {"role": "user", "content": text}],
            max_tokens=max_tokens,
            temperature=0.1,
            mistral=mistral
        )

    
    def multi_categorize_response(self, user_message, categories, max_tokens=1500, mistral: bool = True):
        prompt = f"Wybierz nabrdziej pasujące kategorie do kontekstu, spośród: {', '.join(categories)}. Uzupełnij listę obiektu json."
        context_prompt = (
            "KONTEKST:\n"
            f"{user_message}\n"
            "ZADANIE:\n"
            f"{prompt}\n"
        )
        input_json = {
            "wybrane_kategorie": []
        }
        response = self.json_completion(input_json, context_prompt=context_prompt, return_json=True, max_tokens=max_tokens, mistra=mistral)
        if "wybrane_kategorie" in response:
            if isinstance(response.get("wybrane_kategorie", None), list):
                return response.get("wybrane_kategorie", [])
        return []

    def json_completion(self, input_json, history=None, instruction="Uzupełnij wartości w tym JSON-ie. Odpowiedź musi być kodem JSON.",
                        context_prompt=None, return_json=False, max_tokens=3000, mistral: bool = True):
        if history is None or not isinstance(history, list):
            history = []

        # print("[MISTRAL] raw INPUT", input_json, history, instruction, context_prompt, return_json, max_tokens)

        system_prompt = instruction.strip()
        user_prompt = ""
        if context_prompt:
            user_prompt = user_prompt + context_prompt.strip()

        if input_json:
            user_prompt = user_prompt + f"""\nStruktura JSON: {json.dumps(input_json)}"""

        # print("user_prompt", user_prompt)
        messages = [{"role": "system", "content": system_prompt}]
        messages.extend(history)
        messages.append({"role": "user", "content": user_prompt})


        raw_output = self._post(messages, max_tokens=max_tokens, temperature=.9, mistral=mistral)

        # print("[MISTRAL] raw_output", raw_output)

        clear_json = json_string_to_dict(raw_output)
        dict_from_json = clear_json.get("json", {})

        if return_json and dict_from_json and clear_json.get("success"):
            if not clear_json.get("error"):
                return dict_from_json
            else:
                raise clear_json.get("error")

        return raw_output

    def continue_conversation(self, history, new_user_message, max_tokens=500, temperature: float = 0.7, mistral: bool = True):
        messages = history + [{"role": "user", "content": new_user_message}]
        return self._post(messages, max_tokens=max_tokens, temperature=temperature, mistral=mistral)
    
    def continue_conversation_with_system(
            self, history, 
            system_prompt="Prowadzisz normalną rozmowę w luźnym stylu.", 
            max_tokens=500, 
            temperature: float = 0.7,
            total_timeout: float = 120,
            mistral: bool = True
        ):
        messages = [{"role": "system", "content": system_prompt}] + history
        return self._post(
            messages, 
            max_tokens=max_tokens, 
            temperature=temperature, 
            total_timeout=total_timeout, 
            mistral=mistral
        )

    def summarize(self, text, max_tokens=500, mistral: bool = True):
        messages = [
            {"role": "system", "content": "Streść poniższy tekst w kilku punktach."},
            {"role": "user", "content": text}
        ]
        return self._post(messages, max_tokens=max_tokens, mistral=mistral)

    def synthesize(self, text, max_tokens=100, mistral: bool = True):
        messages = [
            {"role": "system", "content": "Zsyntetyzuj poniższy tekst do jednego słowa, które najlepiej oddaje jego sens. Zwróć tylko to jedno słowo."},
            {"role": "user", "content": text}
        ]
        return self._post(messages, max_tokens=max_tokens, mistral=mistral).strip()


    def tone_shift(self, text, tone="formalny", max_tokens=500, mistral: bool = True):
        messages = [
            {"role": "system", "content": f"Przekształć poniższy tekst na ton: {tone}"},
            {"role": "user", "content": text}
        ]
        return self._post(messages, max_tokens=max_tokens, mistral=mistral)
    
    def interface(
            self, 
            context_prompt, 
            json_template: dict, 
            instruction: str, 
            history=None, 
            max_attempts=15, 
            as_string=False, 
            max_tokens=3200,
            mistral: bool = True
            ):
        """
        Metoda wyboru interfejsu: zmienia wartości z false na true zgodnie z instrukcją, bez zmiany kluczy.

        Returns:
            dict lub string: zweryfikowana odpowiedź JSON
        """
        if history is None or not isinstance(history, list):
            history = []
        
        base_prompt = (
            instruction.strip() +
            "\n\nZasady:\n"
            "- Nie zmieniaj żadnych kluczy.\n"
            "- Pod żadnym pozorem nie zmieniaj struktury jak również typów wartości w niej.\n"
            "- Zmieniaj tylko wartości, tam gdzie uznasz to za właściwe.\n"
            "- Odpowiedz tylko i wyłącznie poprawnym JSON-em.\n"
            "- Nie dodawaj tekstów przed ani po strukturze JSON.\n"
        )

        for attempt in range(max_attempts):
            response_raw = self.json_completion(
                input_json=json_template,
                instruction=base_prompt,
                context_prompt=context_prompt,
                history=history,
                return_json=True,
                max_tokens=max_tokens,
                mistral=mistral
            )
            # print(attempt, "response_raw", response_raw)

            validation = validate_response_structure(json_template, response_raw)
            # print(attempt, "validation", validation)

            if validation["zgodnosc_struktury"]:
                if as_string:
                    return json.dumps(response_raw, ensure_ascii=False)
                return response_raw
            else:
                if validation["error"]:
                    return {"error": validation["error"]}

        return {"error": "Nie udało się uzyskać poprawnej odpowiedzi JSON w zadanej liczbie prób."} 