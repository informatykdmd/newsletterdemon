### 📝 Notatka techniczna — stabilizacja pipeline’u SI (Mistral / Ollama)

**Zakres prac:** luty 2026
**Cel:** zapewnienie ciągłości odpowiedzi na czacie firmowym mimo limitów API i timeoutów modeli zewnętrznych

---

#### 1. Instalacja i uruchomienie Ollamy (lokalny fallback)

* Zainstalowano Ollamę jako lokalny backend LLM (CPU).
* Skonfigurowano endpoint `/api/chat` z obsługą:

  * `keep_alive` (utrzymanie modelu w RAM),
  * retry przy `ReadTimeout`,
  * dynamiczny `total_timeout` (do 600s przy cold start).
* Wybrany model: `llama3.1:8b` (roboczo, możliwość zmiany na mniejszy).

---

#### 2. Aktualizacja wrappera (`MistralChatManager`)

* Przebudowano metodę `_post()`:

  * dodano parametr `mistral: bool = True`,
  * **rozłączono ścieżki**:

    * `mistral=True` → wyłącznie SDK Mistrala
    * `mistral=False` → wyłącznie Ollama
* Usunięto fallback Ollamy z `except` Mistrala (Plan A).
* Zachowano pełną kompatybilność kontraktów z poprzednią wersją wrappera.
* Każda metoda publiczna (`text_response`, `categorize_response`, `continue_conversation`, itd.) obsługuje teraz jawnie `mistral=True/False`.

**Plan A (nieudany):**

* Automatyczny fallback Mistral → Ollama w `except`.
* Problem: blokowanie pipeline’u przez długie timeouty Ollamy (cold start).
* Decyzja: **porzucenie fallbacku synchronicznego** na rzecz sterowania ścieżką wyżej (daemon).

---

#### 3. Aktualizacja pipeline’u daemona (routing i sterowanie)

* Routing bota (Gerina / Pionier / Aifa) wykonywany **na pierwszym kontakcie**.
* Wprowadzono flagę stanu:

  * `acive_bot_valided = True/False`
* Jeśli selektor (Mistral) **nie potwierdzi bota**:

  * domyślnie ustawiana jest **Aifa**,
  * dalsza odpowiedź idzie **wyłącznie przez Ollamę**,
  * generacja odbywa się **w tle (thread)**.

---

#### 4. Przetwarzanie w tle (Aifa + Ollama)

* Przy `acive_bot_valided=False`:

  * historia rozmowy jest **ucinana do ogona** (`hist_aifa[-12:]`),
  * uruchamiany jest wątek (`threading.Thread`, `daemon=True`),
  * odpowiedź Aify zapisywana jest asynchronicznie przez `save_chat_message`,
  * pipeline główny **nie jest blokowany**.
* Ograniczono równoległość (semafor) w celu ochrony CPU.

---

#### 5. Komunikacja z użytkownikiem — `[warning]`

* Dodano mechanizm komunikatu ostrzegawczego:

  * `[warning]` wstrzykiwany na indeks `-2`,
  * `-1` zawsze zawiera ostatnie pytanie użytkownika.
* Treść ostrzeżenia:

  * informacja o chwilowych utrudnieniach funkcji SI,
  * brak technikaliów (modele, tokeny, API),
  * przeprosiny + deklaracja trwających prac.
* Efekt: użytkownik **widzi odpowiedź**, nawet jeśli przyszła z opóźnieniem, i rozumie sytuację.

---

#### 6. Testy i weryfikacja

Przetestowano scenariusze:

* brak tokenów Mistrala (429),
* routing niepotwierdzony,
* pełna obsługa przez Ollamę,
* odpowiedzi synchroniczne i asynchroniczne,
* wielokrotne wiadomości użytkownika bez odpowiedzi pośredniej.

**Przykładowy pomiar czasu:**

* pierwsza wiadomość: `18:00:54 GMT`
* odpowiedź Aify: `18:09:11 GMT`
* **czas odpowiedzi:** ~8 min 17 s
* **timeout systemowy:** 12 minut
  ➡ odpowiedź dostarczona poprawnie, bez zerwania sesji.

---

#### 7. Stan końcowy

* System działa w trybie **degradacji kontrolowanej**.
* Brak tokenów lub awaria Mistrala **nie blokuje czatu**.
* Zawsze pojawia się odpowiedź (Aifa).
* Architektura odporna na:

  * rate limit,
  * timeouty,
  * cold start modeli,
  * brak dostępności agentów specjalistycznych.

---

Jasne — zróbmy „ściągę” z krótkimi fragmentami kodu, żebyś po miesiącu nie musiał wertować całego daemona/pipeline’u. Poniższe przykłady są spójne z aktualnym wrapperem (`mistral: bool = True` w każdej metodzie) i z rozdzieleniem ścieżek Mistral/Ollama. 

1. Wrapper: jedna metoda `_post`, dwie ścieżki (Mistral vs Ollama)

```python
def _post(..., mistral: bool = True) -> Optional[str]:
    # OLLAMA
    if not mistral:
        txt = _ollama_chat(...)
        return self._normalize_content_to_text(txt)

    # MISTRAL
    with Mistral(...) as mistral_client:
        res = mistral_client.chat.complete(...)
    return self._normalize_content_to_text(res.choices[0].message.content)
```

2. Użycie w kodzie: jawny wybór backendu per wywołanie

```python
# routing / selektor bota (zwykle Mistral)
bot_ident = mgr.categorize_response(prompti, witch_bot_list, max_tokens=100, mistral=True)

# generacja odpowiedzi “tanio / lokalnie”
ans_local = mgr.continue_conversation_with_system(hist, sys_prmt_aifa, max_tokens=800, mistral=False)

# generacja odpowiedzi “normalnie / chmura”
ans_cloud = mgr.continue_conversation_with_system(hist, sys_prmt_aifa, max_tokens=800, mistral=True)
```

3. Daemon: selekcja bota + flaga `acive_bot_valided`

```python
acive_bot_valided = False
bot_rotation = "aifa"  # default

if latest_user_message_author not in ["gerina", "pionier"]:
    bot_ident = mgr.categorize_response(prompti, witch_bot_list, max_tokens=100, mistral=True)

    bot_ident_norm = (bot_ident or "").strip().lower()
    allowed = {b.strip().lower() for b in (witch_bot_list or [])}

    if bot_ident_norm in allowed:
        acive_bot_valided = True
        bot_rotation = bot_ident_norm
    else:
        acive_bot_valided = False
        bot_rotation = "aifa"
```

4. „Plan A” (stary): fallback z `except` — odradzamy (blokował pipeline)
   Tylko jako przypominajka, co porzuciliśmy:

```python
try:
    ans = mistral_call()
except Exception:
    # Plan A: tu odpalano ollamę synchronicznie -> timeouty blokowały pipeline
    ans = ollama_call()
```

5. „Plan B” (obecny): gdy routing niepewny → Aifa na Ollamie w tle (thread)

```python
import threading
_OLLAMA_BG_SEM = threading.Semaphore(2)

def _bg_aifa_job(idx: int, hist_snapshot: list, sys_prompt: str):
    try:
        with _OLLAMA_BG_SEM:
            ans = mgr.continue_conversation_with_system(
                hist_snapshot, sys_prompt, max_tokens=800, mistral=False
            )
            if ans:
                save_chat_message("aifa", ans, 0)
    except Exception as e:
        print(f"[BG AIFA ERROR] idx={idx} err={repr(e)}")
```

6. Ogon historii: nie spamujemy kontekstem

```python
# tylko ogon rozmowy
hist_snapshot = list(hist_aifa[-12:])
```

7. `[warning]` na indeksie -2, a pytanie usera na -1

```python
extra_warning = (
    "[warning]\n"
    "Uwaga: mogą występować chwilowe utrudnienia w działaniu funkcji opartych o SI. "
    "Część agentów może być tymczasowo niedostępna lub działać w ograniczonym zakresie. "
    "Prace nad usunięciem problemów są w toku. Przepraszamy za utrudnienia.\n"
)

# zakładamy, że hist_snapshot[-1] to ostatnia wiadomość usera
if hist_snapshot and hist_snapshot[-1].get("role") == "user":
    hist_snapshot.insert(-1, {"role": "user", "content": extra_warning})
else:
    hist_snapshot.append({"role": "user", "content": extra_warning})

# sanity check
print("⚠️ warning index OK:", len(hist_snapshot) - 2)
```

8. Start wątku tylko gdy `acive_bot_valided=False`

```python
if not acive_bot_valided:
    print(f"🧵 AIFA BG | start task #{i} | routing_valid={acive_bot_valided}")

    t = threading.Thread(
        target=_bg_aifa_job,
        args=(i, hist_snapshot, sys_prmt_aifa),
        daemon=True
    )
    t.start()
else:
    ans = mgr.continue_conversation_with_system(hist_aifa, sys_prmt_aifa, max_tokens=800, mistral=True)
    if ans:
        save_chat_message("aifa", ans, 0)
```

9. Logi, które realnie pomagają (Twoje emoji-formaty)

```python
print(f"🧭 bot={bot_rotation} | validated={acive_bot_valided}")
print(f"🧠 hist_aifa[0]: {hist_aifa[0] if hist_aifa else ''}")
print(f"📚 hist_aifa.len: {len(hist_aifa)}")
print(f"🤖 aifa.tail:\n{hist_aifa[-2:]}")
print(f"🎣 catching_gerina: {catching_gerina} | 🔐 validated: {acive_bot_valided}")
```

10. Pomiar czasu / checkpoint (żeby pamiętać skąd te 12 minut)

```python
start_ts = time.time()

# ... pipeline ...

elapsed = time.time() - start_ts
print(f"🕒 checkpoint_15s: elapsed_time={elapsed:.2f}s, potrzebne=15s")
```