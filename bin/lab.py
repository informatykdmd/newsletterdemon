from wrapper_mistral import MistralChatManager
from config_utils import MISTRAL_API_KEY, api_key, url, tempalate_endpoit, responder_endpoit
import connectAndQuery as cad
import uuid
from datetime import datetime, timedelta

import connectAndQuery as cad

import json
import re
from hashlib import sha1

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
👉 dlaczego się nie udało (jeśli się nie udało)
"""


class MessagesRepo:
    """
    Wrapper/Repozytorium do pracy na tabeli Messages.

    Cel:
    - jedno miejsce na SELECT/UPDATE
    - łatwo filtrować po userze, czasie, grupie (w przyszłości chat_id), LTM statusach
    - używać w labie i potem w demonie/runtime bez duplikowania SQL
    """

    def __init__(self, table_name="Messages"):
        self.table = table_name

    # -------------------------
    # PODSTAWOWE ODCZYTY
    # -------------------------

    def fetch_last_hour(self):
        """
        Zwraca wiadomości z ostatniej godziny (short-term context).
        """
        q = f"""
        SELECT id, user_name, content, timestamp, status,
               ltm_status, ltm_processing_token, ltm_processing_at, ltm_processed_at, ltm_error
        FROM {self.table}
        WHERE timestamp >= NOW() - INTERVAL 1 HOUR
        ORDER BY timestamp ASC;
        """
        return cad.connect_to_database(q)

    def fetch_by_user(self, user_name, limit=200):
        """
        Zwraca ostatnie wiadomości danego usera/agenta.
        """
        q = f"""
        SELECT id, user_name, content, timestamp, status,
               ltm_status, ltm_processing_token, ltm_processing_at, ltm_processed_at, ltm_error
        FROM {self.table}
        WHERE user_name = %s
        ORDER BY timestamp DESC
        LIMIT %s;
        """
        return cad.safe_connect_to_database(q, (user_name, int(limit)))

    def fetch_ltm(self, ltm_status="new", limit=500, older_than_minutes=None):
        """
        Zwraca wiadomości z kolejki LTM.

        Parametry:
        - ltm_status: 'new' | 'processing' | 'processed' | 'skipped' | 'error'
        - older_than_minutes: opcjonalnie filtr np. "processing od > X minut" (do recovery)
        """
        where_extra = ""
        params = [ltm_status, int(limit)]

        if older_than_minutes is not None:
            where_extra = " AND ltm_processing_at <= NOW() - INTERVAL %s MINUTE "
            params.insert(1, int(older_than_minutes))  # wchodzi jako drugi parametr

        q = f"""
        SELECT id, user_name, content, timestamp, status,
               ltm_status, ltm_processing_token, ltm_processing_at, ltm_processed_at, ltm_error
        FROM {self.table}
        WHERE ltm_status = %s
        {where_extra}
        ORDER BY timestamp ASC
        LIMIT %s;
        """
        return cad.safe_connect_to_database(q, tuple(params))

    # -------------------------
    # KONCEPCJA "GRUPY" / "KONTEKSTU"
    # -------------------------

    def fetch_group_context(self, group_id=None, window_minutes=60):
        """
        Koncept docelowy: pobierz short-term context dla danej grupy (chat_id).

        Na dziś:
        - jeśli nie masz chat_id w tabeli, group_id jest ignorowane i lecimy po czasie.
        Docelowo:
        - WHERE chat_id = group_id AND timestamp >= NOW() - INTERVAL window_minutes MINUTE
        """
        q = f"""
        SELECT id, user_name, content, timestamp, status,
               ltm_status, ltm_processing_token, ltm_processing_at, ltm_processed_at, ltm_error
        FROM {self.table}
        WHERE timestamp >= NOW() - INTERVAL %s MINUTE
        ORDER BY timestamp ASC;
        """
        return cad.safe_connect_to_database(q, (int(window_minutes),))

    def detect_active_users(self, group_id=None, window_minutes=60):
        """
        Zwraca listę userów, którzy pisali w oknie czasu.
        (przyda się do kaskady LTM: user-scope dla aktywnych)

        Docelowo dojdzie filtr chat_id.
        """
        q = f"""
        SELECT DISTINCT user_name
        FROM {self.table}
        WHERE timestamp >= NOW() - INTERVAL %s MINUTE;
        """
        rows = cad.safe_connect_to_database(q, (int(window_minutes),))
        # rows może być listą tupli; dopasuj do formatu swojego execute_query
        return rows

    # -------------------------
    # KOLEJKA LTM: REZERWACJA BATCHA (NA RAZIE LAB)
    # -------------------------

    def reserve_ltm_batch(self, limit=20, token=None):
        """
        Rezerwuje batch rekordów do obróbki.

        Flow:
        - token = uuid jeśli nie podany
        - UPDATE: new -> processing, wpisz token i timestamp
        - Zwróć token, aby potem fetchować rekordy po tokenie
        """
        if token is None:
            token = str(uuid.uuid4())

        q = f"""
        UPDATE {self.table}
        SET ltm_status='processing',
            ltm_processing_token=%s,
            ltm_processing_at=NOW()
        WHERE ltm_status='new'
        ORDER BY timestamp ASC
        LIMIT %s;
        """
        cad.safe_connect_to_database(q, (token, int(limit)))
        return token

    def fetch_reserved_batch(self, token):
        """
        Pobiera rekordy, które zostały zarezerwowane tokenem.
        """
        q = f"""
        SELECT id, user_name, content, timestamp, status,
               ltm_status, ltm_processing_token, ltm_processing_at, ltm_processed_at, ltm_error
        FROM {self.table}
        WHERE ltm_status='processing'
          AND ltm_processing_token=%s
        ORDER BY timestamp ASC;
        """
        return cad.safe_connect_to_database(q, (token,))

    def fetch_by_token(self, token):
        """
        Podgląd wszystkich rekordów oznaczonych danym tokenem (niezależnie od ltm_status).
        To jest super do debugowania: widzisz, czy demon zamknął batch na skipped/processed/error.
        """
        q = f"""
        SELECT id, user_name, content, timestamp, status,
               ltm_status, ltm_processing_token, ltm_processing_at, ltm_processed_at, ltm_error
        FROM {self.table}
        WHERE ltm_processing_token=%s
        ORDER BY timestamp ASC;
        """
        return cad.safe_connect_to_database(q, (token,))


    def close_message(self, message_id, new_ltm_status, error_text=None):
        """
        Zamyka pojedynczą wiadomość po obróbce.

        new_ltm_status: 'processed' | 'skipped' | 'error'
        """
        if new_ltm_status not in ("processed", "skipped", "error"):
            raise ValueError("new_ltm_status must be processed/skipped/error")

        q = f"""
        UPDATE {self.table}
        SET ltm_status=%s,
            ltm_processed_at=NOW(),
            ltm_error=%s
        WHERE id=%s;
        """
        cad.safe_connect_to_database(q, (new_ltm_status, error_text, int(message_id)))

    # -------------------------
    # RECOVERY / UTRZYMANIE
    # -------------------------

    def reset_stuck_processing(self, older_than_minutes=30):
        """
        Jeśli coś utknęło w 'processing' (np. demon padł),
        to cofnij z powrotem na 'new'.

        Na razie concept: w praktyce ustawisz:
        - ltm_status='new'
        - ltm_processing_token=NULL
        - ltm_processing_at=NULL
        """
        q = f"""
        UPDATE {self.table}
        SET ltm_status='new',
            ltm_processing_token=NULL,
            ltm_processing_at=NULL
        WHERE ltm_status='processing'
          AND ltm_processing_at <= NOW() - INTERVAL %s MINUTE;
        """
        return cad.safe_connect_to_database(q, (int(older_than_minutes),))


# === LTM: stałe indeksy (bo DB wrapper zwraca tuple) ===
# Kolejność kolumn musi odpowiadać SELECT-om w MessagesRepo (id, user_name, content, timestamp, status, ltm_*)
IDX_ID = 0
IDX_USER_NAME = 1
IDX_CONTENT = 2
IDX_TIMESTAMP = 3
IDX_STATUS = 4
IDX_LTM_STATUS = 5
IDX_LTM_TOKEN = 6
IDX_LTM_PROCESSING_AT = 7
IDX_LTM_PROCESSED_AT = 8
IDX_LTM_ERROR = 9

class ActionGate:
    def __init__(self):
        self.revoke_rx = re.compile(r"\b(odwołuję|odwoluje|cofam|anuluj|przestaje obowiązywać|przestaje obowiazywac|już nie obowiązuje|juz nie obowiazuje)\b", re.I)
        self.supersede_rx = re.compile(r"\b(zamiast|zastępuje|zastapuje|nowa zasada.*zastępuje|zmiana zasady)\b", re.I)

    def might_be_action(self, text: str) -> bool:
        t = (text or "").strip()
        if not t:
            return False
        return bool(self.revoke_rx.search(t) or self.supersede_rx.search(t))


class HeuristicGate:
    """
    Szybka bramka: decyduje czy wołać LLM.
    Zwraca:
      - None => skip
      - dict (partial) => kandydat dla LLM (z wstępnym scope/owner)
    """

    def __init__(self, allow_users=None):
        self.allow_users = set([u.lower() for u in (allow_users or [])])

        self.markers = [
            "zasada:", "ustalenie:", "preferencja:", "od teraz", "ważne:",
            "must have", "reguła", "procedura", "pipeline", "standard:"
        ]

        self.skip_patterns = [
            r"^@help\b", r"^@ustawienia\b", r"^dzięki\b", r"^ok\b", r"^spoko\b",
            r"^rozumiem\b"
        ]

    def check(self, user_name, content):
        u = (user_name or "").strip().lower()
        t = (content or "").strip()
        if not t:
            return None

        # krótkie komendy / small talk
        low = t.lower().strip()
        if len(low) < 20:
            return None

        for pat in self.skip_patterns:
            if re.search(pat, low):
                return None

        # na start ograniczamy źródło do ludzi
        if self.allow_users and u not in self.allow_users:
            return None

        # marker pamięci
        if not any(m in low for m in self.markers):
            return None

        # wstępne scope/owner po prefiksie
        scope = "shared"
        owner_user = None
        owner_agent = None

        if low.startswith("preferencja:"):
            scope = "user"
            owner_user = u

        # prosta obsługa "gerina: ... pamiętaj" jako agent
        if low.startswith("gerina:") or low.startswith("aifa:") or low.startswith("pionier:"):
            if "pamiętaj" in low or "zapamiętaj" in low:
                scope = "agent"
                owner_agent = low.split(":", 1)[0].strip()

        # dedupe key do cache/antyspamu LLM
        norm = re.sub(r"\s+", " ", low)
        dedupe_key = sha1(f"{scope}|{owner_user}|{owner_agent}|{norm}".encode("utf-8")).hexdigest()

        return {
            "scope_hint": scope,
            "owner_user_login": owner_user,
            "owner_agent_id": owner_agent,
            "dedupe_key": dedupe_key,
        }


class LLMMemoryWriter:
    """
    Woła Mistral i zwraca dict klasyfikacji (albo None).
    Wymusza JSON output.
    """

    def __init__(self, mgr, model_system_prompt):
        self.mgr = mgr
        self.system_prompt = model_system_prompt

    def build_ready_hist(self, message_text, meta):
        payload = {
            "message": message_text,
            "meta": meta,
            "output_contract": {
                "type": "memory_payload",
                "variants": ["memory_card", "memory_action", "null"],
                "memory_card_fields": [
                    "scope", "kind", "topic",
                    "owner_user_login", "owner_agent_id",
                    "score", "ttl_days",
                    "summary", "facts"
                ],
                "memory_action_fields": [
                    "type",
                    "scope",
                    "owner_user_login",
                    "owner_agent_id",
                    "target",
                    "reason",
                    "confidence"
                ],
                "memory_action_target_fields": [
                    "card_id",
                    "dedupe_key",
                    "keywords"
                ]
            }

        }
        return [{"role": "user", "content": json.dumps(payload, ensure_ascii=False)}]

    def classify_full(self, message_text, meta, max_tokens=500):
        ready_hist = self.build_ready_hist(message_text, meta)
        out = self.mgr.continue_conversation_with_system(ready_hist, self.system_prompt, max_tokens=max_tokens)
        if not out:
            return None

        txt = out.strip()
        try:
            j = json.loads(txt)
        except Exception:
            m = re.search(r"\{.*\}", txt, flags=re.S)
            if not m:
                return None
            j = json.loads(m.group(0))

        if not isinstance(j, dict):
            return None

        # normalizacja kontraktu
        if "memory_card" not in j:
            j["memory_card"] = None
        if "memory_action" not in j:
            j["memory_action"] = None

        return j


    def classify(self, message_text, meta, max_tokens=400):
        ready_hist = self.build_ready_hist(message_text, meta)
        out = self.mgr.continue_conversation_with_system(
            ready_hist,
            self.system_prompt,
            max_tokens=max_tokens
        )

        # out może być stringiem albo strukturą zależnie od wrappera; zakładam string
        if not out:
            return None

        # próbujemy wyciągnąć JSON (na wypadek gdy model doda tekst)
        txt = out.strip()
        j = None
        try:
            j = json.loads(txt)
        except Exception:
            m = re.search(r"\{.*\}", txt, flags=re.S)
            if m:
                try:
                    j = json.loads(m.group(0))
                except Exception:
                    return None
            else:
                return None

        if not isinstance(j, dict):
            return None

        # kontrakt: {"memory_card": {...}} albo {"memory_card": null}
        mc = j.get("memory_card", None)
        if mc is None:
            return None
        if not isinstance(mc, dict):
            return None

        return mc



class LongTermMemoryDaemon:
    """
    Demon LTM:
    - rezerwuje batch Messages.ltm_status='new'
    - pobiera zarezerwowane po tokenie
    - dla każdej wiadomości robi classify()
    - jeśli None -> skipped
    - jeśli klasyfikacja -> upsert memory_cards + sources + processed
    - w razie błędu -> error
    """

    def __init__(self, repo, write_cards=False, gate=None, llm_writer=None, action_gate=None):
        self.repo = repo
        self.write_cards = bool(write_cards)
        self.gate = gate
        self.llm_writer = llm_writer
        self.action_gate = action_gate

    def apply_memory_action(self, action, message_id, raw_text=None):
        atype = action.get("type")
        target = action.get("target") or {}
        reason = (action.get("reason") or "")[:255]

        card_id = target.get("card_id")
        dedupe_key = target.get("dedupe_key")
        keywords = target.get("keywords") or []

        # FALLBACK 1: jeśli brak keywords, wyciągnij je z raw_text
        if not keywords and raw_text:
            low = raw_text.lower()
            # proste odfiltrowanie słów funkcyjnych
            stop = {"odwołuję","odwoluje","zasadę","zasade","chwilowo","żadnej","zadnej","kawy","kawa","do","w","i","na","przy","podczas","testów","testow","od","teraz"}
            tokens = [t.strip(".,;:!?()[]\"'") for t in low.split()]
            tokens = [t for t in tokens if len(t) >= 3 and t not in stop]
            # jeśli user pisał o kawie/testach, dorzuć to jako keywordy obowiązkowo
            forced = []
            if "kawa" in low or "kawy" in low:
                forced.append("kawa")
            if "test" in low:
                forced.append("test")
            keywords = forced + tokens[:3]  # max 4-5 słów

            # normalizacja PL: tniemy do rdzeni żeby LIKE łapał odmiany (kawa/kawy, testy/testów)
            def _stem_pl(w: str) -> str:
                w = (w or "").strip().lower()
                w = re.sub(r"[^a-z0-9ąćęłńóśźż]", "", w)
                if len(w) <= 3:
                    return w
                # prosta heurystyka: obetnij końcówki fleksyjne
                for suf in ("ami","ach","owi","owe","owego","owych","ami","em","ie","y","a","u","ów","om","e","i","ą","ę"):
                    if w.endswith(suf) and len(w) - len(suf) >= 3:
                        return w[:-len(suf)]
                return w[:4]  # fallback: krótki rdzeń

            keywords = [_stem_pl(k) for k in keywords if k]


        # 1) znajdź kartę po dedupe
        if not card_id and dedupe_key:
            card_id = self.find_active_card_id_by_dedupe(chat_id=0, dedupe_key=dedupe_key)

        # 2) znajdź kartę po keywords
        if not card_id and keywords:
            card_id = self.find_best_card_by_keywords(chat_id=0, keywords=keywords)

        # FALLBACK 2: jeśli wciąż brak targetu -> NIE RZUCAJ wyjątku
        if not card_id:
            # zamiast error: lepiej "skipped" z opisem
            raise RuntimeError(f"memory_action no target found: {atype} (keywords={keywords})")

        if atype == "revoke":
            q = """
            UPDATE memory_cards
            SET status='revoked',
                revoked_at=NOW(),
                revoked_reason=%s,
                revoked_by_message_id=%s,
                updated_at=NOW()
            WHERE id=%s;
            """
            cad.safe_connect_to_database(q, (reason, int(message_id), int(card_id)))
            return

        raise RuntimeError(f"unknown memory_action type: {atype}")


    def find_best_card_by_keywords(self, chat_id, keywords, limit=5):
        """
        Dopasowanie po summary (MVP) ale odporne na odmiany:
        - OR zamiast AND
        - ranking po liczbie trafień
        """
        kws = [k for k in (keywords or []) if k]
        if not kws:
            return None

        # OR do “kandydatów”
        where_or = " OR ".join(["summary LIKE %s" for _ in kws])

        # ranking: zliczamy trafienia (CASE WHEN ...)
        score_expr = " + ".join([f"(CASE WHEN summary LIKE %s THEN 1 ELSE 0 END)" for _ in kws])

        params = [int(chat_id)]
        params += [f"%{k}%" for k in kws]          # do WHERE OR
        params += [f"%{k}%" for k in kws]          # do score_expr
        params += [int(limit)]

        q = f"""
        SELECT id,
            ({score_expr}) AS hits
        FROM memory_cards
        WHERE chat_id=%s
        AND status='active'
        AND (expires_at IS NULL OR expires_at > NOW())
        AND ({where_or})
        ORDER BY hits DESC, score DESC, updated_at DESC
        LIMIT %s;
        """
        rows = cad.safe_connect_to_database(q, tuple(params))
        return rows[0][0] if rows else None



    def run_once(self, batch_size=20, dry_run=False, token=None):
        """
        Jeśli token=None -> demon sam rezerwuje batch.
        Jeśli token podany -> demon przetwarza batch już zarezerwowany tym tokenem (bez rezerwacji).
        """
        if token is None:
            token = self.repo.reserve_ltm_batch(limit=batch_size)
        rows = self.repo.fetch_reserved_batch(token)

        results = {
            "token": token,
            "reserved": len(rows),
            "processed": 0,
            "skipped": 0,
            "errors": 0,
            "dry_run": bool(dry_run),
        }

        # Cache lokalny na czas jednego batcha: dedupe_key -> memory_card_id
        batch_cache = {}

        for row in rows:
            msg_id = row[IDX_ID]
            try:
                classification = self.classify_message(row, batch_cache=batch_cache)
                payload = classification
                if payload is None:
                    if not dry_run:
                        self.repo.close_message(msg_id, "skipped", error_text=None)
                    results["skipped"] += 1
                    continue

                # dry_run: nie dotykamy DB (poza rezerwacją batcha)
                if dry_run:
                    # policzmy tylko co by było
                    if payload.get("memory_action") or payload.get("memory_card") or payload.get("_cache_hit"):
                        results["processed"] += 1
                    else:
                        results["skipped"] += 1
                    continue

                action = payload.get("memory_action")
                card = payload.get("memory_card")

                # 1) akcja revoke/supersede
                if action:
                    confidence = float(action.get("confidence", 0.0))

                    # Bezpiecznik: LLM niepewny → NIE wykonujemy akcji
                    if confidence < 0.6:
                        self.repo.close_message(
                            msg_id,
                            "skipped",
                            error_text=f"memory_action confidence too low: {confidence}"
                        )

                        # smart debug
                        atype = action.get("type")
                        print(
                            f"[LTM] memory_action ignored "
                            f"(type={atype}, confidence={confidence}) msg_id={msg_id}"
                        )

                        results["skipped"] += 1
                        continue

                    # Akcja zaakceptowana
                    try:
                        self.apply_memory_action(action, msg_id, raw_text=payload.get("_raw_text"))
                    except RuntimeError as e:
                        # brak targetu = normalne -> skipped (a nie error)
                        msg = str(e)
                        if "no target found" in msg:
                            self.repo.close_message(msg_id, "skipped", error_text=msg[:255])
                            print(f"[LTM] memory_action skipped: {msg} msg_id={msg_id}")
                            results["skipped"] += 1
                            continue
                        raise

                    self.repo.close_message(msg_id, "processed", error_text=None)
                    results["processed"] += 1
                    continue


                # 2) cache hit -> bump + źródło
                if payload.get("_cache_hit"):
                    card_id = int(payload["memory_card_id"])
                    self.bump_memory_card_signal(card_id, bump_score=True)
                    self.link_source_message(card_id, msg_id)
                    self.repo.close_message(msg_id, "processed", error_text=None)
                    results["processed"] += 1
                    continue

                # 3) nowa karta
                if card:
                    # kanoniczny dedupe_key z gate'a, jeśli jest
                    if payload.get("dedupe_key"):
                        card["dedupe_key"] = payload["dedupe_key"]

                    card_id = self.upsert_memory_card(card)

                    dk = card.get("dedupe_key") or payload.get("dedupe_key")
                    if dk:
                        batch_cache[dk] = int(card_id)

                    self.link_source_message(card_id, msg_id)
                    self.repo.close_message(msg_id, "processed", error_text=None)
                    results["processed"] += 1
                    continue

                # 4) nic
                self.repo.close_message(msg_id, "skipped", error_text=None)
                results["skipped"] += 1

                




                # if classification is None:
                #     if not dry_run:
                #         self.repo.close_message(msg_id, "skipped", error_text=None)
                #     results["skipped"] += 1
                #     continue

                # if dry_run:
                #     # tylko symulacja: nie dotykamy DB poza rezerwacją
                #     results["processed"] += 1
                #     continue

                # # Jeśli write_cards=False, to tylko oznaczamy processed/skipped bez tabel memory_*
                # if self.write_cards:
                #     # CACHE HIT: nie wołamy LLM i nie robimy upsert – tylko bump wersji + źródło
                #     if classification.get("_cache_hit"):
                #         card_id = int(classification["memory_card_id"])
                #         print(f"[LTM] CACHE HIT dedupe={classification.get('dedupe_key')[:10]}.. -> card_id={card_id}")
                #         self.bump_memory_card_signal(card_id, bump_score=True)
                #         self.link_source_message(card_id, msg_id)

                #     else:
                #         card_id = self.upsert_memory_card(classification)
                #         dk = classification.get("dedupe_key")
                #         if dk:
                #             batch_cache[dk] = int(card_id)

                #         self.link_source_message(card_id, msg_id)


                # self.repo.close_message(msg_id, "processed", error_text=None)


                # results["processed"] += 1

            except Exception as e:
                if not dry_run:
                    self.repo.close_message(msg_id, "error", error_text=str(e)[:1000])
                results["errors"] += 1

        return results

    def classify_message(self, row, batch_cache=None):
        user_name = row[IDX_USER_NAME]
        content = row[IDX_CONTENT]

        if not content or not str(content).strip():
            return None

        # 0) action gate -> przepuszcza do LLM bez markerów
        is_action = bool(self.action_gate and self.action_gate.might_be_action(content))

        # 1) heurystyka bramkująca (jeśli nie action)
        hint = None
        if not is_action:
            if self.gate:
                hint = self.gate.check(user_name, content)
                if hint is None:
                    return None
        else:
            hint = {"scope_hint": "shared", "owner_user_login": None, "owner_agent_id": None, "dedupe_key": None}

        if not self.llm_writer:
            return None

        meta = {
            "chat_id": 0,
            "author_login": (user_name or "").strip(),
            "scope_hint": (hint or {}).get("scope_hint"),
            "owner_user_login": (hint or {}).get("owner_user_login"),
            "owner_agent_id": (hint or {}).get("owner_agent_id"),
            "dedupe_key": (hint or {}).get("dedupe_key"),
        }

        dedupe_key = meta.get("dedupe_key")

        # 2) CACHE HIT (tylko gdy mamy dedupe_key i nie jest to action)
        if dedupe_key and not is_action:
            if batch_cache is not None and dedupe_key in batch_cache:
                return {"_cache_hit": True, "memory_card_id": batch_cache[dedupe_key], "dedupe_key": dedupe_key, "memory_card": None, "memory_action": None}

            existing_id = self.find_active_card_id_by_dedupe(chat_id=0, dedupe_key=dedupe_key)
            if existing_id:
                if batch_cache is not None:
                    batch_cache[dedupe_key] = existing_id
                return {"_cache_hit": True, "memory_card_id": existing_id, "dedupe_key": dedupe_key, "memory_card": None, "memory_action": None}

        # 3) LLM
        out = self.llm_writer.classify_full(content, meta)

        if not out or not isinstance(out, dict):
            return None

        out.setdefault("memory_card", None)
        out.setdefault("memory_action", None)

        # dopnij dedupe_key z gate'a jako kanoniczny
        if dedupe_key and out.get("memory_card"):
            out["dedupe_key"] = dedupe_key

        out["_raw_text"] = content

        return out


        # user_name = row[IDX_USER_NAME]
        # content = row[IDX_CONTENT]

        # # 1) heurystyka bramkująca
        # if self.gate:
        #     hint = self.gate.check(user_name, content)
        #     if hint is None:
        #         return None
        # else:
        #     hint = None

        # # 2) LLM (tylko jeśli mamy writer)
        # if not self.llm_writer:
        #     return None

        # meta = {
        #     "chat_id": 0,
        #     "author_login": (user_name or "").strip(),
        #     "scope_hint": (hint or {}).get("scope_hint"),
        #     "owner_user_login": (hint or {}).get("owner_user_login"),
        #     "owner_agent_id": (hint or {}).get("owner_agent_id"),
        #     "dedupe_key": (hint or {}).get("dedupe_key"),
        # }
        # # 1.5) CACHE HIT: jeśli już mamy kartę o tym dedupe_key, nie wołamy LLM
        # dedupe_key = meta.get("dedupe_key")
        # if dedupe_key:
        #     # 1) RAM cache (ten batch)
        #     if batch_cache is not None and dedupe_key in batch_cache:
        #         return {
        #             "_cache_hit": True,
        #             "memory_card_id": batch_cache[dedupe_key],
        #             "dedupe_key": dedupe_key,
        #         }

        #     # 2) DB cache
        #     existing_id = self.find_active_card_id_by_dedupe(chat_id=0, dedupe_key=dedupe_key)
        #     if existing_id:
        #         if batch_cache is not None:
        #             batch_cache[dedupe_key] = existing_id
        #         return {
        #             "_cache_hit": True,
        #             "memory_card_id": existing_id,
        #             "dedupe_key": dedupe_key,
        #         }



        # mc = self.llm_writer.classify(content, meta, max_tokens=400)
        # if mc is None:
        #     return None
        
        # # Utrwalamy kanoniczny dedupe_key z gate'a
        # if meta.get("dedupe_key"):
        #     mc["dedupe_key"] = meta["dedupe_key"]


        # # dopnij pola wymagane przez upsert w Twoim kodzie
        # mc["chat_id"] = 0
        # mc.setdefault("owner_user_login", meta.get("owner_user_login"))
        # mc.setdefault("owner_agent_id", meta.get("owner_agent_id"))
        # mc.setdefault("visibility", "all")
        # mc.setdefault("audience_json", None)
        # mc.setdefault("trust_level", 2)
        # mc.setdefault("status", "active")

        # return mc

        # user_name = (row[IDX_USER_NAME] or "").strip().lower()
        # content = (row[IDX_CONTENT] or "").strip()
        # if not content:
        #     return None

        # low = content.lower()

        # # 1) Bezpiecznik: nie chcemy na start pamiętać paplaniny botów.
        # # Zmienisz to później, na razie ograniczamy źródło.
        # ALLOW_USERS = {"michal"}   # <- dopisz inne loginy ludzi, jeśli chcesz
        # if user_name not in ALLOW_USERS:
        #     return None

        # # 2) Markery "to jest ustalenie/procedura"
        # MARKERS = ["zasada", "reguła", "od teraz", "ustalamy", "procedura", "zawsze rób", "nie rób", "must have"]
        # if not any(m in low for m in MARKERS):
        #     return None

        # # 3) Minimalna karta shared
        # summary = content.replace("\n", " ").strip()
        # if len(summary) > 280:
        #     summary = summary[:280].rstrip() + "…"

        # return {
        #     "chat_id": 0,                 # dopóki Messages nie ma chat_id
        #     "scope": "shared",
        #     "kind": "procedure",
        #     "topic": "general",
        #     "owner_user_login": None,
        #     "owner_agent_id": None,
        #     "visibility": "all",
        #     "audience_json": None,
        #     "score": 4,
        #     "trust_level": 2,
        #     "status": "active",
        #     "ttl_days": 180,
        #     "summary": summary,
        #     "facts": [summary],
        # }

    def find_active_card_id_by_dedupe(self, chat_id, dedupe_key):
        q = """
        SELECT id
        FROM memory_cards
        WHERE chat_id=%s AND dedupe_key=%s
          AND status='active'
          AND (expires_at IS NULL OR expires_at > NOW())
        LIMIT 1;
        """
        rows = cad.safe_connect_to_database(q, (int(chat_id), str(dedupe_key)))
        return rows[0][0] if rows else None

    def bump_memory_card_version(self, memory_card_id):
        q = """
        UPDATE memory_cards
        SET version = version + 1,
            updated_at = NOW()
        WHERE id=%s;
        """
        cad.safe_connect_to_database(q, (int(memory_card_id),))

    def bump_memory_card_signal(self, memory_card_id, bump_score=False):
        """
        Podbija wersję zawsze, a opcjonalnie score (max 5).
        """
        if bump_score:
            q = """
            UPDATE memory_cards
            SET version = version + 1,
                score = LEAST(5, score + 1),
                updated_at = NOW()
            WHERE id=%s;
            """
        else:
            q = """
            UPDATE memory_cards
            SET version = version + 1,
                updated_at = NOW()
            WHERE id=%s;
            """
        cad.safe_connect_to_database(q, (int(memory_card_id),))


    def upsert_memory_card(self, c):
        """
        Docelowo:
        - INSERT memory_cards
        - ON DUPLICATE KEY UPDATE ...
        - SELECT id po (chat_id, dedupe_key)
        Na razie: zostawiam realny szkielet SQL, ale jeśli tabeli nie ma, poleci wyjątek
        i wiadomość trafi w error (to OK na tym etapie).
        """
        import json
        from hashlib import sha1

        chat_id = int(c.get("chat_id", 0))
        scope = c["scope"]
        topic = c["topic"]
        owner_user = c.get("owner_user_login") or ""
        owner_agent = c.get("owner_agent_id") or ""
        summary = c["summary"]

        # base = f"{chat_id}|{scope}|{owner_user}|{owner_agent}|{topic}|{summary.strip().lower()}"
        # dedupe_key = sha1(base.encode("utf-8")).hexdigest()
        # c["dedupe_key"] = dedupe_key

        # Jeśli dedupe_key przychodzi z gate'a/klasyfikacji – używamy go jako kanonicznego.
        dedupe_key = c.get("dedupe_key")
        if not dedupe_key:
            base = f"{chat_id}|{scope}|{owner_user}|{owner_agent}|{topic}|{summary.strip().lower()}"
            dedupe_key = sha1(base.encode("utf-8")).hexdigest()
        c["dedupe_key"] = dedupe_key


        ttl_days = c.get("ttl_days")
        expires_at_sql = "NULL"
        if ttl_days is not None:
            expires_at_sql = f"DATE_ADD(NOW(), INTERVAL {int(ttl_days)} DAY)"

        facts_json = None
        if c.get("facts") is not None:
            facts_json = json.dumps(c["facts"], ensure_ascii=False)

        audience_json = None
        if c.get("audience_json") is not None:
            audience_json = json.dumps(c["audience_json"], ensure_ascii=False)

        # UWAGA: tu używamy cad.safe_connect_to_database, bo mamy parametry
        q = f"""
        INSERT INTO memory_cards (
            chat_id, scope, kind, topic,
            owner_user_login, owner_agent_id,
            visibility, audience_json,
            score, trust_level, status,
            ttl_days, expires_at,
            summary, facts_json,
            dedupe_key, version,
            created_at, updated_at
        ) VALUES (
            %s,%s,%s,%s,
            %s,%s,
            %s,%s,
            %s,%s,%s,
            %s,{expires_at_sql},
            %s,%s,
            %s,1,
            NOW(), NOW()
        )
        ON DUPLICATE KEY UPDATE
            summary = VALUES(summary),
            facts_json = VALUES(facts_json),
            score = GREATEST(score, VALUES(score)),
            trust_level = GREATEST(trust_level, VALUES(trust_level)),
            version = version + 1,
            updated_at = NOW();
        """

        params = (
            chat_id, c["scope"], c["kind"], c["topic"],
            c.get("owner_user_login"), c.get("owner_agent_id"),
            c.get("visibility", "all"), audience_json,
            int(c.get("score", 1)), int(c.get("trust_level", 1)), c.get("status", "active"),
            (int(ttl_days) if ttl_days is not None else None),
            c["summary"], facts_json,
            dedupe_key
        )

        cad.safe_connect_to_database(q, params)

        # pobierz id karty po dedupe
        q2 = """
        SELECT id FROM memory_cards
        WHERE chat_id = %s AND dedupe_key = %s
        LIMIT 1;
        """
        rows = cad.safe_connect_to_database(q2, (chat_id, dedupe_key))
        if not rows:
            raise RuntimeError("memory_cards upsert ok but cannot fetch id")
        return rows[0][0]  # id

    def link_source_message(self, memory_card_id, message_id):
        """
        INSERT IGNORE do memory_card_sources.
        """
        q = """
        INSERT IGNORE INTO memory_card_sources (memory_card_id, message_id, created_at)
        VALUES (%s, %s, NOW());
        """
        cad.safe_connect_to_database(q, (int(memory_card_id), int(message_id)))


class MemorySelector:
    """
    Składa kontekst dla modelu:
    - bierze short-term (np. last hour)
    - dobiera long-term (memory_cards kaskadą)
    - loguje selekcję (memory_selections + items)
    """

    def __init__(self, repo):
        self.repo = repo

    def build_context(self, agent_id="lab_agent", group_id=None, window_minutes=60, budget_chars=4000):
        """
        group_id na razie ignorowane (dopóki Messages nie ma chat_id).
        """
        # 1) short-term
        last_rows = self.repo.fetch_group_context(group_id=group_id, window_minutes=window_minutes)

        # 2) aktywni userzy
        active_users = self.repo.detect_active_users(group_id=group_id, window_minutes=window_minutes)

        # 3) long-term selection (na dziś: jeśli nie ma tabel -> pusto)
        mem_cards = self._select_memory_cards(group_id=group_id, agent_id=agent_id, active_users=active_users, budget_chars=budget_chars)

        # 4) złożenie tekstu (memory injection + short-term)
        memory_block = self._render_memory_block(mem_cards)
        st_block = self._render_short_term(last_rows)

        return {
            "memory_block": memory_block,
            "short_term_block": st_block,
            "active_users": active_users,
            "last_rows_count": len(last_rows),
            "mem_cards_count": len(mem_cards),
        }

    def _select_memory_cards(self, group_id, agent_id, active_users, budget_chars):
        """
        Docelowo:
        - shared
        - user dla active_users
        - agent
        Na razie: jeśli brak tabel memory_cards, po prostu zwróci [] (bez wywalania).
        """
        try:
            # Na dziś (brak chat_id): traktujemy wszystko jako chat_id = 0
            chat_id = 0
            selected = []
            used = 0

            def try_add(card):
                nonlocal used
                line = f"- [{card['scope']}/{card['topic']}/s{card['score']}] {card['summary']}\n"
                cost = len(line)
                if used + cost > budget_chars:
                    return False
                selected.append((card, cost))
                used += cost
                return True

            # shared
            for c in self.fetch_cards_shared(chat_id):
                if not try_add(c):
                    break

            # user
            for u in self._normalize_users(active_users):
                for c in self.fetch_cards_user(chat_id, u):
                    if not try_add(c):
                        break

            # agent
            for c in self.fetch_cards_agent(chat_id, agent_id):
                if not try_add(c):
                    break

            return [x[0] for x in selected]

        except Exception:
            return []

    def fetch_cards_shared(self, chat_id, limit=50):
        q = """
        SELECT id, scope, kind, topic, owner_user_login, owner_agent_id,
               score, summary
        FROM memory_cards
        WHERE chat_id=%s AND scope='shared' AND status='active'
          AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY score DESC, updated_at DESC
        LIMIT %s;
        """
        rows = cad.safe_connect_to_database(q, (int(chat_id), int(limit)))
        return [self._row_to_card(r) for r in rows]

    def fetch_cards_user(self, chat_id, user_login, limit=50):
        q = """
        SELECT id, scope, kind, topic, owner_user_login, owner_agent_id,
               score, summary
        FROM memory_cards
        WHERE chat_id=%s AND scope='user' AND owner_user_login=%s AND status='active'
          AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY score DESC, updated_at DESC
        LIMIT %s;
        """
        rows = cad.safe_connect_to_database(q, (int(chat_id), str(user_login), int(limit)))
        return [self._row_to_card(r) for r in rows]

    def fetch_cards_agent(self, chat_id, agent_id, limit=50):
        q = """
        SELECT id, scope, kind, topic, owner_user_login, owner_agent_id,
               score, summary
        FROM memory_cards
        WHERE chat_id=%s AND scope='agent' AND owner_agent_id=%s AND status='active'
          AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY score DESC, updated_at DESC
        LIMIT %s;
        """
        rows = cad.safe_connect_to_database(q, (int(chat_id), str(agent_id), int(limit)))
        return [self._row_to_card(r) for r in rows]

    def _row_to_card(self, r):
        # r: tuple w kolejności SELECT powyżej
        return {
            "id": r[0],
            "scope": r[1],
            "kind": r[2],
            "topic": r[3],
            "owner_user_login": r[4],
            "owner_agent_id": r[5],
            "score": r[6],
            "summary": r[7],
        }

    def _normalize_users(self, rows):
        # detect_active_users może zwracać [('michal',), ('gerina',)] albo podobnie
        users = []
        for x in rows or []:
            if isinstance(x, (list, tuple)):
                users.append(x[0])
            else:
                users.append(x)
        return [u for u in users if u]

    def _render_memory_block(self, mem_cards):
        if not mem_cards:
            return "LONG-TERM MEMORY:\n- (empty)\n"
        out = ["LONG-TERM MEMORY:"]
        for c in mem_cards:
            out.append(f"- [{c['scope']}/{c['topic']}/s{c['score']}] {c['summary']}")
        return "\n".join(out) + "\n"

    def _render_short_term(self, last_rows):
        out = ["SHORT-TERM (window):"]
        for r in last_rows:
            user = r[IDX_USER_NAME]
            ts = r[IDX_TIMESTAMP]
            txt = (r[IDX_CONTENT] or "").replace("\n", " ")
            if len(txt) > 160:
                txt = txt[:160] + "…"
            out.append(f"- {ts} @{user}: {txt}")
        return "\n".join(out) + "\n"


def seed_memory_card_if_empty():
    """
    Wrzuca jedną testową kartę do memory_cards, jeśli tabela istnieje i jest pusta.
    Dzięki temu od razu widzisz, czy MemorySelector składa memory_block.
    """
    try:
        # czy są jakieś karty?
        rows = cad.safe_connect_to_database("SELECT COUNT(*) FROM memory_cards WHERE chat_id=%s;", (0,))
        cnt = int(rows[0][0]) if rows else 0
        if cnt > 0:
            return

        # wrzuć 1 testową kartę
        q = """
        INSERT INTO memory_cards
        (chat_id, scope, kind, topic, owner_user_login, owner_agent_id,
         visibility, audience_json, score, trust_level, status, ttl_days, expires_at,
         summary, facts_json, dedupe_key, version, created_at, updated_at)
        VALUES
        (%s,'shared','procedure','memory',NULL,NULL,
         'all',NULL,5,2,'active',180,DATE_ADD(NOW(), INTERVAL 180 DAY),
         %s,%s,%s,1,NOW(),NOW());
        """
        summary = "TEST: pamięć shared działa (seed z laba)."
        facts_json = '["TEST: pamięć shared działa (seed z laba)."]'
        dedupe_key = "seed-demo-0001"
        cad.safe_connect_to_database(q, (0, summary, facts_json, dedupe_key))

    except Exception as e:
        print("seed_memory_card_if_empty(): pomijam (brak tabeli lub błąd):", str(e)[:160])


if __name__ == "__main__":

    mgr = MistralChatManager(MISTRAL_API_KEY)

    repo = MessagesRepo()

    DRY_RUN = False
    BATCH_SIZE = 5

    # 0) (opcjonalnie) posprzątaj stare processing, jeśli coś utknęło
    # repo.reset_stuck_processing(older_than_minutes=30)

    # 1) podgląd kolejki
    rows_new = repo.fetch_ltm(ltm_status="new", limit=10)
    print("ltm_new (preview 10):", len(rows_new))
    print(rows_new[-1] if rows_new else None)

    # 2) demon: jeden przebieg = jedna rezerwacja
    # daemon = LongTermMemoryDaemon(repo, write_cards=True)
    # res = daemon.run_once(batch_size=BATCH_SIZE, dry_run=DRY_RUN)
    classifier_system_prompt = (
        "Jesteś klasyfikatorem pamięci długoterminowej (LTM) dla czatu grupowego.\n"
        "Twoim zadaniem jest zdecydować, czy wiadomość:\n"
        "- tworzy nową pamięć (memory_card),\n"
        "- wykonuje akcję na istniejącej pamięci (memory_action),\n"
        "- albo nie wnosi nic trwałego (null).\n\n"

        "ZWRAJASZ WYŁĄCZNIE poprawny JSON. Bez markdown, bez komentarzy, bez tekstu poza JSON.\n\n"

        "FORMAT ODPOWIEDZI (ZAWSZE TEN SAM):\n"
        "{\n"
        '  "memory_card": { ... } | null,\n'
        '  "memory_action": { ... } | null\n'
        "}\n\n"

        "Jeśli wiadomość NIE tworzy pamięci i NIE jest akcją:\n"
        '{"memory_card": null, "memory_action": null}\n\n'

        "ZASADY OGÓLNE:\n"
        "- Nie zapisuj small talku, żartów, reakcji, potwierdzeń, podziękowań.\n"
        "- Nie zapisuj pytań ani poleceń, jeśli nie zawierają trwałego ustalenia.\n"
        "- Pamięć musi być użyteczna w przyszłych rozmowach.\n"
        "- Summary: neutralne, 1–2 zdania.\n"
        "- Facts: 1–5 krótkich, konkretnych punktów.\n"
        "- score: liczba całkowita 1–5 (ważność).\n"
        "- ttl_days: jedna z wartości 30 / 90 / 180 / 365 lub null.\n"
        "- scope: shared / user / agent (zgodne z meta.scope_hint jeśli podane).\n"
        "- topic: infra / db / marketing / memory / general.\n\n"

        "MEMORY_CARD (gdy tworzysz nową pamięć):\n"
        "- Użyj wyłącznie pól wymienionych w output_contract.memory_card_fields.\n"
        "- Nie dodawaj dodatkowych kluczy.\n\n"

        "MEMORY_ACTION (gdy wiadomość odwołuje lub zastępuje pamięć):\n"
        "- type: 'revoke' albo 'supersede'.\n"
        "- target: wskaż istniejącą pamięć przez:\n"
        "  * card_id LUB\n"
        "  * dedupe_key LUB\n"
        "  * keywords (co najmniej jedno słowo kluczowe).\n"
        "- reason: krótko wyjaśnij dlaczego.\n"
        "- confidence: liczba 0.0–1.0 (pewność trafności akcji).\n"
        "- Jeśli nie jesteś wystarczająco pewny (confidence < 0.6), NIE wykonuj akcji.\n\n"
        "- Jeśli type=revoke/supersede, ZAWSZE wypełnij target.keywords (min 1), nawet jeśli nie znasz card_id."

        "PRIORYTET:\n"
        "- Jeśli wiadomość jednocześnie zawiera nową zasadę i odwołuje starą → wybierz memory_action.\n"
        "- Jeśli treść jest niejednoznaczna → zwróć null.\n\n"

        "ZWRAJASZ TYLKO JSON."
    )



    gate = HeuristicGate(allow_users=["michal"])  # na start tylko ludzie
    writer = LLMMemoryWriter(mgr, classifier_system_prompt)

    action_gate = ActionGate()
    daemon = LongTermMemoryDaemon(
        repo,
        write_cards=True,
        gate=gate,
        llm_writer=writer,
        action_gate=action_gate
    )

    res = daemon.run_once(batch_size=BATCH_SIZE, dry_run=DRY_RUN)


    print(f"\nDAEMON RUN (dry_run={DRY_RUN}):", res)

    # 3) podgląd batcha po tokenie (widzisz finalne statusy)
    token = res["token"]
    tok_rows = repo.fetch_by_token(token)
    print("\nBATCH BY TOKEN:", token, "rows:", len(tok_rows))
    if tok_rows:
        # pokaż pierwsze 3 dla czytelności
        for r in tok_rows[:3]:
            print("  ", (r[0], r[1], r[5], r[7], r[8]))  # id, user, ltm_status, proc_at, processed_at

    # # test memory card
    # seed_memory_card_if_empty()


    # 4) selector: złożenie kontekstu (memory empty na tym etapie)
    selector = MemorySelector(repo)
    ctx = selector.build_context(agent_id="lab_agent", group_id=None, window_minutes=60, budget_chars=2000)
    print("\n--- MEMORY BLOCK ---")
    print(ctx["memory_block"])
    print("--- SHORT TERM BLOCK ---")
    print(ctx["short_term_block"])

