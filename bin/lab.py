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

import uuid
from datetime import datetime, timedelta

import connectAndQuery as cad


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

    def __init__(self, repo):
        self.repo = repo

    def run_once(self, batch_size=20, dry_run=False):
        """
        1) reserve batch (new -> processing)
        2) fetch reserved
        3) process each message:
           - classify
           - skipped OR upsert card + link source + processed
        """
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

        for row in rows:
            msg_id = row[IDX_ID]
            try:
                classification = self.classify_message(row)

                if classification is None:
                    if not dry_run:
                        self.repo.close_message(msg_id, "skipped", error_text=None)
                    results["skipped"] += 1
                    continue

                if dry_run:
                    # tylko symulacja: nie dotykamy DB poza rezerwacją
                    results["processed"] += 1
                    continue

                # 1) upsert karta
                card_id = self.upsert_memory_card(classification)

                # 2) link źródła
                self.link_source_message(card_id, msg_id)

                # 3) zamknij wiadomość
                self.repo.close_message(msg_id, "processed", error_text=None)

                results["processed"] += 1

            except Exception as e:
                if not dry_run:
                    self.repo.close_message(msg_id, "error", error_text=str(e)[:1000])
                results["errors"] += 1

        return results

    def classify_message(self, row):
        """
        Minimalna, bezpieczna klasyfikacja (MVP):
        - Na start: nie budujemy jeszcze faktycznej pamięci -> wszystko skipped
        - Jak będziesz gotowy: podmień tę funkcję na heurystyki/LLM.

        Zwraca dict (classification) albo None.
        """
        # >>> START: w tej iteracji świadomie nic nie zapamiętujemy
        # (bo jeszcze nie mamy ustalonych reguł i tabel pamięci w DB)
        return None
        # <<< END

        # Przykład (zostawiam jako “ściąga” do przyszłej edycji):
        # user_name = row[IDX_USER_NAME]
        # content = (row[IDX_CONTENT] or "").strip()
        # if not content:
        #     return None
        # return {
        #     "chat_id": 0,                 # dopóki nie masz chat_id w Messages
        #     "scope": "shared",
        #     "kind": "temp",
        #     "topic": "general",
        #     "owner_user_login": None,
        #     "owner_agent_id": None,
        #     "visibility": "all",
        #     "audience_json": None,
        #     "score": 2,
        #     "trust_level": 1,
        #     "status": "active",
        #     "ttl_days": 30,
        #     "summary": content[:300],
        #     "facts": [content[:300]],
        #     "dedupe_key": "TODO_HASH",
        # }

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

if __name__ == "__main__":
    repo = MessagesRepo()

    # 1) podgląd kolejki
    rows_new = repo.fetch_ltm(ltm_status="new", limit=10)
    print("ltm_new (preview 10):", len(rows_new))
    print(rows_new[-1] if rows_new else None)

    # 2) rezerwacja batcha (lab)
    token = repo.reserve_ltm_batch(limit=5)
    batch = repo.fetch_reserved_batch(token)
    print("\nRESERVED TOKEN:", token)
    print("reserved batch:", len(batch))
    print(batch[0] if batch else None)

    # 3) demon: uruchomienie 1 przebiegu (na start DRY RUN)
    daemon = LongTermMemoryDaemon(repo)
    res = daemon.run_once(batch_size=5, dry_run=True)
    print("\nDAEMON RUN (dry_run=True):", res)

    # 4) selector: złożenie kontekstu (memory empty na tym etapie)
    selector = MemorySelector(repo)
    ctx = selector.build_context(agent_id="lab_agent", group_id=None, window_minutes=60, budget_chars=2000)
    print("\n--- MEMORY BLOCK ---")
    print(ctx["memory_block"])
    print("--- SHORT TERM BLOCK ---")
    print(ctx["short_term_block"])
