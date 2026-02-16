"""
memoria_v2.py
LTM v2 – event-sourcing based long-term memory engine

ZAŁOŻENIA:
- turn_messages jako źródło prawdy
- ekstrakcja z user i assistant
- scope relacji: (chat_id, owner_user_login, owner_agent_id)
- shared OFF
- tags/keywords_json jako mechanizm wyszukiwania
- dedupe per (chat_id, user, bot)
"""

import uuid
import json
import time
from hashlib import sha1
from datetime import datetime

import connectAndQuery as cad


# ==========================================================
# REPO – TURN MESSAGES (EVENT STORE)
# ==========================================================

class TurnMessagesRepo:

    def insert_turn_message(self, chat_id, user_login, bot_id, role, content):
        """
        Każda wiadomość ma własny turn_id.
        seq liczone jako MAX(seq)+1 per (chat_id, user_login, bot_id)
        """

        turn_id = str(uuid.uuid4())

        # seq = MAX(seq)+1
        q_seq = """
        SELECT COALESCE(MAX(seq),0)
        FROM turn_messages
        WHERE chat_id=%s
          AND owner_user_login=%s
          AND owner_agent_id=%s
        FOR UPDATE;
        """

        rows = cad.safe_connect_to_database(
            q_seq, (int(chat_id), str(user_login), str(bot_id))
        )

        last_seq = int(rows[0][0]) if rows else 0
        new_seq = last_seq + 1

        q_insert = """
        INSERT INTO turn_messages
        (turn_id, chat_id, owner_user_login, owner_agent_id,
         seq, role, content, content_hash,
         ltm_status, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'new',NOW());
        """

        content_hash = sha1(content.encode("utf-8")).hexdigest()

        cad.insert_to_database(
            q_insert,
            (
                turn_id,
                int(chat_id),
                str(user_login),
                str(bot_id),
                int(new_seq),
                str(role),
                content,
                content_hash,
            ),
        )

        return turn_id, new_seq


    def claim_batch(self, limit=20, token=None):
        """
        Rezerwuje batch ltm_status='new'
        """

        if token is None:
            token = str(uuid.uuid4())

        q = """
        UPDATE turn_messages
        SET ltm_status='processing',
            ltm_processing_token=%s,
            ltm_processing_at=NOW()
        WHERE ltm_status='new'
        ORDER BY created_at ASC
        LIMIT %s;
        """

        cad.insert_to_database(q, (token, int(limit)))
        return token


    def fetch_by_token(self, token):
        q = """
        SELECT id, turn_id, chat_id, owner_user_login,
               owner_agent_id, seq, role, content
        FROM turn_messages
        WHERE ltm_processing_token=%s
        ORDER BY seq ASC;
        """
        return cad.safe_connect_to_database(q, (token,))


    def fetch_window(self, chat_id, user_login, bot_id, center_seq, before=3, after=3):
        """
        Okno -3/+3 w scope relacji
        """

        q = """
        SELECT turn_id, seq, role, content
        FROM turn_messages
        WHERE chat_id=%s
          AND owner_user_login=%s
          AND owner_agent_id=%s
          AND seq BETWEEN %s AND %s
        ORDER BY seq ASC;
        """

        return cad.safe_connect_to_database(
            q,
            (
                int(chat_id),
                str(user_login),
                str(bot_id),
                int(center_seq - before),
                int(center_seq + after),
            ),
        )


    def close(self, turn_id, status, error_text=None):
        q = """
        UPDATE turn_messages
        SET ltm_status=%s,
            ltm_processed_at=NOW(),
            ltm_error=%s
        WHERE turn_id=%s;
        """
        cad.insert_to_database(q, (status, error_text, str(turn_id)))


# ==========================================================
# MEMORY CARDS
# ==========================================================

class MemoryCardsRepo:

    def find_by_dedupe(self, chat_id, user_login, bot_id, dedupe_key):
        q = """
        SELECT id
        FROM memory_cards
        WHERE chat_id=%s
          AND owner_user_login=%s
          AND owner_agent_id=%s
          AND dedupe_key=%s
          AND status='active'
        LIMIT 1;
        """
        rows = cad.safe_connect_to_database(
            q, (chat_id, user_login, bot_id, dedupe_key)
        )
        return rows[0][0] if rows else None


    def upsert(self, card, created_from_turn_id):
        """
        dedupe UNIQUE(chat_id,user,bot,dedupe_key)
        """

        dedupe_key = card.get("dedupe_key")
        if not dedupe_key:
            base = f"{card['chat_id']}|{card['owner_user_login']}|{card['owner_agent_id']}|{card['kind']}|{card['summary'].strip().lower()}"
            dedupe_key = sha1(base.encode()).hexdigest()

        q = """
        INSERT INTO memory_cards
        (chat_id, scope, kind, topic,
         owner_user_login, owner_agent_id,
         summary, facts_json, keywords_json,
         score, status, dedupe_key,
         created_from_turn_id,
         created_at, updated_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'active',%s,%s,NOW(),NOW())
        ON DUPLICATE KEY UPDATE
            summary=VALUES(summary),
            facts_json=VALUES(facts_json),
            keywords_json=VALUES(keywords_json),
            score=GREATEST(score, VALUES(score)),
            updated_at=NOW();
        """

        cad.insert_to_database(
            q,
            (
                card["chat_id"],
                card["scope"],
                card["kind"],
                card["topic"],
                card["owner_user_login"],
                card["owner_agent_id"],
                card["summary"],
                json.dumps(card.get("facts", []), ensure_ascii=False),
                json.dumps(card.get("keywords", []), ensure_ascii=False),
                card.get("score", 1),
                dedupe_key,
                created_from_turn_id,
            ),
        )


    def revoke(self, chat_id, user_login, bot_id, card_id, turn_id, reason):
        q = """
        UPDATE memory_cards
        SET status='revoked',
            revoked_by_turn_id=%s,
            revoked_at=NOW(),
            revoked_reason=%s,
            updated_at=NOW()
        WHERE id=%s
          AND chat_id=%s
          AND owner_user_login=%s
          AND owner_agent_id=%s;
        """
        cad.insert_to_database(
            q,
            (turn_id, reason, card_id, chat_id, user_login, bot_id),
        )


# ==========================================================
# MEMORY LINKS (pochodne)
# ==========================================================

class MemoryLinksRepo:

    def link(self, from_card_id, to_card_id, link_type="derived"):
        q = """
        INSERT INTO memory_card_links
        (from_card_id, to_card_id, link_type, created_at)
        VALUES (%s,%s,%s,NOW());
        """
        cad.insert_to_database(q, (from_card_id, to_card_id, link_type))


    def find_derived(self, card_id):
        q = """
        SELECT to_card_id
        FROM memory_card_links
        WHERE from_card_id=%s
          AND link_type='derived';
        """
        return cad.safe_connect_to_database(q, (card_id,))


# ==========================================================
# DAEMON V2
# ==========================================================

class LongTermMemoryDaemonV2:

    def __init__(self, turn_repo, card_repo, links_repo, llm_writer):
        self.turn_repo = turn_repo
        self.card_repo = card_repo
        self.links_repo = links_repo
        self.llm = llm_writer


    def run_once(self, batch_size=20):
        token = self.turn_repo.claim_batch(limit=batch_size)
        rows = self.turn_repo.fetch_by_token(token)

        for row in rows:
            (
                _id,
                turn_id,
                chat_id,
                user_login,
                bot_id,
                seq,
                role,
                content,
            ) = row

            try:
                window = self.turn_repo.fetch_window(
                    chat_id, user_login, bot_id, seq
                )

                classification = self.llm.classify_full(
                    content,
                    {
                        "chat_id": chat_id,
                        "author_login": user_login,
                        "owner_user_login": user_login,
                        "owner_agent_id": bot_id,
                        "window": window,
                    },
                )

                if not classification:
                    self.turn_repo.close(turn_id, "skipped")
                    continue

                card = classification.get("memory_card")
                action = classification.get("memory_action")

                if action:
                    self.handle_action(
                        action,
                        chat_id,
                        user_login,
                        bot_id,
                        turn_id,
                    )

                if card:
                    card["chat_id"] = chat_id
                    card["owner_user_login"] = user_login
                    card["owner_agent_id"] = bot_id

                    self.card_repo.upsert(card, turn_id)

                self.turn_repo.close(turn_id, "processed")

            except Exception as e:
                self.turn_repo.close(turn_id, "error", str(e)[:500])


    def handle_action(self, action, chat_id, user_login, bot_id, turn_id):

        target_id = action.get("target", {}).get("card_id")
        reason = action.get("reason")

        if not target_id:
            return

        # revoke
        self.card_repo.revoke(
            chat_id,
            user_login,
            bot_id,
            target_id,
            turn_id,
            reason,
        )

        # cascade pochodnych
        derived = self.links_repo.find_derived(target_id)
        for row in derived:
            derived_id = row[0]
            self.card_repo.revoke(
                chat_id,
                user_login,
                bot_id,
                derived_id,
                turn_id,
                "parent_revoked",
            )
