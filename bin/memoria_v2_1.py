# memoria_v2_0.py
# Memoria 2.0 (LTM v2) — event store + memory cards + selection audit
# Autor: (twój projekt) — moduł biblioteczny, gotowy do podpięcia pod daemon

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Iterable
import json
import hashlib
import time
import logging
import re
from config_utils import MISTRAL_API_KEY, DBDATA
from wrapper_mistral import MistralChatManager

import uuid
from typing import Callable

# =============================================================================
# Utils
# =============================================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()

def normalize_dedupe_key(s: str, max_len: int = 64) -> str:
    """
    Dedupe key z LLM bywa zbyt długi / niestabilny.
    Trzymamy w DB zawsze krótki, stabilny klucz.
    - jeśli key jest krótki i "bezpieczny" -> zostawiamy
    - w przeciwnym razie -> sha1(key) (40 hex)
    """
    raw = (s or "").strip()
    if not raw:
        return ""
    raw = normalize_whitespace(raw)

    # typowe "dobre" klucze (np. sha1, slug, itp.)
    if len(raw) <= max_len and re.match(r"^[a-zA-Z0-9:_\-\.\|]+$", raw):
        return raw

    # fallback: stabilny hash zawsze mieści się w kolumnie
    return sha1_hex(raw)


def safe_json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

def safe_json_loads(s: Optional[str]) -> Any:
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        return None

def normalize_whitespace(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())

def clamp_int(x: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, x))

T_TURNS = "turn_messages_v2"
T_CARDS = "memory_cards_v2"
T_SOURCES = "memory_card_sources_v2"
T_LINKS = "memory_links_v2"
T_SELECTIONS = "memory_selections_v2"
T_SELECTION_ITEMS = "memory_selection_items_v2"
T_MESSAGES = "Messages"



SG = set(['a','ą','e','ę','i','o','ó','u','y','A','Ą','E','Ę','I','O','Ó','U','Y'])

def sam_g(x: str) -> bool:
    return x in SG

def sufix_pl(word: str) -> str:
    if not word:
        return word
    word = str(word)

    i = len(word) - 1
    while i > 0 and not sam_g(word[i]):
        i -= 1
    if i <= 0:
        return word

    start = max(0, i - 2)
    pre = word[:i]

    for tri in ("dż", "dź"):
        if pre.endswith(tri):
            start = max(0, i - 3)
            break
    else:
        for di in ("ch", "cz", "rz", "dz"):
            if pre.endswith(di):
                start = max(0, i - 3)
                break

    return word[start:]


def normalize_keyword_pl(word: str) -> str:
    """
    BAZOWE słowo do dopasowań w DB (powinno realnie występować w summary/facts).
    Tu nie robimy suffix/stem — tylko czyszczenie.
    """
    w = (word or "").strip().lower()
    if not w:
        return ""
    w = re.sub(r"[^a-z0-9ąćęłńóśźż]", "", w)
    return w



def keyword_variants_pl(word: str) -> list:
    """
    Warianty do dopasowania w DB.
    1) base word (pełne, czyste)
    2) prefix (pierwsze 4 znaki) – łapie odmiany
    3) sufix_pl – Twój sygnał językowy (opcjonalny)
    """
    w = normalize_keyword_pl(word)
    if not w:
        return []

    out = [w]

    if len(w) >= 4:
        out.append(w[:4])
    elif len(w) >= 3:
        out.append(w[:3])

    try:
        s = sufix_pl(w)
        s = (s or "").strip().lower()
        if s and len(s) >= 2:
            out.append(s)
    except Exception:
        pass

    # dedup w kolejności
    uniq = []
    seen = set()
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


# =============================================================================
# DB Abstraction
# =============================================================================

class DBError(RuntimeError):
    pass

class DB:
    """
    Minimalny interfejs DB. Masz tylko:
      - query(): zwraca listę dictów
      - execute(): wykonuje INSERT/UPDATE/DELETE
      - transaction(): kontekst transakcji na jednym połączeniu
    """
    def query(self, sql: str, params: Optional[Tuple[Any, ...]] = None) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def execute(self, sql: str, params: Optional[Tuple[Any, ...]] = None) -> int:
        raise NotImplementedError

    def transaction(self) -> "DBTx":
        raise NotImplementedError

class DBTx(DB):
    """
    Transakcyjny DB — ten sam interfejs co DB, ale w kontekście BEGIN/COMMIT/ROLLBACK.
    """
    def commit(self) -> None:
        raise NotImplementedError

    def rollback(self) -> None:
        raise NotImplementedError

    def __enter__(self) -> "DBTx":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc:
            try:
                self.rollback()
            finally:
                return
        self.commit()


# =============================================================================
# Default MySQL implementation (mysql-connector-python)
# =============================================================================

class MySQLDB(DB):
    """
    Domyślna implementacja DB na mysql-connector.
    Jeśli u Ciebie DB idzie przez connectAndQuery, to:
      - albo dopisujesz adapter klasy CadDB,
      - albo podstawiasz swój obiekt DB.
    """
    def __init__(self, *, host: str = DBDATA['host'], user: str = DBDATA['user'], password: str = DBDATA['pass'], database: str = DBDATA['base'], port: int = 3306):
        self._cfg = dict(host=host, user=user, password=password, database=database, port=port)

    def _connect(self):
        try:
            import mysql.connector  # type: ignore
            return mysql.connector.connect(**self._cfg)
        except Exception as e:
            raise DBError(f"MySQL connect error: {e}") from e

    def query(self, sql: str, params: Optional[Tuple[Any, ...]] = None) -> List[Dict[str, Any]]:
        conn = self._connect()
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute(sql, params or ())
            rows = cur.fetchall()
            return rows or []
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def execute(self, sql: str, params: Optional[Tuple[Any, ...]] = None) -> int:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(sql, params or ())
            conn.commit()
            return cur.rowcount
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def transaction(self) -> "MySQLTx":
        return MySQLTx(self)

class MySQLTx(DBTx):
    def __init__(self, parent: MySQLDB):
        self._parent = parent
        self._conn = parent._connect()
        self._conn.autocommit = False

    def query(self, sql: str, params: Optional[Tuple[Any, ...]] = None) -> List[Dict[str, Any]]:
        cur = self._conn.cursor(dictionary=True)
        cur.execute(sql, params or ())
        rows = cur.fetchall()
        return rows or []

    def execute(self, sql: str, params: Optional[Tuple[Any, ...]] = None) -> int:
        cur = self._conn.cursor()
        cur.execute(sql, params or ())
        return cur.rowcount

    def commit(self) -> None:
        self._conn.commit()
        try:
            self._conn.close()
        except Exception:
            pass

    def rollback(self) -> None:
        self._conn.rollback()
        try:
            self._conn.close()
        except Exception:
            pass


# =============================================================================
# Domain DTO
# =============================================================================

@dataclass(frozen=True)
class Scope:
    chat_id: int
    owner_user_login: str
    owner_agent_id: str  # bot_id

@dataclass
class TurnMessage:
    turn_id: str
    scope: Scope
    seq: int
    role: str  # "user" / "assistant"
    content: str
    timestamp_utc: datetime

@dataclass
class ExtractedMemory:
    """
    Wynik ekstrakcji z jednego "center" turnu (rola dowolna).
    """
    action: str  # "create" | "update" | "revoke" | "supersede" | "noop"
    kind: str    # np. "fact", "preference", "task", "profile", ...
    topic: str   # np. "work", "devops", "marketing", ...
    title: str
    body: str
    keywords: List[str]
    importance: int  # 1..5
    confidence: float  # 0..1
    dedupe_key: str   # klucz deduplikacji (stabilny)
    target_hint: Optional[Dict[str, Any]] = None  # np. {"dedupe_key": "..."} albo {"card_id": "..."}
    supersedes_dedupe_key: Optional[str] = None

@dataclass
class MemoryCard:
    id: int
    scope: Scope
    kind: str
    topic: str
    summary: str
    facts_json: str
    keywords_json: str
    score: float
    trust_level: int
    dedupe_key: str
    version: int
    status: str
    created_at: datetime
    updated_at: datetime
    created_from_turn_id: str
    revoked_by_turn_id: Optional[str]

# =============================================================================
# Repo: Messages (stare źródło) + migracja do turn_messages_v2
# =============================================================================

class MessagesRepoV2:
    """
    Repo dla starej tabeli Messages, używanej jako źródło prawdy w runtime.
    Tu robimy tylko claim + mark_processed/mark_error dla migracji.
    """
    def __init__(self, db: DB):
        self.db = db

    def claim_new(
        self,
        *,
        limit: int,
        processing_token: str,
        max_age_seconds: int = 900,
    ) -> List[Dict[str, Any]]:
        """
        Claimuje rekordy Messages.ltm_status='new' i ustawia 'processing'.
        Zwraca listę dictów z danymi (id, user_name, content, timestamp).
        """
        now = utc_now()

        with self.db.transaction() as tx:
            # odzysk zombie processing
            tx.execute(
                f"""
                UPDATE {T_MESSAGES}
                SET ltm_status='new', ltm_processing_token=NULL, ltm_processing_at=NULL
                WHERE ltm_status='processing'
                  AND ltm_processing_at IS NOT NULL
                  AND ltm_processing_at < (UTC_TIMESTAMP() - INTERVAL %s SECOND)
                """,
                (int(max_age_seconds),),
            )

            rows = tx.query(
                f"""
                SELECT id, user_name, content, timestamp
                FROM {T_MESSAGES}
                WHERE ltm_status='new'
                ORDER BY timestamp ASC, id ASC
                LIMIT %s
                FOR UPDATE
                """,
                (int(limit),),
            )
            if not rows:
                return []

            ids = [int(r["id"]) for r in rows]
            placeholders = ",".join(["%s"] * len(ids))

            tx.execute(
                f"""
                UPDATE {T_MESSAGES}
                SET ltm_status='processing', ltm_processing_token=%s, ltm_processing_at=%s
                WHERE id IN ({placeholders})
                """,
                tuple([processing_token, now] + ids),
            )

            return rows

    def mark_processed(self, *, msg_id: int) -> None:
        self.db.execute(
            f"""
            UPDATE {T_MESSAGES}
            SET ltm_status='processed', ltm_processed_at=UTC_TIMESTAMP(6), ltm_error=NULL
            WHERE id=%s
            """,
            (int(msg_id),),
        )

    def mark_error(self, *, msg_id: int, error: str) -> None:
        self.db.execute(
            f"""
            UPDATE {T_MESSAGES}
            SET ltm_status='error', ltm_processed_at=UTC_TIMESTAMP(6), ltm_error=%s
            WHERE id=%s
            """,
            ((error or "")[:255], int(msg_id)),
        )


class MessagesToTurnsMigrator:
    """
    Migrator/ingester:
    - bierze Messages (ltm_status='new')
    - przerzuca do turn_messages_v2 (event store)
    - oznacza Messages jako processed/error
    """
    def __init__(
        self,
        *,
        db: DB,
        scope: Scope,
        logger: Optional[logging.Logger] = None,
        bots: Optional[Iterable[str]] = None,
        role_mode: str = "per_bot",
    ):

        self.db = db
        self.scope = scope

        self.bots = set(bots) if bots else {"aifa", "gerina", "pionier"}
        self.role_mode = (role_mode or "per_bot").strip().lower()
        if self.role_mode not in ("per_bot", "global"):
            self.role_mode = "per_bot"


        self.log = logger or logging.getLogger("memoria_v2.migrator")
        self.msg_repo = MessagesRepoV2(db)
        self.turns_repo = TurnMessagesRepo(db)

    def _role_from_user_name(self, user_name: str) -> str:
        """
        Odtwarzanie roli z Messages.user_name (bo w Messages nie ma roli).

        Tryby:
        - per_bot (domyślny, zgodny z Twoją appką):
            assistant  -> nick == owner_agent_id (czyli “ten bot” mówi jako assistant)
            user       -> każdy inny (człowiek + inne boty)
        - global:
            assistant  -> nick należy do self.bots
            user       -> reszta
        """
        nick = (user_name or "").strip()

        if self.role_mode == "global":
            return "assistant" if nick in self.bots else "user"

        # per_bot
        return "assistant" if nick == self.scope.owner_agent_id else "user"


    def run_once(self, *, processing_token: str, limit: int = 50) -> Dict[str, Any]:
        rows = self.msg_repo.claim_new(limit=limit, processing_token=processing_token)
        if not rows:
            return {"status": "idle", "claimed": 0}

        moved = 0
        err = 0

        for r in rows:
            msg_id = int(r["id"])
            try:
                turn_id = f"msg:{msg_id}"  # stabilny, deterministyczny
                role = self._role_from_user_name(str(r.get("user_name") or ""))
                content = str(r.get("content") or "")
                ts = r.get("timestamp")
                timestamp_utc = ts if isinstance(ts, datetime) else utc_now()

                # append do event store (wyliczy seq per scope)
                _ = self.turns_repo.append_turn(
                    scope=self.scope,
                    turn_id=turn_id,
                    role=role,
                    content=content,
                    timestamp_utc=timestamp_utc,
                )

                self.msg_repo.mark_processed(msg_id=msg_id)
                moved += 1

            except Exception as e:
                err += 1
                self.log.exception("migrate msg_id=%s failed", msg_id)
                self.msg_repo.mark_error(msg_id=msg_id, error=str(e))

        return {"status": "done", "claimed": len(rows), "moved": moved, "error": err}



# =============================================================================
# Repo: turn_messages (event store)
# =============================================================================

class TurnMessagesRepo:
    def __init__(self, db: DB):
        self.db = db

    def append_turn(
        self,
        *,
        scope: Scope,
        turn_id: str,
        role: str,
        content: str,
        timestamp_utc: Optional[datetime] = None,
    ) -> int:
        """
        Wstawia nowy turn i wylicza seq w transakcji per scope.chat_id+user+agent.
        Zwraca seq.
        """
        ts = timestamp_utc or utc_now()
        content_norm = normalize_whitespace(content)
        content_hash = sha1_hex(content_norm)


        with self.db.transaction() as tx:
            # Uwaga: FOR UPDATE działa tylko sensownie jeśli to jest transakcja na jednym połączeniu.
            row = tx.query(
                f"""
                SELECT COALESCE(MAX(seq), 0) AS max_seq
                FROM {T_TURNS}
                WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
                FOR UPDATE
                """,
                (scope.chat_id, scope.owner_user_login, scope.owner_agent_id),
            )
            max_seq = int(row[0]["max_seq"]) if row else 0
            next_seq = max_seq + 1

            tx.execute(
                f"""
                INSERT INTO {T_TURNS}
                    (turn_id, chat_id, owner_user_login, owner_agent_id, seq, role, content, content_hash, timestamp_utc)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                    role=VALUES(role),
                    content=VALUES(content),
                    content_hash=VALUES(content_hash),
                    timestamp_utc=VALUES(timestamp_utc)
                """,
                (turn_id, scope.chat_id, scope.owner_user_login, scope.owner_agent_id, next_seq, role, content_norm, content_hash, ts),
            )
            row2 = tx.query(
                f"""
                SELECT seq
                FROM {T_TURNS}
                WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s AND turn_id=%s
                LIMIT 1
                """,
                (scope.chat_id, scope.owner_user_login, scope.owner_agent_id, turn_id),
            )

            if row2:
                return int(row2[0]["seq"])
            return next_seq


    def fetch_window(self, *, scope: Scope, center_seq: int, prev_n: int = 3, next_n: int = 3) -> List[TurnMessage]:
        lo = center_seq - prev_n
        hi = center_seq + next_n
        rows = self.db.query(
            f"""
            SELECT turn_id, chat_id, owner_user_login, owner_agent_id, seq, role, content, timestamp_utc
            FROM {T_TURNS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
              AND seq BETWEEN %s AND %s
            ORDER BY seq ASC
            """,
            (scope.chat_id, scope.owner_user_login, scope.owner_agent_id, lo, hi),
        )
        out: List[TurnMessage] = []
        for r in rows:
            out.append(
                TurnMessage(
                    turn_id=str(r["turn_id"]),
                    scope=scope,
                    seq=int(r["seq"]),
                    role=str(r["role"]),
                    content=str(r["content"] or ""),
                    timestamp_utc=r["timestamp_utc"] if isinstance(r["timestamp_utc"], datetime) else utc_now(),
                )
            )
        return out

    def claim_batch(
        self,
        *,
        scope: Scope,
        limit: int = 10,
        processing_token: str,
        max_age_seconds: int = 900,
    ) -> List[TurnMessage]:
        """
        Prosta kolejka robocza na {T_TURNS}:
          - bierzemy turny o ltm_status='new'
          - ustawiamy ltm_status='processing' + token + ltm_processing_at
          - zwracamy claimed
        Zakładamy kolumny:
          ltm_status, ltm_processing_token, ltm_processing_at, ltm_processed_at, ltm_error
        """
        now = utc_now()

        with self.db.transaction() as tx:
            # 1) odzysk "zombie" processing (opcjonalnie): stare processing wracają na new
            tx.execute(
                f"""
                UPDATE {T_TURNS}
                SET ltm_status='new', ltm_processing_token=NULL, ltm_processing_at=NULL
                WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
                  AND ltm_status='processing'
                  AND ltm_processing_at IS NOT NULL
                  AND ltm_processing_at < (UTC_TIMESTAMP() - INTERVAL %s SECOND)
                """,
                (scope.chat_id, scope.owner_user_login, scope.owner_agent_id, max_age_seconds),
            )

            # 2) wybór do claim
            rows = tx.query(
                f"""
                SELECT turn_id, seq, role, content, timestamp_utc
                FROM {T_TURNS}
                WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
                  AND ltm_status='new'
                ORDER BY seq ASC
                LIMIT %s
                FOR UPDATE
                """,
                (scope.chat_id, scope.owner_user_login, scope.owner_agent_id, limit),
            )
            turn_ids = [str(r["turn_id"]) for r in rows]
            if not turn_ids:
                return []

            # 3) aktualizacja claim
            # (IN ...) — składamy placeholders
            placeholders = ",".join(["%s"] * len(turn_ids))
            tx.execute(
                f"""
                UPDATE {T_TURNS}
                SET ltm_status='processing', ltm_processing_token=%s, ltm_processing_at=%s
                WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
                  AND turn_id IN ({placeholders})
                """,
                tuple([processing_token, now, scope.chat_id, scope.owner_user_login, scope.owner_agent_id] + turn_ids),
            )

            out: List[TurnMessage] = []
            for r in rows:
                out.append(
                    TurnMessage(
                        turn_id=str(r["turn_id"]),
                        scope=scope,
                        seq=int(r["seq"]),
                        role=str(r["role"]),
                        content=str(r["content"] or ""),
                        timestamp_utc=r["timestamp_utc"] if isinstance(r["timestamp_utc"], datetime) else utc_now(),
                    )
                )
            return out

    def mark_processed(self, *, scope: Scope, turn_id: str, status: str, error: Optional[str] = None) -> None:
        """
        status: 'processed' | 'skipped' | 'error'
        """
        now = utc_now()
        self.db.execute(
            f"""
            UPDATE {T_TURNS}
            SET ltm_status=%s, ltm_processed_at=%s, ltm_error=%s
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
              AND turn_id=%s
            """,
            (status, now, error, scope.chat_id, scope.owner_user_login, scope.owner_agent_id, turn_id),
        )


# =============================================================================
# Repo: memory_cards + sources + links + selections
# =============================================================================

class MemoryCardsRepo:
    def __init__(self, db: DB):
        self.db = db
    
    def find_by_id(self, *, scope: Scope, card_id: int) -> Optional[MemoryCard]:
        rows = self.db.query(
            f"""
            SELECT *
            FROM {T_CARDS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s AND id=%s
            LIMIT 1
            """,
            (scope.chat_id, scope.owner_user_login, scope.owner_agent_id, int(card_id)),
        )
        return self._row_to_card(scope, rows[0]) if rows else None


    def find_by_dedupe_key(self, *, scope: Scope, dedupe_key: str) -> Optional[MemoryCard]:
        rows = self.db.query(
            f"""
            SELECT *
            FROM {T_CARDS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s AND dedupe_key=%s
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            (scope.chat_id, scope.owner_user_login, scope.owner_agent_id, dedupe_key),
        )
        return self._row_to_card(scope, rows[0]) if rows else None

    def search_candidates(
        self,
        *,
        scope: Scope,
        kind: str,
        topic: str,
        keywords: List[str],
        limit: int = 10,
    ) -> List[MemoryCard]:
        """
        Prosty matcher: kind+topic + overlap keywords (JSON_CONTAINS jeśli masz MySQL 5.7+/8.0).
        Jeśli nie masz JSON, możesz przejść na LIKE (gorsze).
        """
        keywords = [k.lower() for k in keywords if k]
        if not keywords:
            rows = self.db.query(
                f"""
                SELECT *
                FROM {T_CARDS}
                WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
                  AND status='active'
                  AND kind=%s AND topic=%s
                ORDER BY score DESC, updated_at DESC
                LIMIT %s
                """,
                (scope.chat_id, scope.owner_user_login, scope.owner_agent_id, kind, topic, limit),
            )
            return [self._row_to_card(scope, r) for r in rows]

        # JSON-first: próbujemy JSON_OVERLAPS (MySQL 8.0.17+).
        # Fallback: LIKE tylko jeśli DB nie wspiera JSON_OVERLAPS lub kolumna nie jest JSON.
        try:
            rows = self.db.query(
                f"""
                SELECT *
                FROM {T_CARDS}
                WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
                AND status='active'
                AND kind=%s AND topic=%s
                AND JSON_OVERLAPS(keywords_json, CAST(%s AS JSON))
                ORDER BY score DESC, updated_at DESC
                LIMIT %s
                """,
                (
                    scope.chat_id, scope.owner_user_login, scope.owner_agent_id,
                    kind, topic,
                    safe_json_dumps(keywords),
                    limit
                ),
            )
            return [self._row_to_card(scope, r) for r in rows]
        except Exception:
            # Fallback LIKE (debug/kompatybilność)
            like_clauses = " OR ".join(["keywords_json LIKE %s"] * len(keywords))
            like_params = tuple([f'%"{k}"%' for k in keywords])
            rows = self.db.query(
                f"""
                SELECT *
                FROM {T_CARDS}
                WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
                AND status='active'
                AND kind=%s AND topic=%s
                AND ({like_clauses})
                ORDER BY score DESC, updated_at DESC
                LIMIT %s
                """,
                tuple([scope.chat_id, scope.owner_user_login, scope.owner_agent_id, kind, topic] + list(like_params) + [limit]),
            )
            return [self._row_to_card(scope, r) for r in rows]


    def upsert_active(
        self,
        *,
        scope: Scope,
        kind: str,
        topic: str,
        title: str,
        body: str,
        keywords: List[str],
        importance: int,
        confidence: float,
        dedupe_key: str,
        created_from_turn_id: str,
    ) -> Tuple[int, int]:

        keywords_norm = sorted(list({k.lower().strip() for k in keywords if k.strip()}))
        keywords_json = safe_json_dumps(keywords_norm)

        summary = normalize_whitespace(f"{title}\n{body}".strip())
        facts_json = safe_json_dumps({"title": title, "body": body})

        self.db.execute(
            f"""
            INSERT INTO {T_CARDS}
            (chat_id, kind, topic, owner_user_login, owner_agent_id,
            visibility, audience_json,
            score, trust_level, status,
            ttl_days, expires_at,
            summary, facts_json, keywords_json,
            dedupe_key, version,
            replaces_card_id,
            usage_count_7d, last_used_at,
            created_from_turn_id, revoked_by_turn_id,
            created_at, updated_at)
            VALUES (%s,%s,%s,%s,%s,'private',NULL,%s,%s,'active',NULL,NULL,%s,%s,%s,%s,1,NULL,0,NULL,%s,NULL,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))
            ON DUPLICATE KEY UPDATE
            kind=VALUES(kind),
            topic=VALUES(topic),
            summary=VALUES(summary),
            facts_json=VALUES(facts_json),
            keywords_json=VALUES(keywords_json),
            score=VALUES(score),
            trust_level=VALUES(trust_level),
            status='active',
            revoked_at=NULL,
            revoked_reason=NULL,
            revoked_by_turn_id=NULL,
            superseded_by_card_id=NULL,
            version=version+1,
            updated_at=UTC_TIMESTAMP(6)

            """,
            (
                scope.chat_id, kind, topic, scope.owner_user_login, scope.owner_agent_id,
                float(importance),
                clamp_int(int(round(float(confidence) * 5.0)), 1, 5),

                summary, facts_json, keywords_json,
                dedupe_key,
                created_from_turn_id
            ),
        )

        row = self.db.query(
            f"""
            SELECT id, version
            FROM {T_CARDS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s AND dedupe_key=%s
            LIMIT 1
            """,
            (scope.chat_id, scope.owner_user_login, scope.owner_agent_id, dedupe_key),
        )
        if not row:
            raise DBError(f"Upsert failed: cannot read back {T_CARDS} row.")
        return int(row[0]["id"]), int(row[0]["version"])


    def revoke(
        self,
        *,
        scope: Scope,
        card_id: int,
        revoked_by_turn_id: str,
        new_status: str = "revoked",  # lub "superseded"
        revoked_reason: Optional[str] = None,
    ) -> int:
        reason = (revoked_reason or "").strip()
        if reason:
            reason = reason[:255]

        return self.db.execute(
            f"""
            UPDATE {T_CARDS}
            SET status=%s,
                revoked_at=UTC_TIMESTAMP(6),
                revoked_reason=%s,
                revoked_by_turn_id=%s,
                version=version+1,
                updated_at=UTC_TIMESTAMP(6)
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
            AND id=%s
            AND status='active'
            """,
            (new_status, reason or None, revoked_by_turn_id, scope.chat_id, scope.owner_user_login, scope.owner_agent_id, int(card_id)),
        )


    def mark_conflicted(
        self,
        *,
        scope: Scope,
        card_id: int,
        conflict_reason: Optional[str] = None,
    ) -> int:
        reason = (conflict_reason or "").strip()
        if reason:
            reason = reason[:255]

        return self.db.execute(
            f"""
            UPDATE {T_CARDS}
            SET status='conflicted',
                revoked_at=UTC_TIMESTAMP(6),
                revoked_reason=%s,
                version=version+1,
                updated_at=UTC_TIMESTAMP(6)
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
            AND id=%s
            AND status='active'
            """,
            (reason or None, scope.chat_id, scope.owner_user_login, scope.owner_agent_id, int(card_id)),
        )



    def _row_to_card(self, scope: Scope, r: Dict[str, Any]) -> MemoryCard:
        return MemoryCard(
            id=int(r["id"]),
            scope=scope,
            kind=str(r.get("kind") or ""),
            topic=str(r.get("topic") or ""),
            summary=str(r.get("summary") or ""),
            facts_json=safe_json_dumps(r.get("facts_json")) if isinstance(r.get("facts_json"), (dict, list)) else (r.get("facts_json") or "{}"),
            keywords_json=safe_json_dumps(r.get("keywords_json")) if isinstance(r.get("keywords_json"), (dict, list)) else (r.get("keywords_json") or "[]"),
            score=float(r.get("score") or 0.0),
            trust_level=int(r.get("trust_level") or 1),
            dedupe_key=str(r.get("dedupe_key") or ""),
            version=int(r.get("version") or 1),
            status=str(r.get("status") or "active"),
            created_at=r["created_at"] if isinstance(r.get("created_at"), datetime) else utc_now(),
            updated_at=r["updated_at"] if isinstance(r.get("updated_at"), datetime) else utc_now(),
            created_from_turn_id=str(r.get("created_from_turn_id") or ""),
            revoked_by_turn_id=str(r["revoked_by_turn_id"]) if r.get("revoked_by_turn_id") else None,
        )


class MemorySourcesRepo:

    def __init__(self, db: DB):
        self.db = db

    def add_sources(
        self,
        *,
        scope: Scope,
        card_id: int,
        window: List[TurnMessage],
        center_seq: int,
    ) -> None:
        for tm in window:
            offset = int(tm.seq - center_seq)
            snippet = (tm.content or "")[:800]

            # v2: dedup po UNIQUE(memory_card_id, turn_id, seq, offset)
            self.db.execute(
                f"""
                INSERT INTO {T_SOURCES}
                (memory_card_id, chat_id, owner_user_login, owner_agent_id,
                 turn_id, seq, offset, role, snippet, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(6))
                ON DUPLICATE KEY UPDATE
                    snippet=VALUES(snippet),
                    role=VALUES(role)
                """,
                (
                    int(card_id),
                    scope.chat_id, scope.owner_user_login, scope.owner_agent_id,
                    tm.turn_id, tm.seq, offset, tm.role, snippet,
                ),
            )



class MemoryLinksRepo:

    def __init__(self, db: DB):
        self.db = db


    def link(self, *, scope: Scope, parent_card_id: int, child_card_id: int, link_type: str) -> None:
        self.db.execute(
            f"""
            INSERT INTO {T_LINKS}
            (chat_id, owner_user_login, owner_agent_id,
            parent_card_id, child_card_id, link_type, created_at, revoked_at)
            VALUES (%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(6),NULL)
            """,
            (scope.chat_id, scope.owner_user_login, scope.owner_agent_id, int(parent_card_id), int(child_card_id), link_type),
        )


    def revoke_by_parent(self, *, scope: Scope, parent_card_id: int) -> int:
        return self.db.execute(
            f"""
            UPDATE {T_LINKS}
            SET revoked_at=UTC_TIMESTAMP(6)
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
            AND parent_card_id=%s
            AND revoked_at IS NULL
            """,
            (scope.chat_id, scope.owner_user_login, scope.owner_agent_id, int(parent_card_id)),
        )

    
    def list_children(
            self,
            *,
            scope: Scope,
            parent_card_id: int,
            link_types: Optional[List[str]] = None,
            only_active: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Zwraca listę: child_card_id + link_type (i ewentualnie link_id).
        """
        params: List[Any] = [scope.chat_id, scope.owner_user_login, scope.owner_agent_id, int(parent_card_id)]
        type_sql = ""
        if link_types:
            placeholders = ",".join(["%s"] * len(link_types))
            type_sql = f" AND link_type IN ({placeholders}) "
            params.extend(link_types)

        active_sql = " AND revoked_at IS NULL " if only_active else ""

        rows = self.db.query(
            f"""
            SELECT id, child_card_id, link_type
            FROM {T_LINKS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
            AND parent_card_id=%s
            {type_sql}
            {active_sql}
            """,
            tuple(params),
        )
        return rows or []


    def revoke_links_by_parent_and_types(
        self,
        *,
        scope: Scope,
        parent_card_id: int,
        link_types: List[str],
    ) -> int:
        """
        Ustaw revoked_at dla wybranych typów linków parent->child.
        """
        if not link_types:
            return 0
        now = utc_now()
        placeholders = ",".join(["%s"] * len(link_types))
        return self.db.execute(
            f"""
            UPDATE {T_LINKS}
            SET revoked_at=%s
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
            AND parent_card_id=%s
            AND revoked_at IS NULL
            AND link_type IN ({placeholders})
            """,
            tuple([now, scope.chat_id, scope.owner_user_login, scope.owner_agent_id, int(parent_card_id)] + link_types),
        )



class MemorySelectionsRepo:
    def __init__(self, db: DB):
        self.db = db

    def create_selection(
        self,
        *,
        scope: Scope,
        center_turn_id: str,
        center_seq: int,
        selector_version: str,
        budget_chars: int,
        query_keywords: List[str],
        notes: str = "",
    ) -> int:
        with self.db.transaction() as tx:
            tx.execute(
                f"""
                INSERT INTO {T_SELECTIONS}
                (chat_id, owner_user_login, owner_agent_id,
                center_turn_id, center_seq,
                budget_chars, used_chars,
                selector_version, query_keywords_json, cascade_json,
                selected_at)
                VALUES (%s,%s,%s,%s,%s,%s,0,%s,%s,NULL,UTC_TIMESTAMP(6))
                """,
                (
                    scope.chat_id, scope.owner_user_login, scope.owner_agent_id,
                    center_turn_id, int(center_seq),
                    int(budget_chars),
                    selector_version,
                    safe_json_dumps(query_keywords),
                ),
            )
            row = tx.query("SELECT LAST_INSERT_ID() AS id")
            return int(row[0]["id"])


    def add_item(
        self,
        *,
        selection_id: int,
        card_id: int,
        rank: int,
        score: float,
        char_cost: int,
        reason_json: Optional[Dict[str, Any]] = None,
        card_version_at_selection: Optional[int] = None,
    ) -> None:
        payload = reason_json.copy() if isinstance(reason_json, dict) else {}

        self.db.execute(
            f"""
            INSERT INTO {T_SELECTION_ITEMS}
            (selection_id, memory_card_id, card_version_at_selection,
             rank_pos, rank_score, reason_json, char_cost)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                int(selection_id),
                int(card_id),
                int(card_version_at_selection or 0),
                int(rank),
                float(score),
                safe_json_dumps(payload) if payload else None,
                int(char_cost),
            ),
        )





# =============================================================================
# LLM Extractor interface
# =============================================================================

class LLMExtractor:
    """
    Interfejs ekstraktora. Zwraca 0..N obiektów ExtractedMemory dla center turnu.
    """
    def extract(self, *, scope: Scope, window: List[TurnMessage], center: TurnMessage) -> List[ExtractedMemory]:
        raise NotImplementedError

class LLMClient:
    """
    Minimalny interfejs klienta LLM.
    Implementujesz to u siebie adapterem pod Mistral/Ollama.
    """
    def chat(self, *, messages: List[Dict[str, str]], max_tokens: int = 900, temperature: float = 0.2) -> str:
        raise NotImplementedError

class MistralLLMAdapter(LLMClient):
    """
    Adapter: dopasowuje wrapper_mistral.MistralChatManager do interfejsu LLMClient.
    """
    def __init__(self, mgr: MistralChatManager):
        self.mgr = mgr

    def chat(self, *, messages: List[Dict[str, str]], max_tokens: int = 900, temperature: float = 0.2) -> str:
        # UWAGA: dopasuj nazwę metody jeśli w Twoim wrapperze jest np. ask()/complete()/chat()
        return self.mgr._post(messages=messages, max_tokens=max_tokens, temperature=temperature)


class SimpleHeuristicExtractor(LLMExtractor):

    def extract(self, *, scope: Scope, window: List[TurnMessage], center: TurnMessage) -> List[ExtractedMemory]:
        text = (center.content or "").strip()
        if not text:
            return []

        # Minimalny heurystyczny przykład:
        # - jeśli zawiera "preferuję" => preference
        # - jeśli zawiera "mam" + rzecz => fact/profile
        low = text.lower()
        items: List[ExtractedMemory] = []

        if "preferuję" in low or "wolę" in low:
            kws = ["preference"]
            dedupe_key = sha1_hex(f"pref|{normalize_whitespace(low)[:80]}")
            items.append(
                ExtractedMemory(
                    action="create",
                    kind="preference",
                    topic="general",
                    title="Preferencja użytkownika",
                    body=normalize_whitespace(text),
                    keywords=kws,
                    importance=2,
                    confidence=0.55,
                    dedupe_key=dedupe_key,
                )
            )
            return items

        if low.startswith("mam ") or " pracuję " in low or " jestem " in low:
            kws = ["profile"]
            dedupe_key = sha1_hex(f"profile|{normalize_whitespace(low)[:80]}")
            items.append(
                ExtractedMemory(
                    action="create",
                    kind="profile",
                    topic="general",
                    title="Informacja o użytkowniku",
                    body=normalize_whitespace(text),
                    keywords=kws,
                    importance=2,
                    confidence=0.5,
                    dedupe_key=dedupe_key,
                )
            )
            return items

        return []

class LLMJsonExtractor(LLMExtractor):

    def __init__(
        self,
        *,
        llm: LLMClient,
        logger: Optional[logging.Logger] = None,
        max_retries: int = 3,
        base_delay: float = 0.8,
        max_delay: float = 6.0,
    ):
        self.llm = llm
        self.log = logger or logging.getLogger("memoria_v2")
        self.max_retries = int(max_retries)
        self.base_delay = float(base_delay)
        self.max_delay = float(max_delay)

    def extract(self, *, scope: Scope, window: List[TurnMessage], center: TurnMessage) -> List[ExtractedMemory]:
        sys_prompt = (
            "Jesteś silnikiem ekstrakcji pamięci długoterminowej (LTM). "
            "Na podstawie okna rozmowy (-3..+3) wygeneruj 0..3 wpisów pamięci.\n\n"
            "ZWRÓĆ WYŁĄCZNIE JSON (bez markdown), w formacie:\n"
            "{\n"
            '  "items": [\n'
            "    {\n"
            '      "action": "create|update|revoke|supersede|noop",\n'
            '      "kind": "rule|policy|decision|task|fact|preference|profile|note",\n'
            '      "topic": "general|work|devops|marketing|...",\n'
            '      "title": "krótki tytuł",\n'
            '      "body": "konkretna treść",\n'
            '      "keywords": ["tag1","tag2"],\n'
            '      "importance": 1-5,\n'
            '      "confidence": 0.0-1.0,\n'
            '      "dedupe_key": "stabilny_klucz",\n'
            '      "target_hint": {"card_id": 123} lub {"dedupe_key":"..."} (opcjonalne),\n'
            '      "supersedes_dedupe_key": "..." (opcjonalne)\n'
            "    }\n"
            "  ]\n"
            "}\n\n"
            "Zasady bezpieczeństwa:\n"
            "- revoke/supersede tylko jeśli użytkownik wyraźnie odwołuje/zmienia wcześniejsze ustalenie.\n"
            "- dedupe_key ma być stabilny dla tej samej informacji (np. sha1(kind|topic|title)).\n"
            "- jeśli podajesz target_hint.card_id, to ma to być LICZBA (BIGINT), nie string.\n"
        )

        convo_lines = []
        for tm in window:
            marker = "U" if tm.role == "user" else "A"
            convo_lines.append(f"{marker}[{tm.seq}] {tm.content}")
        user_prompt = (
            f"scope: chat_id={scope.chat_id}, user={scope.owner_user_login}, agent={scope.owner_agent_id}\n"
            f"center_turn: {center.turn_id} seq={center.seq} role={center.role}\n\n"
            "WINDOW:\n" + "\n".join(convo_lines)
        )

        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
        ]

        last_err = None
        for attempt in range(self.max_retries + 1):
            try:
                raw = self.llm.chat(messages=messages, max_tokens=900, temperature=0.2)
                items = self._parse_items(raw)
                return [self._to_extracted(x) for x in items]
            except Exception as e:
                last_err = e
                if attempt >= self.max_retries:
                    break
                delay = min(self.max_delay, self.base_delay * (2 ** attempt))
                time.sleep(delay)

        self.log.warning("LLMJsonExtractor failed: %s", str(last_err))
        return []

    def _parse_items(self, raw: str) -> List[Dict[str, Any]]:
        s = (raw or "").strip()

        # 1) szybka próba: raw jako JSON
        try:
            obj = json.loads(s)
        except Exception:
            # 2) fallback: wytnij największy sensowny fragment JSON od pierwszego '{' do ostatniego '}'
            if "{" in s and "}" in s:
                cut = s[s.find("{"): s.rfind("}") + 1]
                obj = json.loads(cut)
            else:
                raise

        items = obj.get("items", [])
        if not isinstance(items, list):
            return []

        out: List[Dict[str, Any]] = []
        for it in items:
            if isinstance(it, dict):
                out.append(it)

        return out[:3]


    def _to_extracted(self, it: Dict[str, Any]) -> ExtractedMemory:
        action = str(it.get("action", "noop")).strip().lower()
        ALLOWED_ACTIONS = (
            "create",
            "update",
            "revoke",
            "supersede",
            "noop",
        )
        if action not in ALLOWED_ACTIONS:
            action = "noop"

        kind = str(it.get("kind", "note")).strip().lower()
        ALLOWED_KINDS = (
            "rule",
            "policy",
            "decision",
            "task",
            "fact",
            "preference",
            "profile",
            "note",
        )
        if kind not in ALLOWED_KINDS:
            kind = "note"


        topic = str(it.get("topic", "general")).strip().lower()

        title = normalize_whitespace(str(it.get("title", "")))[:180]
        body = normalize_whitespace(str(it.get("body", "")))

        keywords = it.get("keywords", []) or []
        if not isinstance(keywords, list):
            keywords = []
        keywords = [normalize_whitespace(str(k)).lower() for k in keywords if str(k).strip()]
        keywords = keywords[:20]

        importance = clamp_int(int(it.get("importance", 2) or 2), 1, 5)
        confidence = float(it.get("confidence", 0.5) or 0.5)
        confidence = max(0.0, min(1.0, confidence))

        dedupe_key = normalize_dedupe_key(str(it.get("dedupe_key", "")).strip())
        if not dedupe_key:
            dedupe_key = sha1_hex(f"{kind}|{topic}|{title}")

        target_hint = it.get("target_hint", None)
        if target_hint is not None and not isinstance(target_hint, dict):
            target_hint = None

        # v2: normalizacja target_hint.card_id -> int (BIGINT)
        if isinstance(target_hint, dict) and "card_id" in target_hint and target_hint["card_id"] is not None:
            try:
                # pozwalamy na "123" i 123, ale finalnie ma być int
                target_hint["card_id"] = int(target_hint["card_id"])
            except Exception:
                # jak model da śmieci, wywalamy card_id z hintu
                target_hint.pop("card_id", None)


        supersedes_dedupe_key = it.get("supersedes_dedupe_key", None)
        if supersedes_dedupe_key is not None:
            supersedes_dedupe_key = str(supersedes_dedupe_key).strip() or None

        return ExtractedMemory(
            action=action,
            kind=kind,
            topic=topic,
            title=title,
            body=body,
            keywords=keywords,
            importance=importance,
            confidence=confidence,
            dedupe_key=dedupe_key,
            target_hint=target_hint,
            supersedes_dedupe_key=supersedes_dedupe_key,
        )


# =============================================================================
# Selector (keywords-first) + budget + audit
# =============================================================================

@dataclass
class SelectedCard:
    card: MemoryCard
    score: float
    char_cost: int

class MemorySelector:

    def __init__(self, *, cards_repo: MemoryCardsRepo, selections_repo: MemorySelectionsRepo):
        self.cards_repo = cards_repo
        self.selections_repo = selections_repo
        self.selector_version = "memoria2.selector.v1"

    def select(
        self,
        *,
        scope: Scope,
        center_turn_id: str,
        center_seq: int,
        query_keywords: List[str],
        kind: Optional[str] = None,
        topic: Optional[str] = None,
        budget_chars: int = 1800,
        max_items: int = 8,
    ) -> List[SelectedCard]:
   

        # normalizacja + warianty (PL)
        expanded: List[str] = []
        for k in (query_keywords or []):
            if not k:
                continue
            expanded.extend(keyword_variants_pl(k))

        qk = []
        seen = set()
        for k in expanded:
            k = (k or "").strip().lower()
            if not k or len(k) < 2:
                continue
            if k in seen:
                continue
            seen.add(k)
            qk.append(k)


        # Zbieramy kandydatów: jeśli kind/topic nie podane, bierzemy kilka “koszyków”
        candidates: List[MemoryCard] = []

        if kind and topic:
            candidates = self.cards_repo.search_candidates(scope=scope, kind=kind, topic=topic, keywords=qk, limit=30)
        else:
            # bardzo prosty fallback: pobierz po overlap z każdym kind/topic? (tu: 1 zapytanie = LIKE po keywords)
            # przy braku wiedzy o strukturze kinds/topics — bierzemy top aktywne matchujące keywords
            if qk:
                # JSON-first: próbujemy JSON_OVERLAPS na keywords_json
                try:
                    rows = self.cards_repo.db.query(
                        f"""
                        SELECT *
                        FROM {T_CARDS}
                        WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
                        AND status='active'
                        AND JSON_OVERLAPS(keywords_json, CAST(%s AS JSON))
                        ORDER BY score DESC, updated_at DESC
                        LIMIT 50
                        """,
                        (scope.chat_id, scope.owner_user_login, scope.owner_agent_id, safe_json_dumps(qk)),
                    )
                except Exception:
                    # Fallback LIKE (tylko kompat)
                    like_clauses = " OR ".join(["keywords_json LIKE %s"] * len(qk))
                    like_params = tuple([f'%"{k}"%' for k in qk])
                    rows = self.cards_repo.db.query(
                        f"""
                        SELECT *
                        FROM {T_CARDS}
                        WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
                        AND status='active'
                        AND ({like_clauses})
                        ORDER BY score DESC, updated_at DESC
                        LIMIT 50
                        """,
                        tuple([scope.chat_id, scope.owner_user_login, scope.owner_agent_id] + list(like_params)),
                    )

                candidates = [self.cards_repo._row_to_card(scope, r) for r in rows]

            else:
                rows = self.cards_repo.db.query(
                    f"""
                    SELECT *
                    FROM {T_CARDS}
                    WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
                      AND status='active'
                    ORDER BY score DESC, updated_at DESC
                    LIMIT 30
                    """,
                    (scope.chat_id, scope.owner_user_login, scope.owner_agent_id),
                )
                candidates = [self.cards_repo._row_to_card(scope, r) for r in rows]

        # score
        selected: List[SelectedCard] = []
        for c in candidates:
            kws = safe_json_loads(c.keywords_json) or []
            kws = [str(x).lower() for x in kws]
            overlap = len(set(kws) & set(qk)) if qk else 0

            kind_l = (c.kind or "").lower().strip()
            kind_bonus = KIND_PRIORITY.get(kind_l, 0) / 100.0

            # v2: score + trust_level + overlap
            score = float(c.score) + (0.20 * float(c.trust_level)) + (0.35 * overlap) + kind_bonus

            # v2: koszt znaków = summary + overhead
            char_cost = len(c.summary or "") + 40

            selected.append(SelectedCard(card=c, score=score, char_cost=char_cost))


        selected.sort(key=lambda x: (x.score, x.card.updated_at), reverse=True)

        # budżet
        budget = clamp_int(int(budget_chars), 200, 20000)
        max_items = clamp_int(int(max_items), 1, 30)
        out: List[SelectedCard] = []
        used = 0
        for s in selected:
            if len(out) >= max_items:
                break
            if used + s.char_cost > budget:
                continue
            out.append(s)
            used += s.char_cost

        # audit
        sel_id = self.selections_repo.create_selection(
            scope=scope,
            center_turn_id=center_turn_id,
            center_seq=center_seq,
            selector_version=self.selector_version,
            budget_chars=budget,
            query_keywords=qk,
            notes=f"selected={len(out)}, used_chars={used}",
        )
        rank = 1
        for s in out:
            self.selections_repo.add_item(
                selection_id=int(sel_id),
                card_id=int(s.card.id),
                rank=rank,
                score=s.score,
                char_cost=s.char_cost,
                card_version_at_selection=int(s.card.version),
            )

            rank += 1

        return out


# =============================================================================
# Applier: create/update/revoke/supersede
# =============================================================================

class MemoryApplier:
    def __init__(
        self,
        *,
        cards_repo: MemoryCardsRepo,
        sources_repo: MemorySourcesRepo,
        links_repo: MemoryLinksRepo,
        logger: Optional[logging.Logger] = None,
    ):
        self.cards_repo = cards_repo
        self.sources_repo = sources_repo
        self.links_repo = links_repo
        self.log = logger or logging.getLogger("memoria_v2")

    def _find_best_rule_parent(self, *, scope: Scope, extracted: ExtractedMemory) -> Optional[MemoryCard]:
        """
        Heurystyka: jeśli powstaje decision/task, próbujemy znaleźć aktywną RULE/POLICY
        o podobnym topic i overlap keywords.
        """
        topic = extracted.topic or "general"
        keywords = extracted.keywords or []

        # 1) najpierw rule w tym samym topic
        cands = self.cards_repo.search_candidates(scope=scope, kind="rule", topic=topic, keywords=keywords, limit=3)
        if cands:
            return cands[0]

        # 2) potem policy w tym samym topic
        cands = self.cards_repo.search_candidates(scope=scope, kind="policy", topic=topic, keywords=keywords, limit=3)
        if cands:
            return cands[0]

        # 3) na końcu: rule/policy w general
        cands = self.cards_repo.search_candidates(scope=scope, kind="rule", topic="general", keywords=keywords, limit=3)
        if cands:
            return cands[0]
        cands = self.cards_repo.search_candidates(scope=scope, kind="policy", topic="general", keywords=keywords, limit=3)
        if cands:
            return cands[0]

        return None

    
    def apply(
        self,
        *,
        scope: Scope,
        extracted: ExtractedMemory,
        window: List[TurnMessage],
        center: TurnMessage,
    ) -> Dict[str, Any]:
        """
        Zwraca dict z wynikiem (status, card_id, details...).
        """
        action = (extracted.action or "noop").lower().strip()
        confidence = float(extracted.confidence or 0.0)

        # Bezpieczeństwo akcji:
        # - create/update: mogą być luźniejsze (bo dedupe nas chroni)
        # - revoke/supersede: muszą być twarde
        min_conf = 0.35 if action in ("create", "update") else 0.70 if action in ("revoke", "supersede") else 0.2

        if action == "noop" or confidence < min_conf:
            return {"status": "skipped", "reason": f"low_confidence<{min_conf}", "confidence": confidence}


        # helper: target resolution
        target_card: Optional[MemoryCard] = None

        # 1) jeśli mamy hint card_id
        if extracted.target_hint and extracted.target_hint.get("card_id"):
            try:
                target_card = self.cards_repo.find_by_id(scope=scope, card_id=int(extracted.target_hint["card_id"]))
            except Exception:
                target_card = None


        # 2) jeśli hint dedupe_key
        if not target_card and extracted.target_hint and extracted.target_hint.get("dedupe_key"):
            target_card = self.cards_repo.find_by_dedupe_key(scope=scope, dedupe_key=str(extracted.target_hint["dedupe_key"]))

        # 3) jeśli supersede wskazuje dedupe
        if not target_card and extracted.supersedes_dedupe_key:
            target_card = self.cards_repo.find_by_dedupe_key(scope=scope, dedupe_key=str(extracted.supersedes_dedupe_key))

        # 4) fallback: szukaj kandydatów po kind/topic/keywords
        if not target_card and action in ("update", "revoke", "supersede"):
            cands = self.cards_repo.search_candidates(
                scope=scope,
                kind=extracted.kind,
                topic=extracted.topic,
                keywords=extracted.keywords,
                limit=5,
            )
            target_card = cands[0] if cands else None

        # CREATE / UPDATE
        if action in ("create", "update"):
            # dedupe_key — jeśli pusty: wylicz stabilnie
            dedupe_key = extracted.dedupe_key.strip() if extracted.dedupe_key else ""
            if not dedupe_key:
                dedupe_key = sha1_hex(f"{extracted.kind}|{extracted.topic}|{normalize_whitespace(extracted.title)[:80]}|{normalize_whitespace(extracted.body)[:120]}")

            card_id, card_ver = self.cards_repo.upsert_active(
                scope=scope,
                kind=extracted.kind,
                topic=extracted.topic,
                title=normalize_whitespace(extracted.title)[:180],
                body=normalize_whitespace(extracted.body),
                keywords=extracted.keywords,
                importance=clamp_int(int(extracted.importance or 1), 1, 5),
                confidence=float(extracted.confidence or 0.0),
                dedupe_key=dedupe_key,
                created_from_turn_id=center.turn_id,
            )

            self.sources_repo.add_sources(scope=scope, card_id=int(card_id), window=window, center_seq=center.seq)


            # link (jeśli to jest update i mamy target => parent->child)
            if action == "update" and target_card:
                self.links_repo.link(scope=scope, parent_card_id=int(target_card.id), child_card_id=int(card_id), link_type="update")

            # Sprint 6: semantyczne linki dla pochodnych (decision/task) -> rule/policy
            try:
                k = (extracted.kind or "").lower().strip()
                if k in ("decision", "task"):
                    parent_rule = self._find_best_rule_parent(scope=scope, extracted=extracted)
                    if parent_rule:
                        # rule/policy -> decision/task
                        self.links_repo.link(
                            scope=scope,
                            parent_card_id=parent_rule.id,
                            child_card_id=card_id,
                            link_type=SEM_LINK_DERIVED,
                        )
                        self.links_repo.link(
                            scope=scope,
                            parent_card_id=parent_rule.id,
                            child_card_id=card_id,
                            link_type=SEM_LINK_SUPPORTS,
                        )
            except Exception:
                # linkowanie nie może psuć głównego flow
                pass

            return {"status": "ok", "action": action, "card_id": card_id, "card_version": card_ver}

        # REVOKE
        if action == "revoke":
            if not target_card:
                return {"status": "skipped", "reason": "no_target"}
            
            changed = self.cards_repo.revoke(
                scope=scope,
                card_id=target_card.id,
                revoked_by_turn_id=center.turn_id,
                new_status="revoked",
                revoked_reason=extracted.body,
            )

            if changed:
                # Najpierw zwykłe revoke linków "update/supersede" etc. (jak było)
                self.links_repo.revoke_by_parent(scope=scope, parent_card_id=target_card.id)

                # Sprint 6: jeśli to RULE/POLICY — oznacz pochodne jako conflicted
                if is_rule_kind(target_card.kind):
                    children = self.links_repo.list_children(
                        scope=scope,
                        parent_card_id=target_card.id,
                        link_types=[SEM_LINK_DERIVED, SEM_LINK_SUPPORTS],
                        only_active=True,
                    )
                    # konfliktujemy aktywne dzieci
                    for ch in children:
                        

                        # child_id = str(ch.get("child_card_id"))
                        child_id = int(ch.get("child_card_id"))
                        self.cards_repo.mark_conflicted(
                            scope=scope,
                            card_id=child_id,
                            conflict_reason=f"Derived from revoked {target_card.kind}: {extracted.body[:180] if extracted.body else ''}",
                        )
                    # zamykamy semantyczne linki
                    self.links_repo.revoke_links_by_parent_and_types(
                        scope=scope,
                        parent_card_id=target_card.id,
                        link_types=[SEM_LINK_DERIVED, SEM_LINK_SUPPORTS],
                    )

            return {
                "status": "ok",
                "action": "revoke",
                "target_card_id": target_card.id,
                "changed": changed,
                "reason": extracted.body[:180] if extracted.body else None,
            }


        # SUPERSEDE
        if action == "supersede":
            if not target_card:
                return {"status": "skipped", "reason": "no_target"}

            # Supersede = (1) tworzę NOWĄ kartę (active) (2) oznaczam starą jako superseded (3) linkuję replace
            # Robimy to w transakcji, żeby nie było połówek.
            
            dedupe_key_new = normalize_dedupe_key(extracted.dedupe_key.strip() if extracted.dedupe_key else "")
            if not dedupe_key_new:
                dedupe_key_new = sha1_hex(
                    f"{extracted.kind}|{extracted.topic}|{normalize_whitespace(extracted.title)[:80]}|{normalize_whitespace(extracted.body)[:120]}"
                )

            try:
                with self.cards_repo.db.transaction() as tx:
                    # upsert nowej karty
                    tmp_cards = MemoryCardsRepo(tx)
                    tmp_sources = MemorySourcesRepo(tx)
                    tmp_links = MemoryLinksRepo(tx)

                    new_card_id, new_ver = tmp_cards.upsert_active(
                        scope=scope,
                        kind=extracted.kind,
                        topic=extracted.topic,
                        title=normalize_whitespace(extracted.title)[:180],
                        body=normalize_whitespace(extracted.body),
                        keywords=extracted.keywords,
                        importance=clamp_int(int(extracted.importance or 1), 1, 5),
                        confidence=float(extracted.confidence or 0.0),
                        dedupe_key=dedupe_key_new,
                        created_from_turn_id=center.turn_id,
                    )


                    # sources dla nowej karty
                    tmp_sources.add_sources(scope=scope, card_id=new_card_id, window=window, center_seq=center.seq)

                    tx.execute(
                        f"""
                        UPDATE {T_CARDS}
                        SET replaces_card_id=%s, updated_at=UTC_TIMESTAMP(6), version=version+1
                        WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s AND id=%s
                        """,
                        (int(target_card.id), scope.chat_id, scope.owner_user_login, scope.owner_agent_id, int(new_card_id)),
                    )

                    # oznaczenie starej jako superseded
                    tx.execute(
                        f"""
                        UPDATE {T_CARDS}
                        SET status='superseded',
                            revoked_at=UTC_TIMESTAMP(6),
                            revoked_reason=%s,
                            revoked_by_turn_id=%s,
                            superseded_by_card_id=%s,
                            version=version+1,
                            updated_at=UTC_TIMESTAMP(6)
                        WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
                        AND id=%s
                        AND status='active'
                        """,
                        (
                            (extracted.body or "")[:255] if extracted.body else None,
                            center.turn_id,
                            int(new_card_id),
                            scope.chat_id, scope.owner_user_login, scope.owner_agent_id,
                            int(target_card.id),
                        ),
                    )



                    # link replace (stara -> nowa)
                    tmp_links.link(scope=scope, parent_card_id=target_card.id, child_card_id=new_card_id, link_type="supersede")

                    # Sprint 6: jeśli supersedujemy RULE/POLICY — konfliktujemy pochodne starej
                    if is_rule_kind(target_card.kind):
                        children = tmp_links.list_children(
                            scope=scope,
                            parent_card_id=target_card.id,
                            link_types=[SEM_LINK_DERIVED, SEM_LINK_SUPPORTS],
                            only_active=True,
                        )
                        for ch in children:
                            child_id = int(ch.get("child_card_id"))
                            tmp_cards.mark_conflicted(
                                scope=scope,
                                card_id=child_id,
                                conflict_reason=f"Derived from superseded {target_card.kind}: {extracted.body[:180] if extracted.body else ''}",
                            )

                        tmp_links.revoke_links_by_parent_and_types(
                            scope=scope,
                            parent_card_id=target_card.id,
                            link_types=[SEM_LINK_DERIVED, SEM_LINK_SUPPORTS],
                        )


                return {
                    "status": "ok",
                    "action": "supersede",
                    "old_card_id": target_card.id,
                    "new_card_id": int(new_card_id),
                    "reason": extracted.body[:180] if extracted.body else None,
                }
            except Exception as e:
                self.log.exception("supersede tx failed")
                return {"status": "error", "action": "supersede", "error": str(e)}

        return {"status": "skipped", "reason": "unknown_action"}


# =============================================================================
# Orchestrator: pipeline per claimed turn
# =============================================================================
class FastGateV2:

    TRIGGERS = {
        # akcje / pamięć
        "zapomnij", "cofnij", "odwołuję", "odwoluje", "anuluj", "usuń", "usun",
        "nie pamiętaj", "wycofuję", "wycofuje",
        # preferencje / profil
        "preferuję", "preferuje", "wolę", "wole", "mam", "pracuję", "pracuje", "jestem",
    }

    def should_process(self, text: str) -> bool:
        t = (text or "").strip()
        if not t:
            return False

        low = t.lower()

        # dłuższe wiadomości zwykle niosą treść
        if len(low) >= 80:
            return True

        # krótkie, ale “triggerujące”
        for trig in self.TRIGGERS:
            if trig in low:
                return True

        # pytania często są ważne (bo mogą zawierać decyzje/ustalenia)
        if "?" in low and len(low) >= 20:
            return True

        return False

KIND_PRIORITY = {
    # najwyżej: reguły/ustalenia
    "rule": 100,
    "policy": 95,
    "decision": 90,
    "task": 85,
    # fakty i preferencje
    "fact": 70,
    "preference": 65,
    "profile": 60,
    # reszta
    "note": 40,
}

SEM_LINK_SUPPORTS = "supports"
SEM_LINK_DERIVED = "derived"
SEM_LINK_CONTRADICTS = "contradicts"

def is_rule_kind(kind: str) -> bool:
    k = (kind or "").strip().lower()
    return k in ("rule", "policy")


def render_memory_block(selected: List["SelectedCard"]) -> str:
    """
    Render do tekstu, który możesz wkleić do system promptu / contextu.
    """
    lines: List[str] = []
    for s in selected:
        c = s.card
        kind = (c.kind or "").strip()
        topic = (c.topic or "").strip()
        summary = (c.summary or "").strip()
        hdr = f"[{kind}/{topic}]".strip()
        if hdr:
            lines.append(hdr)
        if summary:
            lines.append(summary)
        lines.append("")

    return "\n".join(lines).strip()


class MemoriaEngine:

    def __init__(
        self,
        *,
        db: DB,
        extractor: LLMExtractor,
        logger: Optional[logging.Logger] = None,
    ):
        self.db = db
        self.turns = TurnMessagesRepo(db)
        self.cards = MemoryCardsRepo(db)
        self.sources = MemorySourcesRepo(db)
        self.links = MemoryLinksRepo(db)
        self.selections = MemorySelectionsRepo(db)

        self.selector = MemorySelector(cards_repo=self.cards, selections_repo=self.selections)
        self.applier = MemoryApplier(cards_repo=self.cards, sources_repo=self.sources, links_repo=self.links, logger=logger)

        self.extractor = extractor
        self.log = logger or logging.getLogger("memoria_v2")
        self.gate = FastGateV2()
        self.metrics = {
            "claimed": 0,
            "processed_ok": 0,
            "processed_error": 0,
            "skipped_gate": 0,
            "skipped_no_extractions": 0,
            "action_ok": 0,
            "action_skipped_low_conf": 0,
            "action_skipped_no_target": 0,
        }


    def get_long_memory(
        self,
        *,
        scope: Scope,
        query_text: str,
        center_turn_id: str,
        center_seq: int,
        budget_chars: int = 1800,
        max_items: int = 10,
    ) -> Dict[str, Any]:
        """
        Publiczne API dla bota:
        - wybiera karty na podstawie query_text
        - loguje selection (audit)
        - zwraca memory_block_text + metadane
        """
        qk = self._keywords_from_text(query_text)

        selected = self.selector.select(
            scope=scope,
            center_turn_id=center_turn_id,
            center_seq=center_seq,
            query_keywords=qk,
            budget_chars=budget_chars,
            max_items=max_items,
        )

        # ranking dodatkowy: kind priority + score z selektora
        selected_sorted = sorted(
            selected,
            key=lambda s: (KIND_PRIORITY.get((s.card.kind or "").lower(), 0), s.score),
            reverse=True,
        )

        block = render_memory_block(selected_sorted)

        return {
            "memory_block_text": block,
            "cards": [

                {
                    "id": s.card.id,
                    "version": s.card.version,
                    "kind": s.card.kind,
                    "topic": s.card.topic,
                    "summary": s.card.summary,
                    "score": s.card.score,
                    "trust_level": s.card.trust_level,
                    "status": s.card.status,
                    "dedupe_key": s.card.dedupe_key,
                }

                for s in selected_sorted
            ],
            "query_keywords": qk,
        }


    def process_one_turn(self, *, scope: Scope, turn: TurnMessage) -> Dict[str, Any]:
        window = self.turns.fetch_window(scope=scope, center_seq=turn.seq, prev_n=3, next_n=3)

        # center
        center = None
        for tm in window:
            if tm.turn_id == turn.turn_id:
                center = tm
                break
        if not center:
            center = turn

        if not self.gate.should_process(center.content):
            self.metrics["skipped_gate"] += 1
            return {"status": "skipped", "reason": "gate_drop"}


        # query_keywords — w praktyce: z center content + ewentualnie tagi z promptu
        query_keywords = self._keywords_from_text(center.content)

        # selection audit (to nie jest konieczne do ekstrakcji, ale jest wymagane do "co model widział")
        # Jeśli nie chcesz selekcji na tym etapie, zostaw jako "audyt pusty" (tu robimy realną selekcję).
        _ = self.selector.select(
            scope=scope,
            center_turn_id=center.turn_id,
            center_seq=center.seq,
            query_keywords=query_keywords,
            budget_chars=1800,
            max_items=8,
        )

        # extract (z obu stron — center.role może być user/assistant, i tak leci)
        extracted_items = self.extractor.extract(scope=scope, window=window, center=center)

        if not extracted_items:
            self.metrics["skipped_no_extractions"] += 1
            return {"status": "skipped", "reason": "no_extractions"}


        results = []
        for ex in extracted_items:
            try:
                res = self.applier.apply(scope=scope, extracted=ex, window=window, center=center)
                results.append(res)
                if res.get("status") == "ok":
                    self.metrics["action_ok"] += 1
                else:
                    r = (res.get("reason") or "")
                    if "low_confidence" in r:
                        self.metrics["action_skipped_low_conf"] += 1
                    if r == "no_target":
                        self.metrics["action_skipped_no_target"] += 1

            except Exception as e:
                self.log.exception("apply error")
                results.append({"status": "error", "error": str(e)})

        if any((r.get("status") == "error") for r in results if isinstance(r, dict)):
            return {"status": "error", "reason": "apply_error", "results": results}

        return {"status": "ok", "results": results}

    def run_once(self, *, scope: Scope, processing_token: str, limit: int = 10) -> Dict[str, Any]:
        claimed = self.turns.claim_batch(scope=scope, limit=limit, processing_token=processing_token)
        if not claimed:
            return {"status": "idle", "claimed": 0}
        
        self.metrics["claimed"] += len(claimed)

        ok = 0
        err = 0
        for t in claimed:
            try:
                out = self.process_one_turn(scope=scope, turn=t)
                if out.get("status") == "ok":
                    self.turns.mark_processed(scope=scope, turn_id=t.turn_id, status="processed", error=None)
                    ok += 1
                    self.metrics["processed_ok"] += 1
                else:
                    st = out.get("status")
                    if st == "error":
                        err += 1
                        self.metrics["processed_error"] += 1
                        self.turns.mark_processed(scope=scope, turn_id=t.turn_id, status="error", error=out.get("reason"))
                    else:
                        self.turns.mark_processed(scope=scope, turn_id=t.turn_id, status="skipped", error=out.get("reason"))

            except Exception as e:
                err += 1
                self.metrics["processed_error"] += 1
                self.turns.mark_processed(scope=scope, turn_id=t.turn_id, status="error", error=str(e))

        self.log.info("memoria.metrics %s", self.metrics)
        return {"status": "done", "claimed": len(claimed), "ok": ok, "error": err}


    def _keywords_from_text(self, text: str) -> List[str]:
        """
        Keywordizer pod selekcję i dopasowania w DB.

        Z v1 bierzemy:
        - normalize_keyword_pl: czyszczenie do formy “DB-friendly”
        - keyword_variants_pl: warianty (prefix/sufix) pod odmiany PL
        """
        raw = (text or "").strip()
        if not raw:
            return []

        low = raw.lower()
        low = re.sub(r"[^a-z0-9ąćęłńóśźż]+", " ", low)
        tokens = [t for t in low.split() if t]

        # Filtr: odrzucamy ultra-krótkie śmieci, ale dopuszczamy 3 znaki (bo potem i tak robimy warianty)
        tokens = [t for t in tokens if len(t) >= 3]

        expanded: List[str] = []
        for t in tokens[:30]:
            expanded.extend(keyword_variants_pl(t))

        # dedup w kolejności + filtr długości
        out: List[str] = []
        seen = set()
        for k in expanded:
            k = (k or "").strip()
            if not k or len(k) < 2:
                continue
            if k in seen:
                continue
            seen.add(k)
            out.append(k)

        # “top N”
        return out[:12]


class LongTermMemoryClientV2:

    def __init__(self, *, engine: MemoriaEngine, scope: Scope):
        self.engine = engine
        self.scope = scope

    def get_long_memory(
        self,
        *,
        query_text: str,
        center_turn_id: str,
        center_seq: int,
        budget_chars: int = 1800,
        max_items: int = 10,
    ) -> Dict[str, Any]:
        """
        Zwraca:
          - memory_block_text (string do promptu)
          - cards[] (metadane)
          - query_keywords[]
        """
        return self.engine.get_long_memory(
            scope=self.scope,
            query_text=query_text,
            center_turn_id=center_turn_id,
            center_seq=center_seq,
            budget_chars=budget_chars,
            max_items=max_items,
        )


# =============================================================================
# Daemon runner (opcjonalnie)
# =============================================================================

class MemoriaDaemon:

    def __init__(
        self,
        *,
        engine: MemoriaEngine,
        scope: Scope,
        processing_token: str,
        poll_seconds: float = 2.0,
        migrate_batch_limit: int = 50,
        ltm_batch_limit: int = 10,
        logger: Optional[logging.Logger] = None,
    ):
        self.engine = engine
        self.scope = scope
        self.processing_token = processing_token
        self.poll_seconds = float(poll_seconds)
        self.migrate_batch_limit = int(migrate_batch_limit)
        self.ltm_batch_limit = int(ltm_batch_limit)
        self.log = logger or logging.getLogger("memoria_v2")

        # migrator używa tego samego DB i scope
        self.migrator = MessagesToTurnsMigrator(
            db=self.engine.db,
            scope=self.scope,
            logger=self.log,
            bots={"aifa","gerina","pionier"},
            role_mode="per_bot",   # albo "global"
        )

    def loop_forever(self) -> None:
        while True:
            # 1) Najpierw zaciągnij świeże Messages do event store
            mig = self.migrator.run_once(
                processing_token=self.processing_token + ":migrate",
                limit=self.migrate_batch_limit,
            )

            # 2) Potem normalny LTM processing po turn_messages_v2
            out = self.engine.run_once(
                scope=self.scope,
                processing_token=self.processing_token + ":ltm",
                limit=self.ltm_batch_limit,
            )

            # jeśli oba są idle — śpimy dłużej
            if mig.get("status") == "idle" and out.get("status") == "idle":
                time.sleep(self.poll_seconds)
            else:
                time.sleep(0.2)



# =============================================================================
# Helper: minimal schema check (opcjonalnie, nie przerywa pracy)
# =============================================================================

def sanity_check_tables(db: DB, logger: Optional[logging.Logger] = None) -> Dict[str, Any]:
    """
    Szybki check czy tabele istnieją.
    """
    log = logger or logging.getLogger("memoria_v2")
    needed = [
        T_TURNS,
        T_CARDS,
        T_SOURCES,
        T_LINKS,
        T_SELECTIONS,
        T_SELECTION_ITEMS,
    ]
    found = set()
    try:
        rows = db.query("SHOW TABLES")
        for r in rows:
            # mysql-connector zwraca dict z kluczem typu 'Tables_in_dbname'
            for _, v in r.items():
                found.add(str(v))
    except Exception as e:
        log.warning("sanity_check_tables failed: %s", e)
        return {"status": "unknown", "error": str(e)}

    missing = [t for t in needed if t not in found]
    return {"status": "ok" if not missing else "missing", "missing": missing, "found_count": len(found)}

# =============================================================================
# Public API helpers (pod integrację w apce)
# =============================================================================

# Cache, żeby nie tworzyć DB/LLM/Engine na każde wywołanie.
# Klucz: (db_class_name, owner_agent_id) — wystarczy na start.
_MEMORIA_RUNTIME: Dict[Tuple[str, str], Dict[str, Any]] = {}

DEFAULT_BOTS = {"aifa", "gerina", "pionier"}

def _get_or_create_runtime(*, owner_agent_id: str) -> Dict[str, Any]:
    """
    Tworzy i cachuje:
      - db
      - extractor (LLM)
      - engine
    """
    owner_agent_id = (owner_agent_id or "aifa").strip()
    key = ("MySQLDB", owner_agent_id)

    rt = _MEMORIA_RUNTIME.get(key)
    if rt:
        return rt

    log = logging.getLogger("memoria_v2")

    # 1) DB
    db = MySQLDB()

    # 2) LLM + extractor
    _mgr = MistralChatManager(MISTRAL_API_KEY)
    llm = MistralLLMAdapter(_mgr)
    extractor = LLMJsonExtractor(llm=llm, logger=log)

    # 3) Engine
    engine = MemoriaEngine(db=db, extractor=extractor, logger=log)

    rt = {"db": db, "engine": engine, "extractor": extractor}
    _MEMORIA_RUNTIME[key] = rt
    return rt


def get_memory_block(text: str, chat_id: int, owner_user_login: str, owner_agent_id: str) -> str:

    rt = _get_or_create_runtime(owner_agent_id=owner_agent_id)
    engine: MemoriaEngine = rt["engine"]

    owner_user_login = (owner_user_login or "").strip()
    owner_agent_id = (owner_agent_id or "").strip()

    scope = Scope(chat_id=int(chat_id), owner_user_login=owner_user_login, owner_agent_id=owner_agent_id)

    # turn_id — stabilny identyfikator eventu; możesz tu też wkładać np. "msg:<id z Messages>"
    turn_id = f"turn:{uuid.uuid4().hex}"

    # 1) ZAPIS do event store (turn_messages_v2) — to jest brakujący element u Ciebie
    center_seq = engine.turns.append_turn(
        scope=scope,
        turn_id=turn_id,
        role="user",
        content=text,
        timestamp_utc=utc_now(),
    )

    # 2) Pobranie bloku pamięci do promptu
    client = LongTermMemoryClientV2(engine=engine, scope=scope)
    mem = client.get_long_memory(
        query_text=text,
        center_turn_id=turn_id,
        center_seq=int(center_seq),
        budget_chars=1800,
        max_items=8,
    )
    return str(mem.get("memory_block_text") or "")


def run_daemon_loop(
    chat_id: int,
    owner_user_login: str,
    owner_agent_id: str,
    *,
    processing_token: str = "memoria-worker-1",
    ltm_batch_limit: int = 20,
) -> Dict[str, Any]:
    """
    Jeden „tick” pod daemon/cron/pm2 (bez pętli nieskończonej).

    Co robi:
      - odpala MemoriaEngine.run_once() na turn_messages_v2

    UWAGA:
      - To NIE przerzuca Messages -> turn_messages_v2.
        Migrator masz osobno (i słusznie). Tu dajemy minimalny, stabilny loop LTM na event-store.
        Jeśli chcesz: podepnę Ci tu optional callback migrate_fn() — wtedy w 1 ticku robisz migrate + LTM.
    """
    owner_user_login = (owner_user_login or "").strip()
    owner_agent_id = (owner_agent_id or "").strip()
    rt = _get_or_create_runtime(owner_agent_id=owner_agent_id)
    engine: MemoriaEngine = rt["engine"]

    scope = Scope(chat_id=int(chat_id), owner_user_login=owner_user_login, owner_agent_id=owner_agent_id)

    t0 = time.monotonic()
    out = engine.run_once(scope=scope, processing_token=processing_token, limit=int(ltm_batch_limit))
    dt = max(0.0, time.monotonic() - t0)

    claimed = int(out.get("claimed", 0) or 0)
    ok = int(out.get("ok", 0) or 0)
    errors = int(out.get("error", 0) or 0)
    skipped = max(0, claimed - ok - errors)

    report = {
        "processed": ok,
        "skipped": skipped,
        "errors": errors,
        "reserved": claimed,
        "dry_run": False,
        "duration_sec": round(dt, 3),
        "engine_status": out.get("status"),
    }
    return report


def format_memoria_report(report: Dict[str, Any]) -> str:
    return (
        "[MEMORIA] "
        f"processed={report.get('processed', 0)} "
        f"skipped={report.get('skipped', 0)} "
        f"errors={report.get('errors', 0)} "
        f"reserved={report.get('reserved', 0)} "
        f"dry_run={report.get('dry_run', False)} "
        f"t={report.get('duration_sec', '?')}s"
    )

"""
#Jak tego używasz w apce
#Przykład A: responder bota (blok pamięci do promptu)
mem_block = get_memory_block(
    text=user_text,
    chat_id=chat_id,
    owner_user_login=f"{user_login}",  # np. "michal"
    owner_agent_id=f"{bot_id}"   # np. "aifa"
)
# potem składasz prompt:
# system + mem_block + historia + user_text


#Przykład B: daemon tick (raport string)
report = run_daemon_loop(
    chat_id=chat_id,
    wner_user_login=f"{user_login}", 
    owner_agent_id=f"{bot_id}"   
    processing_token="memoria-worker-1",
    ltm_batch_limit=20,
)
str_report = format_memoria_report(report)
print(f"[MEMORIA BG REPORT]::({str_report})")
"""

# =============================================================================
# Example usage (odkomentuj u siebie)
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # 1) DB – standardowo Twoje dane z config_utils.DBDATA
    db = MySQLDB()

    # 2) Scope – to jest “tożsamość strumienia rozmowy”:
    #    chat_id + owner_user_login + owner_agent_id (bot_id)
    #    WAŻNE: seq jest liczone per (chat_id, owner_user_login, owner_agent_id)
    scope = Scope(chat_id=1, owner_user_login="michal", owner_agent_id="aifa")

    # 3) LLM extractor – adapter dopasowuje Twojego Mistrala do interfejsu LLMClient
    _mgr = MistralChatManager(MISTRAL_API_KEY)
    ADAPTER_LLM = MistralLLMAdapter(_mgr)
    extractor = LLMJsonExtractor(llm=ADAPTER_LLM, logger=logging.getLogger("memoria_v2"))

    # 4) Engine – to jest serce v2 (claim z turn_messages_v2 + extract/apply)
    engine = MemoriaEngine(db=db, extractor=extractor)

    # 5) Szybki check tabel
    print(sanity_check_tables(db))

    # -------------------------------------------------------------------------
    # PRZYKŁAD A: client -> pobierz blok pamięci do promptu bota
    # -------------------------------------------------------------------------
    # Używasz tego w responderze bota (przed zapytaniem do LLM),
    # żeby dołączyć “long memory” jako tekstowy blok kontekstu.
    client = LongTermMemoryClientV2(engine=engine, scope=scope)

    # UWAGA: center_turn_id / center_seq to identyfikacja turnu, dla którego robisz selekcję.
    # Jeśli jesteś w runtime, to zwykle:
    # - zapisujesz turn do turn_messages_v2 (append_turn)
    # - dostajesz seq
    # - potem robisz get_long_memory dla tego samego turnu
    example_center_turn_id = "msg:12345"  # przykładowo (jak migrator) albo uuid z Twojego systemu
    example_center_seq = 100             # przykładowo

    mem = client.get_long_memory(
        query_text="potrzebuję statusów LTM i deduplikacji sources",
        center_turn_id=example_center_turn_id,
        center_seq=example_center_seq,
        budget_chars=1800,
        max_items=8,
    )

    print("\n--- MEMORY BLOCK (do promptu) ---\n")
    print(mem["memory_block_text"])
    print("\n--- META ---\n")
    print(safe_json_dumps({"query_keywords": mem["query_keywords"], "cards_count": len(mem["cards"])}))

    # -------------------------------------------------------------------------
    # PRZYKŁAD B: daemon -> migracja Messages->turn_messages_v2 + LTM processing
    # -------------------------------------------------------------------------
    # Ten daemon robi dwie rzeczy:
    # 1) bierze Messages.ltm_status='new' i przepisuje do turn_messages_v2
    # 2) potem MemoriaEngine obrabia turn_messages_v2 (ltm_status='new')
    daemon = MemoriaDaemon(
        engine=engine,
        scope=scope,
        processing_token="memoria-worker-1",
        poll_seconds=2.0,
        migrate_batch_limit=100,  # ile Messages naraz przerzuca do event store
        ltm_batch_limit=20,       # ile turnów naraz obrabia LTM
    )
    daemon.loop_forever()

