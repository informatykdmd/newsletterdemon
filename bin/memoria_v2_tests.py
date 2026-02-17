#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MEMORIA V2 TOOL TESTER (DEV) — odporne na różnice schematu

Komendy:
  python3 memoria_v2_tests.py sanity
  python3 memoria_v2_tests.py snap
  python3 memoria_v2_tests.py seed_msgs
  python3 memoria_v2_tests.py migrate <loops>
  python3 memoria_v2_tests.py ltm <loops>
  python3 memoria_v2_tests.py blocks <loops> "query text"
  python3 memoria_v2_tests.py real

ENV:
  MEM_CHAT_ID=900001
  MEM_USER=michal
  MEM_BOT=aifa
  MEM_TOKEN=memoria-test-worker
"""

import os
import sys
import time
import traceback
from datetime import datetime

import memoria_v2_1 as m


# ------------------------------------------------------------------------------
# Konfiguracja
# ------------------------------------------------------------------------------

TEST_CHAT_ID = int(os.getenv("MEM_CHAT_ID", "900001"))
TEST_USER_LOGIN = os.getenv("MEM_USER", "michal")
TEST_BOT_ID = os.getenv("MEM_BOT", "aifa")
TEST_TOKEN = os.getenv("MEM_TOKEN", "memoria-test-worker")

DEFAULT_MIGRATE_LIMIT = int(os.getenv("MEM_MIGRATE_LIMIT", "50"))
DEFAULT_LTM_LIMIT = int(os.getenv("MEM_LTM_LIMIT", "20"))

# Jeśli 1 -> real() NIE będzie dodawał seed_msgs, tylko jedzie na tym co już jest w Messages
REAL_SKIP_SEED = os.getenv("MEM_REAL_SKIP_SEED", "0") == "1"


SEED_MESSAGES = [
    ("michal", "Wolę lody owocowe."),
    ("michal", "Mam psa. Ma na imię Bąbel."),
    ("michal", "Jutro spotkanie po 16:00."),
    ("mariajot", "Ja wolę lody czekoladowe, ale nie mogę ich jeść."),
    ("mariajot", "Co to za pogoda, -15'C!"),
    ("michal", "Nieważne ile stopni, tylko ile słońca."),
]


# ------------------------------------------------------------------------------
# Helpers: print
# ------------------------------------------------------------------------------

def hr(char="=", n=70):
    return char * n

def print_title(txt: str):
    print("\n" + hr("="))
    print(txt)
    print(hr("="))

def print_section(txt: str):
    print("\n" + hr("-"))
    print(txt)
    print(hr("-"))

def trunc(s: str, n: int = 140) -> str:
    s = str(s or "")
    s = s.replace("\n", " ").strip()
    if len(s) <= n:
        return s
    return s[: n - 3] + "..."

def safe_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        print(f"ERROR: {e}")
        traceback.print_exc()
        return None


# ------------------------------------------------------------------------------
# Runtime/DB
# ------------------------------------------------------------------------------

def get_runtime():
    return m._get_or_create_runtime(owner_agent_id=TEST_BOT_ID)

def db():
    return get_runtime()["db"]

def engine():
    return get_runtime()["engine"]

def scope():
    return m.Scope(chat_id=TEST_CHAT_ID, owner_user_login=TEST_USER_LOGIN, owner_agent_id=TEST_BOT_ID)

def q(sql: str, params=None):
    return db().query(sql, params or ())

def x(sql: str, params=None):
    return db().execute(sql, params or ())

def table_exists(table_name: str) -> bool:
    rows = q("SHOW TABLES")
    for r in rows:
        for _, v in r.items():
            if str(v) == table_name:
                return True
    return False

def table_cols(table_name: str) -> set:
    if not table_exists(table_name):
        return set()
    rows = q(f"SHOW COLUMNS FROM {table_name}")
    return {str(r.get("Field")) for r in rows}

def has_cols(table: str, *cols: str) -> bool:
    cs = table_cols(table)
    return all(c in cs for c in cols)

def count_simple(table: str, where_sql: str = "", params=None) -> int:
    if not table_exists(table):
        return 0
    sql = f"SELECT COUNT(*) AS c FROM {table} "
    if where_sql:
        sql += f" WHERE {where_sql} "
    row = q(sql, params or ())
    return int(row[0]["c"]) if row else 0


# ------------------------------------------------------------------------------
# Snapshot
# ------------------------------------------------------------------------------

def snap_counts():
    out = {}

    # Messages
    if table_exists(m.T_MESSAGES):
        out["Messages_total"] = count_simple(m.T_MESSAGES)
        if has_cols(m.T_MESSAGES, "ltm_status"):
            out["Messages_new"] = count_simple(m.T_MESSAGES, "ltm_status='new'")
            out["Messages_processing"] = count_simple(m.T_MESSAGES, "ltm_status='processing'")
            out["Messages_processed"] = count_simple(m.T_MESSAGES, "ltm_status='processed'")
            out["Messages_error"] = count_simple(m.T_MESSAGES, "ltm_status='error'")
        else:
            out["Messages_new"] = out["Messages_processing"] = out["Messages_processed"] = out["Messages_error"] = None
    else:
        out["Messages_total"] = None
        out["Messages_new"] = out["Messages_processing"] = out["Messages_processed"] = out["Messages_error"] = None

    # Turns
    out["Turns_total"] = count_simple(
        m.T_TURNS,
        "chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )
    if has_cols(m.T_TURNS, "ltm_status"):
        out["Turns_new"] = count_simple(
            m.T_TURNS,
            "chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s AND ltm_status='new'",
            (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
        )
        out["Turns_processing"] = count_simple(
            m.T_TURNS,
            "chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s AND ltm_status='processing'",
            (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
        )
        out["Turns_processed"] = count_simple(
            m.T_TURNS,
            "chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s AND ltm_status='processed'",
            (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
        )
        out["Turns_skipped"] = count_simple(
            m.T_TURNS,
            "chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s AND ltm_status='skipped'",
            (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
        )
        out["Turns_error"] = count_simple(
            m.T_TURNS,
            "chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s AND ltm_status='error'",
            (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
        )
    else:
        out["Turns_new"] = out["Turns_processing"] = out["Turns_processed"] = out["Turns_skipped"] = out["Turns_error"] = None

    # Cards
    out["Cards_total"] = count_simple(
        m.T_CARDS,
        "chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )

    # Sources (ma scope kolumny w v2)
    out["Sources_total"] = count_simple(
        m.T_SOURCES,
        "chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )

    # Selections (ma scope kolumny w v2)
    out["Selections_total"] = count_simple(
        m.T_SELECTIONS,
        "chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )

    # Selection items:
    # - czasem tabela ma scope kolumny (chat_id/owner...), a czasem nie (tylko selection_id).
    if table_exists(m.T_SELECTION_ITEMS):
        if has_cols(m.T_SELECTION_ITEMS, "chat_id", "owner_user_login", "owner_agent_id"):
            out["SelectionItems_total"] = count_simple(
                m.T_SELECTION_ITEMS,
                "chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s",
                (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
            )
        else:
            # JOIN do selections
            rows = q(
                f"""
                SELECT COUNT(*) AS c
                FROM {m.T_SELECTION_ITEMS} si
                JOIN {m.T_SELECTIONS} s ON s.id = si.selection_id
                WHERE s.chat_id=%s AND s.owner_user_login=%s AND s.owner_agent_id=%s
                """,
                (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
            )
            out["SelectionItems_total"] = int(rows[0]["c"]) if rows else 0
    else:
        out["SelectionItems_total"] = 0

    return out


def print_snapshot(label: str = "SNAPSHOT"):
    print_section(label)
    counts = snap_counts()
    for k in sorted(counts.keys()):
        print(f"{k}: {counts[k]}")

    # last turns
    if table_exists(m.T_TURNS):
        turns = q(
            f"""
            SELECT seq, turn_id, role, ltm_status, ltm_error, content
            FROM {m.T_TURNS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
            ORDER BY seq DESC
            LIMIT 5
            """,
            (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
        )
        print("\nLast turns (max 5):")
        for r in turns:
            print(f"  seq={r['seq']} role={r['role']} status={r.get('ltm_status')} err={trunc(r.get('ltm_error'), 60)} | {trunc(r.get('content'))}")
    else:
        print("\nLast turns: (table missing)")

    # last cards
    if table_exists(m.T_CARDS):
        cards = q(
            f"""
            SELECT id, kind, topic, status, version, dedupe_key, summary
            FROM {m.T_CARDS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
            ORDER BY id DESC
            LIMIT 5
            """,
            (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
        )
        print("\nLast cards (max 5):")
        if not cards:
            print("  (none)")
        for r in cards:
            print(f"  id={r['id']} v={r['version']} status={r['status']} kind={r['kind']} topic={r['topic']} dk={trunc(r['dedupe_key'], 40)} | {trunc(r.get('summary'))}")
    else:
        print("\nLast cards: (table missing)")


# ------------------------------------------------------------------------------
# Commands
# ------------------------------------------------------------------------------

def cmd_sanity():
    print_title("MEMORIA V2 TOOL TESTER")
    print_section("sanity_check_tables")
    rt = get_runtime()
    out = m.sanity_check_tables(rt["db"])
    print(out)

def try_insert_message(user_name: str, content: str) -> bool:
    """
    Best-effort insert do Messages (jeśli schema pozwala).
    """
    if not table_exists(m.T_MESSAGES):
        print("Messages table not found -> skip seed.")
        return False

    cols = table_cols(m.T_MESSAGES)
    if "user_name" not in cols or "content" not in cols:
        print("Messages missing user_name/content -> skip seed.")
        return False

    fields = ["user_name", "content"]
    values = [user_name, content]

    # timestamp
    if "timestamp" in cols:
        fields.append("timestamp")
        values.append(datetime.utcnow())

    # anti-dup: jeśli taki sam content od tego usera był w ostatnich 10 minutach, to pomiń
    if "timestamp" in cols:
        exists = q(
            f"SELECT id FROM {m.T_MESSAGES} "
            f"WHERE user_name=%s AND content=%s AND timestamp >= (NOW() - INTERVAL 10 MINUTE) "
            f"LIMIT 1",
            (user_name, content),
        )
        if exists:
            return False

    # ltm_status
    if "ltm_status" in cols:
        fields.append("ltm_status")
        values.append("new")

    # opcjonalne
    for extra in ["group_id", "is_group", "chat_id"]:
        if extra in cols:
            fields.append(extra)
            values.append(0 if extra != "chat_id" else TEST_CHAT_ID)

    placeholders = ",".join(["%s"] * len(fields))
    sql = f"INSERT INTO {m.T_MESSAGES} ({','.join(fields)}) VALUES ({placeholders})"
    try:
        x(sql, tuple(values))
        return True
    except Exception as e:
        print(f"Insert into Messages failed: {e}")
        traceback.print_exc()
        return False

def cmd_seed_msgs():
    print_title("MEMORIA V2 TOOL TESTER")
    print_section("SEED -> Messages (best-effort)")
    ok = 0
    for user_name, content in SEED_MESSAGES:
        if try_insert_message(user_name, content):
            ok += 1
            print(f"  + {user_name}: {trunc(content)}")
        else:
            print(f"  ! skipped: {user_name}: {trunc(content)}")
    print(f"\nSeed inserted: {ok}/{len(SEED_MESSAGES)}")
    print_snapshot("SNAPSHOT after seed_msgs")

def migrate_once(limit=DEFAULT_MIGRATE_LIMIT):
    mig = m.MessagesToTurnsMigrator(
        db=db(),
        scope=scope(),
        logger=None,
        bots={"aifa", "gerina", "pionier"},
        role_mode="per_bot",
    )
    return mig.run_once(processing_token=TEST_TOKEN + ":migrate", limit=int(limit))

def cmd_migrate(loops: int = 1):
    print_title("MEMORIA V2 TOOL TESTER")
    print_section(f"MIGRATE loops={loops}")
    for i in range(1, loops + 1):
        out = safe_call(migrate_once, DEFAULT_MIGRATE_LIMIT) or {}
        print(f"[migrate {i}/{loops}] {out}")
        print_snapshot(f"SNAPSHOT after migrate loop {i}")
        time.sleep(0.15)

def ltm_once(limit=DEFAULT_LTM_LIMIT):
    return m.run_daemon_loop(
        chat_id=TEST_CHAT_ID,
        owner_user_login=TEST_USER_LOGIN,
        owner_agent_id=TEST_BOT_ID,
        processing_token=TEST_TOKEN + ":ltm",
        ltm_batch_limit=int(limit),
    )

def cmd_ltm(loops: int = 1):
    print_title("MEMORIA V2 TOOL TESTER")
    print_section(f"LTM loops={loops}")
    for i in range(1, loops + 1):
        rep = safe_call(ltm_once, DEFAULT_LTM_LIMIT) or {}
        print(f"[ltm {i}/{loops}] {rep}")
        print(f"  report_str: {m.format_memoria_report(rep)}")
        print_snapshot(f"SNAPSHOT after ltm loop {i}")
        time.sleep(0.2)

def cmd_blocks(loops: int, text: str):
    print_title("MEMORIA V2 TOOL TESTER")
    print_section(f"BLOCKS loops={loops}")
    for i in range(1, loops + 1):
        mem_block = safe_call(
            m.get_memory_block,
            text=text,
            chat_id=TEST_CHAT_ID,
            owner_user_login=TEST_USER_LOGIN,
            owner_agent_id=TEST_BOT_ID,
        )
        print(f"\n[block {i}/{loops}] query={trunc(text, 120)}")
        print("--- MEMORY BLOCK ---")
        print(mem_block or "")
        print("--- END ---")
        print_snapshot(f"SNAPSHOT after block loop {i}")
        time.sleep(0.15)

def cmd_real():
    print_title("MEMORIA V2 TOOL TESTER")
    print_section("REAL SCENARIO")
    print(f"Scope: chat_id={TEST_CHAT_ID} user={TEST_USER_LOGIN} bot={TEST_BOT_ID} token={TEST_TOKEN}")

    print_snapshot("SNAPSHOT start")

    print_section("FALA 1 — seed_msgs (best-effort)")
    if REAL_SKIP_SEED:
        print("SKIP: seed_msgs disabled (MEM_REAL_SKIP_SEED=1) — lecimy na istniejących wpisach w Messages.")
    else:
        cmd_seed_msgs()


    print_section("FALA 2 — migrate x3")
    for i in range(1, 4):
        out = safe_call(migrate_once, DEFAULT_MIGRATE_LIMIT) or {}
        print(f"[migrate {i}/3] {out}")
        print_snapshot(f"SNAPSHOT after migrate {i}")
        time.sleep(0.15)

    print_section("FALA 3 — ltm x3")
    for i in range(1, 4):
        rep = safe_call(ltm_once, DEFAULT_LTM_LIMIT) or {}
        print(f"[ltm {i}/3] {rep} | {m.format_memoria_report(rep)}")
        print_snapshot(f"SNAPSHOT after ltm {i}")
        time.sleep(0.2)

    print_section("FALA 4 — blocks x3")
    queries = [
        "Wolę lody owocowe.",
        "Mam psa. Ma na imię Bąbel.",
        "Jutro spotkanie po 16:00.",
    ]
    for qi, qtext in enumerate(queries, start=1):
        mem_block = safe_call(
            m.get_memory_block,
            text=qtext,
            chat_id=TEST_CHAT_ID,
            owner_user_login=TEST_USER_LOGIN,
            owner_agent_id=TEST_BOT_ID,
        )
        print(f"\n[block {qi}/3] query={qtext}")
        print("--- MEMORY BLOCK ---")
        print(mem_block or "")
        print("--- END ---")
        print_snapshot(f"SNAPSHOT after block {qi}")
        time.sleep(0.15)

    print_section("REAL SCENARIO DONE")
    print_snapshot("FINAL SNAPSHOT")


# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------

def usage():
    print("Usage:")
    print("  python3 memoria_v2_tests.py sanity")
    print("  python3 memoria_v2_tests.py snap")
    print("  python3 memoria_v2_tests.py seed_msgs")
    print("  python3 memoria_v2_tests.py migrate <loops>")
    print("  python3 memoria_v2_tests.py ltm <loops>")
    print('  python3 memoria_v2_tests.py blocks <loops> "query text"')
    print("  python3 memoria_v2_tests.py real")

def main():
    if len(sys.argv) < 2:
        usage()
        return 2

    cmd = (sys.argv[1] or "").strip().lower()

    if cmd == "sanity":
        cmd_sanity()
        return 0

    if cmd == "snap":
        print_title("MEMORIA V2 TOOL TESTER")
        print_snapshot("SNAPSHOT")
        return 0

    if cmd == "seed_msgs":
        cmd_seed_msgs()
        return 0

    if cmd == "migrate":
        loops = int(sys.argv[2]) if len(sys.argv) >= 3 else 1
        cmd_migrate(loops)
        return 0

    if cmd == "ltm":
        loops = int(sys.argv[2]) if len(sys.argv) >= 3 else 1
        cmd_ltm(loops)
        return 0

    if cmd == "blocks":
        if len(sys.argv) < 4:
            usage()
            return 2
        loops = int(sys.argv[2])
        text = sys.argv[3]
        cmd_blocks(loops, text)
        return 0

    if cmd == "real":
        cmd_real()
        return 0

    usage()
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
