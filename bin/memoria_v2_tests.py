#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MEMORIA V2 TOOL TESTER (DEV)

Cel:
- test end-to-end w pętlach:
  (A) seed -> Messages
  (B) migrate -> turn_messages_v2
  (C) ltm -> memory_cards_v2 + memory_card_sources_v2
  (D) blocks -> get_memory_block (selections + selection_items)
  (E) combo -> dosiew + migrate/ltm + blocks

Użycie przykładowe:
  python3 memoria_v2_tests.py sanity
  python3 memoria_v2_tests.py snap

  # 1) dosiej do Messages (jeśli schema pozwala)
  python3 memoria_v2_tests.py seed_msgs

  # 2) migracja + LTM w pętli
  python3 memoria_v2_tests.py migrate 3
  python3 memoria_v2_tests.py ltm 3

  # 3) pobieranie bloków pamięci (3 razy)
  python3 memoria_v2_tests.py blocks 3 "Wolę lody owocowe."

  # 4) scenariusz REAL: seed->migrate/ltm loops->blocks loops->combo
  python3 memoria_v2_tests.py real

Konfiguracja (opcjonalnie env):
  MEM_CHAT_ID=900001
  MEM_USER=michal
  MEM_BOT=aifa
  MEM_TOKEN=memoria-test-worker
"""

import os
import sys
import time
import traceback
from datetime import datetime, timedelta

# import modułu z implementacją
import memoria_v2_1 as m


# ------------------------------------------------------------------------------
# Konfiguracja
# ------------------------------------------------------------------------------

TEST_CHAT_ID = int(os.getenv("MEM_CHAT_ID", "900001"))
TEST_USER_LOGIN = os.getenv("MEM_USER", "michal")
TEST_BOT_ID = os.getenv("MEM_BOT", "aifa")
TEST_TOKEN = os.getenv("MEM_TOKEN", "memoria-test-worker")

# limity
DEFAULT_MIGRATE_LIMIT = int(os.getenv("MEM_MIGRATE_LIMIT", "50"))
DEFAULT_LTM_LIMIT = int(os.getenv("MEM_LTM_LIMIT", "20"))

# seed messages (do Messages)
SEED_MESSAGES = [
    # krótkie i “pamięciowe” – gate może przepuścić/odrzucić zależnie od reguł; dajemy też pewniaki:
    ("michal", "Wolę lody owocowe."),
    ("michal", "Mam psa. Ma na imię Bąbel."),
    ("michal", "Jutro spotkanie po 16:00."),

    # trochę dialogu + inny user (global/per_bot role mapping pokaże różnicę)
    ("mariajot", "Ja wolę lody czekoladowe, ale nie mogę ich jeść."),
    ("mariajot", "Co to za pogoda, -15'C!"),
    ("michal", "Nieważne ile stopni, tylko ile słońca."),
]


# ------------------------------------------------------------------------------
# Helpers: printing
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

def safe_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        print(f"ERROR: {e}")
        traceback.print_exc()
        return None

def trunc(s: str, n: int = 140) -> str:
    s = str(s or "")
    s = s.replace("\n", " ").strip()
    if len(s) <= n:
        return s
    return s[: n - 3] + "..."


# ------------------------------------------------------------------------------
# DB helpers
# ------------------------------------------------------------------------------

def get_runtime():
    # runtime cached per bot_id (zgodnie z memoria_v2_1)
    rt = m._get_or_create_runtime(owner_agent_id=TEST_BOT_ID)
    return rt

def db():
    return get_runtime()["db"]

def engine():
    return get_runtime()["engine"]

def scope():
    return m.Scope(chat_id=TEST_CHAT_ID, owner_user_login=TEST_USER_LOGIN, owner_agent_id=TEST_BOT_ID)

def show_table_cols(table_name: str):
    rows = db().query(f"SHOW COLUMNS FROM {table_name}")
    return [r.get("Field") for r in rows]

def table_exists(table_name: str) -> bool:
    rows = db().query("SHOW TABLES")
    for r in rows:
        for _, v in r.items():
            if str(v) == table_name:
                return True
    return False

def q(sql: str, params=None):
    return db().query(sql, params or ())

def x(sql: str, params=None):
    return db().execute(sql, params or ())

def snap_counts():
    """
    Snapshot liczników w kluczowych tabelach.
    """
    out = {}

    # Messages (stare)
    if table_exists(m.T_MESSAGES):
        out["Messages_total"] = q(f"SELECT COUNT(*) AS c FROM {m.T_MESSAGES}")[0]["c"]
        out["Messages_new"] = q(f"SELECT COUNT(*) AS c FROM {m.T_MESSAGES} WHERE ltm_status='new'")[0]["c"]
        out["Messages_processing"] = q(f"SELECT COUNT(*) AS c FROM {m.T_MESSAGES} WHERE ltm_status='processing'")[0]["c"]
        out["Messages_processed"] = q(f"SELECT COUNT(*) AS c FROM {m.T_MESSAGES} WHERE ltm_status='processed'")[0]["c"]
        out["Messages_error"] = q(f"SELECT COUNT(*) AS c FROM {m.T_MESSAGES} WHERE ltm_status='error'")[0]["c"]
    else:
        out["Messages_total"] = None

    # turns v2
    out["Turns_total"] = q(
        f"SELECT COUNT(*) AS c FROM {m.T_TURNS} WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )[0]["c"]

    out["Turns_new"] = q(
        f"""SELECT COUNT(*) AS c FROM {m.T_TURNS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s AND ltm_status='new'""",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )[0]["c"]

    out["Turns_processing"] = q(
        f"""SELECT COUNT(*) AS c FROM {m.T_TURNS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s AND ltm_status='processing'""",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )[0]["c"]

    out["Turns_processed"] = q(
        f"""SELECT COUNT(*) AS c FROM {m.T_TURNS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s AND ltm_status='processed'""",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )[0]["c"]

    out["Turns_skipped"] = q(
        f"""SELECT COUNT(*) AS c FROM {m.T_TURNS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s AND ltm_status='skipped'""",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )[0]["c"]

    out["Turns_error"] = q(
        f"""SELECT COUNT(*) AS c FROM {m.T_TURNS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s AND ltm_status='error'""",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )[0]["c"]

    # cards
    out["Cards_total"] = q(
        f"SELECT COUNT(*) AS c FROM {m.T_CARDS} WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )[0]["c"]

    # sources
    out["Sources_total"] = q(
        f"""SELECT COUNT(*) AS c FROM {m.T_SOURCES}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s""",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )[0]["c"]

    # selections
    out["Selections_total"] = q(
        f"""SELECT COUNT(*) AS c FROM {m.T_SELECTIONS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s""",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )[0]["c"]

    out["SelectionItems_total"] = q(
        f"""SELECT COUNT(*) AS c FROM {m.T_SELECTION_ITEMS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s""",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )[0]["c"]

    return out

def print_snapshot(label: str = "SNAPSHOT"):
    print_section(label)
    counts = snap_counts()
    for k in sorted(counts.keys()):
        print(f"{k}: {counts[k]}")

    # last turns
    turns = q(
        f"""SELECT seq, turn_id, role, ltm_status, ltm_error, content
            FROM {m.T_TURNS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
            ORDER BY seq DESC
            LIMIT 5""",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )
    print("\nLast turns (max 5):")
    for r in turns:
        print(
            f"  seq={r['seq']} role={r['role']} status={r['ltm_status']} err={trunc(r.get('ltm_error'), 60)} | {trunc(r.get('content'))}"
        )

    # last cards
    cards = q(
        f"""SELECT id, kind, topic, status, version, dedupe_key, summary
            FROM {m.T_CARDS}
            WHERE chat_id=%s AND owner_user_login=%s AND owner_agent_id=%s
            ORDER BY id DESC
            LIMIT 5""",
        (TEST_CHAT_ID, TEST_USER_LOGIN, TEST_BOT_ID),
    )
    print("\nLast cards (max 5):")
    if not cards:
        print("  (none)")
    for r in cards:
        print(
            f"  id={r['id']} v={r['version']} status={r['status']} kind={r['kind']} topic={r['topic']} dk={trunc(r['dedupe_key'], 40)} | {trunc(r.get('summary'))}"
        )


# ------------------------------------------------------------------------------
# Actions: sanity
# ------------------------------------------------------------------------------

def cmd_sanity():
    print_title("MEMORIA V2 TOOL TESTER")
    print_section("sanity_check_tables")
    rt = get_runtime()
    out = m.sanity_check_tables(rt["db"])
    print(out)


# ------------------------------------------------------------------------------
# Actions: seed into Messages
# ------------------------------------------------------------------------------

def try_insert_message(user_name: str, content: str) -> bool:
    """
    Próbuje dodać rekord do Messages. Działa tylko jeśli tabela ma sensowne kolumny.
    """
    if not table_exists(m.T_MESSAGES):
        print("Messages table not found -> skip seed.")
        return False

    cols = set(show_table_cols(m.T_MESSAGES))
    needed_min = {"user_name", "content"}
    if not needed_min.issubset(cols):
        print(f"Messages schema missing {needed_min - cols} -> skip seed.")
        return False

    # budujemy insert adaptacyjnie
    fields = ["user_name", "content"]
    values = [user_name, content]

    if "timestamp" in cols:
        fields.append("timestamp")
        values.append(datetime.utcnow())

    if "ltm_status" in cols:
        fields.append("ltm_status")
        values.append("new")

    # opcjonalne: group_id / chat_id / is_group — jeśli istnieją, ustawiamy 0
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
    print_section("SEED -> Messages")
    ok = 0
    for user_name, content in SEED_MESSAGES:
        if try_insert_message(user_name, content):
            ok += 1
            print(f"  + {user_name}: {trunc(content)}")
        else:
            print(f"  ! skipped: {user_name}: {trunc(content)}")
    print(f"\nSeed inserted: {ok}/{len(SEED_MESSAGES)}")
    print_snapshot("SNAPSHOT after seed_msgs")


# ------------------------------------------------------------------------------
# Actions: migrate loops
# ------------------------------------------------------------------------------

def migrate_once(limit=DEFAULT_MIGRATE_LIMIT):
    rt = get_runtime()
    mig = m.MessagesToTurnsMigrator(
        db=rt["db"],
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


# ------------------------------------------------------------------------------
# Actions: ltm loops
# ------------------------------------------------------------------------------

def ltm_once(limit=DEFAULT_LTM_LIMIT):
    # używamy publicznego helpera (tylko turns->cards)
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


# ------------------------------------------------------------------------------
# Actions: blocks loops (get_memory_block)
# ------------------------------------------------------------------------------

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


# ------------------------------------------------------------------------------
# Actions: combo scenario (real)
# ------------------------------------------------------------------------------

def cmd_real():
    """
    Realny scenariusz w “falach”:

    FALA 0: snapshot start
    FALA 1: seed do Messages (jeśli możliwe)
    FALA 2: 3x migrate (żeby przenieść new -> turns)
    FALA 3: 3x ltm (żeby przerobić turns -> cards)
    FALA 4: 3x blocks (żeby zobaczyć co wraca w prompt)
    FALA 5: combo (dosiew + migrate/ltm + blocks)
    """
    print_title("MEMORIA V2 TOOL TESTER")
    print_section("REAL SCENARIO")
    print(f"Scope: chat_id={TEST_CHAT_ID} user={TEST_USER_LOGIN} bot={TEST_BOT_ID} token={TEST_TOKEN}")

    print_snapshot("SNAPSHOT start")

    # FALA 1
    print_section("FALA 1 — seed_msgs (best-effort)")
    cmd_seed_msgs()

    # FALA 2
    print_section("FALA 2 — migrate x3")
    for i in range(1, 4):
        out = safe_call(migrate_once, DEFAULT_MIGRATE_LIMIT) or {}
        print(f"[migrate {i}/3] {out}")
        print_snapshot(f"SNAPSHOT after migrate {i}")
        time.sleep(0.15)

    # FALA 3
    print_section("FALA 3 — ltm x3")
    for i in range(1, 4):
        rep = safe_call(ltm_once, DEFAULT_LTM_LIMIT) or {}
        print(f"[ltm {i}/3] {rep} | {m.format_memoria_report(rep)}")
        print_snapshot(f"SNAPSHOT after ltm {i}")
        time.sleep(0.2)

    # FALA 4
    print_section("FALA 4 — blocks x3")
    queries = [
        "Wolę lody owocowe.",
        "Jutro spotkanie po 16:00.",
        "Co z pogodą?",
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

    # FALA 5: combo
    print_section("FALA 5 — COMBO (dosiew + migrate/ltm + blocks)")
    combo_msgs = [
        ("michal", "Mam preferencję: wolę kawę z mlekiem."),
        ("michal", "Odwołuję: jutro spotkanie po 16:00 nieaktualne."),
        ("michal", "Zamiast tego: spotkanie jutro o 18:30."),
    ]
    inserted = 0
    for u, c in combo_msgs:
        if try_insert_message(u, c):
            inserted += 1
            print(f"  + {u}: {trunc(c)}")
        else:
            print(f"  ! skipped: {u}: {trunc(c)}")
    print(f"combo seed inserted: {inserted}/{len(combo_msgs)}")
    print_snapshot("SNAPSHOT after combo seed")

    # migrate 3x
    for i in range(1, 4):
        out = safe_call(migrate_once, DEFAULT_MIGRATE_LIMIT) or {}
        print(f"[combo migrate {i}/3] {out}")
        time.sleep(0.15)

    # ltm 3x
    for i in range(1, 4):
        rep = safe_call(ltm_once, DEFAULT_LTM_LIMIT) or {}
        print(f"[combo ltm {i}/3] {rep} | {m.format_memoria_report(rep)}")
        time.sleep(0.2)

    # blocks 3x
    for i in range(1, 4):
        qtext = "Kawa z mlekiem i spotkanie jutro — przypomnij mi."
        mem_block = safe_call(
            m.get_memory_block,
            text=qtext,
            chat_id=TEST_CHAT_ID,
            owner_user_login=TEST_USER_LOGIN,
            owner_agent_id=TEST_BOT_ID,
        )
        print(f"\n[combo block {i}/3] query={qtext}")
        print("--- MEMORY BLOCK ---")
        print(mem_block or "")
        print("--- END ---")
        print_snapshot(f"SNAPSHOT after combo block {i}")
        time.sleep(0.15)

    print_section("REAL SCENARIO DONE")
    print_snapshot("FINAL SNAPSHOT")


# ------------------------------------------------------------------------------
# Misc: snapshots
# ------------------------------------------------------------------------------

def cmd_snap():
    print_title("MEMORIA V2 TOOL TESTER")
    print_snapshot("SNAPSHOT")


# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------

def usage():
    print("Usage:")
    print("  python memoria_v2_tests.py sanity")
    print("  python memoria_v2_tests.py snap")
    print("  python memoria_v2_tests.py seed_msgs")
    print("  python memoria_v2_tests.py migrate <loops>")
    print("  python memoria_v2_tests.py ltm <loops>")
    print('  python memoria_v2_tests.py blocks <loops> "query text"')
    print("  python memoria_v2_tests.py real")
    print("")
    print("Env config:")
    print("  MEM_CHAT_ID=900001 MEM_USER=michal MEM_BOT=aifa MEM_TOKEN=memoria-test-worker")


def main():
    if len(sys.argv) < 2:
        usage()
        return 2

    cmd = (sys.argv[1] or "").strip().lower()

    if cmd == "sanity":
        cmd_sanity()
        return 0

    if cmd == "snap":
        cmd_snap()
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
