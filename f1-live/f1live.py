#!/usr/bin/env python3
"""F1 Live — personal live timing board.

Pulls timing data from the OpenF1 API (https://openf1.org), stores every row in a
local SQLite database, works out overtakes, and serves a live web dashboard.

    python f1live.py live                      # the session happening right now
    python f1live.py replay --year 2025 --gp Monaco --speed 8
    python f1live.py replay --session 9158 --start-min 20

Then open http://localhost:8000.  Standard library only, no installs needed.

Real-time data on OpenF1 needs a (paid) account: set OPENF1_USERNAME and
OPENF1_PASSWORD.  Historical sessions (replay mode) are free.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

API = "https://api.openf1.org/v1"
HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
DB_PATH = HERE / "f1.db"

PIT_LANE_SECONDS = 25.0  # how long a car shows "IN PIT" after its pit record


# ── OpenF1 client ────────────────────────────────────────────────────────────

class OpenF1:
    def __init__(self) -> None:
        self.user = os.environ.get("OPENF1_USERNAME")
        self.password = os.environ.get("OPENF1_PASSWORD")
        self.token: str | None = None
        self.token_expiry = 0.0

    def _auth_header(self) -> dict:
        if not (self.user and self.password):
            return {}
        if time.time() > self.token_expiry - 60:
            body = urllib.parse.urlencode({"username": self.user, "password": self.password}).encode()
            with urllib.request.urlopen("https://api.openf1.org/token", body, timeout=20) as r:
                tok = json.load(r)
            self.token = tok["access_token"]
            self.token_expiry = time.time() + float(tok.get("expires_in", 3600))
        return {"Authorization": f"Bearer {self.token}"}

    def get(self, endpoint: str, **params) -> list[dict]:
        # OpenF1 filters look like `date>2025-05-25T13:00:00`, so the operator
        # lives in the key. Build the query by hand to keep `>` intact.
        parts = []
        for key, val in params.items():
            key = key.replace("__gt", ">")
            parts.append(f"{key}={urllib.parse.quote(str(val), safe=':-.T')}")
        url = f"{API}/{endpoint}" + ("?" + "&".join(parts) if parts else "")
        for attempt in range(4):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "f1-live/1.0", **self._auth_header()})
                with urllib.request.urlopen(req, timeout=30) as r:
                    data = json.load(r)
                return data if isinstance(data, list) else []
            except urllib.error.HTTPError as e:
                if e.code == 404:  # OpenF1 answers 404 for "no rows match"
                    return []
                if e.code in (401, 403):
                    sys.exit("OpenF1 refused the request. Live data needs OPENF1_USERNAME / OPENF1_PASSWORD; "
                             "replay mode works without an account.")
                if e.code == 429:
                    time.sleep(2 + attempt * 2)
                    continue
                raise
            except (urllib.error.URLError, TimeoutError):
                time.sleep(2 ** attempt)
        return []


def ts(iso: str | None) -> float | None:
    if not iso:
        return None
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def iso_naive(t: float) -> str:
    """OpenF1 reads timezone-less dates as UTC; this avoids a '+' in the URL."""
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")


# ── Database ─────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (session_key INTEGER PRIMARY KEY, name TEXT, circuit TEXT,
    country TEXT, year INTEGER, t_start REAL, t_end REAL);
CREATE TABLE IF NOT EXISTS drivers (session_key INTEGER, driver_number INTEGER, acronym TEXT,
    full_name TEXT, team TEXT, colour TEXT, PRIMARY KEY (session_key, driver_number));
CREATE TABLE IF NOT EXISTS positions (session_key INTEGER, t REAL, driver_number INTEGER, position INTEGER);
CREATE TABLE IF NOT EXISTS intervals (session_key INTEGER, t REAL, driver_number INTEGER, gap TEXT, interval TEXT);
CREATE TABLE IF NOT EXISTS laps (session_key INTEGER, driver_number INTEGER, lap_number INTEGER,
    t_start REAL, duration REAL, pit_out INTEGER, PRIMARY KEY (session_key, driver_number, lap_number));
CREATE TABLE IF NOT EXISTS pits (session_key INTEGER, t REAL, driver_number INTEGER, lap_number INTEGER,
    duration REAL, PRIMARY KEY (session_key, t, driver_number));
CREATE TABLE IF NOT EXISTS stints (session_key INTEGER, driver_number INTEGER, stint_number INTEGER,
    compound TEXT, lap_start INTEGER, lap_end INTEGER, tyre_age INTEGER,
    PRIMARY KEY (session_key, driver_number, stint_number));
CREATE TABLE IF NOT EXISTS race_control (session_key INTEGER, t REAL, category TEXT, flag TEXT,
    message TEXT, lap_number INTEGER, PRIMARY KEY (session_key, t, message));
CREATE TABLE IF NOT EXISTS overtakes (session_key INTEGER, t REAL, driver_number INTEGER,
    passed_number INTEGER, position INTEGER, kind TEXT);
CREATE INDEX IF NOT EXISTS ix_pos ON positions (session_key, t);
CREATE INDEX IF NOT EXISTS ix_int ON intervals (session_key, t);
CREATE INDEX IF NOT EXISTS ix_ovt ON overtakes (session_key, t);
"""


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    return db


# ── Overtake detection ───────────────────────────────────────────────────────

def classify_overtake(passer: int, passed: int, t: float, pit_times: dict[int, list[float]]) -> str:
    """Label a position swap as a real on-track pass or a pit-stop shuffle.

    The board shows "track" passes in bold and "pit" gains dimmed, so this is
    the rule that decides what counts as a proper overtake. Tweak it to taste:
    e.g. widen the window, or treat swaps under Safety Car as their own kind.
    """
    window = PIT_LANE_SECONDS + 15
    if any(t - window <= p <= t + 5 for p in pit_times.get(passed, [])):
        return "pit"  # the car "passed" was sitting in the pit lane
    if any(t - 5 <= p <= t + window for p in pit_times.get(passer, [])):
        return "pit"  # the passer jumped someone thanks to their own stop
    return "track"


class OvertakeTracker:
    """Replays position updates in time order and records who passed whom."""

    def __init__(self, db: sqlite3.Connection, sk: int) -> None:
        self.db, self.sk = db, sk
        self.order: dict[int, int] = {}  # driver -> current position
        self.last_t = 0.0

    def feed(self, rows: list[tuple[float, int, int]]) -> None:
        pit_times: dict[int, list[float]] = {}
        for t, dn in self.db.execute("SELECT t, driver_number FROM pits WHERE session_key=?", (self.sk,)):
            pit_times.setdefault(dn, []).append(t)
        found = []
        for t, dn, pos in sorted(rows):
            old = self.order.get(dn)
            if old is not None and pos < old:
                passed = [d for d, p in self.order.items() if d != dn and pos <= p < old]
                for victim in passed:
                    found.append((self.sk, t, dn, victim, self.order[victim],
                                  classify_overtake(dn, victim, t, pit_times)))
            self.order[dn] = pos
            self.last_t = max(self.last_t, t)
        if found:
            self.db.executemany("INSERT INTO overtakes VALUES (?,?,?,?,?,?)", found)


# ── Ingestion ────────────────────────────────────────────────────────────────

class Collector:
    def __init__(self, db: sqlite3.Connection, api: OpenF1, sk: int) -> None:
        self.db, self.api, self.sk = db, api, sk
        self.tracker = OvertakeTracker(db, sk)
        self.cursor: dict[str, float] = {}
        self.lock = threading.Lock()

    def _since(self, name: str) -> dict:
        t = self.cursor.get(name)
        return {"date__gt": iso_naive(t)} if t else {}

    def load_static(self) -> None:
        drivers = self.api.get("drivers", session_key=self.sk)
        self.db.executemany(
            "INSERT OR REPLACE INTO drivers VALUES (?,?,?,?,?,?)",
            [(self.sk, d["driver_number"], d.get("name_acronym") or str(d["driver_number"]),
              d.get("full_name") or d.get("broadcast_name") or "", d.get("team_name") or "",
              "#" + (d.get("team_colour") or "888888")) for d in drivers])
        self.db.commit()

    def poll(self) -> None:
        """Fetch everything newer than what we already have."""
        with self.lock:
            pits = self.api.get("pit", session_key=self.sk, **self._since("pit"))
            self.db.executemany("INSERT OR REPLACE INTO pits VALUES (?,?,?,?,?)", [
                (self.sk, ts(p["date"]), p["driver_number"], p.get("lap_number"),
                 p.get("pit_duration") or p.get("lane_duration")) for p in pits])
            if pits:
                self.cursor["pit"] = max(ts(p["date"]) for p in pits)

            pos = self.api.get("position", session_key=self.sk, **self._since("position"))
            rows = [(ts(p["date"]), p["driver_number"], p["position"]) for p in pos]
            self.db.executemany("INSERT INTO positions VALUES (?,?,?,?)", [(self.sk, *r) for r in rows])
            self.tracker.feed(rows)
            if rows:
                self.cursor["position"] = max(r[0] for r in rows)

            ints = self.api.get("intervals", session_key=self.sk, **self._since("intervals"))
            self.db.executemany("INSERT INTO intervals VALUES (?,?,?,?,?)", [
                (self.sk, ts(i["date"]), i["driver_number"],
                 None if i.get("gap_to_leader") is None else str(i["gap_to_leader"]),
                 None if i.get("interval") is None else str(i["interval"])) for i in ints])
            if ints:
                self.cursor["intervals"] = max(ts(i["date"]) for i in ints)

            rc = self.api.get("race_control", session_key=self.sk, **self._since("race_control"))
            self.db.executemany("INSERT OR IGNORE INTO race_control VALUES (?,?,?,?,?,?)", [
                (self.sk, ts(m["date"]), m.get("category"), m.get("flag"), m.get("message"),
                 m.get("lap_number")) for m in rc])
            if rc:
                self.cursor["race_control"] = max(ts(m["date"]) for m in rc)

            # Laps get their duration filled in after they finish, so re-read
            # the last few minutes each time instead of only new rows.
            since = self.cursor.get("laps")
            lap_filter = {"date_start__gt": iso_naive(since - 300)} if since else {}
            laps = self.api.get("laps", session_key=self.sk, **lap_filter)
            self.db.executemany("INSERT OR REPLACE INTO laps VALUES (?,?,?,?,?,?)", [
                (self.sk, l["driver_number"], l["lap_number"], ts(l.get("date_start")),
                 l.get("lap_duration"), int(bool(l.get("is_pit_out_lap")))) for l in laps])
            starts = [ts(l["date_start"]) for l in laps if l.get("date_start")]
            if starts:
                self.cursor["laps"] = max(starts)

            stints = self.api.get("stints", session_key=self.sk)
            self.db.executemany("INSERT OR REPLACE INTO stints VALUES (?,?,?,?,?,?,?)", [
                (self.sk, s["driver_number"], s["stint_number"], s.get("compound"), s.get("lap_start"),
                 s.get("lap_end"), s.get("tyre_age_at_start") or 0) for s in stints])
            self.db.commit()


def resolve_session(api: OpenF1, args) -> dict:
    if args.session and args.session != "latest":
        found = api.get("sessions", session_key=args.session)
    elif getattr(args, "year", None) and getattr(args, "gp", None):
        found = api.get("sessions", year=args.year, session_name=args.type)
        needle = args.gp.lower()
        found = [s for s in found if needle in " ".join(
            str(s.get(k, "")) for k in ("country_name", "location", "circuit_short_name")).lower()]
    else:
        found = api.get("sessions", session_key="latest")
    if not found:
        sys.exit("No matching session found on OpenF1.")
    return found[-1]


def save_session(db: sqlite3.Connection, s: dict) -> None:
    db.execute("INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?,?)", (
        s["session_key"], s.get("session_name"), s.get("circuit_short_name") or s.get("location"),
        s.get("country_name"), s.get("year"), ts(s.get("date_start")), ts(s.get("date_end"))))
    db.commit()


# ── State at a moment in time ────────────────────────────────────────────────

def fmt_gap(v: str | None) -> str:
    if v is None:
        return ""
    try:
        return f"+{float(v):.3f}"
    except ValueError:
        return v  # e.g. "+1 LAP"


def track_status(rc_rows) -> str:
    status = "GREEN"
    for category, flag, message in rc_rows:
        msg = (message or "").upper()
        if flag == "RED":
            status = "RED"
        elif flag == "CHEQUERED":
            status = "CHEQUERED"
        elif category == "SafetyCar" and "DEPLOYED" in msg:
            status = "VSC" if "VIRTUAL" in msg else "SC"
        elif flag in ("GREEN", "CLEAR") and "TRACK" in msg:
            status = "GREEN"
    return status


def build_state(db: sqlite3.Connection, sk: int, at: float, mode: str) -> dict:
    q = lambda sql, *a: db.execute(sql, (sk, *a)).fetchall()
    sess = db.execute("SELECT name, circuit, country, year FROM sessions WHERE session_key=?", (sk,)).fetchone()
    drivers = {r[0]: r[1:] for r in q("SELECT driver_number, acronym, full_name, team, colour FROM drivers WHERE session_key=?")}
    pos_now = {d: p for d, p, _ in q("SELECT driver_number, position, MAX(t) FROM positions WHERE session_key=? AND t<=? GROUP BY driver_number", at)}
    pos_start = {d: p for d, p, _ in q("SELECT driver_number, position, MIN(t) FROM positions WHERE session_key=? GROUP BY driver_number")}
    gaps = {d: (g, i) for d, g, i, _ in q("SELECT driver_number, gap, interval, MAX(t) FROM intervals WHERE session_key=? AND t<=? GROUP BY driver_number", at)}
    cur_lap = {d: n for d, n in q("SELECT driver_number, MAX(lap_number) FROM laps WHERE session_key=? AND t_start<=? GROUP BY driver_number", at)}
    done = q("SELECT driver_number, lap_number, duration FROM laps WHERE session_key=? AND duration IS NOT NULL AND t_start + duration <= ? ORDER BY lap_number", at)
    last_lap, best_lap = {}, {}
    for d, _, dur in done:
        last_lap[d] = dur
        best_lap[d] = min(dur, best_lap.get(d, 1e9))
    fastest = min(best_lap.values(), default=None)
    pit_rows = q("SELECT t, driver_number, lap_number, duration FROM pits WHERE session_key=? AND t<=? ORDER BY t", at)
    pit_count, in_pit = {}, set()
    for t, d, _, _ in pit_rows:
        pit_count[d] = pit_count.get(d, 0) + 1
        if at - t < PIT_LANE_SECONDS:
            in_pit.add(d)
    stints = q("SELECT driver_number, compound, lap_start, lap_end, tyre_age FROM stints WHERE session_key=? ORDER BY stint_number")

    rows = []
    for d, pos in pos_now.items():
        acr, name, team, colour = drivers.get(d, (str(d), "", "", "#888888"))
        lap = cur_lap.get(d, 0)
        compound, age = None, None
        for sd, comp, ls, le, ta in stints:
            if sd == d and (ls or 0) <= max(lap, 1):
                compound, age = comp, max(lap, 1) - (ls or 1) + (ta or 0)
        gap, interval = gaps.get(d, (None, None))
        rows.append({
            "num": d, "acr": acr, "name": name, "team": team, "colour": colour,
            "pos": pos, "start": pos_start.get(d, pos), "lap": lap,
            "gap": "LEADER" if pos == 1 else fmt_gap(gap), "interval": "" if pos == 1 else fmt_gap(interval),
            "last": last_lap.get(d), "best": best_lap.get(d),
            "fastest": fastest is not None and best_lap.get(d) == fastest,
            "compound": compound, "tyre_age": age, "pits": pit_count.get(d, 0), "in_pit": d in in_pit,
        })
    rows.sort(key=lambda r: r["pos"])

    acr = lambda n: drivers.get(n, (str(n),))[0]
    feed = []
    for t, d, v, p, kind in q("SELECT t, driver_number, passed_number, position, kind FROM overtakes WHERE session_key=? AND t<=? ORDER BY t DESC LIMIT 40", at):
        feed.append({"t": t, "type": "overtake", "kind": kind, "who": acr(d), "victim": acr(v), "pos": p,
                     "colour": drivers.get(d, ("", "", "", "#888888"))[3], "lap": cur_lap.get(d)})
    for t, d, lapno, dur in pit_rows[-20:]:
        feed.append({"t": t, "type": "pit", "who": acr(d), "lap": lapno, "duration": dur,
                     "colour": drivers.get(d, ("", "", "", "#888888"))[3]})
    rc = q("SELECT t, category, flag, message, lap_number FROM race_control WHERE session_key=? AND t<=? ORDER BY t", at)
    for t, cat, flag, msg, lapno in rc[-15:]:
        feed.append({"t": t, "type": "rc", "flag": flag, "category": cat, "text": msg, "lap": lapno})
    feed.sort(key=lambda e: -e["t"])

    return {
        "mode": mode, "clock": at,
        "session": {"name": sess[0], "circuit": sess[1], "country": sess[2], "year": sess[3]} if sess else {},
        "lap": max(cur_lap.values(), default=0),
        "status": track_status([(c, f, m) for _, c, f, m, _ in rc]),
        "drivers": rows, "feed": feed[:40],
    }


# ── Web server ───────────────────────────────────────────────────────────────

class App:
    def __init__(self, db, sk: int, mode: str, clock) -> None:
        self.db, self.sk, self.mode, self.clock = db, sk, mode, clock


def make_handler(app: App):
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(STATIC), **kw)

        def log_message(self, *a):  # keep the console quiet
            pass

        def do_GET(self):
            if self.path.startswith("/api/state"):
                body = json.dumps(build_state(app.db, app.sk, app.clock(), app.mode)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                super().do_GET()
    return Handler


def main() -> None:
    ap = argparse.ArgumentParser(description="F1 live timing board")
    sub = ap.add_subparsers(dest="cmd", required=True)
    live = sub.add_parser("live", help="follow the session happening now")
    live.add_argument("--session", default="latest")
    live.add_argument("--delay", type=float, default=3.0, help="seconds behind real time")
    rep = sub.add_parser("replay", help="replay a past session as if it were live")
    rep.add_argument("--session", help="OpenF1 session_key")
    rep.add_argument("--year", type=int)
    rep.add_argument("--gp", help="country or circuit, e.g. Monaco, Silverstone")
    rep.add_argument("--type", default="Race", help="Race, Sprint, Qualifying ...")
    rep.add_argument("--speed", type=float, default=1.0, help="playback speed multiplier")
    rep.add_argument("--start-min", type=float, default=0.0, help="start this many minutes in")
    for p in (live, rep):
        p.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    api, db = OpenF1(), connect()
    s = resolve_session(api, args)
    sk = s["session_key"]
    save_session(db, s)
    print(f"Session {sk}: {s.get('year')} {s.get('country_name')} · {s.get('session_name')}")
    col = Collector(db, api, sk)
    col.load_static()

    # Start the time-series tables clean so a restart never double-counts;
    # the overtake tracker rebuilds its table from the positions it reads.
    for table in ("positions", "intervals", "overtakes"):
        db.execute(f"DELETE FROM {table} WHERE session_key=?", (sk,))
    db.commit()

    if args.cmd == "replay":
        print("Downloading the full session into f1.db …")
        col.poll()
        first = db.execute("SELECT MIN(t) FROM positions WHERE session_key=?", (sk,)).fetchone()[0]
        t0 = (first or ts(s["date_start"])) + args.start_min * 60
        wall0 = time.time()
        clock = lambda: t0 + (time.time() - wall0) * args.speed
        mode = "REPLAY"
    else:
        def loop():
            while True:
                try:
                    col.poll()
                except Exception as e:  # keep the board alive through API hiccups
                    print("poll failed:", e)
                time.sleep(2)
        col.poll()
        threading.Thread(target=loop, daemon=True).start()
        clock = lambda: time.time() - args.delay
        mode = "LIVE"

    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(App(db, sk, mode, clock)))
    print(f"Board running at http://localhost:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
