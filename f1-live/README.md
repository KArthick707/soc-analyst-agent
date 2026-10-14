# F1 Live Board

A personal live timing board for Formula 1. It shows who is passing whom, places gained and lost since the start, gaps, tyres, pit stops and race control messages, and saves everything in a local SQLite database (`f1.db`).

Data comes from [OpenF1](https://openf1.org), a free, unofficial F1 data API. This is for personal use and is not affiliated with Formula 1.

## Run it

Needs Python 3.10 or newer. There is nothing to install.

```bash
# Replay a past race as if it were live (free, no account needed)
python f1live.py replay --year 2025 --gp Monaco --speed 8

# Start 40 minutes into the race, at normal speed
python f1live.py replay --year 2025 --gp Silverstone --start-min 40

# Follow the session that is running right now
export OPENF1_USERNAME=you@example.com
export OPENF1_PASSWORD=...
python f1live.py live
```

Open http://localhost:8000 in a browser. If you open `static/index.html` directly without the server, it runs a simulated demo race.

> OpenF1 serves historical data for free. Real-time data during a live session needs a paid OpenF1 account. Without one, use `replay` after the race ends. Data is usually available shortly after the session.

## What's on screen

| Area | Shows |
|---|---|
| Header | Grand Prix, lap counter, track status (green, SC, VSC, red, chequered) |
| Biggest gains / Dropped | Drivers who gained or lost the most places since the start |
| Classification | Position, ▲/▼ places vs. start, gap to leader, interval (DRS when under 1s), last lap (purple = fastest), tyre + age, pit stops. Rows slide when positions change, flashing green for a gain and red for a loss. |
| Race feed | Overtakes (on-track passes vs. gains made through pit stops), pit stops, race control messages |

## How it works

```
OpenF1 API ──poll every 2s──▶ f1live.py ──▶ f1.db (SQLite)
                                  │
                                  ├─ detects overtakes from position changes
                                  └─ /api/state ──▶ static/index.html (refreshes every 1s)
```

Database tables: `sessions`, `drivers`, `positions`, `intervals`, `laps`, `pits`, `stints`, `race_control`, `overtakes`. You can query them yourself, for example:

```bash
sqlite3 f1.db "SELECT d.acronym, COUNT(*) FROM overtakes o JOIN drivers d
  ON d.driver_number=o.driver_number AND d.session_key=o.session_key
  WHERE o.kind='track' GROUP BY 1 ORDER BY 2 DESC;"
```

The rule for what counts as a real overtake and what counts as a pit-stop gain is in `classify_overtake()` in `f1live.py`.
