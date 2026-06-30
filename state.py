"""Persistent state for Gmail push pipeline.

Schema: {lastHistoryId: str|None, watchExpiration: str|None}
File lives alongside scripts so deployment is self-contained.
"""

import json
from pathlib import Path

STATE_FILE = Path(__file__).parent / "state.json"


def load():
    if not STATE_FILE.exists():
        return {"lastHistoryId": None, "watchExpiration": None}
    return json.loads(STATE_FILE.read_text())


def save(state):
    STATE_FILE.write_text(json.dumps(state, indent=2))


def update(**kwargs):
    s = load()
    s.update(kwargs)
    save(s)
    return s
