"""Persistent per-account state for the Gmail push pipeline.

Schema: {lastHistoryId: str|None, watchExpiration: str|None}

StateStore is keyed by file path, one per account, so a shared process holds
independent cursors per user. The backend is a plain JSON file today; a sealed
store can subclass without touching callers. There is no default account and
no default path: every account, including the box owner, gets
`database/<id>/state.json` unless a caller names something else.
"""

import json
from pathlib import Path


class StateStore:
    def __init__(self, path):
        self.path = Path(path)

    def load(self):
        if not self.path.exists():
            return {"lastHistoryId": None, "watchExpiration": None}
        return json.loads(self.path.read_text())

    def save(self, data):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2))

    def update(self, **kwargs):
        s = self.load()
        s.update(kwargs)
        self.save(s)
        return s
