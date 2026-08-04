# Manual smoke scripts

Ad-hoc scripts that talk to the real Gmail, DeepSeek, and Telegram accounts.
Run them by hand against a box that is already provisioned:

```bash
venv/bin/python tools/manual/draft_pipeline.py
```

They used to sit in `tests/` with `test_` names, which meant `pytest tests/`
tried to collect them, executed their live API calls at import time, and aborted
the whole run before the real suite could start. The automated suite is
`tests/`, is hermetic (see `tests/conftest.py`), and needs no credentials.
