from dotenv import load_dotenv
load_dotenv(".env")
import os, time, itertools
os.environ.setdefault("LANGCHAIN_API_KEY", os.environ.get("LANGSMITH_API_KEY", ""))
time.sleep(5)
from langsmith import Client
c = Client()
runs = list(itertools.islice(c.list_runs(project_name="email-drafter"), 8))
print(f"found {len(runs)} recent runs")
for r in runs:
    md = (r.extra or {}).get("metadata", {}) or {}
    sid = md.get("session_id")
    tid = md.get("thread_id")
    t = r.start_time.isoformat()[11:19]
    print(f"  {t}  name={r.name}  session_id={sid}  thread_id={tid}")
