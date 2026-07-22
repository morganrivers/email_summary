#!/bin/sh
cd /home/protected/email_summary
exec ./venv/bin/python -m backend.daemons.daemon_loop
