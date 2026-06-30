#!/bin/sh
cd /home/protected/email_summary
exec ./venv/bin/python ./daemon_loop.py
