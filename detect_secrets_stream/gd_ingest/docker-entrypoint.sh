#!/bin/bash
set -e

exec gunicorn --workers 1 --bind 0.0.0.0:5000 --worker-class gevent --keep-alive 75 --timeout 120 detect_secrets_stream.gd_ingest.api:app
