#!/bin/sh
# Start the NetCheck local web service.
#
# Uses the system Python 3.9 interpreter, which is the only one on this machine
# with FastAPI + uvicorn installed. Everything else is stdlib, so there are no
# dependencies to install.
#
# Usage:
#   sh run_netcheck.sh                 # bind 127.0.0.1:8777 (local-only)
#   sh run_netcheck.sh --port 9000     # custom port
#   sh run_netcheck.sh --host 0.0.0.0  # expose on LAN (no auth; use with care)

set -eu

# Resolve the directory this script lives in, so it works from any cwd.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# The system interpreter is the one with fastapi/uvicorn available here.
PYTHON="${NETCHECK_PYTHON:-/usr/bin/python3}"

if ! "$PYTHON" -c 'import fastapi, uvicorn' >/dev/null 2>&1; then
    echo "错误：$PYTHON 缺少 fastapi/uvicorn。" >&2
    echo "请安装：$PYTHON -m pip install fastapi uvicorn" >&2
    echo "或用 NETCHECK_PYTHON 指定其它已安装依赖的解释器。" >&2
    exit 1
fi

# Run as a module from the parent dir so the `netcheck` package imports cleanly.
cd "$SCRIPT_DIR"
exec "$PYTHON" -m netcheck.server "$@"
