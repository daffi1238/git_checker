#!/usr/bin/env python3
"""Entry point. ALWAYS run with `python3 -I` (isolated mode) so Python never imports modules
from the current directory (which may be the repository being analysed).

  gitcheck.py <repo> [--json out] [--report out.md] [--name n] [--no-llm] [--no-external]
  gitcheck.py sentinel <precheck|hook|ack|trust|untrust|status|rescan|record|cache-get|cache-put> …
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

if len(sys.argv) > 1 and sys.argv[1] == "sentinel":
    from checker.sentinel import main as sentinel_main  # noqa: E402
    sys.exit(sentinel_main(sys.argv[2:]))

from checker.main import main  # noqa: E402

sys.exit(main())
