#!/usr/bin/env python3
"""Punto de entrada. Ejecutar SIEMPRE con `python3 -I` (modo aislado): así Python no
importa módulos desde el directorio actual (que podría ser el repo analizado)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from checker.main import main  # noqa: E402

sys.exit(main())
