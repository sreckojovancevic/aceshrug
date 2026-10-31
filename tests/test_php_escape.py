#!/usr/bin/env python3
"""Regresioni test serijalizatora manifesta (python_to_php_array / php_escape).

Python vrednost -> manifest.php -> PHP require -> JSON -> Python mora vratiti
iste vrednosti I ključeve (imena fajlova su ključevi u routes/includes).
Isti test builder pokreće u smoke testu pri svakom build-u.

Pokretanje (potreban PHP CLI):
    python3 tests/test_php_escape.py
"""
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BUILDER = os.path.join(HERE, "..", "builder", "aceshrug_build.py")

spec = importlib.util.spec_from_file_location("aceshrug_build", BUILDER)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

with tempfile.TemporaryDirectory() as d:
    ok = b.check_serializer_roundtrip(d)

for c in b.ROUNDTRIP_CASES:
    print(("OK  " if ok else "?   "), repr(c))
print("\nrezultat:", "sve prolazi" if ok else "KORUPCIJA (vidi poruku iznad)")
sys.exit(0 if ok else 1)
