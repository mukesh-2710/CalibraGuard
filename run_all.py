#!/usr/bin/env python3
"""One command: generate -> detect -> validate (incl. reproducibility) -> SQLite. Usage: python run_all.py [--small] [--skip-repro] [--sql-dump]"""
import sys, time
import generate, detect, validate, loaddb
t = time.time(); small = "--small" in sys.argv; out = "out"
params = dict(n_inst=200, n_cal=500, n_use=10000) if small else dict(n_inst=2000, n_cal=5000, n_use=100000)
print("1/4 generating (seed 20261022)", params); generate.generate(20261022, out=out, **params)
print("2/4 rules engine detection"); fd, ud, al = detect.run(out); print(f"    findings={len(fd)} alerts={len(al)}")
print("3/4 loading SQLite"); loaddb.load(out, "--sql-dump" in sys.argv)
print("4/4 validation\n"); validate.run(out, "--skip-repro" in sys.argv); print(f"\nDone in {time.time()-t:.0f}s. Start the app: python server.py  ->  http://localhost:8000")
