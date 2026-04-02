#!/usr/bin/env python3
"""Daily security sweep — workspace integrity + Unicode scanning.
Run via cron before morning routines. Exit 1 on any failure."""
import sys, os, json, argparse
from sanitize_engine import sanitize_text, register_workspace, load_immutable_file_safe, _HASH_CACHE, UnicodeSecurityError

def main():
    parser = argparse.ArgumentParser(description="Daily security check")
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--db", default="agent.db")
    parser.add_argument("--mutable", nargs="*", default=["MEMORY.md"], help="Mutable files to scan")
    args = parser.parse_args()

    failures = 0

    # 1. Register and verify immutable files
    count = register_workspace(args.workspace)
    print(f"Checking {count} immutable files in {args.workspace}...")

    for filepath in list(_HASH_CACHE.keys()):
        try:
            load_immutable_file_safe(filepath, args.db)
            print(f"  OK: {os.path.basename(filepath)}")
        except UnicodeSecurityError as e:
            print(f"  FAIL: {e}")
            failures += 1

    # 2. Scan mutable context files
    print(f"\nScanning {len(args.mutable)} mutable files...")
    for mutable in args.mutable:
        filepath = os.path.join(args.workspace, mutable)
        if not os.path.exists(filepath):
            continue
        try:
            with open(filepath) as f:
                _, report = sanitize_text(f.read(), f"scan:{mutable}", args.db)
            if report["max_severity"] == "CRITICAL":
                print(f"  CONTAMINATED: {mutable} — {report['modifications']} hidden chars")
                failures += 1
            else:
                print(f"  OK: {mutable}")
        except Exception as e:
            print(f"  ERROR: {mutable} — {e}")
            failures += 1

    # 3. Summary
    print(f"\n{'='*40}")
    if failures:
        print(f"⚠️  {failures} SECURITY FAILURES. HALT AND ALERT OPERATOR.")
        sys.exit(1)
    else:
        print(f"Security: ALL CLEAR ({count} files verified)")
        sys.exit(0)

if __name__ == "__main__":
    main()
