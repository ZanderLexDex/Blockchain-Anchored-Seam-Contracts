#!/usr/bin/env python3
"""Deploy seam contracts + security engine on an agent workspace.
Usage: python deploy_agent.py --workspace /path/to/agent --db agent.db"""
import argparse, os, sys

def main():
    parser = argparse.ArgumentParser(description="Deploy Seam Contracts + Security Engine")
    parser.add_argument("--workspace", required=True, help="Agent workspace path")
    parser.add_argument("--db", default="agent.db", help="Database path")
    args = parser.parse_args()

    ws = os.path.abspath(args.workspace)
    db = os.path.join(ws, args.db) if not os.path.isabs(args.db) else args.db

    print(f"Deploying to: {ws}")
    print(f"Database: {db}")
    print()

    # 1. Initialize tracking database
    from seam_contracts import init_tracking_db
    init_tracking_db(db)
    print("1. Tracking database initialized (seam_contract + seam_verification + security_event tables)")

    # 2. Register immutable files
    from sanitize_engine import register_workspace, load_immutable_file_safe, _HASH_CACHE
    count = register_workspace(ws)
    print(f"2. Registered {count} immutable files for integrity monitoring")

    # 3. Verify all registered files
    failures = 0
    for filepath in list(_HASH_CACHE.keys()):
        try:
            load_immutable_file_safe(filepath, db)
        except Exception as e:
            print(f"   FAIL: {os.path.basename(filepath)} — {e}")
            failures += 1

    if failures:
        print(f"\n⚠️  {failures} files failed. Fix before proceeding.")
        sys.exit(1)
    else:
        print(f"3. All {count} files passed integrity + sanitization check")

    # 4. Summary
    print(f"""
{'='*50}
DEPLOYMENT COMPLETE
{'='*50}
Workspace:       {ws}
Database:        {db}
Files monitored: {count}
Status:          CLEAN

Next steps:
  - Add security_check.py to your daily cron
  - Call sanitize_text() at every seam boundary
  - Call load_immutable_file_safe() for bootstrap files
  - Define your seam contracts in JSON
  - Run: python seam_contracts.py verify --db {args.db} --contracts your_contracts.json
{'='*50}
""")

if __name__ == "__main__":
    main()
