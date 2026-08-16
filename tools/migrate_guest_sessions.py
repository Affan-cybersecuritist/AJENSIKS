"""Move sessions stranded in the old shared `guest_devsecops_user` workspace into a real account.

Guest sign-in used to drop every unauthenticated visitor into one shared workspace. Requiring a
real sign-in made that directory unreachable from the UI, so any work done as "guest" is still
on disk but invisible. This copies those sessions into a signed-in account's workspace.

Usage:
    python tools/migrate_guest_sessions.py --list
    python tools/migrate_guest_sessions.py --to <your-supabase-user-id>
    python tools/migrate_guest_sessions.py --to <id> --move    # remove the guest copies after
"""
import argparse
import json
import os
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACES = os.path.join(ROOT, "user_workspaces")
GUEST = os.path.join(WORKSPACES, "guest_devsecops_user")


def load_index(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--to", help="destination Supabase user id")
    ap.add_argument("--list", action="store_true", help="show what is recoverable and exit")
    ap.add_argument("--move", action="store_true", help="delete the guest copy after copying")
    args = ap.parse_args()

    guest_sessions_dir = os.path.join(GUEST, "sessions")
    if not os.path.isdir(guest_sessions_dir):
        print("Nothing to migrate — no guest workspace found.")
        return

    index = load_index(os.path.join(guest_sessions_dir, "sessions_index.json"))
    titles = {s["id"]: s.get("title", "") for s in index}
    ids = sorted(d for d in os.listdir(guest_sessions_dir)
                 if d.startswith("session_") and os.path.isdir(os.path.join(guest_sessions_dir, d)))

    if not ids:
        print("Nothing to migrate — guest workspace has no sessions.")
        return

    print(f"{len(ids)} recoverable session(s) in the guest workspace:")
    for sid in ids:
        print(f"  {sid}  {titles.get(sid, '(untitled)')[:60]}")

    if args.list or not args.to:
        if not args.to:
            print("\nRe-run with --to <your-supabase-user-id> to migrate them.")
        return

    dest_sessions = os.path.join(WORKSPACES, args.to, "sessions")
    os.makedirs(dest_sessions, exist_ok=True)

    dest_index_path = os.path.join(dest_sessions, "sessions_index.json")
    dest_index = load_index(dest_index_path)
    existing = {s["id"] for s in dest_index}

    migrated = 0
    for sid in ids:
        src = os.path.join(guest_sessions_dir, sid)
        dst = os.path.join(dest_sessions, sid)
        if os.path.exists(dst):
            print(f"  skip {sid} (already present in destination)")
            continue
        shutil.copytree(src, dst)
        if sid not in existing:
            entry = next((s for s in index if s["id"] == sid), {"id": sid, "title": "Recovered session"})
            dest_index.insert(0, entry)
        migrated += 1
        if args.move:
            shutil.rmtree(src, ignore_errors=True)

    with open(dest_index_path, "w", encoding="utf-8") as f:
        json.dump(dest_index, f, indent=2)

    print(f"\nMigrated {migrated} session(s) into {args.to}.")
    print("Refresh the app — they'll appear in your sidebar.")


if __name__ == "__main__":
    main()
