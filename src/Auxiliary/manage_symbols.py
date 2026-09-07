#!/usr/bin/env python3
"""
manage_symbols.py
------------------
Small CLI for maintaining a workspace's permanent global/type denylist.

Why this exists: dump_global_values.py's filters are heuristics and will
never catch every compiler/runtime artifact Ghidra surfaces. Editing the
generated data_globals.h by hand doesn't help -- it gets fully regenerated
from symbols.db on the very next run (of either dump_global_values.py or
c_code_enhancer.py), so anything you delete by hand just comes back. Use
this instead: it deletes the entry right now AND records a permanent
exclusion in the database, so it stays gone across every future run.

Usage:
    python manage_symbols.py --workspace . exclude-global was_init switchdataD_1400041a4
    python manage_symbols.py --workspace . exclude-type __mingwthr_key
    python manage_symbols.py --workspace . sync data_globals.h data_globals.c
    python manage_symbols.py --workspace . list
    python manage_symbols.py --workspace . unexclude-global was_init

The `sync` command is the fast path: hand-clean data_globals.h (and/or
data_globals.c) however you like -- delete every junk line, no need to
track names -- then run `sync` pointing at the file(s) you edited. It
diffs the DB's current globals/custom_types against what's still in the
file(s) and permanently excludes anything missing, in one shot, instead
of you calling exclude-global one name at a time.
"""
import argparse
import re,os,sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.symbol_db import SymbolDB

def main():
    parser = argparse.ArgumentParser(
        description="Manage the permanent global/type denylist for a SymbolDB workspace."
    )
    parser.add_argument("--workspace", default=".", help="Workspace directory containing symbols.db")
    sub = parser.add_subparsers(dest="command", required=True)

    p_excl = sub.add_parser("exclude-global", help="Permanently blacklist one or more globals by name")
    p_excl.add_argument("names", nargs="+")

    p_unexcl = sub.add_parser("unexclude-global", help="Remove one or more globals from the blacklist")
    p_unexcl.add_argument("names", nargs="+")

    p_excl_t = sub.add_parser("exclude-type", help="Permanently blacklist one or more custom types by name")
    p_excl_t.add_argument("names", nargs="+")

    p_unexcl_t = sub.add_parser("unexclude-type", help="Remove one or more custom types from the blacklist")
    p_unexcl_t.add_argument("names", nargs="+")

    sub.add_parser("list", help="List everything currently blacklisted")

    p_sync = sub.add_parser(
        "sync",
        help="Diff your hand-cleaned data_globals.h/.c against the DB and bulk-exclude everything you deleted",
    )
    p_sync.add_argument("files", nargs="+", help="Path(s) to your hand-edited data_globals.h and/or data_globals.c")

    args = parser.parse_args()
    db = SymbolDB(workspace_dir=args.workspace)

    if args.command == "exclude-global":
        for name in args.names:
            db.exclude_global(name)
            print(f"Excluded global: {name}")
    elif args.command == "unexclude-global":
        for name in args.names:
            db.unexclude_global(name)
            print(f"Un-excluded global: {name}")
    elif args.command == "exclude-type":
        for name in args.names:
            db.exclude_custom_type(name)
            print(f"Excluded type: {name}")
    elif args.command == "unexclude-type":
        for name in args.names:
            db.unexclude_custom_type(name)
            print(f"Un-excluded type: {name}")
    elif args.command == "list":
        globals_excluded = db.list_excluded_globals()
        types_excluded = db.list_excluded_custom_types()
        print(f"Excluded globals ({len(globals_excluded)}):")
        for name in globals_excluded:
            print(f"  {name}")
        print(f"Excluded types ({len(types_excluded)}):")
        for name in types_excluded:
            print(f"  {name}")
    elif args.command == "sync":
        # Read whatever files were handed in (typically the header and/or
        # the .c source you just hand-cleaned) into one blob, then treat
        # any DB name that no longer appears *anywhere* in that blob as
        # something you deleted on purpose -- bulk-exclude it instead of
        # making you type each name out individually.
        blob = ""
        for path in args.files:
            with open(path, "r", encoding="utf-8") as f:
                blob += f.read() + "\n"

        removed_globals = []
        for name in db.list_global_names():
            if not re.search(rf"\b{re.escape(name)}\b", blob):
                db.exclude_global(name)
                removed_globals.append(name)

        removed_types = []
        for name in db.list_custom_type_names():
            if not re.search(rf"\b{re.escape(name)}\b", blob):
                db.exclude_custom_type(name)
                removed_types.append(name)

        print(f"Detected {len(removed_globals)} global(s) you removed by hand -- permanently excluded:")
        for name in removed_globals:
            print(f"  {name}")
        print(f"Detected {len(removed_types)} type(s) you removed by hand -- permanently excluded:")
        for name in removed_types:
            print(f"  {name}")
        if not removed_globals and not removed_types:
            print("Nothing new to exclude -- the DB already matches what's in the file(s).")

    # Regenerate the header/source so an exclude/unexclude takes effect
    # immediately, without waiting for the next full dump or enhancer run.
    if args.command != "list":
        db.export_header("data_globals.h")
        db.export_source("data_globals.c")
        print("Regenerated data_globals.h/.c")


if __name__ == "__main__":
    main()