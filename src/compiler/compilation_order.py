"""
compile_order.py -- callees before callers; cycles fall back to file order.
Tolerates call_graph entries being either full func_ids or bare names.
"""
import json
import os
import graphlib


def compilation_order(target_dir, files):
    by_base = {os.path.splitext(os.path.basename(f))[0]: f for f in files}
    graph_path = os.path.join(target_dir, "call_graph.json")
    if not os.path.exists(graph_path):
        return sorted(files)
    with open(graph_path, encoding="utf-8") as f:
        call_graph = json.load(f)

    ts = graphlib.TopologicalSorter()
    for caller, entry in call_graph.items():
        if caller not in by_base:
            continue
        callees = entry.get("callees", []) if isinstance(entry, dict) else entry
        for callee in callees:
            base = callee if callee in by_base else callee.rsplit("_", 1)[0]
            if base in by_base and base != caller:
                ts.add(caller, base)
    for name in by_base:
        ts.add(name)
    try:
        return [by_base[n] for n in ts.static_order()]
    except graphlib.CycleError:
        return sorted(files)   # prototypes-first makes order quality-only