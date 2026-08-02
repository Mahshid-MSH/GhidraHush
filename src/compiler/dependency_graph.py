import os
import json

class DependencyGraph:
    @staticmethod
    def get_compilation_order(target_dir, c_files):
        """Sorts compilation order so callees are compiled before their callers."""
        graph_path = os.path.join(target_dir, "call_graph.json")
        if not os.path.exists(graph_path):
            return c_files

        with open(graph_path, 'r', encoding='utf-8') as f:
            call_graph = json.load(f)

        available_nodes = {f.replace('.c', '') for f in c_files}
        in_degree = {n: 0 for n in available_nodes}
        adj = {n: [] for n in available_nodes}

        for caller, callees in call_graph.items():
            if caller not in available_nodes:
                continue
            for callee in callees:
                if callee in available_nodes and callee != caller:
                    adj[callee].append(caller)
                    in_degree[caller] += 1

        queue = [n for n in available_nodes if in_degree[n] == 0]
        sorted_nodes = []

        while queue:
            current = queue.pop(0)
            sorted_nodes.append(current)
            for caller in adj[current]:
                in_degree[caller] -= 1
                if in_degree[caller] == 0:
                    queue.append(caller)

        remaining = [n for n in available_nodes if in_degree[n] > 0]
        if remaining:
            sorted_nodes.extend(sorted(remaining))

        return [f"{n}.c" for n in sorted_nodes]