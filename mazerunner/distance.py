import networkx as nx
from collections import deque

class CFGraph:
    def __init__(self, cfg):
        self.cfg = cfg
        self.targets = set()
        self.prob = {}
    
    def _extract_location(self, node):
        def extract(nx_node):
            if 'label' not in nx_node:
                return ''
            label = nx_node['label']
            if "{%" in label:
                return ''
            return label.strip('{}:')
        
        return extract(self.cfg.nodes[node])

    # sys.setrecursionlimit(100000) in case CFG is too deep
    def _cal_prob_recursive(self, b, visited):
        visited.add(b)
        if b in self.prob:
            return
        if b in self.targets:
            self.prob[b] = 1.
            return

        jmp_prob = []
        call_prob = []
        for succ in self.cfg.successors(b):
            # skip loops in CFG
            if succ in visited and succ not in self.prob:
                continue
            if succ not in self.prob:
                self._cal_prob_recursive(succ, visited)
            if self.cfg[b][succ]['edge_type'] == 'call':
                call_prob.append(self.prob[succ])
            if self.cfg[b][succ]['edge_type'] == 'jmp':
                jmp_prob.append(self.prob[succ])
        # jmp edge
        if len(jmp_prob) <= 0:
            self.prob[b] = 0
        elif len(jmp_prob) == 1:
            self.prob[b] = jmp_prob[0]
        else:
            self.prob[b] = sum(jmp_prob) / len(jmp_prob)
        # call edge
        p_call = 1
        for p_call in call_prob:
            p_call *= (1 - p_call)
        self.prob[b] = 1 - (1 - self.prob[b]) * p_call

    def _cal_prob_iterative(self, b, visited):

        def cal_prob_helper(curr_n):
            jmp_prob = []
            call_prob = []
            for succ in self.cfg.successors(curr_n):
                # skip loops in CFG
                if succ not in self.prob:
                    continue
                if self.cfg[curr_n][succ]['edge_type'] == 'call':
                    call_prob.append(self.prob[succ])
                if self.cfg[curr_n][succ]['edge_type'] == 'jmp':
                    jmp_prob.append(self.prob[succ])
            # jmp edge
            if len(jmp_prob) <= 0:
                self.prob[curr_n] = 0
            elif len(jmp_prob) == 1:
                self.prob[curr_n] = jmp_prob[0]
            else:
                self.prob[curr_n] = sum(jmp_prob) / len(jmp_prob)
            # call edge
            p_call = 1
            for p_call in call_prob:
                p_call *= (1 - p_call)
            self.prob[curr_n] = 1 - (1 - self.prob[curr_n]) * p_call

        stack = [b]
        while stack:
            node = stack[-1]
            if node in visited:
                stack.pop()
                if node not in self.prob:
                    cal_prob_helper(node)
                continue
            visited.add(node)
            if node in self.targets:
                self.prob[node] = 1.
                stack.pop()
                continue
            all_successors_visited = True
            for succ in self.cfg.successors(node):
                if succ in visited and succ not in self.prob:
                    continue
                if succ not in visited:
                    all_successors_visited = False
                    stack.append(succ)
            if all_successors_visited:
                stack.pop()
                if node not in self.prob:
                    cal_prob_helper(node)

    def compute_target_prob(self):
        reachable_nodes = set()
        for target in self.targets:
            reachable_nodes.update(nx.ancestors(self.cfg, target))
        for b in reachable_nodes:
            visited = set()
            self._cal_prob_iterative(b, visited)
    
    def compute_targets_distances(self, targets):
        t = {node for node in self.cfg.nodes() if self._extract_location(node) in targets}
        self.targets.update(t)
        self.compute_target_prob()
        distances = {}
        for node, p in self.prob.items():
            if p != 0:
                distances[node] = 1 / p
        return distances

    def save_result(self, res, output_path):
        sorted_distances = dict(sorted(res.items(), key=lambda item: item[1]))
        with open(output_path, 'w') as f:
            for node, d in res.items():
                loc = self._extract_location(node)
                if loc and d:
                    f.write(f"{loc},{d}\n")

    def print_result(self, res):
        sorted_distances = dict(sorted(res.items(), key=lambda item: item[1]))
        for node, d in sorted_distances.items():
            loc = self._extract_location(node)
            if loc and d:
                print(f"{node},{d}")

if __name__ == '__main__':
    dot_file = 'merged_cfg.dot'
    targets = ['valid.c:2637']

    cfg = nx.DiGraph(nx.drawing.nx_agraph.read_dot(dot_file))
    g = CFGraph(cfg)
    res = g.compute_targets_distances(targets)
    g.save_result(res, "distance.cfg.txt")
