import collections
import os
import pickle
import re
import sys
from decimal import Decimal, getcontext
from functools import lru_cache
from pathlib import Path
import networkx as nx

# Retrieve function name for a CFG
get_fun_name = lambda cfg: cfg.graph['graph']['label'].split(" ")[2].strip("'")
# Returns nodes with zero in-degree, i.e., starting nodes.
get_starting_nodes = lambda G: [node for node in G.nodes if G.in_degree(node) == 0]
# Returns nodes with zero out-degree, i.e., ending nodes.
get_ending_nodes = lambda G: [node for node in G.nodes if G.out_degree(node) == 0]
# Compute a longer hash value for the old node name
compute_new_name = lambda old_name, fun_name: old_name + '_' + fun_name

@lru_cache
def get_starting_node(cfg):
    if len(cfg.nodes) == 1:
        return list(cfg.nodes)[0]
    nodes = get_starting_nodes(cfg)
    if len(nodes) != 1: # should have ONE starting node for a function
        print(f"function '{get_fun_name(cfg)}' has more than one entry, entries={str(nodes)}")
    return nodes[0]

@lru_cache
def cfg_preprocessing(cfg):
    to_be_removed = []
    for node in cfg.nodes:
        if 'Node' not in node:
            to_be_removed.append(node)
    for node in to_be_removed:
        cfg.remove_node(node)
    fun_name = get_fun_name(cfg)
    name_mapping = {node: compute_new_name(node, fun_name) for node in cfg.nodes}
    G_renamed = nx.relabel_nodes(cfg, name_mapping)
    for node, attrs in G_renamed.nodes(data=True):
        if '%' in attrs.get('label', ''):
            attrs['label'] = '"{' + fun_name + '_' + attrs['label'].strip('\"{}') + '}"'
    return G_renamed

def extract_loc(input_string):
    cleaned_string = input_string.strip('{}\"')
    if '_%' in cleaned_string:
        return cleaned_string
    parts = cleaned_string.split(':')
    return parts[0] + ':' + parts[1]

def get_program_entry():
    for cfg_path in cfg_folder.glob("cfg.*.dot"):
        if '13_main' in cfg_path.name:
            F_cfg = nx.DiGraph(nx.drawing.nx_pydot.read_dot(cfg_path))
            F_cfg = cfg_preprocessing(F_cfg)
            entry_node = get_starting_node(F_cfg)
            print(f'Using {os.path.basename(cfg_path)} as main function, entry_node={entry_node}')
            return entry_node
    return None

def get_program_exit():
    for cfg_path in cfg_folder.glob("cfg.*.dot"):
        if '_main_' in cfg_path.name:
            F_cfg = nx.DiGraph(nx.drawing.nx_pydot.read_dot(cfg_path))
            F_cfg = cfg_preprocessing(F_cfg)
            exit_nodes = get_ending_nodes(F_cfg)
            if not exit_nodes and len(F_cfg) == 1:
                exit_nodes = list(F_cfg.nodes)[0]
            if not exit_nodes:
                print(f'Using {os.path.basename(cfg_path)} as main function but cannot find any exit node')
            return exit_nodes
    return []

def get_exit_locs():
    exit_funs = ['_terminate_','_exit_','_Exit_','_abort_']
    locs = set()
    with open(direct_calls_path, 'r') as fd:
        for l in fd.readlines():
            s = l.split(',')
            for f in exit_funs:
                if f in s[1]:
                    locs.add(s[0])
    return locs

def build_function_cfgs():
    """
    Build and return a dictionary mapping each function name to its CFG.
    """
    function_cfgs = {}
    function_loc = {}
    function_mangle_mappping = collections.defaultdict(set)
    for cfg_path in cfg_folder.glob("cfg.*.dot"):
        print(f'Reading {cfg_path}', end='\r')    
        F_cfg = nx.DiGraph(nx.drawing.nx_pydot.read_dot(cfg_path))
        F_cfg = cfg_preprocessing(F_cfg)
        fname = get_fun_name(F_cfg)
        mangled_fname = os.path.basename(cfg_path).lstrip('cfg.').rstrip('.dot')
        function_cfgs[mangled_fname] = F_cfg
        entry_node = F_cfg.nodes[get_starting_node(F_cfg)]
        function_loc[extract_loc(entry_node['label'])] = mangled_fname
        function_mangle_mappping[fname].add(mangled_fname)
    return function_cfgs, function_loc, function_mangle_mappping

# function_cfgs: dict, {fun_name: fun_cfg}, parsed from cfg.*.dot
# function_loc: dict, {fun_loc: fun_name}, parsed from cfg.*.dot
# direct_callsite: dict, {code_loc: fun_name}, parsed from BBcalls.txt
# indirect_callsite: ditc, {caller_loc, callee_loc}, parsed from indirect.txt of selectfuzz
def merge_cfgs(function_cfgs):
    CFG_global = nx.DiGraph()
    CG = nx.DiGraph()
    exit_node = "Node_exit"
    CFG_global.add_node(exit_node)
    visited = set()

    # Link the current node (making the function call) to the starting node of the called function
    def link_function(source_node, target_fun, visited, is_indirect):
        target_node = merge_function(target_fun, visited)
        if target_node:
            if target_node not in CG: CG.add_node(target_node)
            if source_node not in CG: CG.add_node(source_node)
            CG.add_edge(source_node, target_node)            
            CFG_global.add_edge(source_node, target_node)
            if is_indirect:
                CFG_global[source_node][target_node]['edge_type'] = 'indirect call'
            else:
                CFG_global[source_node][target_node]['edge_type'] = 'direct call'

    def merge_function(fun_name, visited):
        if fun_name not in function_cfgs:
            return None
        G_func = function_cfgs[fun_name]
        node = get_starting_node(G_func)
        if node in visited:
            return node
        visited.add(node)
        for v, data in G_func.nodes(data=True):
            CFG_global.add_node(v, **data)
            CFG_global.nodes[v]['entry'] = node
            # If target node is a function call, replace with that function's CFG
            v_source = extract_loc(G_func.nodes[v]['label'])
            # direct calls
            if v_source in direct_callsite:
                for target_fun in direct_callsite[v_source]:
                    # print(f"Merging direct call {target_fun} into {fun_name}", end='\r')
                    link_function(v, target_fun, visited, False)
            # indirect calls
            if v_source in indirect_callsite:
                for target_fun in indirect_callsite[v_source]:
                    for mangled_fun in function_mangle_mappping[target_fun]:
                        # print(f"Merging indirect call {target_fun} into {fun_name}", end='\r')
                        link_function(v, mangled_fun , visited, True)
            # exit node
            if v_source in exit_locs:
                CFG_global.add_edge(v, exit_node)
                CFG_global[v][exit_node]['edge_type'] = 'jmp'
        for u, v in G_func.edges():
            CFG_global.add_edge(u, v)
            CFG_global[u][v]['edge_type'] = 'jmp'
        return node

    for starting_fun in function_cfgs:
        merge_function(starting_fun, visited)

    # draw exit nodes for main
    exits_nodes = get_program_exit()
    for ret_node in exits_nodes:
        CFG_global.add_edge(ret_node, exit_node)

    return CFG_global, CG

class CFGraph:
    # Constants
    ZERO = Decimal(0)
    ONE = Decimal(1)
    TWO = Decimal(2)

    def __init__(self, workdir):
        self.indirect_calls_enabled = has_indirect_calls
        self.compute_unreachable_enabled = False
        self.my_dir = workdir
        self.dist = {}
        self.visited = collections.Counter()
        self.reachable_nodes = set()
        self.unreachable_nodes = set()
        self._load_cfg()
        self._load_cg()
        self._get_targets()
    
    def _load_cfg(self):
        if self.indirect_calls_enabled:
            self.cfg = nx.DiGraph(nx.drawing.nx_agraph.read_dot(self.my_dir/'merged_cfg_indirect_calls.dot'))
        else:
            self.cfg = nx.DiGraph(nx.drawing.nx_agraph.read_dot(self.my_dir/'merged_cfg_direct_calls.dot'))
    
    def _load_cg(self):
        if self.indirect_calls_enabled:
            self.cg = nx.DiGraph(nx.drawing.nx_agraph.read_dot(self.my_dir/'indirect_call_sites.dot'))
        else:
            self.cg = nx.DiGraph(nx.drawing.nx_agraph.read_dot(self.my_dir/'direct_call_sites.dot'))

    def _get_targets(self):
        self.targets = set()
        targets_loc = set()
        with open(target_BB_file, 'r') as fd:
            for l in fd.readlines():
                if '.c:' not in l: continue
                targets_loc.add(l.strip())
        assert (len(targets_loc) > 0), "no target in the BBtargets.txt"
        t = {node for node in self.cfg.nodes if self.extract_location(node) in targets_loc}
        # if the target location not found in the CFG, this could be due to optimization or inlining.
        for node in t:
            self.targets.add(node)
        assert (len(self.targets) > 0), "no target in the CFG"

    def _cal_dist_helper(self, b, jmp_dist, dcall_dist, incall_dist):
        """
        Computes the probability based on jmp_dist and call_dist, Store the result into self.prob[b]
        
        Args:
            jmp_dist: A list of floats representing j_1, j_2, ..., j_p.
            call_dist: A list of floats representing c_1, c_2, ..., c_q.
        """
        # jmp edge
        if len(jmp_dist) == 0:
            self.dist[b] = CFGraph.prob_to_distance(CFGraph.ZERO)
        elif len(jmp_dist) == 1:
            self.dist[b] = jmp_dist[0]
        else:
            self.dist[b] = CFGraph.prob_to_distance(sum([CFGraph.distance_to_prob(d) for d in jmp_dist]) / len(jmp_dist))
        # indirect call edge
        if len(incall_dist) == 0:
            p_incall = CFGraph.ZERO
        elif len(incall_dist) == 1:
            p_incall = CFGraph.distance_to_prob(incall_dist[0])
        else:
            p_incall = sum([CFGraph.distance_to_prob(d) for d in incall_dist]) / len(incall_dist)
        # direct call edge
        p_call = CFGraph.ONE
        for d in dcall_dist:
            p_call *= (CFGraph.ONE - CFGraph.distance_to_prob(d))
        self.dist[b] = CFGraph.prob_to_distance(
            CFGraph.ONE - (
                (CFGraph.ONE - CFGraph.distance_to_prob(self.dist[b])) *
                (CFGraph.ONE - p_incall) * p_call)
        )

    def _should_unroll(self, node):
        if self.stage == 1 and self.visited[node] == 2 and node not in self.dist:
            return False
        if self.stage == 2 and self.visited[node] == 2 and self.dist[node] < 0:
            return False
        return True

    def _cal_dist_recursive(self, b):
        if ((self.stage == 1 and b in self.dist)
           or (self.stage == 2 and self.dist[b] >= 0)):
            return

        self.visited.update([b])
        assert self.visited[b] <= 2
        if b in self.targets:
            self.dist[b] = 0.
            return
        if b not in self.reachable_nodes:
            self.dist[b] = CFGraph.prob_to_distance(CFGraph.ZERO)
            return
        
        jmp_dist = []
        dcall_dist = []
        incall_dist = []
        for succ in self.cfg.successors(b):
            # unroll loops and recursive calls only once
            if not self._should_unroll(succ):
                continue
            if ((self.stage == 1 and succ not in self.dist)
               or (self.stage ==2 and self.dist[b] < 0)):
                self._cal_dist_recursive(succ)
            if self.cfg[b][succ]['edge_type'] == 'direct call':
                dcall_dist.append(self.dist[succ])
            if self.cfg[b][succ]['edge_type'] == 'indirect call':
                incall_dist.append(self.dist[succ])
            if self.cfg[b][succ]['edge_type'] == 'jmp':
                jmp_dist.append(self.dist[succ])
        if b in self.targets:
            self.dist[b] = 0.
        else:
            self._cal_dist_helper(b, jmp_dist, dcall_dist, incall_dist)

    def _compute_reachable_nodes(self, main_node):
        for target in self.targets:
            self.reachable_nodes.update(nx.ancestors(self.cfg, target))
        if not main_node:
            print("main entry not found")
            return False
        if main_node in self.reachable_nodes:
            return True
        return False

    def _compute_unreachable_nodes(self):
        # (1) nodes directly connect to the exit node
        def helper(current):
            visited.add(current)
            for pre_node in self.cfg.predecessors(current):
                successors = []
                for succ in self.cfg.successors(pre_node):
                    if 'call' not in g.cfg[pre_node][succ].get('edge_type', ''):
                        successors.append(succ)
                if len(successors) != 1 or pre_node in visited or pre_node in self.reachable_nodes:
                    continue
                self.unreachable_nodes.add(pre_node)
                helper(pre_node)

        visited = set()
        helper('Node_exit')
        # (2) both node and its all caller do not have a path to the targets
        may_reachable_nodes = set(self.cfg.nodes) - self.reachable_nodes - self.unreachable_nodes - {'Node_exit'}
        for current in may_reachable_nodes:
            fun_entry = self.cfg.nodes[current]['entry']
            if fun_entry not in self.cg:
                continue
            ret_sites = nx.ancestors(self.cg, fun_entry)
            if not ret_sites or all([ret not in self.reachable_nodes for ret in ret_sites]):
                self.unreachable_nodes.add(current)

    def _sort_reachable_nodes(self):
        # Calculate shortest path distance from each node to all targets and take the minimum
        node_distances = {}
        for node in self.reachable_nodes:
            min_distance = float('inf')
            for target in self.targets:
                try:
                    distance = nx.shortest_path_length(self.cfg, source=node, target=target)
                    min_distance = min(min_distance, distance)
                except nx.NetworkXNoPath:
                    continue
            node_distances[node] = min_distance
        # Sort nodes based on their distances to any target
        sorted_nodes = sorted(self.reachable_nodes, key=lambda node: node_distances[node])
        return sorted_nodes, node_distances[sorted_nodes[-1]]

    @staticmethod
    def distance_to_prob(d):
        """
        Converts a distance to a probability.
        Returns: 1 / 2 ** d
        """
        if d == -2.:
            return CFGraph.ZERO
        return CFGraph.ONE / (CFGraph.TWO ** Decimal(d))

    @staticmethod
    def prob_to_distance(p):
        """
        Converts a probability to a distance.
        Returns: -log_2(p)
        """
        if p == CFGraph.ZERO:
            return -2.
        res = - (p.ln() / CFGraph.TWO.ln())
        return float(res)
    
    def reset(self):
        self.dist.clear()
        self.visited.clear()
        self.reachable_nodes.clear()
        self.stage = 0

    def compute_target_dist_from_node(self, node):
        self._cal_dist_recursive(node)

    # compute the distance from source code loc
    def compute_target_dist_from_loc(self,loc):
        res = []
        loc_2_nodes = g.compute_loc_node_mapping()
        for n in loc_2_nodes[loc]:
            g.compute_target_dist_from_node(n)
            print(f"{n}: {g.dist[n]}")
            res.append((n, g.dist[n]))
        return res

    def compute_targets_distances(self):
        print("stage 0")
        self.stage = 0
        print("computing reachable nodes")
        for target in self.targets:
            self.dist[target] = 0.
        main_entry = get_program_entry()
        if not self._compute_reachable_nodes(main_entry):
            print("none of targets can be reached from main entry")
        max_len = 200
        # in case CFG is too deep
        sys.setrecursionlimit(100000)
        # in case the prob is too small, prevent precession loss
        getcontext().prec = max_len
        print(f"Decimal preccession: {max_len} \n"
              f"{len(self.reachable_nodes)} nodes are reachable")

        done = True
        print("stage 1")
        self.stage = 1
        for node in self.reachable_nodes:
            self.visited.clear()
            self._cal_dist_recursive(node)
            if node not in self.dist or self.dist[node] < 0:
                done = False

        rounds = 1
        self.stage = 2
        while not done:
            print(f"stage 2, round {rounds}", end = '\r')
            res = []
            for node in self.reachable_nodes:
                self.visited.clear()
                self._cal_dist_recursive(node)
                res.append(True if self.dist[node] >= 0 else False)
            done = False not in res
            rounds += 1

        if self.compute_unreachable_enabled:
            print("stage 3, computing unreachable nodes")
            self.stage = 3
            self._compute_unreachable_nodes()
            for node in self.unreachable_nodes:
                self.dist[node] = -1.

    # Returns a dict that maps source coude location and nodes
    # key: loc, value: list of nodes
    def compute_loc_node_mapping(self):
        loc_2_nodes = collections.defaultdict(list)
        for node, data in self.cfg.nodes(data=True):
            if node == 'Node_exit': continue
            loc = data['label'].strip('{}:')
            loc_2_nodes[loc].append(node)
        return loc_2_nodes

    def save_result(self, output_path):
        def sort_key(item):
            return item[1] if item[1] >= 0 else float('inf')

        distances = collections.defaultdict(list)
        for node, d in self.dist.items():
            loc = self.extract_location(node)
            if loc and d is not None and '_%' not in loc:
                distances[loc].append(d)
        # nodes can map to the same loc
        average_d = {key: sum(values) / len(values) for key, values in distances.items()}
        sorted_distances = dict(sorted(average_d.items(), key=sort_key))
        with open(output_path, 'w') as f:
            for loc, d in sorted_distances.items():
                if 'unamed' in loc:
                    continue
                if d < 0 and (d != -1 or not self.unreachable_nodes):
                    continue
                d = d * 1000 if d > 0 else d
                f.write(f"{loc},{d}\n")

    def print_result(self, res):
        sorted_distances = dict(sorted(res.items(), key=lambda item: item[1]))
        for node, d in sorted_distances.items():
            if node and d >= 0:
                print(f"{node},{d}")

    def extract_location(self, node):
        nx_node = self.cfg.nodes[node]
        if 'label' not in nx_node:
            return ''
        label = nx_node['label']
        if "_%" in label:
            return ''
        return extract_loc(label)

def parse_cfg(dot_file_path):
    G = nx.DiGraph(nx.drawing.nx_agraph.read_dot(dot_file_path))
    cfg_data = {}
    node_id_mapping = {}
    for node in G.nodes(data=True):
        node_name = node[0]
        if node_name == 'Node_exit':
            continue
        label = node[1].get('label', '')
        if 'id:' not in label:
            print(f'node {node_name} has no id')
            continue
        node_id = re.search(r"id:(\d+)", label).group(1)
        node_id_mapping[node_id] = node_name

    for node in G.nodes(data=True):
        node_name = node[0]
        label = node[1].get('label', '')
        if node_name == 'Node_exit' or 'id:' not in label:
            continue
        node_id = re.search(r"id:(\d+)", label).group(1)
        match = re.search(r'(\w+\.c:\d+):.*,T:(\d+),F:(\d+)', label)
        if match:
            _, true_id, false_id = match.groups()
            true_target = node_id_mapping[true_id]
            false_target = node_id_mapping[false_id]
            if true_target == false_target:
                continue
            true_line = G.nodes[true_target]['label'].split(',')[0].strip('{}:')
            true_line = ':'.join(true_line.split(':')[:2]) if '%' not in true_line and 'unamed' not in true_line else ''
            false_line = G.nodes[false_target]['label'].split(',')[0].strip('{}:')
            false_line = ':'.join(false_line.split(':')[:2]) if '%' not in false_line and 'unamed' not in false_line else ''
            cfg_data[node_id] = {'T': true_line, 'F': false_line}
    return cfg_data

def parse_distances(file_path):
    distance_data = {}
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.strip().split(',')
            if len(parts) == 2:
                file_line, distance = parts
                distance_data[file_line] = float(distance)
    return distance_data

def correlate_data(cfg_data, distance_data):
    result = {}
    for node_id, targets in cfg_data.items():
        true_dist = distance_data.get(targets['T'], None)
        false_dist = distance_data.get(targets['F'], None)
        if true_dist is not None or false_dist is not None:
            result[node_id] = (false_dist, true_dist)
    return result

if __name__ == '__main__':
    global cfg_folder, direct_calls_path, target_BB_file, has_indirect_calls, function_loc, \
        function_mangle_mappping, direct_callsite, indirect_callsite, exit_locs
    # setup paths
    tmp_folder = Path(sys.argv[1])
    if not tmp_folder.is_dir():
        print(f"{tmp_folder} is not a valid directory")
        sys.exit(1)
    cfg_folder = tmp_folder / "dot-files"
    direct_calls_path = tmp_folder / "direct_calls.txt"
    indirect_calls_path = tmp_folder / "indirect_calls.txt"
    target_BB_file = tmp_folder/'BBtargets.txt'
    target_fun_file = tmp_folder/'Ftargets.txt'
    has_indirect_calls = os.path.isfile(indirect_calls_path)
    # preprocessing after AFLGO_PREPROCESSING pass, remove repearted lines and invalid loc
    def remove_repeated_lines(fp):
        if not os.path.isfile(fp):
            print(f"{fp} does not exist")
            return
        lines = set()
        with open(fp, 'r') as f:
            for l in f.readlines():
                if not l: continue
                if l == '\n': continue
                lines.add(l)
        lines = list(lines)
        with open(fp, 'w') as f:
            f.writelines(lines)

    remove_repeated_lines(target_fun_file)
    remove_repeated_lines(target_BB_file)
    remove_repeated_lines(direct_calls_path)
    if has_indirect_calls:
        remove_repeated_lines(indirect_calls_path)
    
    # merge CFGs
    function_cfgs, function_loc, function_mangle_mappping = build_function_cfgs()
    exit_locs = get_exit_locs()
    direct_callsite = collections.defaultdict(list)
    indirect_callsite = collections.defaultdict(list)
    if has_indirect_calls:
        with open(indirect_calls_path, 'r') as fd:
            for l in fd.readlines():
                s = l.strip().split(',')
                indirect_callsite[s[0]].append(s[1])
    with open(direct_calls_path, 'r') as f:
        for l in f.readlines():
            s = l.strip().split(",")
            direct_callsite[s[0]].append(s[1])
    G, cg = merge_cfgs(function_cfgs)
    print(f"saving the merged indirect {G} ...")
    nx.drawing.nx_pydot.write_dot(G, tmp_folder / "merged_cfg_indirect_calls.dot")
    print(f"saving the indirect ret {cg}...")
    nx.drawing.nx_pydot.write_dot(G, tmp_folder / "indirect_call_sites.dot")
    indirect_callsite.clear()
    G, cg = merge_cfgs(function_cfgs)
    print(f"saving the merged direct {G} ...")
    nx.drawing.nx_pydot.write_dot(G, tmp_folder / "merged_cfg_direct_calls.dot")
    print(f"saving the direct ret {cg}...")
    nx.drawing.nx_pydot.write_dot(cg, tmp_folder / "direct_call_sites.dot")

    # compute distances
    g = CFGraph(tmp_folder)
    g.compute_targets_distances()
    out_path = tmp_folder/"distance.cfg.txt"
    print(f"saving result to {out_path}")
    g.save_result(out_path)
    
    # compute the initial policy
    if has_indirect_calls:
        cfg_data = parse_cfg(tmp_folder/'merged_cfg_indirect_calls.dot')
    else:
        cfg_data = parse_cfg(tmp_folder/'merged_cfg_direct_calls.dot')
    distance_data = parse_distances(tmp_folder/'distance.cfg.txt')
    policy = correlate_data(cfg_data, distance_data)
    print(f"saving initial policy to {tmp_folder/'policy.pkl'}")
    with open(tmp_folder/'policy.pkl', 'wb') as fd:
        pickle.dump(policy, fd)
