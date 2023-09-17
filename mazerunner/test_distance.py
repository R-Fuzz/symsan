import networkx as nx
import pygraphviz as pgv
import unittest
from distance import CFGraph

class TestComputeDistances(unittest.TestCase):

    def helper(self, g, t):
        cfg = nx.DiGraph(pgv.AGraph(string=g))
        g = CFGraph(cfg)
        distances = g.compute_targets_distances(t)
        return distances

    def test_cfg_with_multiple_targets(self):
        graph = """
digraph "CFG for 'xmlAddID' function" {
    label="CFG for 'xmlAddID' function";
    Node0 [shape=record,label="{valid.c:2578:}"];
    Node0 -> Node1 [edge_type="jmp"];
    Node0 -> Node2 [edge_type="jmp"];
    Node1 [shape=record,label="{valid.c:2584:}"];
    Node1 -> Node3 [edge_type="jmp"];
    Node2 [shape=record,label="{valid.c:2586:}"];
    Node2 -> Node4 [edge_type="jmp"];
    Node2 -> Node5 [edge_type="jmp"];
    Node3 [shape=record,label="{valid.c:2587:}"];
    Node3 -> Node6 [edge_type="jmp"];
    Node4 [shape=record,label="{valid.c:2589:}"];
    Node4 -> Node7 [edge_type="jmp"];
    Node4 -> Node8 [edge_type="jmp"];
    Node7 [shape=record,label="{valid.c:2590:}"];
    Node7 -> Node6 [edge_type="jmp"];
    Node8 [shape=record,label="{valid.c:2596:}"];
    Node8 -> Node9 [edge_type="jmp"];
    Node8 -> Node10 [edge_type="jmp"];
    Node9 [shape=record,label="{valid.c:2598:}"];
    Node9 -> Node10 [edge_type="jmp"];
    Node10 [shape=record,label="{valid.c:2600:}"];
    Node10 -> Node11 [edge_type="jmp"];
    Node10 -> Node12 [edge_type="jmp"];
    Node11 [shape=record,label="{valid.c:2601:}"];
    Node11 -> Node6 [edge_type="jmp"];
    Node12 [shape=record,label="{valid.c:2606:}"];
    Node12 -> Node13 [edge_type="jmp"];
    Node12 -> Node14 [edge_type="jmp"];
    Node13 [shape=record,label="{valid.c:2608:}"];
    Node13 -> Node6 [edge_type="jmp"];
    Node14 [shape=record,label="{valid.c:2615:}"];
    Node14 -> Node15 [edge_type="jmp"];
    Node14 -> Node16 [edge_type="jmp"];
    Node15 [shape=record,label="{valid.c:2617:}"];
    Node15 -> Node17 [edge_type="jmp"];
    Node15 -> Node16 [edge_type="jmp"];
    Node17 [shape=record,label="{valid.c:2621:}"];
    Node17 -> Node18 [edge_type="jmp"];
    Node17 -> Node19 [edge_type="jmp"];
    Node18 [shape=record,label="{valid.c:2622:}"];
    Node18 -> Node20 [edge_type="jmp"];
    Node19 [shape=record,label="{valid.c:2624:}"];
    Node19 -> Node20 [edge_type="jmp"];
    Node20 [shape=record,label="{valid.c:2625:}"];
    Node20 -> Node21 [edge_type="jmp"];
    Node21 [shape=record,label="{valid.c:2627:}"];
    Node21 -> Node22 [edge_type="jmp"];
    Node22 [shape=record,label="{valid.c:2630:}"];
    Node22 -> Node23 [edge_type="jmp"];
    Node22 -> Node24 [edge_type="jmp"];
    Node23 [shape=record,label="{valid.c:2637:}"];
    Node23 -> Node25 [edge_type="jmp"];
    Node23 -> Node26 [edge_type="jmp"];
    Node25 [shape=record,label="{valid.c:2638:}"];
    Node25 -> Node26 [edge_type="jmp"];
    Node26 [shape=record,label="{valid.c:2642:}"];
    Node26 -> Node6 [edge_type="jmp"];
    Node24 [shape=record,label="{valid.c:2645:}"];
    Node24 -> Node27 [edge_type="jmp"];
    Node24 -> Node28 [edge_type="jmp"];
    Node27 [shape=record,label="{valid.c:2646:}"];
    Node27 -> Node28 [edge_type="jmp"];
    Node28 [shape=record,label="{valid.c:2647:}"];
    Node28 -> Node6 [edge_type="jmp"];
    Node6 [shape=record,label="{valid.c:2648:}"];
}
"""
        answer = {
        'Node23':1.0,
        'Node13':1.0,
        'Node12':1.7777777777777777,
        'Node22':2.0,
        'Node21':2.0,
        'Node20':2.0,
        'Node18':2.0,
        'Node19':2.0,
        'Node17':2.0,
        'Node10':3.5555555555555554,
        'Node9':3.5555555555555554,
        'Node8':3.5555555555555554,
        'Node15':4.0,
        'Node4':7.111111111111111,
        'Node14':8.0,
        'Node2':14.222222222222221,
        'Node0':28.444444444444443,
        }
        targets = ["valid.c:2637", "valid.c:2608"]
        self.assertEqual(self.helper(graph, targets), answer)

    def test_cfg_with_loop(self):
        graph = """
strict digraph "CFG for 'parseAndPrintFile' function" {
A [label="{valid.c:2615:}", shape=record];
B [label="{valid.c:2617:}", shape=record];
C [label="{valid.c:2621:}", shape=record];
D [label="{valid.c:2622:}", shape=record];
E [label="{valid.c:2624:}", shape=record];
F [label="{valid.c:2625:}", shape=record];
G [label="{valid.c:2627:}", shape=record];
H [label="{valid.c:2630:}", shape=record];
I [label="{valid.c:2637:}", shape=record];
J [label="{valid.c:2638:}", shape=record];
K [label="{valid.c:2642:}", shape=record];
L [label="{valid.c:2645:}", shape=record];
B -> A [edge_type="jmp"];
B -> D [edge_type="jmp"];
D -> E [edge_type="jmp"];
E -> C [edge_type="jmp"];
C -> L [edge_type="jmp"];
D -> F [edge_type="jmp"];
F -> G [edge_type="jmp"];
G -> H [edge_type="jmp"];
H -> I [edge_type="jmp"];
I -> J [edge_type="jmp"];
J -> F [edge_type="jmp"];
F -> K [edge_type="jmp"];
K -> L [edge_type="jmp"];
K -> I [edge_type="jmp"];
}
"""
        answer = {
        'I':1.0,
        'H':1.0,
        'G':1.0,
        'F':1.3333333333333333,
        'J':1.3333333333333333,
        'K':2.0,
        'D':2.6666666666666665,
        'B':5.333333333333333,
        }

        targets = ["valid.c:2637"]
        self.assertEqual(self.helper(graph, targets), answer)

    def test_cfg_with_call_edge(self):
        graph = """
strict digraph "CFG for 'parseAndPrintFile' function" {
A [label="{valid.c:2615:}", shape=record];
B [label="{valid.c:2617:}", shape=record];
C [label="{valid.c:2621:}", shape=record];
D [label="{valid.c:2622:}", shape=record];
E [label="{valid.c:2624:}", shape=record];
F [label="{valid.c:2625:}", shape=record];
G [label="{valid.c:2627:}", shape=record];
H [label="{valid.c:2630:}", shape=record];
I [label="{valid.c:2637:}", shape=record];
J [label="{valid.c:2638:}", shape=record];
K [label="{valid.c:2642:}", shape=record];
L [label="{valid.c:2645:}", shape=record];
B -> A [edge_type="jmp"];
B -> D [edge_type="jmp"];
D -> E [edge_type="jmp"];
E -> C [edge_type="jmp"];
C -> L [edge_type="jmp"];
D -> F [edge_type="jmp"];
F -> G [edge_type="call"];
G -> H [edge_type="jmp"];
H -> I [edge_type="jmp"];
I -> J [edge_type="jmp"];
F -> K [edge_type="jmp"];
K -> L [edge_type="jmp"];
K -> I [edge_type="jmp"];
}
"""
        answer = {
        'I':1.0,
        'H':1.0,
        'G':1.0,
        'F':1.0,
        'K':2.0,
        'D':2.0,
        'B':4.0,
        }

        targets = ["valid.c:2637"]
        self.assertEqual(self.helper(graph, targets), answer)

if __name__ == '__main__':
    unittest.main()
