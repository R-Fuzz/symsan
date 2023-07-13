#!/usr/bin/env python3
import os
import sys
import angr
import pickle

def addr_convert(addr, old_base=0, new_base=0):
    return (addr-old_base+new_base)    

def append_loops(loops):
    looplist = []
    for loop in loops:
        loopinfo = {}
        loopinfo['entry'] = addr_convert(loop.entry.addr)
        loopinfo['back_edges'] = [(addr_convert(node[0].addr), addr_convert(node[1].addr)) for node in loop.continue_edges]
        loopinfo['break_edges'] = [(addr_convert(node[0].addr), addr_convert(node[1].addr)) for node in loop.break_edges]
        loopinfo['body_nodes'] = [addr_convert(node.addr) for node in loop.body_nodes]
        looplist.append(loopinfo)
        if not loop.subloops is None:
            for li in append_loops(loop.subloops):
                looplist.append(li)
    return looplist

def save_loop_info(infile, loopinfo_fp):
    proj = angr.Project(infile, load_options={'auto_load_libs': False})
    cfg = proj.analyses.CFGFast()
    loopFinder = proj.analyses.LoopFinder(functions=[f for f in cfg.kb.functions.values()])
    loopMap = []
    for (addr, loops) in loopFinder.loops_hierarchy.items():
        if len(loops) > 0:
            function = addr_convert(addr)
            looplist = append_loops(loops)
            loopMap.append((function,looplist))
    with open(loopinfo_fp, 'wb') as fp:
        pickle.dump(loopMap, fp, protocol=pickle.HIGHEST_PROTOCOL)

if __name__ == '__main__':
    infile = sys.argv[1]
    loopinfo_fp = sys.argv[2]
    if not os.path.isfile(infile):
        print(f'{infile} does not exists')
        sys.exit(1)
    loop_dir = os.path.dirname(loopinfo_fp)
    if not os.path.exists(loop_dir):
        print(f'{loop_dir} does not exists')
        sys.exit(1)
    save_loop_info(infile, loopinfo_fp)
