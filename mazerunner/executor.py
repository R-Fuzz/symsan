#!/usr/bin/env python3

import os
import sys
import mmap
from multiprocessing import shared_memory
import subprocess
import ctypes
import collections
import z3
from enum import Enum
import logging

from config import *
from defs import *
import agent

# for output
output_dir = "."
__instance_id = 0
__session_id = 0
__current_index = 0
__z3_context = z3.Context()
__z3_solver = z3.SolverFor("QF_BV", ctx=__z3_context)

# caches
tsize_cache = {}
deps_cache = {}
expr_cache = {}
memcmp_cache = collections.defaultdict(memcmp_msg)
branch_deps = []

# Constants from dfsan.h
CONST_OFFSET = 1
kInitializingLabel = -1

agent = agent.Agent()
logger = logging.getLogger('mazerunner.executor')

def get_label_info(label):
    offset = label * ctypes.sizeof(dfsan_label_info)
    return dfsan_label_info.from_buffer(shm.buf[offset:offset+ctypes.sizeof(dfsan_label_info)])

def __handle_loop(id, addr):
    logger.debug(f"__handle_loop: id={id}, loop_header={hex(addr)}")
    
def __handle_new_state(id, addr, flag, callstack, bb_dis, avg_dis, action):
    global agent
    logger.debug(f"__handle_new_state: id={id}, addr={hex(addr)}, flag={flag}, callstack={callstack}, bb_dis={bb_dis}, avg_dis={avg_dis}")
    has_dist = False
    if flag & F_HAS_DISTANCE:
        has_dist = True
    agent.offline_learn(addr, callstack, action, avg_dis, has_dist)

def __solve_cond(label, r, add_nested, addr):
    logger.debug(f"__solve_cond: label={label}, result={r}, add_cons={add_nested}, addr={hex(addr)}")

def __handle_gep(ptr_label, ptr, index_label, index, num_elems, elem_size, current_offset, addr):
    logger.debug(f"__handle_gep: ptr_label={ptr_label}, ptr={ptr}, index_label={index_label}, index={index}, "
          f"num_elems={num_elems}, elem_size={elem_size}, current_offset={current_offset}, addr={addr}")

def main(argv):
    global output_dir, logger, input_buf, input_size, shm

    program = argv[1]
    input = argv[2]

    options = os.environ['TAINT_OPTIONS']
    if "output_dir=" in options:
        output = options.split("output_dir=")[1].split(":")[0].split(" ")[0]
        output_dir = output

    with open(input, "rb") as f:
        st = os.stat(input)
        input_size = st.st_size
        input_buf = mmap.mmap(f.fileno(), input_size, access=mmap.ACCESS_READ)

    # Create and map shared memory
    try:
        shm = shared_memory.SharedMemory(create=True, size=UNIONTABLE_SIZE)
    except:
        logger.error(f"Failed to map shm({shm._fd}), size(shm.size)")
        return -1

    # pipefds[0] for read, pipefds[1] for write
    pipefds = os.pipe()

    # create and execute the child symsan process
    options = f"taint_file={input}:shm_id={shm._fd}:pipe_fd={pipefds[1]}:debug=0"
    try:
        proc = subprocess.Popen([program, input], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env={"TAINT_OPTIONS": options}, pass_fds=(shm._fd, pipefds[1]))
    except:
        logger.error("Failed to execute subprocess")
        os.close(pipefds[0])
        os.close(pipefds[1])
        return -1
    os.close(pipefds[1])
    
    # process the request from symsan instrumented process
    while not proc.poll():
        msg_data = os.read(pipefds[0], ctypes.sizeof(pipe_msg))
        if not msg_data:
            break
        msg = pipe_msg.from_buffer_copy(msg_data)
        if msg.msg_type == MsgType.cond_type.value:
            if msg.label:
                __solve_cond(msg.label, msg.result, msg.flags & F_ADD_CONS, msg.addr)
                mazerunner_data = os.read(pipefds[0], ctypes.sizeof(mazerunner_msg))
                mmsg = mazerunner_msg.from_buffer_copy(mazerunner_data)
                __handle_new_state(mmsg.id, mmsg.addr, mmsg.flags, mmsg.context, mmsg.bb_dist, mmsg.avg_dist, msg.result)
            if (msg.flags & F_LOOP_EXIT) and (msg.flags & F_LOOP_LATCH):
                logger.debug(f"Loop exiting: {hex(msg.addr)}")
        elif msg.msg_type == MsgType.gep_type.value:
            gep_data = os.read(pipefds[0], ctypes.sizeof(gep_msg))
            gmsg = gep_msg.from_buffer_copy(gep_data)
            # Double check
            if msg.label != gmsg.index_label:
                logger.debug(f"Incorrect gep msg: {msg.label} vs {gmsg.index_label}")
                continue
            __handle_gep(gmsg.ptr_label, gmsg.ptr, gmsg.index_label, gmsg.index,
                        gmsg.num_elems, gmsg.elem_size, gmsg.current_offset, msg.addr)
        elif msg.msg_type == MsgType.memcmp_type.value:
            pass
        elif msg.msg_type == MsgType.loop_type.value:
            __handle_loop(msg.id, msg.addr)
        elif msg.msg_type == MsgType.fsize_type.value:
            pass
        else:
            logger.error(f"Unknown message type: {msg.msg_type}", file=sys.stderr)

    os.close(pipefds[0])
    return 0

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) != 3:
        print("Usage: {} target input".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    try:
        if main(sys.argv) < 0:
            sys.exit(1)
    finally:
        if shm:
            shm.close()
            shm.unlink()
