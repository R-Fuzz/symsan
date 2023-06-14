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
import agent

class MsgType(Enum):
    cond_type = 0
    gep_type = 1
    memcmp_type = 2
    fsize_type = 3
    loop_type = 4

# 36 bytes
class pipe_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("msg_type", ctypes.c_uint16),
                ("flags", ctypes.c_uint16),
                ("instance_id", ctypes.c_uint32),
                ("addr", ctypes.c_ulong),
                ("context", ctypes.c_uint32),
                ("id", ctypes.c_uint32),
                ("label", ctypes.c_uint32),
                ("result", ctypes.c_uint64)]

# 48 bytes
class gep_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("ptr_label", ctypes.c_uint32),
                ("index_label", ctypes.c_uint32),
                ("ptr", ctypes.c_ulong),
                ("index", ctypes.c_int64),
                ("num_elems", ctypes.c_uint64),
                ("elem_size", ctypes.c_uint64),
                ("current_offset", ctypes.c_int64)]
# 4 bytes
class memcmp_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("label", ctypes.c_uint32),
                ("content", ctypes.c_ubyte * 0)]

class mazerunner_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("flags", ctypes.c_uint16),
                ("id", ctypes.c_uint32),
                ("addr", ctypes.c_ulong),
                ("context", ctypes.c_uint32),
                ("bb_dist", ctypes.c_uint64),
                ("avg_dist", ctypes.c_uint64)]
# 8 bytes
class data(ctypes.Union):
    _fields_ = [("i", ctypes.c_uint64),
                ("f", ctypes.c_float),
                ("d", ctypes.c_double)]
# 32 bytes
class dfsan_label_info(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("l1", ctypes.c_uint32),
                ("l2", ctypes.c_uint32),
                ("op1", data),
                ("op2", data),
                ("op", ctypes.c_uint16),
                ("size", ctypes.c_uint16),
                ("hash", ctypes.c_uint32)]

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
        shm = shared_memory.SharedMemory(create=True, size=0xc00000000)
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
