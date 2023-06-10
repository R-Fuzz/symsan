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

# import pdb; pdb.set_trace()
CONST_LABEL = 0
OPTIMISTIC = 1

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

memcmp_cache = collections.defaultdict(memcmp_msg)

def get_label_info(label):
    offset = label * ctypes.sizeof(dfsan_label_info)
    return dfsan_label_info.from_buffer(shm.buf[offset:offset+ctypes.sizeof(dfsan_label_info)])

def __handle_loop(id, addr):
    print(f"__handle_loop: id={id}, loop_header={hex(addr)}")
    

def __solve_cond(label, r, add_nested, addr):
    print(f"__solve_cond: label={label}, result={r}, add_cons={add_nested}, addr={hex(addr)}")
    # result = z3.BoolVal(r != 0, ctx=z3.__z3_context)

    # inputs = set()
    # cond = serialize(label, inputs)

    # # collect additional input deps
    # worklist = list(inputs)
    # while worklist:
    #     off = worklist.pop()

    #     deps = get_branch_dep(off)
    #     if deps is not None:
    #         for i in deps.input_deps:
    #             if i not in inputs:
    #                 inputs.add(i)
    #                 worklist.append(i)

    # __z3_solver.reset()
    # __z3_solver.set("timeout", 5000)
    
    # # 2. add constraints
    # added = set()
    # for off in inputs:
    #     deps = get_branch_dep(off)
    #     if deps is not None:
    #         for expr in deps.expr_deps:
    #             if expr not in added:
    #                 added.add(expr)
    #                 __z3_solver.add(expr)

    # assert(__z3_solver.check() == z3.sat)

    # e = (cond != result)
    # if z3.__solve_expr(e):
    #     print("branch solved")
    # else:
    #     print("branch not solvable @{}".format(addr))

    # # 3. nested branch
    # if add_nested:
    #     for off in inputs:
    #         c = get_branch_dep(off)
    #         if c is None:
    #             c = branch_dep_t()
    #             set_branch_dep(off, c)
    #         if c is None:
    #             print("WARNING: out of memory")
    #         else:
    #             c.input_deps.update(inputs)
    #             c.expr_deps.add(cond == result)

def __handle_gep(ptr_label, ptr, index_label, index, num_elems, elem_size, current_offset, addr):
    print(f"__handle_gep: ptr_label={ptr_label}, ptr={ptr}, index_label={index_label}, index={index}, "
          f"num_elems={num_elems}, elem_size={elem_size}, current_offset={current_offset}, addr={addr}")

def main(argv):
    global output_dir
    global input_buf
    global input_size
    global shm
    
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
        print(f"Failed to map shm({shm._fd}), size(shm.size)")
        return -1

    # pipefds[0] for read, pipefds[1] for write
    pipefds = os.pipe()

    # create and execute the child symsan process
    options = f"taint_file={input}:shm_id={shm._fd}:pipe_fd={pipefds[1]}:debug=0"
    try:
        proc = subprocess.Popen([program, input], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env={"TAINT_OPTIONS": options}, pass_fds=(shm._fd, pipefds[1]))
    except:
        print("Failed to execute subprocess")
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
                __solve_cond(msg.label, msg.result, msg.flags & CONST_LABEL, msg.addr)
            else:
                print(f"Loop exiting: {hex(msg.addr)}")
        elif msg.msg_type == MsgType.gep_type.value:
            gep_data = os.read(pipefds[0], ctypes.sizeof(gep_msg))
            gmsg = gep_msg.from_buffer_copy(gep_data)
            # Double check
            if msg.label != gmsg.index_label:
                print(f"Incorrect gep msg: {msg.label} vs {gmsg.index_label}")
                continue
            __handle_gep(gmsg.ptr_label, gmsg.ptr, gmsg.index_label, gmsg.index,
                        gmsg.num_elems, gmsg.elem_size, gmsg.current_offset, msg.addr)
        elif msg.msg_type == MsgType.memcmp_type.value:
            pass
            # info = get_label_info(msg.label)
            # if info.l1 != CONST_LABEL and info.l2 != CONST_LABEL:
            #     continue
            # print(f"dfsan_label_info: l1={info.l1}, l2={info.l2}, op1={info.op1.i}, op2={info.op2.i}, op={info.op}, size={info.size}, hash={info.hash}, msg_result={msg.result}")
            # memcmp_data = os.read(pipefds[0], ctypes.sizeof(memcmp_msg) + msg.result)
            # mmsg = memcmp_msg.from_buffer_copy(memcmp_data)
            # # Double check
            # if msg.label != mmsg.label:
            #     print(f"Incorrect memcmp msg: {msg.label} vs {mmsg.label}")
            #     continue
            # memcmp_cache[msg.label] = mmsg
        elif msg.msg_type == MsgType.loop_type.value:
            __handle_loop(msg.id, msg.addr)
        elif msg.msg_type == MsgType.fsize_type.value:
            pass
        else:
            print(f"Unknown message type: {msg.msg_type}", file=sys.stderr)

    os.close(pipefds[0])
    return 0

if __name__ == "__main__":
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
