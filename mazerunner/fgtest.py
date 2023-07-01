#!/usr/bin/env python3
import os
import sys
from multiprocessing import shared_memory
import subprocess
import ctypes
import logging

from config import *
from defs import *
from backend_solver import Solver

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# resources
pipefds = shm = proc = None

def tear_down():
    if pipefds:
        try:
            os.close(pipefds[0])
            os.close(pipefds[1])
        except OSError:
            pass
    if proc and not proc.poll():
        proc.kill()
        proc.wait()
    if shm:
        shm.close()
        shm.unlink()

def setup(input_file):
    global pipefds, shm, solver
    options = os.environ['TAINT_OPTIONS']
    output_dir = "."
    if "output_dir=" in options:
        output_dir = options.split("output_dir=")[1].split(":")[0].split(" ")[0]
    # Create and map shared memory
    try:
        shm = shared_memory.SharedMemory(create=True, size=UNIONTABLE_SIZE)
    except:
        logger.critical(f"setup: Failed to map shm({shm._fd}), size(shm.size)")
        sys.exit(1)
    # pipefds[0] for read, pipefds[1] for write
    pipefds = os.pipe()
    solver = Solver(shm, input_file, output_dir)

# create and execute the child symsan process
def run(program, input_file):
    global pipefds, proc
    options = f"taint_file={input_file}:shm_fd={shm._fd}:pipe_fd={pipefds[1]}:debug=0"
    try:
        proc = subprocess.Popen([program, input_file], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env={"TAINT_OPTIONS": options}, pass_fds=(shm._fd, pipefds[1]))
    except:
        logger.critical("run: Failed to execute subprocess")
        tear_down()
        sys.exit(1)
    os.close(pipefds[1])

def process_request():
    while not proc.poll():
        msg_data = os.read(pipefds[0], ctypes.sizeof(pipe_msg))
        if not msg_data:
            break
        msg = pipe_msg.from_buffer_copy(msg_data)
        if msg.msg_type == MsgType.cond_type.value:
            solver.handle_cond(msg, pipefds[0])
        elif msg.msg_type == MsgType.gep_type.value:
            gep_data = os.read(pipefds[0], ctypes.sizeof(gep_msg))
            gmsg = gep_msg.from_buffer_copy(gep_data)
            if msg.label != gmsg.index_label: # Double check
                logger.error(f"process_request: Incorrect gep msg: {msg.label} vs {gmsg.index_label}")
                continue
            if GEP_SOLVER_ENABLED: solver.handle_gep(gmsg, msg.addr)
        elif msg.msg_type == MsgType.memcmp_type.value:
            solver.handle_memcmp(msg, pipefds[0])
        elif msg.msg_type == MsgType.loop_type.value:
            solver.handle_loop_enter(msg.id, msg.addr)
        elif msg.msg_type == MsgType.fsize_type.value:
            pass
        else:
            logger.error(f"process_request: Unknown message type: {msg.msg_type}", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: {} target input".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)
    program = sys.argv[1]
    input_file = sys.argv[2]
    setup(input_file)
    run(program, input_file)
    process_request()
    tear_down()
