import sys
import ctypes
import symsan

class pipe_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("type", ctypes.c_uint16),
                ("flags", ctypes.c_uint16),
                ("instance_id", ctypes.c_uint32),
                ("addr", ctypes.c_ulonglong),
                ("context", ctypes.c_uint32),
                ("id", ctypes.c_uint32),
                ("label", ctypes.c_uint32),
                ("result", ctypes.c_uint64)]

class memcmp_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("label", ctypes.c_uint32)]
    content = bytes()

class table_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("ptr", ctypes.c_ulonglong),
                ("num_elems", ctypes.c_ulonglong),
                ("elem_size", ctypes.c_ulonglong)]
    content = bytes()

prog = sys.argv[1]
file = sys.argv[2]

symsan.init(sys.argv[1])
symsan.config(file, args=[prog, file], debug=1, bounds=0)
symsan.run()

f = open(file, "rb")
buf = f.read()
symsan.reset_input([buf])

while True:
    e = symsan.read_event(ctypes.sizeof(pipe_msg))
    if len(e) < ctypes.sizeof(pipe_msg):
        break
    msg = pipe_msg.from_buffer_copy(e)
    print(f"received msg: type={msg.type}, flags={msg.flags}, "
          f"addr={msg.addr:x}, context={msg.context}, cid={msg.id}, "
          f"label={msg.label}, result={msg.result}")

    tasks = []
    if msg.type == 0:
        tasks = symsan.parse_cond(msg.label, msg.result, msg.flags)
        print(tasks)
    elif msg.type == 2 and msg.flags == 1:
        label = msg.label
        size = msg.result
        m = symsan.read_event(ctypes.sizeof(memcmp_msg) + size)
        if len(m) < ctypes.sizeof(memcmp_msg) + size:
            print("error reading memcmp msg")
            break
        buf = memcmp_msg.from_buffer_copy(m)
        if buf.label != label:
            print("error reading memcmp msg")
            break
        buf.content = m[ctypes.sizeof(memcmp_msg):]
        print(f"memcmp content: {buf.content.hex()}")
        symsan.record_memcmp(label, buf.content)
    elif msg.type == 11:
        # table_type: the z3 backend does not model tlookup, but the payload
        # still has to be consumed or every later message is misread
        size = msg.result
        m = symsan.read_event(ctypes.sizeof(table_msg) + size)
        if len(m) < ctypes.sizeof(table_msg) + size:
            print("error reading table msg")
            break
        tbl = table_msg.from_buffer_copy(m)
        tbl.content = m[ctypes.sizeof(table_msg):]
        print(f"table {tbl.ptr:x}: {tbl.num_elems} x {tbl.elem_size}, "
              f"{tbl.content.hex()}")

    for task in tasks:
        r, sols = symsan.solve_task(task)
        print(f"Status: {r}")
        for sol in sols:
            if sol['op'] == symsan.OpType.SET:
                print(f"  SET id={sol['id']} offset={sol['offset']} val={sol['val']:#x}")
            elif sol['op'] == symsan.OpType.INSERT:
                print(f"  INSERT id={sol['id']} offset={sol['offset']} data={sol['data'].hex()}")
            elif sol['op'] == symsan.OpType.DELETE:
                print(f"  DELETE id={sol['id']} offset={sol['offset']} len={sol['len']}")

status, is_killed = symsan.terminate()
print(f"exit status {status}, killed? {is_killed}")

symsan.destroy()

