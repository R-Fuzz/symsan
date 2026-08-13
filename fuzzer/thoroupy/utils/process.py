from multiprocessing import Process, active_children
from threading import Thread
import os
from time import sleep
import psutil

import resource
import atexit

from typing import Callable, Iterable, Mapping

def _guard(function: Callable, timeout:int, args, kwargs):
    def _exit():
        sleep(timeout)
        pid = os.getpid()
        for sp in psutil.process_iter():
            try:
                if sp.parent() and sp.parent().pid == pid:
                    for spp in psutil.process_iter():
                        if spp.parent() and spp.parent().pid == sp.pid:
                            spp.kill()
                            sleep(0.5)
                            if spp.is_running():
                                spp.terminate()
                    sp.kill()
                    sleep(0.5)
                    if sp.is_running():
                        sp.terminate()
            except:
                pass
        atexit._run_exitfuncs()
        os._exit(0)
    # _, hard = resource.getrlimit(resource.RLIMIT_AS)
    # resource.setrlimit(resource.RLIMIT_AS, (0xa00000000, hard))
    # Thread(target=_exit, daemon=True).start()
    thread = Process(target=function, args=args, kwargs=kwargs, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        pid = os.getpid()
        for sp in psutil.process_iter():
            try:
                if sp.parent() and sp.parent().pid == pid:
                    for spp in sp.children(recursive=True):
                        spp.kill()
                        sleep(0.5)
                        if spp.is_running():
                            spp.terminate()
                    sp.kill()
                    sleep(0.5)
                    if sp.is_running():
                        sp.terminate()
            except:
                pass
        thread.kill()
    atexit._run_exitfuncs()
    os._exit(0)
    

def process_guard(function:Callable, timeout=10, args:Iterable=[], kwargs:Mapping={}):
    """Run the function in a subprocess and kill it in the process 
    tree(including all child process) after timeout seconds

    Args:
        * `function` (Callable): function to run
        * `timeout` (int, optional): timeout in seconds. Defaults to 10.
        * `args` (list, optional): arguments for the function. Defaults to [].
        * `kwargs` (dict, optional): keyword arguments for the function. Defaults to {}.
    """
    p = Process(target=_guard, args=[function, timeout, args, kwargs])
    p.start()
    return p

def populate_gdb(binary_path: str, args:str, script_name:str = 'gdb', host_port:str = 'localhost:1234'):
    l = args.split()
    l.insert(l.index(binary_path), "gdb")
    cmd = " ".join(l)
    open(f"{script_name}.sh", "w").write(cmd)

    l = args.split()
    l.insert(l.index(binary_path), "gdbserver")
    l.insert(l.index(binary_path), host_port)
    cmd = " ".join(l)
    open(f"{script_name}-server.sh", "w").write(cmd)

    # make the script executable
    os.chmod(f"{script_name}.sh", 0o755)
    os.chmod(f"{script_name}-server.sh", 0o755)

if __name__ == "__main__":
    def _f():
        sleep(20)
        print("should not print")
    process_guard(_f)