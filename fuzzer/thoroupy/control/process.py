import os
import logging
from typing import Any, Callable, Dict, Optional, List, Union
from subprocess import Popen, PIPE
import psutil

from .shared_memory import SharedMemory
from .pipe import Pipe
from .message import PipeMsg, UcsanTicket # type: ignore

logger = logging.getLogger(__name__)

class Process:
    def __init__(self, shm: Union[Optional[SharedMemory], int]=None, 
                       pipe_ct=None,
                       pipe_rpc=None,
                       env: Optional[Dict]=None,
                       args:List[str]=[],
                       target:str="echo",
                       logger:Optional[Callable]=None,
                       adapter: bool|Callable=False
                       ) -> None:
        self._modifier = []
        self._args = args
        if env is None:
            self._env = dict(os.environ)
        else:
            self._env = dict(env)
        if isinstance(shm, int):
            self._shm = SharedMemory(size=shm)
        else:
            self._shm = SharedMemory() if shm is None else shm
        self._modifier.append(self._shm)
        self._pipe = Pipe(flag="control_pipe_name") if pipe_ct is None else pipe_ct
        self._pipe_rpc = Pipe(flag="pipe_name", T=PipeMsg) if pipe_rpc is None else pipe_rpc
        self._modifier.append(self._pipe)
        self._modifier.append(self._pipe_rpc)
        if target is None:
            raise ValueError('target is None')
        self._target = target
        self._args.insert(0, target)
        self._logger = print if logger is None else logger
        self._adapter = adapter

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def reg(self, modifier: Callable[[Dict[str, str], List], None]) -> Callable[[Dict[str, str], List], None]:
        self._modifier.append(modifier)
        return modifier

    def get_output(self, size=1024) -> bytes:
        if self.output:
            return os.read(self.output, size)
        raise RuntimeError('output is None')

    def spawn(self) -> None:
        env = dict(self._env)
        args = self._args
        self.output, w = os.pipe()
        for modifier in self._modifier:
            modifier(env, args)

        # Build UCSAN_OPTIONS from _ucsan_options dict
        ucsan_options = []
        if '_ucsan_options' in env:
            ucsan_opts = env.pop('_ucsan_options')
            for k, v in ucsan_opts.items():
                ucsan_options.append(f"{k}={v}")

        # Build TAINT_OPTIONS from remaining env items
        taint_options = []
        for k, v in env.items():
            if not k.startswith('_'):  # skip internal keys
                taint_options.append(f"{k}={v}")

        if taint_options:
            env['TAINT_OPTIONS'] = ":".join(taint_options)
        if ucsan_options:
            env['UCSAN_OPTIONS'] = ":".join(ucsan_options)
        logger.debug(f"env: {env}, args: {args}")
        str_env = ' '.join([f'{k}={v}' for k,v in env.items()])
        if self._adapter:
            if callable(self._adapter):
                self._adapter(self._target, f"{str_env} {self._target} {' '.join(args[1:])}")
                return
            else:
                print(f"\033[94m{str_env} {self._target} {' '.join(args[1:])}\033[0m")
                return
        pid = os.fork()
        if pid == 0:
            os.close(self.output) # close reading end in the child
            os.dup2(w, 1) # send stdout to the pipe
            os.dup2(w, 2) # send stderr to the pipe
            os.close(w) # this descriptor is no longer needed
            os.execve(self._target, args, env)
            # input("Press Enter to continue...")
        else:
            self._p = psutil.Process(pid)
        # p = Popen([self._target, *args], env=env, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        # stdout, stderr = p.communicate()
        # print(stdout.decode('utf-8'), stderr.decode('utf-8'))

    def listen(self, handler=print):
        if handler == print:
            logger.warning("handler is print")
        for msg in self._pipe_rpc:
            handler(msg.__repr__())

    def close(self):
        exit_msg = UcsanTicket()
        exit_msg.msg_type = 0
        self._pipe.send(exit_msg)
        self._shm.close()
        self._pipe.close()

    def send(self, payload):
        self._pipe.send(payload)

    def get_pipe(self) -> Pipe:
        return self._pipe_rpc

    def get_union_table_shm_name(self) -> str:
        return self._shm.get_name()

    def is_alive(self) -> bool:
        if self._adapter: # skip as we are not able to get the pid since we are using adapter
            return True
        return self._p.status() in [psutil.STATUS_RUNNING, psutil.STATUS_SLEEPING, psutil.STATUS_DISK_SLEEP, psutil.STATUS_WAITING]
