import json
from typing import Optional
from os import PathLike
from logging import getLogger
import ctypes

from . import TerminationConditionBase
from .. import StopExecution, MeetCondition

logger = getLogger(__name__)

class BB(TerminationConditionBase):
    def __init__(self, manager, json_file:Optional[str]=None, whitelist=[], blacklist=[], stall=False) -> None:
        if json_file:
           json_data = json.load(open(json_file))
           self._whitelist = list(map(tuple,json_data.get("whitelist", [])))
           self._blacklist = list(map(tuple,json_data.get("blacklist", [])))
        else:
            self._whitelist = list(map(tuple, whitelist))
            self._blacklist = list(map(tuple, blacklist))
        self._bb = set()
        self._bb_all = set()
        self._stall = stall
        self._triggered = False
        self.call_stack = []
        self.current_bb = (-1, -1)

    def check(self, flags, addr, context, id, result) -> bool:
        return False

    def trace(self, flags, addr, context, id, result):
        pass

    def trace_bb(self, function_index, bb_index):
        function_index = ctypes.c_int32(function_index).value
        if function_index == -1:
            if self.call_stack:
                function_index, bb_index = self.call_stack.pop()
        elif bb_index == 0:
            self.call_stack.append(self.current_bb)
        self.current_bb = (function_index, bb_index)
        logger.debug("\033[92mTrace BB: %s\033[0m",str((function_index, bb_index)))
        # raise Exception("Trace BB!!")
        self._bb.add((function_index, bb_index))
        self._bb_all.add((function_index, bb_index))
        _has_all = True
        for i in self._whitelist:
            if i not in self._bb:
                _has_all = False
                break
        if self._whitelist[-1] != (function_index, bb_index): # use is in the last
            _has_all = False
        # print("BB: ", self._bb)
        # print("WL: ", self._whitelist)
        # print("BL: ", self._blacklist)
        logger.debug("\033[92mTracked BB: %s BB_ALL: %s CALL_STACK: %s\033[0m", str(self._bb), str(self._bb_all), str(self.call_stack))
        if _has_all:
            # print("Has all whitelisted BB")
            # input()
            if self._stall:
                raise MeetCondition("Has all whitelisted BB")
            else:
                self._triggered = True
        if (function_index, bb_index) in self._blacklist:
            # print("have blacklisted BB")
            # input()
            logger.debug("\033[92mHas Blacklisted BB\033[0m")

            raise StopExecution("Blacklisted BB")

    def reset(self):
        self._bb.clear()
        self.call_stack.clear()
        self.current_bb = (-1, -1)
        if self._triggered:
            raise MeetCondition("Has all whitelisted BB")

Bb = BB # export