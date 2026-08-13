import logging
import psutil
from sys import exit
import ctypes
import pickle
import time

from control import Process, GepMsg, PIPE_MSG_TYPE, PIPE_EVENT_TYPE, COND_FLAGS, MEMERR_TO_EVENT # type: ignore
from scheduler.fifo_scheduler import FIFOScheduler
from scheduler.hier_scheduler import HierachicalScheduler
from scheduler.policy_scheduler import PolicyScheduler
from scheduler.ternimation import StopExecution, TerminationManager
from handler import HandlerManager
from solver import Z3Solver, OpType
from scheduler.seed import Seed, UObjectMetadata
from utils import Config
from utils.elf import ELF
from utils.report import decorator_report
from utils.unittest_synth import TypeTable as SynthTypeTable, synthesize as synth_unittest
from debug_config import target_branch, auto_debug
from threading import Thread
import os
logger = logging.getLogger(__name__)

from typing import Callable, NoReturn, Optional

UNION_TABLE_SIZE = 0x7f000000 # FIXME: will mmap failed if set to 0x80000000

CHECKER_UBI = 150

ERROR_EVENTS = {
    'UBI': 150,
    'UAF': 151,
    'OOB': 152,
    'NULL_DEREF': 153,
    'DOUBLE_FREE': 156,
    'OOB_UPCAST': 161,
    'PANIC': 171,
}


class UcsanManager:
    def __init__(self, cmd, pause = False, seed: Optional[str]=None, output:Optional[str]=None, record_all = False, terminate=False,config="config.yaml",env={}, debug=False, report_to=None, save_seeds=False, trace_only=False, policy=None, **kwargs) -> None:
        """
        Initialize the UcsanManager
        @param cmd: the command to run, i.e. path to the binary to run
        @param pause: whether to pause the execution
        @param seed: path to the pickle file containing the seed to run
        @param output: path to the file to save the output
        @param terminate: whether to terminate the whole process execution after finish
        @param config: path to the config file or a dict containing the config
        @param env: a dict containing the environment variables to pass to the binary
        @param debug: whether to enable debug mode
        @param report_to: a function to report the result to, i.e. a function that takes an exit status and a seed
        @param save_seeds: whether to save all the seeds
        @param adapter: a function to hook before the binary is executed
        """
        self.config = Config(config)
        self._target = cmd
        self._weak_ref = []
        target = cmd.split()[0]
        self.binary_path = target
        args = cmd.split()[1:]
        union_table_size:int = self.config.get("union_table_size", UNION_TABLE_SIZE) # type: ignore
        # UCSAN-specific options (passed via UCSAN_OPTIONS)
        _ucsan_opts = {"trace_object": "1"}
        if debug:
            _ucsan_opts['debug'] = '1'
        # Merge any user-provided ucsan options
        if 'ucsan_options' in env:
            _ucsan_opts.update(env.pop('ucsan_options'))
        # When loop skip_solve is enabled, disable runtime loop bounds enforcement
        _term_cfg = self.config.get("termination", None)
        if _term_cfg and 'loop' in _term_cfg and _term_cfg._current['loop']:
            _loop_cfg = _term_cfg._current['loop']
            if isinstance(_loop_cfg, dict) and _loop_cfg.get('skip_solve', False):
                _ucsan_opts['disable_loop_bounds'] = '1'
        _env = {'_ucsan_options': _ucsan_opts}
        # debug goes to TAINT_OPTIONS as well
        if debug:
            _env['debug'] = '1'
        _env.update(env)
        self.elf = ELF(target) if self.config.get("debug_info", False) else None
        UObjectMetadata._elf = self.elf
        self.p = Process(env=_env, target=target, args=args, logger=lambda x: logger.debug(x), shm=union_table_size, **kwargs)
        self.p.spawn()
        self._monitor_thread = Thread(target=self._output_monitor, daemon=True)
        self._monitor_thread.start()
        if policy:
            self.scheduler = PolicyScheduler(policy, save_seeds=save_seeds)
        else:
            self.scheduler = FIFOScheduler(performance=False, save_seeds=save_seeds)
        # self.scheduler = HierachicalScheduler(performance=False, save_seeds=save_seeds)
        if seed:
            self.scheduler.loads(seed)
        self.solver = Z3Solver()
        self._termination_manager = TerminationManager(self.config, self.p._pipe)
        self._event_handlers = HandlerManager(self)
        self._reported_seed = []
        self._reported = set()
        self._pause = pause
        self._output = output
        self._terminate = terminate
        self.exit_status = list()
        self._report_to = decorator_report(report_to)
        self._last_label = 0
        self._last_result = 0
        self._last_addr = 0
        self._ub_solve_seen = set()
        self.solver.initialize(self.p.get_union_table_shm_name(), union_table_size)

        self._stall = False
        self._epilogued = False
        self._bug_reported_for_current_seed = False

        self._stop_requested = False
        self._trace_only = trace_only
        self._auto_debug = auto_debug
        self._enum_index = self.config.get("enum_index", True)

        # Unit test synthesis
        self._synth_type_table = None
        self._synth_output_dir = self.config.get("unittest_output", None)
        type_table_path = self.config.get("type_table", None)
        if type_table_path and os.path.exists(type_table_path):
            self._synth_type_table = SynthTypeTable(type_table_path)

        # Stop-on-error: set of exit status codes that should halt execution
        _stop_cfg = self.config.get("stop_on_error", None)
        if _stop_cfg is None or _stop_cfg is True:
            self._stop_on_error = set(ERROR_EVENTS.values())
        elif _stop_cfg is False:
            self._stop_on_error = set()
        else:
            self._stop_on_error = set()
            for entry in _stop_cfg:
                if isinstance(entry, int):
                    self._stop_on_error.add(entry)
                elif isinstance(entry, str) and entry.upper() in ERROR_EVENTS:
                    self._stop_on_error.add(ERROR_EVENTS[entry.upper()])

        # Debug: flip verification for a target branch
        self._flip_verify = bool(target_branch and target_branch.get("verify_flip"))
        self._flip_bid = target_branch.get("bid") if self._flip_verify else None
        self._flip_pending = None          # seed to immediately verify after current execution
        self._flip_original_result = None  # result seen when generating the solution
        self._flip_original_context = None # context seen when generating the solution
        self._flip_verifying = False       # True when we're replaying the flip seed
        self._flip_succeeded = False       # True if flip was confirmed during replay
        self._flip_expecting_cond = False  # True after BB trace, waiting for target COND
        self._flip_task_id = None          # solving task that produced the flip solution
        self._stop_if_not_flipped = bool(target_branch and target_branch.get("stop_if_not_flipped"))
        self._stop_if_not_reached = bool(target_branch and target_branch.get("stop_if_not_reached"))
        self._flip_original_occurrence = target_branch.get("occurrence", 0) if self._flip_verify else 0
        self._cond_occurrence = {}          # (bid,context) -> count during current execution

    def _output_monitor(self):
        _logger = logging.getLogger("output_monitor")
        while True:
            _logger.debug("\033[96m\n" + self.p.get_output(2**15).decode("utf-8") + '\033[0m')

    def _handle_msg(self, msg) -> bool:
        """
        Return True if the program is still running and should wait for further messages
        """
        match msg.msg_type:
            case PIPE_MSG_TYPE.COND_TYPE:
                if self._stall:
                    return True
                if self._trace_only:
                    return True
                if hasattr(self.scheduler, "trace_branch"):
                    self.scheduler.trace_branch(
                        msg.id, msg.result, msg.addr, msg.context
                    )
                # Track occurrence of (bid, context)
                _cond_key = (msg.id, msg.context)
                self._cond_occurrence[_cond_key] = self._cond_occurrence.get(_cond_key, 0) + 1
                _occurrence = self._cond_occurrence[_cond_key]
                # Flip verification: check result when replaying the flip seed
                if self._flip_verifying and msg.id == self._flip_bid and msg.context == self._flip_original_context:
                    self._flip_expecting_cond = False  # target bid received, clear BB expectation
                    if _occurrence == self._flip_original_occurrence:
                        self._flip_verifying = False
                        if msg.label == 0:
                            logger.critical(f"[FLIP-DBG] *** NOT SYMBOLIC *** bid={msg.id}, context={msg.context:#x}, occurrence={_occurrence}: reached but branch is not symbolic during replay, task_id={self._flip_task_id}")
                            logger.critical(f"[FLIP-DBG]   seed used: {self._current}")
                            self._flip_succeeded = False
                        else:
                            flipped = (self._flip_original_result != msg.result)
                            tag = "FLIPPED" if flipped else "NOT FLIPPED"
                            logger.critical(f"[FLIP-DBG] *** {tag} *** bid={msg.id}, context={msg.context:#x}, occurrence={_occurrence}: original_result={self._flip_original_result}, new_result={msg.result}, task_id={self._flip_task_id}")
                            logger.critical(f"[FLIP-DBG]   seed used: {self._current}")
                            self._flip_succeeded = flipped
                is_ub_solve = msg.id < 100000
                # UB checks are emitted as reserved low bids with flags=0, but
                # their solutions still need the current path constraints.
                # Otherwise the generated seed can satisfy the UB predicate
                # while diverging before the checked access.
                add_nested = ((msg.flags & COND_FLAGS.ADD_CONS) != 0
                              or is_ub_solve)
                # UB-solving ids are shared across instrumentation sites
                # (for example, ub_index_underflow is always id 6).  Deduping
                # only by (label, id) can suppress the same symbolic predicate
                # when it is emitted at a later, security-relevant check site.
                # Keep the spam guard, but make it call-site/context sensitive.
                ub_key = (msg.label, msg.id, msg.addr, msg.context)
                should_solve = False
                if is_ub_solve:
                    should_solve = ub_key not in self._ub_solve_seen
                    self._ub_solve_seen.add(ub_key)
                else:
                    is_loop_related = (msg.flags & 0x6) != 0
                    loop_termination_disabled = (
                        is_loop_related
                        and hasattr(self.scheduler, "should_disable_loop_termination")
                        and self.scheduler.should_disable_loop_termination(msg.id)
                    )
                    if loop_termination_disabled:
                        logger.critical(
                            "[Plan] Skipping loop termination solve for "
                            "bid=%s (flags=%s, result=%s)",
                            msg.id,
                            msg.flags,
                            msg.result,
                        )
                        should_solve = False
                    else:
                        should_solve = self._termination_manager.check(
                            msg.flags, msg.addr, msg.context, msg.id, msg.result)
                    should_solve_policy_loop_target = (
                        not loop_termination_disabled
                        and hasattr(self.scheduler, "should_solve_policy_loop_target")
                        and self.scheduler.should_solve_policy_loop_target(
                            msg.id, msg.result
                        )
                    )
                    should_force_solve_policy_target = (
                        hasattr(self.scheduler, "should_force_solve_policy_target")
                        and self.scheduler.should_force_solve_policy_target(
                            msg.id, msg.result, msg.addr
                        )
                    )
                    if not should_solve and should_solve_policy_loop_target and is_loop_related:
                        # Explicit policy targets must be solvable even when loop
                        # handling is globally suppressed via skip_solve. The
                        # policy scheduler caps retries to avoid path explosion.
                        logger.critical(
                            "[Plan] Solving loop-related policy target bid=%s "
                            "(flags=%s, result=%s)",
                            msg.id,
                            msg.flags,
                            msg.result,
                        )
                        should_solve = True
                    if not should_solve and should_force_solve_policy_target:
                        # A policy target can be globally "seen" in an
                        # uninteresting suffix-only execution.  Re-solve it
                        # after the current trace has confirmed the required
                        # prefix bridge.
                        logger.critical(
                            "[Plan] Force-solving contextual policy target "
                            "bid=%s (result=%s)",
                            msg.id,
                            msg.result,
                        )
                        should_solve = True
                if should_solve:
                    if msg.label == 0:
                        return True
                    elif msg.label == 0xfffffffe: # kUninitialized = -2
                        _msg = lambda: None # create a struct
                        _msg.context = CHECKER_UBI
                        _msg.addr = msg.addr
                        self._event_handlers.handle(_msg)
                        self._report(CHECKER_UBI)
                        self._stall = True
                        return True
                    self._last_label = msg.label
                    self._last_result = msg.result
                    self._last_addr = msg.addr
                    _is_target_bid = self._flip_verify and msg.id == self._flip_bid
                    if _is_target_bid:
                        logger.critical(f"[FLIP-DBG] Hit target bid={msg.id}, label={msg.label:#x}, result={msg.result}, context={msg.context:#x}")
                    try:
                        is_policy_target = (
                            hasattr(self.scheduler, "is_target_bid")
                            and self.scheduler.is_target_bid(msg.id)
                        )
                        try:
                            task_ids = self.solver.parse_cond(msg.label, msg.result, add_nested)
                        except Exception:
                            if not (add_nested and is_policy_target):
                                raise
                            logger.warning(
                                "[Plan] Retrying policy target bid=%s without "
                                "nested constraints after parse failure",
                                msg.id,
                            )
                            task_ids = self.solver.parse_cond(
                                msg.label, msg.result, False
                            )
                        saw_solution = False
                        for task_id in task_ids:
                            # Concrete replay (trace_only): never solve/queue.  Check
                            # BEFORE solve_task — solving is the expensive SMT, and in
                            # trace_only the solution is discarded anyway, so doing it
                            # was pure waste (it churned per loop-iteration branch).
                            if self._trace_only:
                                continue
                            if _is_target_bid or is_policy_target:
                                smt_file = f"task_{msg.id}_{task_id}.smt2"
                                try:
                                    self.solver.export_task_smt2(task_id, smt_file)
                                    logger.critical(
                                        f"[FLIP-DBG]   exported task {task_id} "
                                        f"for bid={msg.id} to {smt_file}"
                                    )
                                except Exception as e:
                                    logger.error(f"[FLIP-DBG]   failed to export SMT2: {e}")
                            status, solutions = self.solver.solve_task(task_id)
                            if _is_target_bid or is_policy_target:
                                logger.critical(
                                    f"[FLIP-DBG]   task {task_id} for "
                                    f"bid={msg.id}: status={status}, "
                                    f"#solutions={len(solutions) if solutions else 0}"
                                )
                            if solutions:
                                saw_solution = True
                                seed = self._current.clone()
                                seed.flip_meta = None  # don't inherit parent's flip_meta
                                self._apply_solutions(seed, solutions)
                                if _is_target_bid:
                                    logger.critical(f"[FLIP-DBG]   solutions: {solutions}")
                                    logger.critical(f"[FLIP-DBG]   original seed: {self._current}")
                                    logger.critical(f"[FLIP-DBG]   mutated  seed: {seed}")
                                if (_is_target_bid or self._auto_debug) and status == 5:
                                    logger.critical(f"[AUTO-DBG] Tagging seed: bid={msg.id}, context={msg.context:#x}, occurrence={_occurrence}, result={msg.result}, task_id={task_id}")
                                    seed.flip_meta = {
                                        'bid': msg.id,
                                        'context': msg.context,
                                        'occurrence': _occurrence,
                                        'original_result': msg.result,
                                        'original_seed': self._current.clone(),
                                        'task_id': task_id,
                                    }
                                    if _is_target_bid and self._flip_pending is None:
                                        self._flip_pending = seed.clone()
                                self.scheduler.append(
                                    seed,
                                    bid=msg.id,
                                    context=msg.context,
                                    addr=msg.addr,
                                    flags=msg.flags,
                                    result=msg.result,
                                )
                            else:
                                logger.debug(f"Solver returned no solution for bid {msg.id} task {task_id}, status={status}")
                                if _is_target_bid or is_policy_target:
                                    logger.critical(f"[FLIP-DBG]   NO SOLUTION for target bid={msg.id}, task={task_id}")
                        if (not saw_solution and add_nested and is_policy_target and
                                hasattr(self.scheduler, "should_force_solve_policy_target") and
                                self.scheduler.should_force_solve_policy_target(
                                    msg.id, msg.result, msg.addr
                                )):
                            logger.critical(
                                "[Plan] Retrying policy target bid=%s without "
                                "nested constraints after no-solution",
                                msg.id,
                            )
                            for task_id in self.solver.parse_cond(
                                    msg.label, msg.result, False):
                                try:
                                    self.solver.export_task_smt2(
                                        task_id, f"task_{msg.id}_{task_id}_nonested.smt2"
                                    )
                                except Exception as e:
                                    logger.error(f"[FLIP-DBG]   failed to export non-nested SMT2: {e}")
                                status, solutions = self.solver.solve_task(task_id)
                                logger.critical(
                                    f"[FLIP-DBG]   non-nested task {task_id} "
                                    f"for bid={msg.id}: status={status}, "
                                    f"#solutions={len(solutions) if solutions else 0}"
                                )
                                if not solutions or self._trace_only:
                                    continue
                                seed = self._current.clone()
                                seed.flip_meta = None
                                self._apply_solutions(seed, solutions)
                                self.scheduler.append(
                                    seed,
                                    bid=msg.id,
                                    context=msg.context,
                                    addr=msg.addr,
                                    flags=msg.flags,
                                    result=msg.result,
                                )
                    except Exception as e:
                        logger.error(f"Solver error: {e}")
                        seed_name = f"./solving-error/{self.binary_path.split('/')[-1]}-{msg.label}-{msg.id}.seed"
                        try:
                            open(seed_name, 'wb').write(pickle.dumps([self._current]))
                        except:
                            pass
                elif msg.label != 0 and add_nested: # Trace nested conditions
                    try:
                        self.solver.add_constraint(msg.label, msg.result)
                    except Exception as e:
                        logger.error(f"Error adding constraint: {e}")
            case PIPE_MSG_TYPE.EXIT_TYPE:
                logger.info("Finish one seed, exit with code: {}".format(msg.result))
                # Only report exit status if we haven't already reported a bug for this seed
                if msg.result != 0 and not self._bug_reported_for_current_seed:
                    self._report(msg.result)
                self._event_handlers.on_seed_done()
                self.solver.ResetCache()
                self._weak_ref.clear()
                self._stall = False
                self._last_switch_label = 0
                self._bug_reported_for_current_seed = False
                return False
            case PIPE_MSG_TYPE.LOOP_TYPE:
                if (hasattr(self.scheduler, "should_disable_loop_termination") and
                        self.scheduler.should_disable_loop_termination(msg.id)):
                    logger.critical(
                        "[Plan] Disabling runtime loop bound for bid=%s "
                        "(flags=%s, depth=%s)",
                        msg.id,
                        msg.flags,
                        msg.result,
                    )
                    self._termination_manager.set_loop_threshold(0x7fffffff)
                self._termination_manager.trace(msg.flags, msg.addr, msg.context, msg.id, msg.result)
            case PIPE_MSG_TYPE.BB_TYPE:
                # payload in msg.result cause only it has 64 bits
                # Flip verification: detect branch reached but not symbolic
                if self._flip_verifying and self._flip_expecting_cond:
                    # Next BB arrived without target COND in between → not symbolic
                    logger.critical(f"[FLIP-DBG] *** NOT FLIPPED (not symbolic) *** bid={self._flip_bid}, context={self._flip_original_context:#x}, occurrence={self._flip_original_occurrence}: branch reached but not symbolic during replay, task_id={self._flip_task_id}")
                    self._flip_verifying = False
                    self._flip_succeeded = False
                    self._flip_expecting_cond = False
                elif self._flip_verifying and msg.result == self._flip_bid:
                    self._flip_expecting_cond = True
                try:
                    _msg = lambda x: None
                    _msg.addr = msg.addr
                    _msg.func_id = msg.id
                    _msg.bb_id = msg.result
                    _msg.context = PIPE_EVENT_TYPE.TRACE_BB
                    self._event_handlers.handle(_msg)
                    self._termination_manager.trace_bb(msg.id, msg.result)
                    if hasattr(self.scheduler, 'trace_bb'):
                        self.scheduler.trace_bb(msg.id, msg.result)
                    if hasattr(self.scheduler, 'loop_threshold_for_current_trace'):
                        threshold = self.scheduler.loop_threshold_for_current_trace()
                        if threshold is not None:
                            self._termination_manager.set_loop_threshold(threshold)
                    if (hasattr(self.scheduler, 'should_disable_loop_termination') and
                            self.scheduler.should_disable_loop_termination(msg.result)):
                        logger.critical(
                            "[Plan] Disabling runtime loop bound after BB %s",
                            msg.result,
                        )
                        self._termination_manager.set_loop_threshold(0x7fffffff)
                    if (hasattr(self.scheduler, 'should_abort_current_trace') and
                            self.scheduler.should_abort_current_trace()):
                        raise StopExecution("Policy must-prefix violation")
                except StopExecution:
                    self._stall = True
                    return False
                return True
            case PIPE_MSG_TYPE.GEP_TYPE:
                gepmsg: GepMsg = self.p.get_pipe().get(T=GepMsg)
                # Concrete replay: drain the gepmsg (keep the pipe in sync) but do no
                # GEP parsing/solving.
                if self._trace_only:
                    return True
                try:
                    index_i64 = ctypes.c_int64(msg.result).value
                    ptr = gepmsg.ptr if gepmsg.ptr is not None else 0
                    task_ids = self.solver.parse_gep(
                        gepmsg.ptr_label, ptr, msg.label, index_i64,
                        gepmsg.num_elems, gepmsg.elem_size, gepmsg.current_offset,
                        self._enum_index)
                    for task_id in task_ids:
                        # Concrete replay (trace_only): skip the SMT solve entirely.
                        if self._trace_only:
                            continue
                        status, solutions = self.solver.solve_task(task_id)
                        if solutions:
                            seed = self._current.clone()
                            seed.flip_meta = None
                            self._apply_solutions(seed, solutions)
                            bid = 0
                            if hasattr(self.scheduler, "current_bb_id"):
                                bid = self.scheduler.current_bb_id() or 0
                            logger.info(
                                "[Plan] GEP solve produced seed at BB %s "
                                "(ptr_label=%s, index_label=%s, index=%s)",
                                bid,
                                gepmsg.ptr_label,
                                msg.label,
                                index_i64,
                            )
                            self.scheduler.append(seed, bid=bid, addr=msg.addr)
                except Exception as e:
                    logger.error(f"GEP solver error: {e}")

            case PIPE_MSG_TYPE.MERRO_TYPE:
                event_type = MEMERR_TO_EVENT.get(msg.flags)
                if event_type is not None:
                    _msg = lambda: None
                    _msg.context = event_type
                    _msg.addr = msg.addr
                    self._event_handlers.handle(_msg)
                else:
                    logger.warning(f"Unknown MERRO flag: {msg.flags:#x}")
            case PIPE_MSG_TYPE.EVENT_TYPE:
                self._event_handlers.handle(msg)
            case PIPE_MSG_TYPE.ADD_CONSTRAINT_TYPE:
                if msg.label != 0:
                    try:
                        self.solver.add_constraint(msg.label, msg.result)
                    except Exception as e:
                        logger.error(f"Error adding constraint (msg_type=3): {e}")
            case PIPE_MSG_TYPE.MEMCMP_TYPE:
                if msg.flags == 1:
                    # Read memcmp_msg struct: u32 label + content bytes
                    raw = self.p.get_pipe().read_raw(4 + msg.result)
                    memcmp_data = raw[4:]  # skip the u32 label header
                    self.solver.record_memcmp(msg.label, memcmp_data)
            case PIPE_MSG_TYPE.GV_TYPE:
                # read gv content
                buf = self.p.get_pipe().read_raw(msg.result)
                obj_id = msg.id
                offset = msg.addr
                size = msg.result
                logger.debug(f"GV_TYPE: obj_id={obj_id}, offset={offset}, size={size}")
                if offset is None:
                    offset = 0
                if size:
                    for i in range(0, size):
                        self._current[obj_id][offset + i] = buf[i:i+1]
                    # Update solver's input cache with new data
                    self.solver.update_input(self._current.to_bytes_list())
            case PIPE_MSG_TYPE.MINIMIZE_TYPE:
                if msg.label != 0:
                    try:
                        self.solver.record_minimize(msg.label)
                    except Exception as e:
                        logger.error(f"Error recording minimize hint: {e}")
            case _:
                raise NotImplementedError("msg_type: {}".format(msg.msg_type))

        return True

    def _report(self, exit_status):
        normalized_status = exit_status if exit_status < 255 else exit_status >> 8
        if normalized_status in self._reported:
            return
        self._reported.add(normalized_status)
        self._bug_reported_for_current_seed = True
        logger.critical(f"Found bug, exit seed: {self._current}, exit_status: {normalized_status}")
        self._bug(exit_status)
        # input("Press any key to continue...")
        self.exit_status.append(exit_status)
        self._reported_seed.append(self._current)
        if self._synth_type_table:
            self._synthesize_unittest(exit_status)
        if self._report_to:
            self._report_to(exit_status, self._current, self._last_label, self._last_result, self._last_addr, self)
        if normalized_status in self._stop_on_error:
            status_name = next((k for k, v in ERROR_EVENTS.items() if v == normalized_status), str(normalized_status))
            logger.critical(f"Stopping execution: error event {status_name} ({normalized_status}) matched stop_on_error config")
            self._stop_requested = True

    def _synthesize_unittest(self, exit_status):
        try:
            output_dir = self._synth_output_dir or "unittest_output"
            os.makedirs(output_dir, exist_ok=True)
            binary_name = os.path.basename(self.binary_path)
            status_code = exit_status if exit_status < 255 else exit_status >> 8
            filename = f"{binary_name}_bug_{status_code}.c"
            filepath = os.path.join(output_dir, filename)
            code = synth_unittest(self._current, self._synth_type_table)
            with open(filepath, 'w') as f:
                f.write(code)
            logger.critical(f"Synthesized unit test: {filepath}")
        except Exception as e:
            logger.error(f"Unit test synthesis failed: {e}")

    def _apply_solutions(self, seed, solutions):
        """Apply solver solutions to seed."""
        solved_bytes = set()  # track (obj_id, flat_offset) written by solver
        for sol in solutions:
            obj_id = sol['id']
            offset = sol['offset']
            op = sol['op']

            if op == OpType.SET:
                # Solver uses 0-based flat buffer offsets, but UObject uses
                # negative indices for lvalue and positive for value.
                # Adjust: flat_offset → UObject_index = flat_offset - len(lvalue)
                # Extension offsets (negative int32) are already in UObject coords.
                obj = seed[obj_id]
                adjusted = offset - len(obj.lvalue) if offset >= 0 else offset
                logger.debug(f"Solution: SET obj[{obj_id}][{offset}] (adjusted={adjusted}) = 0x{sol['val']:02x}")
                seed.set_byte(obj_id, adjusted, sol['val'])
                solved_bytes.add((obj_id, offset))
            elif op == OpType.INSERT:
                logger.debug(f"Solution: INSERT obj[{obj_id}][{offset}] data={sol['data'].hex()}")
                seed.insert_bytes(obj_id, offset, sol['data'])
            elif op == OpType.DELETE:
                logger.debug(f"Solution: DELETE obj[{obj_id}][{offset}] len={sol['len']}")
                seed.delete_bytes(obj_id, offset, sol['len'])

        # Propagate solver data from resign-alias objects to canonical objects.
        # When resign re-labels memory (e.g., return_ptr with KO_RESIGN_PTRARGS),
        # the solver may write to the resigned object (parent != super), but on
        # replay the runtime uses the canonical object (parent == super).
        # Detect this and copy solver bytes to the canonical object.
        solved_obj_ids = {obj_id for obj_id, _ in solved_bytes}
        for obj_idx in solved_obj_ids:
            obj = seed[obj_idx]
            meta = obj.metadata
            if meta.from_object == 0:
                continue  # directly from super object, no aliasing issue
            # Find a canonical sibling: from super object, same data size, no solver data
            for sib_idx, sib in enumerate(seed.objects):
                if sib_idx == obj_idx or sib_idx == 0:
                    continue
                if sib.metadata.from_object != 0 or sib.metadata.object_id == 0:
                    continue
                if len(sib) != len(obj):
                    continue
                if any((sib_idx, off) in solved_bytes for _, off in solved_bytes if _ == sib_idx):
                    continue  # sibling already has its own solver data
                # Copy solver-written bytes from resign alias to canonical object
                for sol_obj_id, sol_offset in solved_bytes:
                    if sol_obj_id != obj_idx:
                        continue
                    adj_src = sol_offset - len(obj.lvalue) if sol_offset >= 0 else sol_offset
                    adj_dst = sol_offset - len(sib.lvalue) if sol_offset >= 0 else sol_offset
                    src_val = obj.value[adj_src] if adj_src >= 0 else obj.lvalue[-adj_src - 1]
                    if adj_dst >= 0:
                        if adj_dst < len(sib.value):
                            sib.value[adj_dst] = src_val
                        else:
                            sib.value.extend([b'\x00'] * (adj_dst - len(sib.value) + 1))
                            sib.value[adj_dst] = src_val
                    else:
                        li = -adj_dst - 1
                        if li < len(sib.lvalue):
                            sib.lvalue[li] = src_val
                        else:
                            sib.lvalue.extend([b'\x00'] * (li - len(sib.lvalue) + 1))
                            sib.lvalue[li] = src_val
                logger.debug(f"Propagated solver data from resign-alias obj[{obj_idx}] to canonical obj[{sib_idx}]")
                break

        # Record target_offset in metadata so the runtime knows where within
        # the child object the pointer points to (e.g., offset 16 for container_of).
        # The runtime reads target_offset from metadata directly — no need to
        # modify pointer bytes (which would shift pseudo-pointers and break
        # obj_map offset lookups on replay).
        for obj in seed.objects:
            meta = obj.metadata
            if meta.from_object == 0 and meta.from_offset == 0 and meta.object_id == 0:
                continue  # skip default/unset metadata
            meta.target_offset = len(obj.lvalue)

    def run(self):
        self._reported.clear()
        self._termination_manager.reset()
        self._last_switch_label = 0
        try:
            for current in self.scheduler(self.p._pipe):
                if not self.p.is_alive():
                    logger.critical("Process terminaed unexpectedly")
                    break
                logger.debug("\n\n================== New seed ================================\n\n")
                self._current = current
                self._bug_reported_for_current_seed = False
                self._cond_occurrence.clear()
                # Save current seed for standalone replay
                with open("current_seed.bin", "wb") as f:
                    f.write(bytes(current))

                # Set up verification from flip_meta (auto-debug/tagged seed)
                # or from target_branch config (trace_only with report.json)
                if current.flip_meta:
                    self._flip_verifying = True
                    self._flip_expecting_cond = False
                    self._flip_succeeded = False
                    self._flip_bid = current.flip_meta['bid']
                    self._flip_original_context = current.flip_meta['context']
                    self._flip_original_occurrence = current.flip_meta['occurrence']
                    self._flip_original_result = current.flip_meta['original_result']
                    self._flip_task_id = current.flip_meta.get('task_id')
                    logger.critical(f"[AUTO-DBG] Verifying seed for bid={self._flip_bid}, context={self._flip_original_context:#x}, occurrence={self._flip_original_occurrence}, expected_flip_from={self._flip_original_result}, task_id={self._flip_task_id}")
                elif self._flip_verify and self._trace_only:
                    self._flip_verifying = True
                    self._flip_expecting_cond = False
                    self._flip_succeeded = False
                    self._flip_original_context = target_branch.get("context")
                    self._flip_original_result = target_branch.get("original_result")
                    logger.critical(f"[FLIP-DBG] Trace-only target: bid={self._flip_bid}, context={self._flip_original_context:#x}, occurrence={self._flip_original_occurrence}")

                # Reset solver with current seed's input bytes (one per object)
                self.solver.reset_input(self._current.to_bytes_list())
                logger.info("Scheduling seed: " + current.__repr__())
                for msg in self.p.get_pipe():
                    logger.debug("\033[92mrecv msg: " + msg.__repr__() + "\033[0m")
                    if not self._handle_msg(msg):
                        self._termination_manager.reset()
                        self._reported.clear()
                        break
                    logger.debug("\033[93mwait for next msg\033[0m")

                # Check verification result for tagged seeds
                if current.flip_meta:
                    if self._flip_verifying:
                        _actual = self._cond_occurrence.get((self._flip_bid, self._flip_original_context), 0)
                        if _actual > 0:
                            logger.critical(f"[AUTO-DBG] NOT REACHED (loop iteration changed): bid={self._flip_bid}, context={self._flip_original_context:#x}, occurrence={self._flip_original_occurrence}, actual_occurrences={_actual}, task_id={self._flip_task_id}")
                        else:
                            logger.critical(f"[AUTO-DBG] *** NOT REACHED (path diverged) *** bid={self._flip_bid}, context={self._flip_original_context:#x}, occurrence={self._flip_original_occurrence}, task_id={self._flip_task_id}")
                            if self._auto_debug or self._stop_if_not_reached:
                                self._create_repro_script(current, "not_reached")
                                self.epilogue()
                                return
                    elif not self._flip_succeeded:
                        logger.critical(f"[AUTO-DBG] *** NOT FLIPPED *** bid={self._flip_bid}, context={self._flip_original_context:#x}, occurrence={self._flip_original_occurrence}, task_id={self._flip_task_id}")
                        if self._auto_debug or self._stop_if_not_flipped:
                            self._create_repro_script(current, "not_flipped")
                            self.epilogue()
                            return
                    else:
                        logger.critical(f"[AUTO-DBG] OK: bid={self._flip_bid}, context={self._flip_original_context:#x}, occurrence={self._flip_original_occurrence}, task_id={self._flip_task_id} flipped successfully")
                    self._flip_verifying = False

                # Immediately replay the flip seed for verification (target_branch mode)
                if self._flip_pending is not None:
                    flip_seed = self._flip_pending
                    self._flip_pending = None
                    meta = flip_seed.flip_meta
                    self._flip_verifying = True
                    self._flip_expecting_cond = False
                    self._flip_succeeded = False
                    self._flip_bid = meta['bid']
                    self._flip_original_context = meta['context']
                    self._flip_original_occurrence = meta['occurrence']
                    self._flip_original_result = meta['original_result']
                    self._flip_task_id = meta.get('task_id')
                    self._cond_occurrence.clear()
                    logger.critical(f"[FLIP-DBG] === Immediately replaying flip seed: bid={self._flip_bid}, context={self._flip_original_context:#x}, occurrence={self._flip_original_occurrence}, task_id={self._flip_task_id}")
                    self._current = flip_seed
                    self._bug_reported_for_current_seed = False
                    self.solver.reset_input(flip_seed.to_bytes_list())
                    self._termination_manager.reset()
                    self.p._pipe.send(flip_seed.to_ticket())
                    for msg in self.p.get_pipe():
                        logger.debug("\033[92mrecv msg: " + msg.__repr__() + "\033[0m")
                        if not self._handle_msg(msg):
                            self._termination_manager.reset()
                            break
                    if self._flip_verifying:
                        logger.critical(f"[FLIP-DBG] *** NOT REACHED *** bid={self._flip_bid}, context={self._flip_original_context:#x}, occurrence={self._flip_original_occurrence}, task_id={self._flip_task_id}")
                        if self._stop_if_not_reached:
                            self._create_repro_script(flip_seed, "not_reached")
                            self.epilogue()
                            return
                    elif not self._flip_succeeded:
                        logger.critical(f"[FLIP-DBG] *** NOT FLIPPED *** bid={self._flip_bid}, context={self._flip_original_context:#x}, occurrence={self._flip_original_occurrence}, task_id={self._flip_task_id}")
                        if self._stop_if_not_flipped:
                            self._create_repro_script(flip_seed, "not_flipped")
                            self.epilogue()
                            return
                    else:
                        logger.critical(f"[FLIP-DBG] OK: bid={self._flip_bid}, context={self._flip_original_context:#x}, occurrence={self._flip_original_occurrence}, task_id={self._flip_task_id} flipped successfully")
                    self._flip_verifying = False
                if self._stop_requested:
                    self.epilogue()
                    return
                if self._pause:
                    self.epilogue()
                    logger.info("Current seed: {}".format(self._current))
                    filename = input("Do you want to save it?")
                    if filename:
                        open(filename, "wb").write(pickle.dumps([self._current]))
                # print("Exit status: ", self.exit_status)
        finally:
            self.epilogue()

    @staticmethod
    def _seed_to_json(seed):
        """Convert a seed to a JSON-serializable dict."""
        import json
        return {
            "objects": [
                {
                    "index": idx,
                    "value_hex": b"".join(obj.value).hex(),
                    "lvalue_hex": b"".join(obj.lvalue).hex(),
                    "size": len(obj),
                    "metadata": {
                        "object_id": obj.metadata.object_id,
                        "from_object": obj.metadata.from_object,
                        "from_offset": obj.metadata.from_offset,
                    }
                }
                for idx, obj in enumerate(seed.objects)
            ]
        }

    def _create_repro_script(self, seed, reason):
        import json
        repro_dir = "auto_debug_repro"
        os.makedirs(repro_dir, exist_ok=True)
        meta = seed.flip_meta
        # Save binary seeds (for replay)
        original_seed_path = os.path.join(repro_dir, "original_seed.bin")
        mutated_seed_path = os.path.join(repro_dir, "mutated_seed.bin")
        with open(original_seed_path, "wb") as f:
            f.write(pickle.dumps([meta['original_seed']]))
        with open(mutated_seed_path, "wb") as f:
            f.write(pickle.dumps([seed]))
        # Save JSON report
        report = {
            "reason": reason,
            "target": {
                "bid": meta['bid'],
                "context": f"{meta['context']:#x}",
                "occurrence": meta['occurrence'],
                "original_result": meta['original_result'],
            },
            "binary": self._target,
            "original_seed": self._seed_to_json(meta['original_seed']),
            "mutated_seed": self._seed_to_json(seed),
        }
        report_path = os.path.join(repro_dir, "report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        # Create reproducing script
        script_path = os.path.join(repro_dir, "repro.sh")
        with open(script_path, "w") as f:
            f.write(f"""#!/bin/bash
# Auto-debug reproducer
# Reason: {reason}
# Target: bid={meta['bid']}, context={meta['context']:#x}, occurrence={meta['occurrence']}
# Original result: {meta['original_result']}

REPORT="{os.path.join(repro_dir, 'report.json')}"

echo "=== Running with ORIGINAL seed (trace only, dumps SMT2 for target) ==="
python debug.py {self._target} {original_seed_path} 1 "$REPORT"

echo ""
echo "=== Running with MUTATED seed (trace only, should flip bid={meta['bid']}) ==="
python debug.py {self._target} {mutated_seed_path} 1 "$REPORT"
""")
        os.chmod(script_path, 0o755)
        logger.critical(f"[AUTO-DBG] Reproducer saved to {repro_dir}/")

    def epilogue(self):
        if self._epilogued:
            return
        self._epilogued = True

        self.p.close()
        self.solver.destroy()
        if self._output:
            self.dump_seeds(self._output)
        logger.critical(f"Generated seeds: {self._reported_seed}")

        logger.warning("Exiting...")

        current_process = psutil.Process()
        children = current_process.children(recursive=True)
        for child in children:
            logger.warning("Kill child process: {}".format(child))
            child.kill()
        logger.warning("Exit with 0")
        ctypes.pythonapi.PyThreadState_SetAsyncExc(self._monitor_thread.native_id, ctypes.py_object(SystemExit))
        if self._terminate:
            os._exit(0)

    def dump_seeds(self, filename):
        logger.info(f"Dumping seeds to {filename}")
        open(filename, "wb").write(pickle.dumps(self._reported_seed))

    def _bug(self, reason=0):
        if reason == 0x10:
            # input("Solver not ready, press enter to continue")
            logger.critical("Solver not ready")

        if reason != 0:
            seed_name = f"./blocking/{self.binary_path.split('/')[-1]}-{reason}-block-{time.time()}.seed"
            logger.critical(f"Seed name: {seed_name}, binary name: {self._target}")
            try:
                open(seed_name, 'wb').write(pickle.dumps([self._current]))
                logger.critical(f"Seed name: {seed_name}, binary name: {self._target}")
            except:
                pass
            # input("Press any key to continue...")
            # self.epilogue()


if __name__ == "__main__":
    logging.basicConfig(level = logging.DEBUG ,format = '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
    m = UcsanManager('/mnt/shared/ucsan/testsuite/binary/linklist', config="/mnt/shared/thoroupy/config.yaml")
    m.run()
