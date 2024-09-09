import logging
import os
import subprocess

import utils

class CoverageAnalyzer:
    def __init__(self, cmd, afl_dir=None, qemu_mode=False):
        self.logger = logging.getLogger(self.__class__.__qualname__)
        self.qemu_mode = qemu_mode
        self._edge_mapping_file = None
        self.edge_to_loc = {}
        self.cmd = cmd.split(' ')
        self.afl_instrument_dir = os.path.dirname(self.cmd[0])
        self.afl_cov_map = "/tmp/afl_cov_map"
        if afl_dir is None:
            self.afl_build_dir = os.getenv('AFL_BUILD_DIR')
        else:
            self.afl_build_dir = afl_dir
        assert os.path.isdir(self.afl_build_dir)
    
    @property
    def afl_showmap(self):
        return os.path.join(self.afl_build_dir, "afl-showmap")
    
    @property
    def edge_mapping_file(self):
        if self._edge_mapping_file is not None:
            return self._edge_mapping_file
        
        env_edge_mapping_file = os.getenv('AFL_LLVM_DOCUMENT_IDS')
        if env_edge_mapping_file and os.path.isfile(env_edge_mapping_file):
            self._edge_mapping_file = env_edge_mapping_file
            return self._edge_mapping_file

        default_edge_mapping_file = os.path.join(self.afl_instrument_dir, "afl_trace_file")
        if os.path.isfile(default_edge_mapping_file):
            self._edge_mapping_file = default_edge_mapping_file
            return self._edge_mapping_file

        self._edge_mapping_file = ''
        return self._edge_mapping_file
    
    def cleanup(self):
        if os.path.exists(self.afl_cov_map):
            os.unlink(self.afl_cov_map)

    def compute_BB_cov(self, input_file):
        command = [self.afl_showmap, "-q", "-r", "-o", self.afl_cov_map, "--"]
        cmd, stdin, _ = utils.fix_at_file(self.cmd, input_file)
        command += cmd
        if stdin:
            subprocess.run(command, input=stdin, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        coverage_data = set()
        with open(self.afl_cov_map) as f:
            for line in f:
                edge_id = line.split(':')[0]
                coverage_data.add(int(edge_id))

        assert coverage_data
        return coverage_data
    
    def print_cov(self, input_file):
        self._load_edge_mapping()
        coverage_data = self.compute_BB_cov(input_file)
        for edge_id in coverage_data:
            if edge_id not in self.edge_to_loc:
                self.logger.error(f"Edge ID {edge_id} not found in edge mapping file")
                continue
            print(self.edge_to_loc[edge_id])

    def _load_edge_mapping(self):
        if self.edge_to_loc:
            return
        if not self.edge_mapping_file:
            return
        with open(self.edge_mapping_file, 'r') as f:
            for line in f:
                parts = line.split(' ')
                if len(parts) != 4:
                    self.logger.error(f"Error parsing edge mapping file: {parts}")
                    continue
                edgeID_part = parts[2]
                location_part = parts[3]
                try:
                    edgeID = int(edgeID_part.split('=')[1])
                    location = location_part.split('=')[1].strip('./\n')
                    if '/usr/include' in location:
                        continue
                    self.edge_to_loc[edgeID] = location
                except Exception as e:
                    self.logger.error(f"Error parsing edge mapping file: {e}")
                    self.logger.error(f"line: {parts}")
