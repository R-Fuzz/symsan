import hashlib
import os
import subprocess
import tempfile

import utils

# status for TestCaseMinimizer
NEW = 0
OLD = 1
CRASH = 2

TIMEOUT = 5 * utils.MILLION_SECONDS_SCALE
DEFAULT_MAP_SIZE = 8388608

def read_bitmap_file(bitmap_file):
    with open(bitmap_file, "rb") as f:
        return list(f.read())

def write_bitmap_file(bitmap_file, bitmap):
    with open(bitmap_file, "wb") as f:
        f.write(bytes(bitmap))

def compute_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

class TestcaseMinimizer:
    def __init__(self, cmd, afl_path, out_dir, qemu_mode, state):
        self.mazerunner_state = state
        self.cmd = cmd
        self.qemu_mode = qemu_mode
        self.showmap = None if not afl_path else os.path.join(afl_path, "afl-showmap")
        self.fuzzer_bitmap_file = os.path.join(out_dir, "fuzz_bitmap")
        _, self.temp_file = tempfile.mkstemp(dir=out_dir)
        self.my_bitmap = self.load_or_initialize_bitmap()

    def load_or_initialize_bitmap(self):
        map_size = self._get_map_size(self.fuzzer_bitmap_file)
        if not self.mazerunner_state.bitmap:
            if os.path.exists(self.fuzzer_bitmap_file):
                fuzzer_bitmap = read_bitmap_file(self.fuzzer_bitmap_file)
                self.mazerunner_state.read_bitmap(fuzzer_bitmap)
            else:
                self.mazerunner_state.create_bitmap(map_size)
        assert len(self.mazerunner_state.bitmap) == map_size, \
            "Bitmap size does not match fuzzer map size."
        return self.mazerunner_state.bitmap

    def is_new_file(self, testcase):
        md5 = compute_md5(testcase)
        if md5 in self.mazerunner_state.testscases_md5:
            return False
        else:
            self.mazerunner_state.testscases_md5.add(md5)
            return True

    def has_closer_distance(self, distance, testcase):
        distance_reached = self.mazerunner_state.min_distance
        if distance < distance_reached:
            self.mazerunner_state.update_best_seed(testcase, distance)
            return True
        else:
            return False

    def has_new_cov(self, testcase):
        if self.showmap is None:
            return False
        cmd = [self.showmap,
               "-t",
               str(TIMEOUT),
               "-m", "256T", # for ffmpeg
               "-b" # binary mode
        ]

        if self.qemu_mode:
            cmd += ['-Q']

        cmd += ["-o",
               self.temp_file,
               "--"
        ] + self.cmd

        cmd, stdin = utils.fix_at_file(cmd, testcase)
        result = subprocess.run(cmd, input=stdin, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ts_bitmap = read_bitmap_file(self.temp_file)
        return self.is_interesting_testcase(ts_bitmap, result.returncode)

    def is_interesting_testcase(self, ts_bitmap, returncode):
        # Maybe need to port in C to speed up
        interesting = False
        for i in range(len(ts_bitmap)):
            old = self.my_bitmap[i]
            new = self.my_bitmap[i] | ts_bitmap[i]
            if old != new:
                interesting = True
                self.my_bitmap[i] = new
        if interesting:
            fuzzer_bitmap = read_bitmap_file(self.fuzzer_bitmap_file)
            for i in range(len(fuzzer_bitmap)):
                self.my_bitmap[i] = fuzzer_bitmap[i] | self.my_bitmap[i]
        return interesting

    def cleanup(self):
        if os.path.exists(self.temp_file):
            os.unlink(self.temp_file)

    def _get_map_size(self, bitmap_file):
        if os.path.exists(bitmap_file):
            return os.path.getsize(bitmap_file)
        else:
            return DEFAULT_MAP_SIZE
