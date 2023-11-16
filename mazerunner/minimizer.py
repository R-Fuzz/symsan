import hashlib
import os
import subprocess
import tempfile
import atexit

import utils

# status for TestCaseMinimizer
NEW = 0
OLD = 1
CRASH = 2

TIMEOUT = 5 * utils.MILLION_SECONDS_SCALE
MAP_SIZE = 65536

def read_bitmap_file(bitmap_file):
    with open(bitmap_file, "rb") as f:
        return list(map(ord, list(f.read())))

def write_bitmap_file(bitmap_file, bitmap):
    with open(bitmap_file, "wb") as f:
        f.write(bytes(map(chr, bitmap)))

def compute_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

class TestcaseMinimizer:
    def __init__(self, cmd, afl_path, out_dir, qemu_mode, state, map_size=MAP_SIZE):
        self.cmd = cmd
        self.qemu_mode = qemu_mode
        self.showmap = None if not afl_path else os.path.join(afl_path, "afl-showmap")
        self.bitmap_file = os.path.join(out_dir, "afl-bitmap")
        self.crash_bitmap_file = os.path.join(out_dir, "afl-crash-bitmap")
        _, self.temp_file = tempfile.mkstemp(dir=out_dir)
        self.bitmap = self.initialize_bitmap(self.bitmap_file, map_size)
        self.crash_bitmap = self.initialize_bitmap(self.crash_bitmap_file, map_size)
        self.mazerunner_state = state
        atexit.register(self.cleanup)

    def initialize_bitmap(self, filename, map_size):
        if os.path.exists(filename):
            bitmap = read_bitmap_file(filename)
            assert len(bitmap) == map_size
        else:
            bitmap = [0] * map_size
        return bitmap

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
        result = subprocess.run(cmd, input=stdin.encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        this_bitmap = read_bitmap_file(self.temp_file)
        return self.is_interesting_testcase(this_bitmap, result.returncode)

    def is_interesting_testcase(self, bitmap, returncode):
        if returncode == 0:
            my_bitmap = self.bitmap
            my_bitmap_file = self.bitmap_file
        else:
            my_bitmap = self.crash_bitmap
            my_bitmap_file = self.crash_bitmap_file

        # Maybe need to port in C to speed up
        interesting = False
        for i in range(len(bitmap)):
            old = my_bitmap[i]
            new = my_bitmap[i] | bitmap[i]
            if old != new:
                interesting = True
                my_bitmap[i] = new

        if interesting:
            write_bitmap_file(my_bitmap_file, my_bitmap)
        return interesting

    def cleanup(self):
        if os.path.exists(self.temp_file):
            os.unlink(self.temp_file)
