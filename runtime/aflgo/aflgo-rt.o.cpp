/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------
   
   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>
   
   LLVM integration design comes from Laszlo Szekeres.
   
   Copyright 2015, 2016 Google Inc. All rights reserved.
   
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:
   
     http://www.apache.org/licenses/LICENSE-2.0
   
   This code is the rewrite of afl-as.h's main_payload.
   
*/

#include "defs.h"
#include "hashset/hashset.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <climits>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <algorithm>

#include <csignal>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>

/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifdef USE_TRACE_PC
#  define CONST_PRIO 5
#else
#  define CONST_PRIO 0
#endif /* ^USE_TRACE_PC */

/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */
u8  __afl_area_initial[MAP_SIZE + 24]; // 8 + 8 + 8 bytes for additional data
u8* __afl_area_ptr = __afl_area_initial;
const char * distance_fp __attribute__((weak)) = nullptr;

// critical branches that used to detect path divergence
HashSet* critical_branches_ptr = nullptr;

std::map<u64, int> bb_to_dis;

// Thread-local storage for previous location
thread_local u32 __afl_prev_loc;

// Flag for persistent mode
static u8 is_persistent;

// Flag to check if basic block map is initialized
static int bb_map_initialized = 0;

// Function to initialize the basic block map from a file
static void init_bb_map() {
    if (distance_fp == nullptr) {
        fprintf(stderr, "Distance file not provided.");
        bb_map_initialized = -1;
        return;
    }

    std::ifstream cf(distance_fp);
    if (!cf.is_open()) {
        fprintf(stderr, "Unable to find %s.", distance_fp);
        bb_map_initialized = -1;
        return;
    }

    std::string line;
    while (std::getline(cf, line)) {
        if (line.empty()) continue;
        std::stringstream ss(line);
        std::string token;

        // Read BB_id
        if (!std::getline(ss, token, ',')) continue;
        u64 BB_id = std::stoull(token);

        // Read filename:loc (not used here)
        if (!std::getline(ss, token, ',')) continue;

        // Read distance
        if (!std::getline(ss, token, ',')) continue;
        int bb_dis = static_cast<int>(std::atof(token.c_str()));
        bb_to_dis[BB_id] = bb_dis;
    }

    cf.close();
    bb_map_initialized = 1;
}

static int get_distance(u64 bbid) {
    if (!bb_map_initialized)
        init_bb_map();

    auto it = bb_to_dis.find(bbid);
    if (it == bb_to_dis.end())
        return -2; // Not found

    return it->second;
}

extern "C" {

void update_distance(uint64_t bbid) {
    if (distance_fp == nullptr)
        return;
    if (bb_map_initialized == -1)
        return;

    int distance = get_distance(bbid);
    if (distance >= 0) {
        // Store global minimal BB distance to __afl_area_ptr[MAP_SIZE]
        u64* global_dist_ptr = reinterpret_cast<u64*>(__afl_area_ptr + MAP_SIZE);
        *global_dist_ptr = std::min(*global_dist_ptr, static_cast<u64>(distance));

        // Store local minimal BB distance to __afl_area_ptr[MAP_SIZE + 8]
        u64* local_dist_ptr = reinterpret_cast<u64*>(__afl_area_ptr + MAP_SIZE + 8);
        *local_dist_ptr = std::min(*local_dist_ptr, static_cast<u64>(distance));

        // Increase counter at __afl_area_ptr[MAP_SIZE + 16]
        u64* map_cnt_ptr = reinterpret_cast<u64*>(__afl_area_ptr + MAP_SIZE + 16);
        *map_cnt_ptr += 1;

    } else if (distance == -1) {
        std::exit(0);
    }
}

void __afl_map_shm(void) {
    const char *id_str = std::getenv(SHM_ENV_VAR);

    // If running under AFL, attach to the appropriate shared memory region
    if (id_str) {
        u32 shm_id = static_cast<u32>(std::atoi(id_str));
        __afl_area_ptr = reinterpret_cast<u8*>(shmat(shm_id, nullptr, 0));

        // Check for failure in attaching shared memory
        if (__afl_area_ptr == reinterpret_cast<u8*>(-1)) std::exit(1);

        // Write a byte to ensure the parent doesn't give up on us
        __afl_area_ptr[0] = 1;
    }
}

void __afl_manual_init(void) {
    static u8 init_done = 0;

    if (!init_done) {
        __afl_map_shm();
        // __afl_start_forkserver();
        init_done = 1;
    }
}

} // extern "C"

void __initialize_critical_branches() {
  critical_branches_ptr = new HashSet(1024);
  const char *filename = getenv("CRITICAL_BRANCH_FILEPATH");
  if (filename == nullptr) {
    fprintf(stderr, "WARNING: ENV VAR CRITICAL_BRANCH_FILEPATH is not set\n");
    return;
  }
  if (strcmp(filename, "") == 0) {
    fprintf(stderr, "WARNING: critical branch file is not set\n");
    return;
  }
  std::ifstream file_stream(filename);
  if (!file_stream.is_open()) {
    fprintf(stderr, "WARNING: failed to open critical branch file with ifstream\n");
    return;
  }
  std::string line;
  while (std::getline(file_stream, line)) {
    std::istringstream iss(line);
    u32 branch_id;
    if (iss >> branch_id) {
      critical_branches_ptr->insert(branch_id);
    } else {
      fprintf(stderr, "WARNING: failed to parse line in critical branch file\n");
      break;
    }
  }
  printf("INFO: read %d critical branches\n", critical_branches_ptr->getSize());
  file_stream.close();
}

__attribute__((constructor(CONST_PRIO))) void __afl_auto_init(void) {
    // Initialize the shared memory area to zero
    std::memset(__afl_area_ptr, 0, MAP_SIZE + 24);

    // Set initial max values
    u64 max = static_cast<u64>(INT_MAX);
    std::memcpy(__afl_area_ptr + MAP_SIZE, &max, sizeof(u64));
    std::memcpy(__afl_area_ptr + MAP_SIZE + 8, &max, sizeof(u64));

    __initialize_critical_branches();
    // Optionally handle persistent mode
    // is_persistent = !!std::getenv(PERSIST_ENV_VAR);

    // Optionally defer initialization
    // if (std::getenv(DEFER_ENV_VAR)) return;

    // Initialize manually if not deferred
    // __afl_manual_init();
}