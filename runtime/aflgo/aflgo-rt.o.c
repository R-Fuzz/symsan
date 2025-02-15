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
#include "hashset/hashmap.h"
#include "hashset/hashset.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <stdint.h>

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
u8 __afl_area_initial[MAP_SIZE + 24];
u8* __afl_area_ptr = __afl_area_initial;
const char *distance_fp __attribute__((weak)) = NULL;

// critical branches that used to detect path divergence
HashSet* critical_branches_ptr = NULL;
HashMap* bb_to_dis = NULL;

// Flag to check if basic block map is initialized
static int bb_map_initialized = 0;
// Flag for persistent mode
static u8 is_persistent;

// Thread-local storage for previous location
__thread u32 __afl_prev_loc;

// Function to initialize the basic block map from a file
static int init_bb_map(void) {
    if (distance_fp == NULL) {
        fprintf(stderr, "Distance file not provided.\n");
        bb_map_initialized = -1;
        return -1;
    }
    FILE *cf = fopen(distance_fp, "r");
    if (cf == NULL) {
        fprintf(stderr, "Unable to find %s.\n", distance_fp);
        bb_map_initialized = -1;
        return -1;
    }
    bb_to_dis = hashmap_create(1024);
    char line[1024];
    while (fgets(line, sizeof(line), cf) != NULL) {
        // Remove any trailing newline characters (handles both \n and \r\n)
        line[strcspn(line, "\r\n")] = '\0';
        // Skip empty lines
        if (line[0] == '\0') continue;
        // Tokenize the line (comma-separated values)
        char *token = strtok(line, ",");
        if (token == NULL)
            continue;
        u32 BB_id = strtoul(token, NULL, 10);
        // Get the second token (filename:loc, which is not used)
        token = strtok(NULL, ",");
        if (token == NULL)
            continue;
        // Get the third token (distance)
        token = strtok(NULL, ",");
        if (token == NULL)
            continue;
        int bb_dis = (int)atof(token);
        hashmap_put(bb_to_dis, BB_id, bb_dis);
    }
    fclose(cf);
    bb_map_initialized = 1;
    return 0;
}

static int get_distance(u32 bbid) {
    if (bb_map_initialized == 0)
        init_bb_map();
    int *val = hashmap_get(bb_to_dis, bbid);
    if (val == NULL)
        return -2; // Not found
    return *val;
}

void __initialize_critical_branches(void) {
    critical_branches_ptr = hashset_create(1024);
    const char *filename = getenv("CRITICAL_BRANCH_FILEPATH");
    if (filename == NULL) {
        fprintf(stderr, "WARNING: ENV VAR CRITICAL_BRANCH_FILEPATH is not set\n");
        return;
    }
    if (strcmp(filename, "") == 0) {
        fprintf(stderr, "WARNING: critical branch file is not set\n");
        return;
    }
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "WARNING: failed to open critical branch file\n");
        return;
    }
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        // Remove any trailing newline character
        buffer[strcspn(buffer, "\n")] = '\0';
        u32 branch_id;
        if (sscanf(buffer, "%u", &branch_id) == 1)
            hashset_insert(critical_branches_ptr, branch_id);
        else {
            fprintf(stderr, "WARNING: failed to parse line in critical branch file\n");
            break;
        }
    }
    printf("INFO: read %d critical branches\n", hashset_get_size(critical_branches_ptr));
    fclose(file);
}

void update_distance(u32 bbid) {
    if (distance_fp == NULL)
        return;
    if (bb_map_initialized == -1)
        return;
    int distance = get_distance(bbid);
    if (distance >= 0) {
        // Store global minimal BB distance to __afl_area_ptr[MAP_SIZE]
        u32 *global_dist_ptr = (u32*)(__afl_area_ptr + MAP_SIZE);
        if (*global_dist_ptr > (u32)distance)
            *global_dist_ptr = distance;
        // Store local minimal BB distance to __afl_area_ptr[MAP_SIZE + 8]
        u32 *local_dist_ptr = (u32*)(__afl_area_ptr + MAP_SIZE + 8);
        if (*local_dist_ptr > (u32)distance)
            *local_dist_ptr = distance;
        // Increase counter at __afl_area_ptr[MAP_SIZE + 16]
        u32 *map_cnt_ptr = (u32*)(__afl_area_ptr + MAP_SIZE + 16);
        (*map_cnt_ptr)++;
    } else if (distance == -1)
        exit(0);
}

void __afl_map_shm(void) {
    const char *id_str = getenv(SHM_ENV_VAR);
    // If running under AFL, attach to the appropriate shared memory region
    if (id_str) {
        u32 shm_id = (u32)atoi(id_str);
        __afl_area_ptr = shmat(shm_id, NULL, 0);
        // Check for failure in attaching shared memory
        if (__afl_area_ptr == (u8*)(-1))
            exit(1);
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

__attribute__((constructor(CONST_PRIO)))
void __afl_auto_init(void) {
    // Initialize the shared memory area to zero
    memset(__afl_area_ptr, 0, MAP_SIZE + 24);
    // Set initial max values
    u32 max = (u32)INT_MAX;
    memcpy(__afl_area_ptr + MAP_SIZE, &max, sizeof(u32));
    memcpy(__afl_area_ptr + MAP_SIZE + 8, &max, sizeof(u32));
    __initialize_critical_branches();

    // Optionally handle persistent mode
    // is_persistent = !!getenv(PERSIST_ENV_VAR);

    // Optionally defer initialization
    // if (getenv(DEFER_ENV_VAR)) return;

    // Initialize manually if not deferred
    // __afl_manual_init();
}
