#ifndef JIGSAW_H_
#define JIGSAW_H_

#include <memory>

#include "ast.h"
#include "task.h"

namespace rgd {

int addFunction(const AstNode* node,
    std::map<size_t, uint32_t> const& local_map,
    uint64_t id);

test_fn_type performJit(uint64_t id);

// Phase-0 spike: verify the JIT honors directed FP rounding (constrained
// intrinsics + llvm.set.rounding).  Returns 0 on success.
int spike_fp_rounding();

bool gd_entry(std::shared_ptr<SearchTask> task);

}

#endif