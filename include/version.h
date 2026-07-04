
#ifndef _ANGORA_LLVM_VERSION_H
#define _ANGORA_LLVM_VERSION_H

#define LLVM_VERSION(major, minor) ((major)*100 + (minor))
#define LLVM_VERSION_CODE LLVM_VERSION(LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR)

// SymSan targets LLVM 18 (the default on Ubuntu 24.04) as its minimum.  These
// headers are only needed by C++ translation units built against LLVM; the
// compiler-driver C sources include this file only for the LLVM_VERSION macros
// above.
#if defined(__cplusplus) && defined(LLVM_VERSION_MAJOR)
#include <optional>
#include "llvm/TargetParser/Triple.h"
#include "llvm/IR/AttributeMask.h"
#endif

#endif
