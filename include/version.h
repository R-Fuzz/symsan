
#ifndef _ANGORA_LLVM_VERSION_H
#define _ANGORA_LLVM_VERSION_H

#define LLVM_VERSION(major, minor) ((major)*100 + (minor))
#define LLVM_VERSION_CODE LLVM_VERSION(LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR)

#if LLVM_VERSION_CODE >= LLVM_VERSION(5, 0)
#define LLVM_ATTRIBUTE_LIST AttributeList

#define LLVM_NEW_ALLOCINST(ty, name, insertp)                                  \
  (new AllocaInst(ty, getDataLayout().getAllocaAddrSpace(), name, insertp))

#define LLVM_REMOVE_ATTRIBUTE(func, attr, attrbuilder)                         \
  func->removeAttributes(attr, attrbuilder)

#else

#define LLVM_ATTRIBUTE_LIST AttributeSet

#define LLVM_NEW_ALLOCINST(ty, name, insertp)                                  \
  (new AllocaInst(ty, name, insertp))

#define LLVM_REMOVE_ATTRIBUTE(func, attr, attrbuilder)                         \
  func->removeAttributes(                                                      \
      attr, LLVM_ATTRIBUTE_LIST::get(func->getContext(), attr, attrbuilder))

#endif

#if LLVM_VERSION_CODE >= LLVM_VERSION(6, 0)

#define SCL_INSECTION(scl, section, prefix, query, category)                   \
  scl->inSection(section, prefix, query, category)

#define LLVM_ADD_PARAM_ATTR(func, argno, attr) func->addParamAttr(argno, attr)

#else

#define SCL_INSECTION(scl, section, prefix, query, category)                   \
  scl->inSection(prefix, query, category)

#define LLVM_ADD_PARAM_ATTR(func, argno, attr)                                 \
  func->addAttribute(argno + 1, attr)

#endif

// The helpers below pull in LLVM C++ headers, so they are only compiled for
// C++ translation units built against LLVM.  The compiler-driver C sources
// include this file too (and may define LLVM_VERSION_MAJOR for version-gating),
// but only need the macros above.
#if defined(__cplusplus) && defined(LLVM_VERSION_MAJOR)

// LLVM 16 removed llvm/ADT/None.h and llvm::Optional/llvm::None in favor of
// std::optional/std::nullopt.
#if LLVM_VERSION_CODE >= LLVM_VERSION(16, 0)
#include <optional>
#define LLVM_NONE std::nullopt
#else
#include "llvm/ADT/None.h"
#define LLVM_NONE None
#endif

// LLVM 17 moved llvm/ADT/Triple.h to llvm/TargetParser/Triple.h.
#if LLVM_VERSION_CODE >= LLVM_VERSION(17, 0)
#include "llvm/TargetParser/Triple.h"
#else
#include "llvm/ADT/Triple.h"
#endif

// LLVM 16 split AttributeMask into its own header.
#if LLVM_VERSION_CODE >= LLVM_VERSION(16, 0)
#include "llvm/IR/AttributeMask.h"
#endif

// LLVM 18 removed the typed-pointer helper Type::getInt8PtrTy; with opaque
// pointers an i8* is just an opaque pointer in the default address space.
#if LLVM_VERSION_CODE >= LLVM_VERSION(18, 0)
#define KO_INT8PTRTY(ctx) llvm::PointerType::getUnqual(ctx)
#else
#define KO_INT8PTRTY(ctx) llvm::Type::getInt8PtrTy(ctx)
#endif

// LLVM 16 removed DataLayout::getABITypeAlignment in favor of getABITypeAlign.
#if LLVM_VERSION_CODE >= LLVM_VERSION(16, 0)
#define KO_GETABITYPEALIGN(dl, ty) (dl).getABITypeAlign(ty).value()
#else
#define KO_GETABITYPEALIGN(dl, ty) (dl).getABITypeAlignment(ty)
#endif

// LLVM 18 removed the arithmetic operators on Align/MaybeAlign; scale a
// MaybeAlign by an integer factor, propagating "no alignment".
#if LLVM_VERSION_CODE >= LLVM_VERSION(18, 0)
#define KO_MULMAYBEALIGN(a, n)                                                  \
  ((a) ? llvm::MaybeAlign(llvm::Align((a)->value() * (uint64_t)(n)))            \
       : llvm::MaybeAlign())
#else
#define KO_MULMAYBEALIGN(a, n) ((a) * (uint64_t)(n))
#endif

// LLVM 16 added the STL-style StringRef::starts_with/ends_with; LLVM 18
// deprecated the old startswith/endswith spellings (removed in LLVM 19).
#if LLVM_VERSION_CODE >= LLVM_VERSION(16, 0)
#define KO_STARTSWITH(s, p) (s).starts_with(p)
#define KO_ENDSWITH(s, p) (s).ends_with(p)
#else
#define KO_STARTSWITH(s, p) (s).startswith(p)
#define KO_ENDSWITH(s, p) (s).endswith(p)
#endif

#endif // LLVM_VERSION_MAJOR

#endif
