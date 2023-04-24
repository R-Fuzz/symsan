/*
  a custom mutator for AFL++
  (c) 2023 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#include "dfsan/dfsan.h"

#include "ast.h"
#include "task.h"

extern "C" {
#include "afl-fuzz.h"
}

#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <queue>
#include <memory>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

using namespace __dfsan;

#ifndef DEBUG
#define DEBUG 1
#endif

#define NEED_OFFLINE 0

#undef alloc_printf
#define alloc_printf(_str...) ({ \
    char* _tmp; \
    s32 _len = snprintf(NULL, 0, _str); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    _tmp = (char*)ck_alloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })

typedef struct my_mutator {
  afl_state_t *afl;
  char *out_dir;
  char *out_file;
  char *symsan_bin;
  char **argv;
  int out_fd;
  int shm_id;
} my_mutator_t;

// FIXME: a temporary way to find out input that has been fuzzed before
static std::unordered_set<u32> __fuzzed_inputs;

// FIXME: find another way to make the union table hash work
static dfsan_label_info *__dfsan_label_info;

dfsan_label_info* __dfsan::get_label_info(dfsan_label label) {
  return &__dfsan_label_info[label];
}

static const std::unordered_map<unsigned, std::pair<unsigned, const char*> > OP_MAP {
  {__dfsan::Extract, {rgd::Extract, "extract"}},
  {__dfsan::Trunc,   {rgd::Extract, "extract"}},
  {__dfsan::Concat,  {rgd::Concat, "concat"}},
  {__dfsan::ZExt,    {rgd::ZExt, "zext"}},
  {__dfsan::SExt,    {rgd::SExt, "sext"}},
  {__dfsan::Add,     {rgd::Add, "add"}},
  {__dfsan::Sub,     {rgd::Sub, "sub"}},
  {__dfsan::UDiv,    {rgd::UDiv, "udiv"}},
  {__dfsan::SDiv,    {rgd::SDiv, "sdiv"}},
  {__dfsan::SRem,    {rgd::SRem, "srem"}},
  {__dfsan::Shl,     {rgd::Shl, "shl"}},
  {__dfsan::LShr,    {rgd::LShr, "lshr"}},
  {__dfsan::AShr,    {rgd::AShr, "ashr"}},
  {__dfsan::And,     {rgd::And, "and"}},
  {__dfsan::Or,      {rgd::Or, "or"}},
  {__dfsan::Xor,     {rgd::Xor, "xor"}},
  // relational comparisons
#define RELATIONAL_ICMP(cmp) (__dfsan::ICmp | (cmp << 8)) 
  {RELATIONAL_ICMP(__dfsan::bveq),  {rgd::Equal, "equal"}},
  {RELATIONAL_ICMP(__dfsan::bvneq), {rgd::Distinct, "distinct"}},
  {RELATIONAL_ICMP(__dfsan::bvugt), {rgd::Ugt, "ugt"}},
  {RELATIONAL_ICMP(__dfsan::bvuge), {rgd::Uge, "uge"}},
  {RELATIONAL_ICMP(__dfsan::bvult), {rgd::Ult, "ult"}},
  {RELATIONAL_ICMP(__dfsan::bvule), {rgd::Ule, "ule"}},
  {RELATIONAL_ICMP(__dfsan::bvsgt), {rgd::Sgt, "sgt"}},
  {RELATIONAL_ICMP(__dfsan::bvsge), {rgd::Sge, "sge"}},
  {RELATIONAL_ICMP(__dfsan::bvslt), {rgd::Slt, "slt"}},
  {RELATIONAL_ICMP(__dfsan::bvsle), {rgd::Sle, "sle"}},
#undef RELATIONAL_ICMP
};

typedef std::shared_ptr<rgd::AstNode> SymExpr;

// global caches
static std::unordered_map<dfsan_label, SymExpr> expr_cache;
static std::unordered_map<dfsan_label, std::unordered_set<size_t> > input_dep_cache;
static std::unordered_map<dfsan_label, std::shared_ptr<u8>> memcmp_cache;

static void clear_global_caches() {
  expr_cache.clear();
  input_dep_cache.clear();
  memcmp_cache.clear();
}

static uint32_t map_arg(const u8 *buf, size_t offset, uint32_t length,
                        std::shared_ptr<rgd::Constraint> constraint) {
  uint32_t hash = 0;
  for (uint32_t i = 0; i < length; ++i, ++offset) {
    u8 val = buf[offset];
    uint32_t arg_index = 0;
    auto itr = constraint->local_map.find(offset);
    if (itr == constraint->local_map.end()) {
      arg_index = (uint32_t)constraint->input_args.size();
      constraint->inputs.insert({offset, val});
      constraint->local_map[offset] = arg_index;
      constraint->input_args.push_back(std::make_pair(true, 0)); // 0 is to be filled in the aggragation
    } else {
      arg_index = itr->second;
    }
    if (i == 0) {
      constraint->shapes[offset] = length;
      hash = rgd::xxhash(length * 8, rgd::Read, arg_index);
    } else {
      constraint->shapes[offset] = 0;
    }
  }
  return hash;
}

// this combines both AST construction and arg mapping
static bool do_uta_rel(dfsan_label label, rgd::AstNode *ret,
                       const u8 *buf, size_t buf_size,
                       std::shared_ptr<rgd::Constraint> constraint,
                       std::unordered_set<dfsan_label> &visited) {

  if (label < CONST_OFFSET || label == kInitializingLabel) {
    WARNF("invalid label: %d\n", label);
    return false;
  }

  dfsan_label_info *info = get_label_info(label);
  DEBUGF("%u = (l1:%u, l2:%u, op:%u, size:%u, op1:%lu, op2:%lu)\n",
         label, info->l1, info->l2, info->op, info->size, info->op1.i, info->op2.i);

  // we can't really reuse AST nodes across constraints,
  // but we still need to avoid duplicate nodes within a constraint
  if (visited.count(label)) {
    // if a node has been visited, just record its label without expanding
    ret->set_label(label);
    ret->set_bits(info->size);
    return true;
  }

  // terminal node
  if (info->op == 0) {
    // input
    ret->set_kind(rgd::Read);
    ret->set_bits(8);
    ret->set_label(label);
    uint64_t offset = info->op1.i;
    assert(offset < buf_size);
    // map arg
    uint32_t hash = map_arg(buf, offset, 1, constraint);
    ret->set_hash(hash);
#if NEED_OFFLINE
    std::string val;
    rgd::buf_to_hex_string(&buf[offset], 1, val);
    ret->set_value(std::move(val));
    ret->set_index(offset);
    ret->set_name("read");
#endif
    return true;
  } else if (info->op == __dfsan::Load) {
    ret->set_kind(rgd::Read);
    ret->set_bits(info->l2 * 8);
    ret->set_label(label);
    uint64_t offset = get_label_info(info->l1)->op1.i;
    assert(offset + info->l2 <= buf_size);
    // map arg
    uint32_t hash = map_arg(buf, offset, info->l2, constraint);
    ret->set_hash(hash);
#if NEED_OFFLINE
    std::string val;
    rgd::buf_to_hex_string(&buf[offset], info->l2, val);
    ret->set_value(std::move(val));
    ret->set_index(offset);
    ret->set_name("read");
#endif
    return true;
  }

  // common ops, make sure no special ops
  auto op_itr = OP_MAP.find(info->op);
  if (op_itr == OP_MAP.end()) {
    WARNF("invalid op: %u\n", info->op);
    return false;
  }
  ret->set_kind(op_itr->second.first);
  ret->set_bits(info->size);
  ret->set_label(label);
#if NEED_OFFLINE
  ret->set_name(op_itr->second.second);
#endif

  // now we visit the children
  rgd::AstNode *left = ret->add_children();
  if (info->l1 >= CONST_OFFSET) {
    if (!do_uta_rel(info->l1, left, buf, buf_size, constraint, visited)) {
      return false;
    }
    visited.insert(info->l1);
  } else {
    // constant
    left->set_kind(rgd::Constant);
    left->set_label(0);
    uint32_t size = info->size;
    // size of concat the sum of the two operands
    // to get the size of the constant, we need to subtract the size
    // of the other operand
    if (info->op == __dfsan::Concat) {
      assert(info->l2 >= CONST_OFFSET);
      size -= get_label_info(info->l2)->size;
    }
    left->set_bits(size);
    // map args
    uint32_t arg_index = (uint32_t)constraint->input_args.size();
    constraint->input_args.push_back(std::make_pair(false, info->op1.i));
    constraint->const_num += 1;
    uint32_t hash = rgd::xxhash(size, rgd::Constant, arg_index);
    left->set_hash(hash);
#if NEED_OFFLINE
    left->set_value(std::to_string(info->op1.i));
    left->set_index(arg_index);
    left->set_name("constant");
#endif
  }
  
  // unary ops
  if (info->op == __dfsan::ZExt || info->op == __dfsan::SExt ||
      info->op == __dfsan::Extract || info->op == __dfsan::Trunc) {
    uint32_t hash = rgd::xxhash(info->size, ret->kind(), left->hash());
    ret->set_hash(hash);
    uint64_t offset = info->op == __dfsan::Extract ? info->op2.i : 0;
    ret->set_index(offset);
    return true;
  }

  rgd::AstNode *right = ret->add_children();
  if (info->l2 >= CONST_OFFSET) {
    if (!do_uta_rel(info->l2, right, buf, buf_size, constraint, visited)) {
      return false;
    }
    visited.insert(info->l2);
  } else {
    // constant
    right->set_kind(rgd::Constant);
    right->set_label(0);
    uint32_t size = info->size;
    // size of concat the sum of the two operands
    // to get the size of the constant, we need to subtract the size
    // of the other operand
    if (info->op == __dfsan::Concat) {
      assert(info->l1 >= CONST_OFFSET);
      size -= get_label_info(info->l1)->size;
    }
    right->set_bits(size);
    // map args
    uint32_t arg_index = (uint32_t)constraint->input_args.size();
    constraint->input_args.push_back(std::make_pair(false, info->op2.i));
    constraint->const_num += 1;
    uint32_t hash = rgd::xxhash(size, rgd::Constant, arg_index);
    right->set_hash(hash);
#if NEED_OFFLINE
    right->set_value(std::to_string(info->op1.i));
    right->set_index(arg_index);
    right->set_name("constant");
#endif
  }

  uint32_t hash = rgd::xxhash(left->hash(), ret->kind(), right->hash());
  ret->set_hash(hash);

  return ret;
}

static bool union_to_ast(bool r, dfsan_label label, dfsan_label_info *label_info,
                         const u8 *buf, size_t buf_size,
                         std::vector<SymExpr> &exprs) {

  // check if the label is already in the cache
  if (expr_cache.find(label) != expr_cache.end()) {
    exprs.push_back(expr_cache[label]);
    return true;
  }

  std::unordered_set<dfsan_label> visited;
  std::shared_ptr<rgd::Constraint> constraint = std::make_shared<rgd::Constraint>();
  rgd::AstNode *root = new rgd::AstNode();
  do_uta_rel(label, root, buf, buf_size, constraint, visited);
  return true;
}

static void handle_cond(pipe_msg &msg, const u8 *buf, size_t buf_size) {
  if (unlikely(msg.label == 0)) {
    return;
  }

  // parse the uniont table AST to protobuf ASTs
  // each protobuf AST is a single relational expression
  std::vector<SymExpr> exprs;
  union_to_ast(msg.result == 0, msg.label, __dfsan_label_info,
               buf, buf_size, exprs);
}

static void handle_gep(gep_msg &gmsg, pipe_msg &msg) {
}

/// no splice input
extern "C" void afl_custom_splice_optout(my_mutator_t *data) {
  (void)(data);
}

/// @brief init the custom mutator
/// @param afl aflpp state
/// @param seed not used
/// @return custom mutator state
extern "C" my_mutator_t *afl_custom_init(afl_state *afl, unsigned int seed) {

  (void)(seed);

  struct stat st;
  my_mutator_t *data = (my_mutator_t *)calloc(1, sizeof(my_mutator_t));
  if (!data) {
    FATAL("afl_custom_init alloc");
    return NULL;
  }

  if (!(data->symsan_bin = getenv("SYMSAN_TARGET"))) {
    FATAL(
        "SYMSAN_TARGET not defined, this should point to the full path of the "
        "symsan compiled binary.");
  }

  if (!(data->out_dir = getenv("SYMSAN_OUTPUT_DIR"))) {
    data->out_dir = alloc_printf("%s/symsan", afl->out_dir);
  }

  if (stat(data->out_dir, &st) && mkdir(data->out_dir, 0755)) {
    PFATAL("Could not create the output directory %s", data->out_dir);
  }

  // setup output file
  char *out_file;
  if (afl->file_extension) {
    out_file = alloc_printf("%s/.cur_input.%s", data->out_dir, afl->file_extension);
  } else {
    out_file = alloc_printf("%s/.cur_input", data->out_dir);
  }
  if (data->out_dir[0] == '/') {
    data->out_file = out_file;
  } else {
    char cwd[PATH_MAX];
    if (getcwd(cwd, (size_t)sizeof(cwd)) == NULL) { PFATAL("getcwd() failed"); }
    data->out_file = alloc_printf("%s/%s", cwd, out_file);
    ck_free(out_file);
  }

  // create the output file
  data->out_fd = open(data->out_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (data->out_fd < 0) {
    FATAL("Failed to create output file %s: %s\n", data->out_file, strerror(errno));
  }

  // setup shmem for label info
  data->shm_id = shmget(IPC_PRIVATE, 0xc00000000,
    O_CREAT | SHM_NORESERVE | S_IRUSR | S_IWUSR);
  if (data->shm_id == -1) {
    FATAL("Failed to get shmid: %s\n", strerror(errno));
  }

  __dfsan_label_info = (dfsan_label_info *)shmat(data->shm_id, NULL, SHM_RDONLY);
  if (__dfsan_label_info == (void *)-1) {
    FATAL("Failed to map shm(%d): %s\n", data->shm_id, strerror(errno));
  }

  data->afl = afl;

  return data;
}

extern "C" void afl_custom_deinit(my_mutator_t *data) {
  close(data->out_fd);
  // unlink(data->out_file);
  shmdt(__dfsan_label_info);
  ck_free(data->argv);
}

static int spawn_symsan_child(my_mutator_t *data, const u8 *buf, size_t buf_size,
                              int pipefds[2]) {
  // setup argv in case of initialized
  if (unlikely(!data->argv)) {
    int argc = 0;
    while (data->afl->argv[argc]) { argc++; }
    data->argv = (char **)calloc(argc, sizeof(char *));
    if (!data->argv) {
      FATAL("Failed to alloc argv\n");
    }
    for (int i = 0; i < argc; i++) {
      if (strstr(data->afl->argv[i], (char*)data->afl->fsrv.out_file)) {
        DEBUGF("Replacing %s with %s\n", data->afl->argv[i], data->out_file);
        data->argv[i] = data->out_file;
      } else {
        data->argv[i] = data->afl->argv[i];
      }
    }
  }

  // FIXME: should we use the afl->queue_cur->fname instead?
  // write the buf to the file
  ck_write(data->out_fd, buf, buf_size, data->out_file);
  if (ftruncate(data->out_fd, buf_size)) {
    WARNF("Failed to truncate output file: %s\n", strerror(errno));
    return 0;
  }

  // setup the env vars for SYMSAN
  const char *taint_file = data->afl->fsrv.use_stdin ? "stdin" : data->out_file;
  char *options = alloc_printf("taint_file=%s:shm_id=%d:pipe_fd=%d:debug=%d",
                                taint_file, data->shm_id, pipefds[1], DEBUG);
  DEBUGF("TAINT_OPTIONS=%s\n", options);
  
  int pid = fork();
  if (pid == 0) {
    close(pipefds[0]); // close the read fd
    setenv("TAINT_OPTIONS", (char*)options, 1);
    if (data->afl->fsrv.use_stdin) {
      close(0);
      dup2(data->out_fd, 0);
    }
#if !DEBUG
    close(1);
    close(2);
    dup2(data->afl->fsrv.dev_null_fd, 1);
    dup2(data->afl->fsrv.dev_null_fd, 2);
#endif
    execv(data->symsan_bin, data->argv);
    DEBUGF("Failed to execv: %s", data->symsan_bin);
    exit(-1);
  } if (pid < 0) {
    WARNF("Failed to fork: %s\n", strerror(errno));
  }

  // free options
  ck_free(options);

  return pid;

}

/// @brief the trace stage for symsan
/// @param data the custom mutator state
/// @param buf input buffer
/// @param buf_size 
/// @return the number of solving tasks
extern "C" u32 afl_custom_fuzz_count(my_mutator_t *data, const u8 *buf,
                                     size_t buf_size) {

  // check the input id to see if it's been run before
  // we don't use the afl_custom_queue_new_entry() because we may not
  // want to solve all the tasks
  u32 input_id = data->afl->queue_cur->id;
  if (__fuzzed_inputs.find(input_id) != __fuzzed_inputs.end()) {
    return 0;
  }
  __fuzzed_inputs.insert(input_id);

  // create pipe for communication
  int pipefds[2];
  if (pipe(pipefds) != 0) {
    WARNF("Failed to create pipe fds: %s\n", strerror(errno));
    return 0;
  }

  // spawn the symsan child
  int pid = spawn_symsan_child(data, buf, buf_size, pipefds);
  close(pipefds[1]); // close the write fd

  if (pid < 0) {
    close(pipefds[0]);
    return 0;
  }
 
  pipe_msg msg;
  gep_msg gmsg;
  dfsan_label_info *info;
  size_t msg_size;
  std::shared_ptr<u8> msg_buf;
  std::shared_ptr<memcmp_msg> mmsg;
  u32 num_tasks = 0;

  // clear all caches
  clear_global_caches();

  while (read(pipefds[0], &msg, sizeof(msg)) > 0) {
    // create solving tasks
    switch (msg.msg_type) {
      // conditional branch
      case cond_type:
        handle_cond(msg, buf, buf_size);
        break;
      case gep_type:
        if (read(pipefds[0], &gmsg, sizeof(gmsg)) != sizeof(gmsg)) {
          WARNF("Failed to receive gep msg: %s\n", strerror(errno));
          break;
        }
        // double check
        if (msg.label != gmsg.index_label) {
          WARNF("Incorrect gep msg: %d vs %d\n", msg.label, gmsg.index_label);
          break;
        }
        handle_gep(gmsg, msg);
        break;
      case memcmp_type:
        info = get_label_info(msg.label);
        // if both operands are symbolic, no content to be read
        if (info->l1 != CONST_LABEL && info->l2 != CONST_LABEL)
          break;
        msg_size = sizeof(memcmp_msg) + msg.result;
        msg_buf = std::make_shared<u8>(msg_size); // use shared_ptr to avoid memory leak
        if (read(pipefds[0], msg_buf.get(), msg_size) != msg_size) {
          WARNF("Failed to receive memcmp msg: %s\n", strerror(errno));
          break;
        }
        // double check
        mmsg = std::reinterpret_pointer_cast<memcmp_msg>(msg_buf);
        if (msg.label != mmsg->label) {
          WARNF("Incorrect memcmp msg: %d vs %d\n", msg.label, mmsg->label);
          break;
        }
        // save the content
        memcmp_cache[msg.label] = msg_buf;
        break;
      case fsize_type:
        break;
      default:
        break;
    }
  }

  pid = waitpid(pid, NULL, 0);

  // clean up
  close(pipefds[0]);

  return 0;

}

extern "C" size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                                  u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                                  size_t max_size) {
  return 0;
}