// METADATA: seed_timeout_cpp.yaml
// FLAG: 121 200
// ENV: KO_USE_NATIVE_LIBCXX seed_timeout

// A seed that runs too long: the fork server waited on it for the whole
// budget.  (In v8's BitVector a solved length of 2^31 had std::fill_n zero
// 2^25 words, every store a bounds query; a loop alone is cut at the loop
// threshold, REASON_LOOP_OOB, so this test takes its time in a sleep.)
// seed_timeout (1 s here) ends it as REASON_TIMEOUT (121), and the other path
// is still explored.
//
//   *a >  1000: sleeps 3 s                  -> 121 (timeout)
//   *a <= 1000: exit(200) when *a == 7
#include <cstdlib>
#include <time.h>

int entry(int *a) {
    if (*a > 1000) {
        struct timespec ts = {3, 0};
        nanosleep(&ts, nullptr);
        return 1;
    }
    if (*a == 7)
        exit(200);
    return 0;
}
