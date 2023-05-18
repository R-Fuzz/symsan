#include "benchmark_unordered_map.h"
#include "benchmark_lockfree_ht.h"
//#include "benchmark_tbb.h"

#include "thread_service.h"
#include "cycle_timer.h"

#include <iostream>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define DEFAULT_OP_COUNT     2000000
#define DEFAULT_THREAD_COUNT 24
#define DEFAULT_READ_PERCENT 90
#define DEFAULT_LOAD_FACTOR  40
#define CAPACITY             8000016

int main(int argc, char *argv[])
{
  char c;
  int  op_count     = DEFAULT_OP_COUNT; 
  int  num_threads  = DEFAULT_THREAD_COUNT;
  int  read_percent = DEFAULT_READ_PERCENT;
  int  load_factor  = DEFAULT_LOAD_FACTOR;

  char *out_file   = NULL;

  // Parse cmd args
  while ((c = getopt(argc, argv, "n:t:or:hl:")) != -1)
  {
    switch (c)
    {
      case 'n':
        op_count = atoi(optarg);
        break;
      case 't':
        printf("Here");
        num_threads = atoi(optarg);
        break;
      case 'o':
        out_file = optarg;
        break;
      case 'r':
        read_percent = atoi(optarg);
        break;
      case 'l':
        load_factor = atoi(optarg);
        break;
      case 'h':
        printf("Options: \n"
               "-n num_elements \n"
               "-t num_threads \n"
               "-l load_factor \n"
               "-r read_percent \n"
               "-o output_file \n");
        break;
      default:
        break;
    }
  }

  int    rweight  = read_percent;
  int    idweight = 100 - read_percent;
  double lfactor  = load_factor / 100.0;

  printf("%d", num_threads);

  // Run tests
  std::cout << "*** STARTING Benchmark ***" << std::endl;
  std::cout << "Parameters: " << std::endl;
  std::cout << "\t" << "op_count     : " << op_count << std::endl;
  std::cout << "\t" << "num_threads  : " << num_threads << std::endl;
  std::cout << "\t" << "load_factor  : " << load_factor << "%" << std::endl;
  std::cout << "\t" << "read_percent : " << read_percent << "%" << std::endl;

  BenchmarkUnorderedMap benchmark_unordered_map(op_count, CAPACITY, rweight, idweight, lfactor);
  benchmark_unordered_map.run();

//  BenchmarkTBB benchmark_tbb(op_count, CAPACITY, rweight, idweight, num_threads, lfactor);
//  benchmark_tbb.run();

  BenchmarkLockFreeHT benchmark_lockfree_ht(op_count, CAPACITY, rweight, idweight, num_threads, lfactor);
  benchmark_lockfree_ht.run();

}
