#include <iostream>
#include <vector>
#include <chrono>

#include "ctpl.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h> /* mmap() is defined in this header */
#include <fcntl.h>
#include <unistd.h>
#include <string.h>


struct SArg {
	int x;
	int y;
};



ctpl::thread_pool* pool;
ctpl::thread_pool* spool;

int some_function(int id, struct SArg *arg) {
	std::cout << "hello " << arg->x << std::endl;
	std::this_thread::sleep_for(std::chrono::seconds(1));
	std::cout << "world " << arg->y << std::endl;
	return arg->y;
}

static void generate_input(uint64_t fid) {
		char path[1000];
		std::string __output_dir = "/hyper/fuzz/tmp";
		std::string output_file = std::string(__output_dir) + "/" + 
			std::to_string(fid) + "-id";
		//std::string input_file = std::string(__output_dir) + "/" + taint_file;
		std::string input_file =  "/home/cju/e2e/filter_des/0-id";
		//std::cout << "out file is " << output_file << std::endl;
		struct stat statbuf;
		void *src, *dst;
		int fdout, fdin;
		int mode = 0x777;
		
		/* open the input file */
		if ((fdin = open (input_file.c_str(), O_RDONLY)) < 0)
		{
			//assert(false && "can't open file for reading");
			printf("cannot open input file!\n");
			return;
		}

		/* open/create the output file */
		if ((fdout = open (output_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, mode)) < 0)//edited here
		{
			//assert(false && "can't create file for writing");
			return;
		}

		/* find size of input file */
		if (fstat (fdin,&statbuf) < 0)
		{
			//assert (false && "fstat error");
			close(fdin);
			return;
		}	

		/* mmap the input file */
		if ((src = mmap (0, statbuf.st_size, PROT_READ, MAP_SHARED, fdin, 0))
				== (caddr_t) -1) {
			close(fdin);
			return;
		}

		dst = malloc(statbuf.st_size);

		/* this copies the input file to the output file */
		memcpy (dst, src, statbuf.st_size);
		for (int i=0;i<4;i++) {
			((uint8_t*)dst)[i] = i;
			//printf("generate_input index is %u and value is %u\n", it->first,(uint32_t)it->second);
		}

		if (write(fdout, dst, statbuf.st_size) < 0) {
			return;
		}

		close(fdin);
		close(fdout);
		free(dst);
}

std::atomic<uint64_t> id(0);
std::atomic<uint64_t> count(0);

void addAll(int i) {
	generate_input(++id);
	count++;
	std::cout << "task count is " << count << std::endl;
	//uint64_t sum = 0;
	//std::this_thread::sleep_for (std::chrono::milliseconds(10));
/*
	for(int i=0;i<10000000;i++) {
		sum += i;	
	}
*/
//	return sum;
}

void task(int i) {
	spool->push(addAll);	
}



int main(int argc, char** argv)
{
		int num_of_threads = 0;
		if (sscanf (argv[1], "%i", &num_of_threads) != 1) {
			fprintf(stderr, "error - not an integer");
		}
  pool = new ctpl::thread_pool(num_of_threads);
	spool = new ctpl::thread_pool(num_of_threads);
	std::vector< std::future<uint64_t> > results;

	for(int i = 0; i < 10000; ++i) {
				pool->push(task);
	}

	//std::cout <<"check results" << std::endl;
	//for(auto && result: results)
	//	std::cout << result.get() << ' ';
	//std::cout << std::endl;
	//delete pool;
	spool->stop(true);
	pool->stop(true);

	return 0;
}
