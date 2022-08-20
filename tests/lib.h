#ifndef LIB_H
#define LIB_H

#include <stdio.h>
#include <stdlib.h>

FILE *chk_fopen(const char *pathname, const char *mode) {
  FILE* fp = fopen(pathname, mode);
  if (!fp) {
    fprintf(stderr, "Failed to open\n");
    exit(0);
  }
  return fp;
}

void chk_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
  if (fread(ptr, size, nmemb, stream) != nmemb) {
    fprintf(stderr, "Failed to read");
    exit(0);
  }
}


#endif /* LIB_H */
