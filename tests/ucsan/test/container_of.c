// METADATA: note.yaml
// FLAG: 200

struct s {
    int a;
    int c;
    char padding[8];
    int b;
};

int cal(int *b) {
  int sum = 0;
  if (b != 0x1234) return 0;
  if (*b != 0xaaaaaa) {
    printf("bad b = %x\n", *b);
    return 0;
    // __builtin_trap();
  }
  void *base = b;
  char* padding = (char*)b - __builtin_offsetof(struct s, b) + __builtin_offsetof(struct s, padding);
  int flag = 0;
  if (padding[1] == 'b') {
    flag = 1;
  }
  base = base - __builtin_offsetof(struct s, b);
  struct s *s = (struct s *)base;
  if (s->a == 0xdeadbeef) {
    char * a = s->padding;
    if (a[1] == 'c' && flag == 1) {
      exit(999); // should not happen
    }
    if (a[0] == 'a') {
        exit(200);
    }

    // __builtin_trap();
  }
}
