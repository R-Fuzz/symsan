// METADATA: note.yaml
// FLAG: 200
struct node
{
  // char padding[10];
  unsigned int v;
  // int v1;
  struct node* next;
};

int *return_ptr(int *a) {
  return a;
}

int* bar(int *b, int unused) {
  *b += 2;
  return b;
}

int foo(int a) {
  return a + 1;
}


int cal(struct node* head) {
  int sum = 0;
  while (head) {
    sum += head->v;
    if (head->v > 40) return 0;
    head = head->next;
  }
  if (sum > 100) {
    if (sum > 200) {
      exit(200);
    }
  }
  return sum;
}