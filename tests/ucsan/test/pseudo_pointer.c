// METADATA: note.yaml
// FLAG: 200

int cal(long* a) {
  int sum;
  long ptr = *a;
  sum = *(int *)ptr + 1;
  if (sum > 5) {
    exit(200);
  };
}