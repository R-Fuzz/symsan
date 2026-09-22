// METADATA: make_input.yaml
// FLAG: 200
#include <stdio.h>
#include <stdlib.h>

extern void __ucsan_symbolize_input(void *, unsigned long, int);

struct node {
    unsigned int v;
    struct node *next;
};

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

void test() {
    // Leaf object (no outgoing pointers to other input objects)
    struct node obj2 = {
        .v = 42,
        .next = NULL,
    };

    // Parent object (points to obj2)
    struct node obj1 = {
        .v = 10,
        .next = &obj2,
    };

    // Register objects as symbolic inputs (leaves first)
    __ucsan_symbolize_input(&obj2, sizeof(obj2), 2);
    __ucsan_symbolize_input(&obj1, sizeof(obj1), 1);

    // Call target
    cal(&obj1);
}
