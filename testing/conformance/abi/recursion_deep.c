// CHECK: PASS: fibonacci
// CHECK: PASS: ackermann
// CHECK: PASS: tree_sum

#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline))
long fib(int n) {
    if (n <= 1) return n;
    return fib(n - 1) + fib(n - 2);
}

__attribute__((noinline))
int ackermann(int m, int n) {
    if (m == 0) return n + 1;
    if (n == 0) return ackermann(m - 1, 1);
    return ackermann(m - 1, ackermann(m, n - 1));
}

struct Node {
    int value;
    struct Node *left;
    struct Node *right;
};

__attribute__((noinline))
struct Node *make_node(int val, struct Node *l, struct Node *r) {
    struct Node *n = malloc(sizeof(struct Node));
    n->value = val;
    n->left = l;
    n->right = r;
    return n;
}

__attribute__((noinline))
long tree_sum(struct Node *n) {
    if (!n) return 0;
    return n->value + tree_sum(n->left) + tree_sum(n->right);
}

__attribute__((noinline))
void free_tree(struct Node *n) {
    if (!n) return;
    free_tree(n->left);
    free_tree(n->right);
    free(n);
}

int main(void) {
    int failed = 0;

    // fibonacci(20) = 6765
    {
        long r = fib(20);
        if (r == 6765) printf("PASS: fibonacci\n");
        else { printf("FAIL: fibonacci: got %ld\n", r); failed = 1; }
    }

    // ackermann(3, 4) = 125
    {
        int r = ackermann(3, 4);
        if (r == 125) printf("PASS: ackermann\n");
        else { printf("FAIL: ackermann: got %d\n", r); failed = 1; }
    }

    // tree sum: build tree, DFS sum
    //        1
    //       / \
    //      2   3
    //     / \ / \
    //    4  5 6  7
    // Sum = 1+2+3+4+5+6+7 = 28
    {
        struct Node *root = make_node(1,
            make_node(2, make_node(4, NULL, NULL), make_node(5, NULL, NULL)),
            make_node(3, make_node(6, NULL, NULL), make_node(7, NULL, NULL))
        );
        long r = tree_sum(root);
        free_tree(root);
        if (r == 28) printf("PASS: tree_sum\n");
        else { printf("FAIL: tree_sum: got %ld\n", r); failed = 1; }
    }

    return failed;
}
