// CHECK: Before sort: 5 2 8 1 9 3 7 4 6
// CHECK: compare: 5 vs 9
// CHECK: compare: 9 vs 6
// CHECK: compare: 5 vs 6
// CHECK: compare: 2 vs 6
// CHECK: compare: 8 vs 6
// CHECK: compare: 5 vs 6
// CHECK: compare: 1 vs 6
// CHECK: compare: 9 vs 6
// CHECK: compare: 4 vs 6
// CHECK: compare: 3 vs 6
// CHECK: compare: 7 vs 6
// CHECK: compare: 7 vs 6
// CHECK: compare: 7 vs 9
// CHECK: compare: 9 vs 8
// CHECK: compare: 7 vs 8
// CHECK: compare: 3 vs 2
// CHECK: compare: 3 vs 5
// CHECK: compare: 5 vs 1
// CHECK: compare: 3 vs 1
// CHECK: compare: 2 vs 1
// CHECK: compare: 5 vs 4
// CHECK: compare: 3 vs 4
// CHECK: After sort: 1 2 3 4 5 6 7 8 9
// CHECK: PASS: array is sorted
/*
 * Test case for libc functions that take function pointers as callbacks.
 *
 * This tests qsort() which internally calls the comparison function via
 * an indirect branch. The bug is that when libc (supervisor code) calls
 * back into the guest's comparison function, it bypasses Weave's dispatcher
 * because the indirect branch originates from supervisor code, not from
 * translated guest code.
 */

#include <stdio.h>
#include <stdlib.h>

/* Comparison callback function - this is guest code that will be called by libc */
int compare_ints(const void *a, const void *b) {
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    printf("compare: %d vs %d\n", ia, ib);
    return ia - ib;
}

int main(int argc, char *argv[]) {
    int arr[] = {5, 2, 8, 1, 9, 3, 7, 4, 6};
    int n = sizeof(arr) / sizeof(arr[0]);

    printf("Before sort: ");
    for (int i = 0; i < n; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");

    /* This call passes our compare_ints function pointer to qsort.
     * qsort will call compare_ints via an indirect branch.
     * If the bug exists, this will crash or behave incorrectly. */
    qsort(arr, n, sizeof(int), compare_ints);

    printf("After sort: ");
    for (int i = 0; i < n; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");

    /* Verify the array is sorted */
    for (int i = 1; i < n; i++) {
        if (arr[i - 1] > arr[i]) {
            printf("FAIL: array not sorted at index %d\n", i);
            return 1;
        }
    }
    printf("PASS: array is sorted\n");
    return 0;
}
