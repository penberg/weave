#include <stdio.h>

int main(int argc, char *argv[], char *envp[])
{
	unsigned long envp_val = (unsigned long)envp;

	/* envp must not be a small integer (indicates register/stack bug) */
	if (envp_val > 0 && envp_val < 4096) {
		fprintf(stderr, "envp has invalid value %p\n", (void *)envp);
		return 1;
	}

	/* envp must not be NULL */
	if (envp == (char **)0) {
		fprintf(stderr, "envp is NULL\n");
		return 1;
	}

	/* envp must contain at least one entry */
	if (envp[0] == (char *)0) {
		fprintf(stderr, "envp is empty\n");
		return 1;
	}

	return 0;
}
