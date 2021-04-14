#include "util.h"
uint8_t argc(char **argv)
{
	uint8_t count = 0;
	char *current_argv = *argv;
	while (current_argv && count != (uint8_t)(-1)) {
		++count;
		current_argv = ++argv;
	}
	return count;
}