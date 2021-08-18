#pragma once

#define MAX_STACK_SIZE	(16 << 10)	/* 16KB max copy size */

struct event
{
	unsigned long len;
	char data[];
};
