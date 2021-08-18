#pragma once

#define MAX_STACK_SIZE	(8 << 20)	/* 8MB max copy size */

struct event
{
	unsigned long len;
	char data[];
};
