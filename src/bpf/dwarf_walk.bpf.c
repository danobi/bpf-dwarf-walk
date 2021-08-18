// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "dwarf_walk.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, char[MAX_STACK_SIZE]);
} scratch SEC(".maps");

const volatile unsigned int stack_to_copy;
static char empty[MAX_STACK_SIZE] = {};

static int try_to_copy_stack(struct event *event, void *sp, u32 size)
{
	long ret = bpf_probe_read_user(&event->data, size, sp);
	if (ret)
		return ret;

	event->len = size;
	return 0;
}

SEC("kprobe/do_nanosleep")
int handle_kprobe(struct pt_regs *ctx)
{
	struct task_struct *current;
	struct pt_regs *user_regs;
	struct event *event;
	u32 cur_size;
	long err = 0;
	u32 key = 0;
	void *sp;

	current = bpf_get_current_task_btf();
	user_regs = (struct pt_regs *)bpf_task_pt_regs(current);
	sp = (void *)user_regs->sp;   /* Stack pointer */

	/* Zero out scratch space before using */
	bpf_map_update_elem(&scratch, &key, &empty, 0);
	event = bpf_map_lookup_elem(&scratch, &key);
	if (!event)
		return 0;

	cur_size = stack_to_copy;
	while (cur_size >= 128) {
		if (!try_to_copy_stack(event, sp, stack_to_copy))
			break;
		cur_size /= 2;
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
			      sizeof(*event) + cur_size);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
