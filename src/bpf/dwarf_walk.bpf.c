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

/* Copy 8K bytes by default */
const unsigned long stack_to_copy = 8192;

SEC("kprobe/do_nanosleep")
int handle_kprobe(struct pt_regs *ctx)
{
	struct task_struct *current;
	struct pt_regs *user_regs;
	struct event *event;
	long err = 0;
	u32 key = 0;

	current = bpf_get_current_task_btf();
	user_regs = (struct pt_regs *)bpf_task_pt_regs(current);

	event = bpf_map_lookup_elem(&scratch, &key);
	if (!event)
		return 0;

	event->len = stack_to_copy;
	if (bpf_probe_read_user(&event->data, stack_to_copy, (void *)user_regs->sp))
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
			      sizeof(*event) + stack_to_copy);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
