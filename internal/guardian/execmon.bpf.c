// +build ignore

// This eBPF program monitors process execution events by attaching to
// the sched:sched_process_exec tracepoint.
//
// Compile with: go generate ./internal/guardian
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -type exec_event ebpf execmon.bpf.c -- -I/usr/include

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define PATH_MAX 256

// exec_event represents a process execution event sent to userspace.
struct exec_event {
	__u32 pid;
	__u32 ppid;
	char comm[TASK_COMM_LEN];
	char filename[PATH_MAX];
};

// Perf event array map for sending events to userspace.
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Tracepoint arguments for sched:sched_process_exec
struct trace_event_raw_sched_process_exec {
	__u64 unused;
	__u32 __data_loc_filename;
	__u32 pid;
	__u32 old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct exec_event event = {};
	struct task_struct *task;

	// Get current task
	task = (struct task_struct *)bpf_get_current_task();

	// Read PID and PPID
	event.pid = bpf_get_current_pid_tgid() >> 32;
	BPF_CORE_READ_INTO(&event.ppid, task, real_parent, tgid);

	// Read process name (comm)
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	// Read filename from tracepoint context
	// The filename is stored at a dynamic location indicated by __data_loc_filename
	unsigned short data_loc = ctx->__data_loc_filename;
	void *filename_ptr = (void *)ctx + (data_loc & 0xFFFF);
	bpf_probe_read_kernel_str(event.filename, sizeof(event.filename), filename_ptr);

	// Submit event to userspace via perf buffer
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
