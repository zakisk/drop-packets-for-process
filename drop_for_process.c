
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <iproute2/bpf_elf.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/ptrace.h>
#include <stdbool.h>
#include <linux/in6.h>

#define TASK_COMM_LEN 16

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpass-failed"
#endif

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, char[TASK_COMM_LEN]);
    __uint(max_entries, 1);
} proc_name_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} proc_name_len_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} port_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, bool);
    __uint(max_entries, 1);
} is_req_process_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} assigned_port_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} pkt_count SEC(".maps");

SEC("xdp")
int drop_packets(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    struct tcphdr *tcp = (void *)ip + sizeof(*ip);

    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    // Check if it's a TCP packet
    if (ip->protocol == IPPROTO_TCP)
    {
        __u32 key = 0;
        __u32 *port = bpf_map_lookup_elem(&port_map, &key);
        __u32 *count = bpf_map_lookup_elem(&pkt_count, &key);
        __u32 *assigned_port = bpf_map_lookup_elem(&assigned_port_map, &key);
        bool *is_proc = bpf_map_lookup_elem(&is_req_process_map, &key);

        // if both or one of them is NULL.
        if (port && assigned_port && is_proc)
        {
            // check if packet belongs to the requested process
            if (*is_proc)
            {   
                unsigned short dest_port = bpf_ntohs(tcp->dest);
                if (*assigned_port == *port && bpf_ntohs(tcp->dest) == *port)
                {
                    // increase passed packets count
                    if (count)
                    {
                        __sync_fetch_and_add(count, 1);
                    }

                    return XDP_PASS;
                }
                else
                {
                    return XDP_DROP;
                }
            }
        }
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("kprobe/inet_bind")
int kprobe_inet_bind(struct pt_regs *ctx)
{
    struct sockaddr_in *sa_ptr = (void *)PT_REGS_PARM2(ctx);
    struct sockaddr_in sa = {};
    bpf_probe_read_kernel(&sa, sizeof(struct sockaddr_in), (void *)sa_ptr);

    char comm[TASK_COMM_LEN] = {};
    // get process name i.e. command
    bpf_get_current_comm(&comm, sizeof(comm));
    comm[sizeof(comm) - 1] = '\0';

    __u32 key = 0;

    // get user defined port and copy it
    char process[TASK_COMM_LEN] = {};
    process[sizeof(process) - 1] = '\0';
    const char *proc_name = bpf_map_lookup_elem(&proc_name_map, &key);
    // if process name isn't found in map.
    if (!proc_name)
    {
        return 1;
    }
    bpf_probe_read(&process, sizeof(process), proc_name);

    __u32 *assigned_port = bpf_map_lookup_elem(&assigned_port_map, &key);
    __u32 *len = bpf_map_lookup_elem(&proc_name_len_map, &key);

    bool result = true;
#pragma clang loop unroll(full)
    for (int i = 0; i < sizeof(process); i++)
    {
        if ((process[i] != '\0' || comm[i] != '\0') && comm[i] != process[i])
        {
            result = false;
            break;
        }
    }

    __u32 value;
    if (result)
    {
        value = (__u32)bpf_ntohs(sa.sin_port);
    }
    else
    {
        // if process doesn't match with intended process then set `assigned_port_map` value to -1
        // because if it is being persisted in map, above XDP program will continue to drop packets
        // for other processes as well.
        value = -1;
    }
    bpf_map_update_elem(&is_req_process_map, &key, &result, BPF_ANY);
    bpf_printk("port %d is assigned to process(%s)", bpf_ntohs(sa.sin_port), comm);
    // update value
    bpf_map_update_elem(&assigned_port_map, &key, &value, BPF_ANY);

    return 1;
}