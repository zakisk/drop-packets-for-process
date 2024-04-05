## Problem statement 2: Drop packets only for a given process

Write an eBPF code to allow traffic only at a specific TCP port (default 4040) for a given process name (for e.g, "myprocess"). All the traffic to all other ports for only that process should be dropped.

## Solution

A simple program written in Golang along with [eBPF/XDP](https://en.wikipedia.org/wiki/Express_Data_Path) and [kprobe/inet_bind](https://elixir.bootlin.com/linux/latest/source/net/ipv4/af_inet.c#L466) programs written in C to drop incoming network packets on all ports except port `P` in the given process.


![](./demo.gif)


### How to run

#### For linux

**Step 1:**
```bash
# install the necessary dependencies to run the program

sudo apt update
sudo apt install clang llvm gcc golang-go
sudo apt install linux-headers-$(uname -r)

sudo apt-get update
sudo apt-get install bpfcc-tools libbpfcc-dev
```

**Step 2:**
```bash
# clone the repository
git clone github.com/zakisk/drop-packets-for-process
```

**Step 3:**
```bash

# build and run program
cd drop-packets-for-process
make build && sudo ./drop-packets-for-process
```

