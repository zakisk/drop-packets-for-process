package main

import (
	"log"
	"net"
	"time"

	// "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := dropObjects{}
	if err := loadDropObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Execute `ip a` command for network interfaces and change this to an interface on your machine.
	ifname := "wlp1s0"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach count_packets to the network interface.
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.DropPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdpLink.Close()

	err = objs.PortMap.Put(uint32(0), uint32(9254))
	if err != nil {
		log.Fatal("Error while putting process name in map:", err)
	}

	process := "Chrome_ChildIOT"
	value := [16]byte{}
	copy(value[:], []byte(process))

	err = objs.ProcNameMap.Put(uint32(0), value[:])
	if err != nil {
		log.Fatal("Error while putting process name in map:", err)
	}

	err = objs.ProcNameLenMap.Put(uint32(0), uint32(len(process)))
	if err != nil {
		log.Fatal("Error while putting process name in map:", err)
	}

	// Attach count_packets to the network interface.
	kLink, err := link.Kprobe("inet_bind", objs.KprobeInetBind, nil)
	if err != nil {
		log.Fatal("Attaching KProbe:", err)
	}
	defer kLink.Close()

	log.Println("Counting packets...")

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var value uint32
		if err := objs.PktCount.Lookup(uint32(0), &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("number of packets passed: %d\n", value)
	}
}
