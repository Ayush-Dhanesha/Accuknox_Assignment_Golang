package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip PacketFilter packet_filter.c

func main() {
	// Parse command line arguments
	interfaceName := "lo"
	targetPort := uint16(4040)
	
	if len(os.Args) > 1 {
		interfaceName = os.Args[1]
	}
	if len(os.Args) > 2 {
		port, err := strconv.Atoi(os.Args[2])
		if err != nil || port < 1 || port > 65535 {
			fmt.Printf("Usage: %s [interface] [port]\n", os.Args[0])
			fmt.Printf("Example: %s lo 8080\n", os.Args[0])
			os.Exit(1)
		}
		targetPort = uint16(port)
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load the compiled eBPF program and maps
	objs := PacketFilterObjects{}
	if err := LoadPacketFilterObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Get network interface
	iface, err := netlink.LinkByName(interfaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", interfaceName, err)
	}

	// Configure the port to block in the eBPF map
	key := uint32(0)
	if err := objs.BlockedPortMap.Put(key, targetPort); err != nil {
		log.Fatalf("Failed to configure blocked port: %v", err)
	}

	// Initialize statistics map
	zero := uint64(0)
	if err := objs.StatsMap.Put(uint32(0), zero); err != nil {
		log.Fatalf("Failed to initialize total counter: %v", err)
	}
	if err := objs.StatsMap.Put(uint32(1), zero); err != nil {
		log.Fatalf("Failed to initialize dropped counter: %v", err)
	}

	// Attach XDP program to interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.TcpPortFilter,
		Interface: iface.Attrs().Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer l.Close()

	fmt.Printf("✅ Packet filter loaded on %s, blocking TCP port %d\n", interfaceName, targetPort)
	fmt.Printf("📊 Filtering active - packets to port %d will be dropped\n", targetPort)
	fmt.Printf("Press Ctrl+C to stop\n")

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	fmt.Printf("\n🛑 Shutting down packet filter...\n")
}
