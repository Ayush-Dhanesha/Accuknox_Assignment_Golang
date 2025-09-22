package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang ProcessFilter process_filter.c

type ProcessInfo struct {
	Comm [16]int8
	PID  uint32
	TGID uint32
}

func main() {
	// Parse command line arguments
	processName := "myprocess"
	allowedPort := uint16(4040)
	interfaceName := "lo"

	if len(os.Args) > 1 {
		processName = os.Args[1]
	}
	if len(os.Args) > 2 {
		port, err := strconv.Atoi(os.Args[2])
		if err != nil || port < 1 || port > 65535 {
			fmt.Printf("Usage: %s [process_name] [allowed_port] [interface]\n", os.Args[0])
			fmt.Printf("Example: %s myprocess 4040 lo\n", os.Args[0])
			os.Exit(1)
		}
		allowedPort = uint16(port)
	}
	if len(os.Args) > 3 {
		interfaceName = os.Args[3]
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load the compiled eBPF program
	spec, err := LoadProcessFilter()
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	// Create the collection of maps and programs
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Configure the target process name
	key := uint32(0)
	processNameBytes := make([]int8, 16)
	for i, b := range []byte(processName) {
		if i >= 16 {
			break
		}
		processNameBytes[i] = int8(b)
	}
	if err := coll.Maps["target_process_map"].Put(key, processNameBytes); err != nil {
		log.Fatalf("Failed to set target process name: %v", err)
	}

	// Configure the allowed port
	if err := coll.Maps["allowed_port_map"].Put(key, allowedPort); err != nil {
		log.Fatalf("Failed to set allowed port: %v", err)
	}

	// Add the target process to monitoring (simulate PID 1000)
	targetPID := uint32(1000)
	procInfo := ProcessInfo{
		Comm: processNameBytes,
		PID:  targetPID,
		TGID: targetPID,
	}
	if err := coll.Maps["process_map"].Put(targetPID, procInfo); err != nil {
		log.Fatalf("Failed to add process to monitoring: %v", err)
	}

	// Initialize statistics
	var zeroCounter uint64 = 0
	for i := uint32(0); i < 4; i++ {
		if err := coll.Maps["stats_map"].Put(i, zeroCounter); err != nil {
			log.Printf("Warning: Failed to initialize stats counter %d: %v", i, err)
		}
	}

	// Get network interface
	iface, err := netlink.LinkByName(interfaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", interfaceName, err)
	}

	// Attach XDP program to interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs["process_specific_filter"],
		Interface: iface.Attrs().Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer l.Close()

	fmt.Printf("✅ Process-specific filter loaded on %s\n", interfaceName)
	fmt.Printf("📋 Target process: '%s' (simulated PID: %d)\n", processName, targetPID)
	fmt.Printf("🔓 Allowed port: %d\n", allowedPort)
	fmt.Printf("🔒 All other ports for '%s' will be blocked\n", processName)
	fmt.Printf("📊 Statistics will be shown every 5 seconds\n")
	fmt.Printf("Press Ctrl+C to stop\n\n")

	// Setup statistics monitoring
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Wait for interrupt signal or ticker
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	go func() {
		for {
			select {
			case <-ticker.C:
				showStats(coll.Maps["stats_map"], processName)
			case <-c:
				return
			}
		}
	}()

	<-c
	fmt.Printf("\n🛑 Shutting down process-specific filter...\n")
	showStats(coll.Maps["stats_map"], processName)
}

func showStats(statsMap *ebpf.Map, processName string) {
	var total, allowed, blocked, otherProcess uint64

	if err := statsMap.Lookup(uint32(0), &total); err != nil {
		total = 0
	}
	if err := statsMap.Lookup(uint32(1), &allowed); err != nil {
		allowed = 0
	}
	if err := statsMap.Lookup(uint32(2), &blocked); err != nil {
		blocked = 0
	}
	if err := statsMap.Lookup(uint32(3), &otherProcess); err != nil {
		otherProcess = 0
	}

	targetProcess := allowed + blocked
	fmt.Printf("📈 Stats: Total=%d | %s: Allowed=%d, Blocked=%d | Other processes=%d\n",
		total, processName, allowed, blocked, otherProcess)
}
