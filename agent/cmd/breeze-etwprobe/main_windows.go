//go:build windows

// Command breeze-etwprobe is a DIAGNOSTIC for the wave-2b Windows spike. It opens
// a real-time ETW session on Microsoft-Windows-Kernel-Network and
// Microsoft-Windows-DNS-Client and dumps, for each delivered event, its EventID,
// the issuing PID, and the value of every candidate property name it can read.
//
// Run it on a test Windows PC as Administrator, then perform an upload (e.g. send
// a document via Zalo/Messenger/a browser). The output tells us the exact
// unknowns marked TODO(windows-spike) in internal/fileegress/upload_windows.go:
//   - which EventIDs are the outbound TCP connects (vs send/recv/accept)
//   - the real property names for destination IP/port + DNS query name/results
//   - how dport / addresses are formatted (so we know whether to byte-swap)
//
// Usage:  breeze-etwprobe            (runs ~60s, or until 200 events, or Ctrl+C)
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
)

const (
	kernelNetworkProviderGUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
	dnsClientProviderGUID     = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
	maxEvents                 = 200
	runFor                    = 60 * time.Second
)

// Candidate property names to probe. We print whichever ones GetPropertyString
// returns without error, so we discover the real schema without guessing.
var candidateProps = []string{
	// Kernel-Network (TCP/UDP)
	"daddr", "saddr", "dport", "sport", "size", "connid", "seqnum", "PID",
	"DestinationIp", "SourceIp", "DestinationPort", "SourcePort",
	"Daddr", "Saddr", "Dport", "Sport",
	// DNS-Client
	"QueryName", "QueryType", "QueryResults", "QueryStatus", "DnsServerList",
	"Address", "AddressLength",
}

func main() {
	fmt.Println("breeze-etwprobe: Kernel-Network + DNS-Client event dump (spike diagnostic)")
	fmt.Println("Do an upload now (Zalo/Messenger/browser). Ctrl+C to stop early.")

	session := etw.NewRealTimeSession("Breeze-ETWProbe")
	defer session.Stop()

	for _, guid := range []string{kernelNetworkProviderGUID, dnsClientProviderGUID} {
		p, err := etw.ParseProvider(guid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse provider %s: %v\n", guid, err)
			os.Exit(1)
		}
		if err := session.EnableProvider(p); err != nil {
			fmt.Fprintf(os.Stderr, "enable provider %s: %v (run as Administrator/SYSTEM)\n", guid, err)
			os.Exit(1)
		}
	}

	var count int64
	consumer := etw.NewRealTimeConsumer(context.Background()).FromSessions(session)
	consumer.EventRecordHelperCallback = func(h *etw.EventRecordHelper) error {
		n := atomic.AddInt64(&count, 1)
		if n > maxEvents {
			h.Skip()
			return nil
		}
		id := h.EventID()
		pid := h.EventRec.EventHeader.ProcessId
		line := fmt.Sprintf("evt #%d  id=%d  pid=%d ", n, id, pid)
		for _, name := range candidateProps {
			if v, err := h.GetPropertyString(name); err == nil && v != "" {
				line += fmt.Sprintf(" %s=%q", name, v)
			}
		}
		fmt.Println(line)
		h.Skip()
		return nil
	}

	if err := consumer.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "consumer start: %v\n", err)
		os.Exit(1)
	}
	defer consumer.Stop()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	select {
	case <-sig:
	case <-time.After(runFor):
	}
	fmt.Printf("breeze-etwprobe: done, %d events observed.\n", atomic.LoadInt64(&count))
}
