package iptables

import "fmt"
import "testing"

func TestOpen(t *testing.T) {
	s, err := NewIPTables("filter")

	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("\n\nip4tables:\n----------\n")
	chains := s.Chains()
	fmt.Printf("chains: %v\n", chains)

	for _, chain := range(chains) {
		counter, err := s.Counters(chain)

		if s.BuiltinChain(chain) {
			if err != nil {
				t.Fatal(err)
			}

			fmt.Printf("%v: %d packets, %d bytes\n", chain, counter.Packets, counter.Bytes)
		} else {
			if err == nil {
				t.Fatal("got counter for a not builtin chain?")
			}
			fmt.Printf("%v\n", chain)
		}

		for i, counter := range(s.RuleCounters(chain)) {
			fmt.Printf("    rule %d: %d packets, %d bytes\n", i, counter.Packets, counter.Bytes) }
	}

	s6, err := NewIP6Tables("filter")

	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("\n\nip6tables:\n----------\n")
	chains = s6.Chains()
	fmt.Printf("chains: %v\n", chains)

	for _, chain := range(chains) {
		counter, err := s6.Counters(chain)

		if s6.BuiltinChain(chain) {
			if err != nil {
				t.Fatal(err)
			}

			fmt.Printf("%v: %d packets, %d bytes\n", chain, counter.Packets, counter.Bytes)
		} else {
			if err == nil {
				t.Fatal("got counter for a not builtin chain?")
			}
			fmt.Printf("%v\n", chain)
		}

		for i, counter := range(s6.RuleCounters(chain)) {
			fmt.Printf("    rule %d: %d packets, %d bytes\n", i, counter.Packets, counter.Bytes)
		}
	}
}
