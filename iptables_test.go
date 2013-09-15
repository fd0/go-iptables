package iptables

import "fmt"
import "testing"

func TestOpen(t *testing.T) {
	s, err := NewIPTables("raw")

	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("ip4tables:\n----------\n")
	chains := s.Chains()
	fmt.Printf("chains: %v\n", chains)

	for _, chain := range chains {
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

		for i, rule := range s.Rules(chain) {
			fmt.Printf("    rule %d: %s\n", i, rule)
		}

		err = s.Zero(chain)
		if err != nil {
			t.Fatalf("error zeroing chain %s: %v", chain, err)
		}
	}
	s.Close()

	s6, err := NewIP6Tables("filter")

	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("\nip6tables:\n----------\n")
	chains = s6.Chains()
	fmt.Printf("chains: %v\n", chains)

	for _, chain := range chains {
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

		for i, rule := range s6.Rules(chain) {
			fmt.Printf("    rule %d: %s\n", i, rule)
		}

		err = s6.Zero(chain)
		if err != nil {
			t.Fatalf("error zeroing chain %s: %v", chain, err)
		}
	}
	s6.Close()
}
