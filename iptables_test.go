// Copyright 2013 by Alexander Neumann <alexander@bumpern.de>
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
//
// For more information on the GPL, please go to:
// http://www.gnu.org/copyleft/gpl.html

package iptables

import "fmt"
import "testing"

func TestOpen(t *testing.T) {
	s, err := NewIPTables("filter")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fmt.Printf("ip4tables:\n----------\n")
	chains := s.Chains()
	fmt.Printf("chains: %v\n", chains)

	for _, chain := range chains {
		counter, err := s.Counter(chain)

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

	s6, err := NewIP6Tables("filter")
	if err != nil {
		t.Fatal(err)
	}
	defer s6.Close()

	fmt.Printf("\nip6tables:\n----------\n")
	chains = s6.Chains()
	fmt.Printf("chains: %v\n", chains)

	for _, chain := range chains {
		counter, err := s6.Counter(chain)

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
}
