package iptables

/*
#cgo pkg-config: libiptc
#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <libiptc/libiptc.h>
#include <libiptc/libip6tc.h>
*/
import "C"
import "errors"
import "unsafe"

type IPTables struct {
	h *C.struct_xtc_handle
}

type IP6Tables struct {
	h *C.struct_xtc_handle
}

type Counter struct {
	Packets uint64
	Bytes uint64
}

var (
	ErrorCustomChain = errors.New("this chain has no counters")
)

// Make a snapshot of the current iptables rules
func NewIPTables(table string) (*IPTables, error) {
	cname := C.CString(table);
	defer C.free(unsafe.Pointer(cname))
	s := new(IPTables)
	h, err := C.iptc_init(cname)

	if err != nil {
		return nil, err
	}
	s.h = h
	return s, nil
}

func (s *IPTables) Chains() []string {
	chains := []string{}

	for c := C.iptc_first_chain(s.h); c != nil; c = C.iptc_next_chain(s.h) {
		chains = append(chains, C.GoString(c))
	}

	return chains
}

func (s *IPTables) BuiltinChain(chain string) bool {
	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	return int(C.iptc_builtin(cname, s.h)) != 0
}

func (s *IPTables) Counters(chain string) (*Counter, error) {
	if !s.BuiltinChain(chain) {
		return nil, ErrorCustomChain
	}

	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	count := new(C.struct_xt_counters)
	_, err := C.iptc_get_policy(cname, count, s.h)

	if err != nil {
		return nil, err
	}

	c := new(Counter)
	c.Packets = uint64(count.pcnt)
	c.Bytes = uint64(count.bcnt)

	return c, nil
}

func (s *IPTables) RuleCounters(chain string) []*Counter {
	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	counters := make([]*Counter, 0)

	for r := C.iptc_first_rule(cname, s.h); r != nil; r = C.iptc_next_rule(r, s.h) {
		c := new(Counter)
		c.Packets = uint64(r.counters.pcnt)
		c.Bytes = uint64(r.counters.bcnt)
		counters = append(counters, c)
	}

	return counters
}

func NewIP6Tables(table string) (*IP6Tables, error) {
	cname := C.CString(table);
	defer C.free(unsafe.Pointer(cname))
	s := new(IP6Tables)
	h, err := C.ip6tc_init(cname)

	if err != nil {
		return nil, err
	}
	s.h = h
	return s, nil
}

func (s *IP6Tables) Chains() []string {
	chains := []string{}

	for c := C.ip6tc_first_chain(s.h); c != nil; c = C.ip6tc_next_chain(s.h) {
		chains = append(chains, C.GoString(c))
	}

	return chains
}

func (s *IP6Tables) BuiltinChain(chain string) bool {
	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	return int(C.ip6tc_builtin(cname, s.h)) != 0
}

func (s *IP6Tables) Counters(chain string) (*Counter, error) {
	if !s.BuiltinChain(chain) {
		return nil, ErrorCustomChain
	}

	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	count := new(C.struct_xt_counters)
	_, err := C.ip6tc_get_policy(cname, count, s.h)

	if err != nil {
		return nil, err
	}

	c := new(Counter)
	c.Packets = uint64(count.pcnt)
	c.Bytes = uint64(count.bcnt)

	return c, nil
}

func (s *IP6Tables) RuleCounters(chain string) []*Counter {
	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	counters := make([]*Counter, 0)

	for r := C.ip6tc_first_rule(cname, s.h); r != nil; r = C.ip6tc_next_rule(r, s.h) {
		c := new(Counter)
		c.Packets = uint64(r.counters.pcnt)
		c.Bytes = uint64(r.counters.bcnt)
		counters = append(counters, c)
	}

	return counters
}

