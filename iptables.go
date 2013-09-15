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
import "fmt"
import "net"
import "unsafe"

type IPTables struct {
	h *C.struct_xtc_handle
}

type IP6Tables struct {
	h *C.struct_xtc_handle
}

type Not bool

type Rule struct {
	Src          *net.IPNet
	Dest         *net.IPNet
	InDev        string
	OutDev       string
	Not struct {
		Src Not
		Dest Not
		InDev Not
		OutDev Not
	}
	Target string
	Counter
}

type Counter struct {
	Packets uint64
	Bytes   uint64
}

var (
	ErrorCustomChain = errors.New("this chain has no counters")
)

// Make a snapshot of the current iptables rules
func NewIPTables(table string) (*IPTables, error) {
	cname := C.CString(table)
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
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	chains := []string{}

	for c := C.iptc_first_chain(s.h); c != nil; c = C.iptc_next_chain(s.h) {
		chains = append(chains, C.GoString(c))
	}

	return chains
}

func (s *IPTables) BuiltinChain(chain string) bool {
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	return int(C.iptc_builtin(cname, s.h)) != 0
}

func (s *IPTables) Counters(chain string) (*Counter, error) {
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

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

func (s *IPTables) Rules(chain string) ([]*Rule) {
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	rules := make([]*Rule, 0)

	for r := C.iptc_first_rule(cname, s.h); r != nil; r = C.iptc_next_rule(r, s.h) {
		c := new(Rule)

		// read counters
		c.Packets = uint64(r.counters.pcnt)
		c.Bytes = uint64(r.counters.bcnt)

		// read network interfaces
		c.InDev = C.GoString(&r.ip.iniface[0])
		c.OutDev = C.GoString(&r.ip.outiface[0])
		if r.ip.invflags & C.IPT_INV_VIA_IN != 0 {
			c.Not.InDev = true
		}
		if r.ip.invflags & C.IPT_INV_VIA_OUT != 0 {
			c.Not.OutDev = true
		}

		// read source ip and mask
		src := uint32(r.ip.src.s_addr)
		c.Src = new(net.IPNet)
		c.Src.IP = net.IPv4(byte(src&0xff),
			byte((src>>8)&0xff),
			byte((src>>16)&0xff),
			byte((src>>24)&0xff))
		mask := uint32(r.ip.smsk.s_addr)
		c.Src.Mask = net.IPv4Mask(byte(mask&0xff),
			byte((mask>>8)&0xff),
			byte((mask>>16)&0xff),
			byte((mask>>24)&0xff))
		if r.ip.invflags & C.IPT_INV_SRCIP != 0 {
			c.Not.Src = true
		}

		// read destination ip and mask
		dest := uint32(r.ip.dst.s_addr)
		c.Dest = new(net.IPNet)
		c.Dest.IP = net.IPv4(byte(dest&0xff),
			byte((dest>>8)&0xff),
			byte((dest>>16)&0xff),
			byte((dest>>24)&0xff))
		mask = uint32(r.ip.dmsk.s_addr)
		c.Dest.Mask = net.IPv4Mask(byte(mask&0xff),
			byte((mask>>8)&0xff),
			byte((mask>>16)&0xff),
			byte((mask>>24)&0xff))
		if r.ip.invflags & C.IPT_INV_DSTIP != 0 {
			c.Not.Dest = true
		}

		// read target
		target := C.iptc_get_target(r, s.h)
		if target != nil {
			c.Target = C.GoString(target)
		}

		rules = append(rules, c)
	}

	return rules
}

func (s *IPTables) Zero(chain string) error {
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	ret, err := C.iptc_zero_entries(cname, s.h)

	if err != nil || ret != 1 {
		return err
	}

	return nil
}

// commit and free resources
func (s *IPTables) Close() error {
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	ret, err := C.iptc_commit(s.h)
	if err != nil || ret != 1 {
		return err
	}

	C.iptc_free(s.h)
	s.h = nil

	return nil
}

func NewIP6Tables(table string) (*IP6Tables, error) {
	cname := C.CString(table)
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
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	chains := []string{}

	for c := C.ip6tc_first_chain(s.h); c != nil; c = C.ip6tc_next_chain(s.h) {
		chains = append(chains, C.GoString(c))
	}

	return chains
}

func (s *IP6Tables) BuiltinChain(chain string) bool {
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	return int(C.ip6tc_builtin(cname, s.h)) != 0
}

func (s *IP6Tables) Counters(chain string) (*Counter, error) {
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

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

func (s *IP6Tables) Rules(chain string) []*Rule {
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	rules := make([]*Rule, 0)

	for r := C.ip6tc_first_rule(cname, s.h); r != nil; r = C.ip6tc_next_rule(r, s.h) {
		c := new(Rule)

		// read counters
		c.Packets = uint64(r.counters.pcnt)
		c.Bytes = uint64(r.counters.bcnt)

		// read network interfaces
		c.InDev = C.GoString(&r.ipv6.iniface[0])
		c.OutDev = C.GoString(&r.ipv6.outiface[0])
		if r.ipv6.invflags & C.IP6T_INV_VIA_IN != 0 {
			c.Not.InDev = true
		}
		if r.ipv6.invflags & C.IP6T_INV_VIA_OUT != 0 {
			c.Not.OutDev = true
		}

		// read source ip and mask
		src := r.ipv6.src.__in6_u
		c.Src = new(net.IPNet)
		c.Src.IP = net.IP{src[0], src[1], src[2], src[3],
			src[4], src[5], src[6], src[7],
			src[8], src[9], src[10], src[11],
			src[12], src[13], src[14], src[15]}
		mask := r.ipv6.smsk.__in6_u
		c.Src.Mask = net.IPMask{mask[0], mask[1], mask[2], mask[3],
			mask[4], mask[5], mask[6], mask[7],
			mask[8], mask[9], mask[10], mask[11],
			mask[12], mask[13], mask[14], mask[15]}
		if r.ipv6.invflags & C.IP6T_INV_SRCIP != 0 {
			c.Not.Src = true
		}

		// read destination ip and mask
		dest := r.ipv6.dst.__in6_u
		c.Dest = new(net.IPNet)
		c.Dest.IP = net.IP{dest[0], dest[1], dest[2], dest[3],
			dest[4], dest[5], dest[6], dest[7],
			dest[8], dest[9], dest[10], dest[11],
			dest[12], dest[13], dest[14], dest[15]}
		mask = r.ipv6.dmsk.__in6_u
		c.Dest.Mask = net.IPMask{mask[0], mask[1], mask[2], mask[3],
			mask[4], mask[5], mask[6], mask[7],
			mask[8], mask[9], mask[10], mask[11],
			mask[12], mask[13], mask[14], mask[15]}
		if r.ipv6.invflags & C.IP6T_INV_DSTIP != 0 {
			c.Not.Dest = true
		}

		// read target
		target := C.ip6tc_get_target(r, s.h)
		if target != nil {
			c.Target = C.GoString(target)
		}

		rules = append(rules, c)
	}

	return rules
}

func (s *IP6Tables) Zero(chain string) error {
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	cname := C.CString(chain)
	defer C.free(unsafe.Pointer(cname))

	ret, err := C.ip6tc_zero_entries(cname, s.h)

	if err != nil || ret != 1 {
		return err
	}

	return nil
}

// commit and free resources
func (s *IP6Tables) Close() error {
	if s.h == nil {
		panic("trying to use libiptc handle after Close()")
	}

	if s.h == nil {
		return nil;
	}

	ret, err := C.ip6tc_commit(s.h)
	if err != nil || ret != 1 {
		return err
	}

	C.ip6tc_free(s.h)
	s.h = nil

	return nil
}

func (r Rule) String() string {
	return fmt.Sprintf("in: %s%s, out: %s%s, %s%s -> %s%s -> %s: %d packets, %d bytes",
		r.Not.InDev, r.InDev,
		r.Not.OutDev, r.OutDev,
		r.Not.Src, r.Src,
		r.Not.Dest, r.Dest,
		r.Target,
		r.Packets, r.Bytes)
}

func (n Not) String() string {
	if n {
		return "!"
	}
	return " "
}

