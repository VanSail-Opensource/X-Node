package firewall

import (
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"net/netip"
)

type expressions = []expr.Any

func cat(groups ...expressions) expressions {
	var out expressions
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}
func verdict(kind expr.VerdictKind, chain string) expressions {
	return expressions{&expr.Verdict{Kind: kind, Chain: chain}}
}
func accept() expressions           { return verdict(expr.VerdictAccept, "") }
func drop() expressions             { return verdict(expr.VerdictDrop, "") }
func jump(chain string) expressions { return verdict(expr.VerdictJump, chain) }
func goTo(chain string) expressions { return verdict(expr.VerdictGoto, chain) }
func cmp(data []byte, invert bool) expressions {
	op := expr.CmpOpEq
	if invert {
		op = expr.CmpOpNeq
	}
	return expressions{&expr.Cmp{Op: op, Register: 1, Data: data}}
}
func meta(key expr.MetaKey, data []byte, invert bool) expressions {
	return cat(expressions{&expr.Meta{Key: key, Register: 1}}, cmp(data, invert))
}
func family(v6 bool) expressions {
	value := byte(unix.NFPROTO_IPV4)
	if v6 {
		value = unix.NFPROTO_IPV6
	}
	return meta(expr.MetaKeyNFPROTO, []byte{value}, false)
}
func l4(proto byte) expressions { return meta(expr.MetaKeyL4PROTO, []byte{proto}, false) }
func payload(base expr.PayloadBase, offset, length uint32) expressions {
	return expressions{&expr.Payload{DestRegister: 1, Base: base, Offset: offset, Len: length}}
}
func mask(data []byte) expressions {
	return expressions{&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(len(data)), Mask: data, Xor: make([]byte, len(data))}}
}
func source(v6 bool, subnet bool) expressions {
	offset, size := uint32(12), uint32(4)
	if v6 {
		offset, size = 8, 16
	}
	result := cat(family(v6), payload(expr.PayloadBaseNetworkHeader, offset, size))
	if subnet {
		result = cat(result, mask(netip.MustParseAddr("ffff:ffff:ffff:ffff::").AsSlice()))
	}
	return result
}
func address(raw string, dest bool, invert bool) expressions {
	prefix := netip.MustParsePrefix(raw).Masked()
	v6 := prefix.Addr().Is6()
	offset, size := uint32(12), uint32(4)
	if v6 {
		offset, size = 8, 16
	}
	if dest {
		offset += size
	}
	bits := make([]byte, size)
	for i := 0; i < prefix.Bits(); i++ {
		bits[i/8] |= 0x80 >> (i % 8)
	}
	return cat(family(v6), payload(expr.PayloadBaseNetworkHeader, offset, size), mask(bits), cmp(prefix.Addr().AsSlice(), invert))
}
func lookup(name string, invert bool) expressions {
	return expressions{&expr.Lookup{SourceRegister: 1, SetName: name, Invert: invert}}
}
func sourceSet(v6 bool, name string, invert bool, subnet bool) expressions {
	return cat(source(v6, subnet), lookup(name, invert))
}
func port(proto byte, value uint16, dest bool) expressions {
	offset := uint32(0)
	if dest {
		offset = 2
	}
	return cat(l4(proto), payload(expr.PayloadBaseTransportHeader, offset, 2), cmp(binaryutil.BigEndian.PutUint16(value), false))
}
func portSet(proto byte, name string, invert bool) expressions {
	return cat(l4(proto), payload(expr.PayloadBaseTransportHeader, 2, 2), lookup(name, invert))
}
func ct(key expr.CtKey, data []byte, invert bool) expressions {
	return cat(expressions{&expr.Ct{Register: 1, Key: key}}, cmp(data, invert))
}
func ctState(bits uint32, invert bool) expressions {
	return cat(expressions{&expr.Ct{Register: 1, Key: expr.CtKeySTATE}}, mask(binaryutil.NativeEndian.PutUint32(bits)), cmp(make([]byte, 4), !invert))
}
func direction(reply bool, invert bool) expressions {
	value := byte(0)
	if reply {
		value = 1
	}
	return ct(expr.CtKeyDIRECTION, []byte{value}, invert)
}
func counter(name string) expressions {
	return expressions{&expr.Objref{Type: unix.NFT_OBJECT_COUNTER, Name: name}}
}
func flags(bits, expected byte, invert bool) expressions {
	return cat(l4(unix.IPPROTO_TCP), payload(expr.PayloadBaseTransportHeader, 13, 1), mask([]byte{bits}), cmp([]byte{expected}, invert))
}
func icmp(v6 bool, kind byte) expressions {
	proto := byte(unix.IPPROTO_ICMP)
	if v6 {
		proto = unix.IPPROTO_ICMPV6
	}
	return cat(family(v6), l4(proto), payload(expr.PayloadBaseTransportHeader, 0, 1), cmp([]byte{kind}, false))
}
func hop(value byte) expressions {
	return cat(family(true), payload(expr.PayloadBaseNetworkHeader, 7, 1), cmp([]byte{value}, false))
}
