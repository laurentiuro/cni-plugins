package utils

import (
	"fmt"
	current "github.com/containernetworking/cni/pkg/types/040"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"net"
)

func addPostRoutingSourceNatRule(opts map[string]interface{}) error {
	v := opts["version"].(string)
	tableName := opts["table"].(string)
	chainName := opts["chain"].(string)
	bridgeIntfName := opts["bridge_interface"].(string)
	addr := opts["ip_address"].(*current.IPConfig)
	outboundAddress := opts["outbound_address"].(net.IPNet)

	if v != "4" && v != "6" {
		return nil
	}

	conn, err := initNftConn()
	if err != nil {
		return err
	}

	var Family nftables.TableFamily
	if v == "4" {
		Family = nftables.TableFamilyIPv4
	} else {
		Family = nftables.TableFamilyIPv6
	}

	tb := &nftables.Table{
		Name:   tableName,
		Family: Family,
	}

	ch := &nftables.Chain{
		Name:  chainName,
		Table: tb,
	}

	r := &nftables.Rule{
		Table: tb,
		Chain: ch,
		Exprs: []expr.Any{},
	}

	r.Exprs = append(r.Exprs, &expr.Meta{
		Key:      expr.MetaKeyIIFNAME,
		Register: 1,
	})
	r.Exprs = append(r.Exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     EncodeInterfaceName(bridgeIntfName),
	})

	if v == "4" {
		r.Exprs = append(r.Exprs, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		})
		r.Exprs = append(r.Exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     addr.Address.IP.To4(),
		})
	} else {
		r.Exprs = append(r.Exprs, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       8,
			Len:          16,
		})
		r.Exprs = append(r.Exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     addr.Address.IP.To16(),
		})
	}

	r.Exprs = append(r.Exprs, &expr.Counter{})

	// nat or snat
	if outboundAddress.IP == nil {
		r.Exprs = append(r.Exprs, &expr.Masq{})
	} else {
		if v == "4" {
			r.Exprs = append(r.Exprs, &expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // TODO
				Len:          2, // TODO
			})

			r.Exprs = append(r.Exprs, &expr.Immediate{
				Register: 1,
				Data:     outboundAddress.IP.To4(),
			})

			r.Exprs = append(r.Exprs, &expr.NAT{
				Type:       expr.NATTypeSourceNAT,
				Family:     unix.NFPROTO_IPV4,
				RegAddrMin: 1,
			})
		} else {
			r.Exprs = append(r.Exprs, &expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // TODO
				Len:          2, // TODO
			})

			r.Exprs = append(r.Exprs, &expr.Immediate{
				Register: 1,
				Data:     outboundAddress.IP.To16(),
			})

			r.Exprs = append(r.Exprs, &expr.NAT{
				Type:       expr.NATTypeSourceNAT,
				Family:     unix.NFPROTO_IPV6,
				RegAddrMin: 1,
			})
		}
	}

	conn.AddRule(r)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf(
			"failed adding source NAT rule in chain %s of ipv%s %s table for %v: %s",
			chainName, v, tableName, addr, err,
		)
	}
	return nil
}
