package firewall

import (
	"fmt"
	current "github.com/containernetworking/cni/pkg/types/040"
	"github.com/laurentiuro/cni-plugins/pkg/utils"
	"net"
)

// Interface represents a collection of addresses
// associated with a network interface.
type Interface struct {
	addrs []*current.IPConfig
}

// Plugin represents the nftables firewall/filter CNI plugin.
type Plugin struct {
	name                    string
	cniVersion              string
	supportedVersions       []string
	filterTableName         string
	forwardFilterChainName  string
	natTableName            string
	postRoutingNatChainName string
	snatTo4					string
	snatTo6					string
	interfaceChain          []string
	targetInterfaces        map[string]*Interface
	targetIPVersions        map[string]bool
}

// NewPlugin returns an instance of Plugin.
func NewPlugin(conf *Config) *Plugin {
	return &Plugin{
		name:                    "cni-nftables-firewall",
		cniVersion:              "0.4.0",
		supportedVersions:       supportedVersions,
		filterTableName:         conf.FilterTableName,
		forwardFilterChainName:  conf.ForwardFilterChainName,
		natTableName:            conf.NatTableName,
		postRoutingNatChainName: conf.PostRoutingNatChainName,
		snatTo4:				 conf.SnatTo4,
		snatTo6:				 conf.SnatTo6,
		targetIPVersions:        make(map[string]bool),
		interfaceChain:          []string{},
	}
}

// Add adds firewall rules.
func (p *Plugin) Add(conf *Config, result *current.Result) error {
	if err := p.execAdd(conf, result); err != nil {
		return fmt.Errorf("%s.Add() error: %s", p.name, err)
	}
	return nil
}

// Check checks whether appropriate firewall rules exist.
func (p *Plugin) Check(conf *Config, result *current.Result) error {
	if err := p.execCheck(conf, result); err != nil {
		return fmt.Errorf("%s.Check() error: %s", p.name, err)
	}
	return nil
}

// Delete deletes appropriate firewall rules, if any.
func (p *Plugin) Delete(conf *Config, result *current.Result) error {
	if err := p.execDelete(conf, result); err != nil {
		return fmt.Errorf("%s.Del() error: %s", p.name, err)
	}
	return nil
}

func (p *Plugin) execAdd(conf *Config, prevResult *current.Result) error {
	if err := p.validateInput(prevResult); err != nil {
		return fmt.Errorf("failed validating input: %s", err)
	}

	for v := range p.targetIPVersions {
		exists, err := utils.IsTableExist(v, p.filterTableName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s filter table info: %s", v, err)
		}
		if !exists {
			if err := utils.CreateTable(v, p.filterTableName); err != nil {
				return fmt.Errorf("failed creating ipv%s filter table: %s", v, err)
			}
		}
		exists, err = utils.IsChainExists(v, p.filterTableName, p.forwardFilterChainName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s forward chain info: %s", v, err)
		}
		if !exists {
			if err := utils.CreateFilterForwardChain(v, p.filterTableName, p.forwardFilterChainName); err != nil {
				return fmt.Errorf("failed creating ipv%s forward chain: %s", v, err)
			}
		}

		// NAT Table and Chains Setup
		exists, err = utils.IsTableExist(v, p.natTableName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s %s table info: %s", v, p.natTableName, err)
		}
		if !exists {
			if err := utils.CreateTable(v, p.natTableName); err != nil {
				return fmt.Errorf("failed creating ipv%s %s table: %s", v, p.natTableName, err)
			}
		}

		exists, err = utils.IsChainExists(v, p.natTableName, p.postRoutingNatChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining info about ipv%s %s chain in %s table: %s",
				v, p.postRoutingNatChainName, p.natTableName, err,
			)
		}
		if !exists {
			if err := utils.CreateNatPostRoutingChain(v, p.natTableName, p.postRoutingNatChainName); err != nil {
				return fmt.Errorf(
					"failed creating ipv%s %s chain in %s table: %s",
					v, p.postRoutingNatChainName, p.natTableName, err,
				)
			}
		}

	}

	// Set bridge interface name
	bridgeIntfName := p.interfaceChain[0]

	for _, targetInterface := range p.targetInterfaces {
		for _, addr := range targetInterface.addrs {

			chainName := utils.GetChainName("ffw", conf.ContainerID)
			exists, err := utils.IsChainExists(addr.Version, p.filterTableName, chainName)
			if err != nil {
				return fmt.Errorf(
					"failed obtaining ipv%s filter %s chain info: %s",
					addr.Version, chainName, err,
				)
			}

			if !exists {
				if err := utils.CreateChain(
					addr.Version,
					p.filterTableName,
					chainName,
					"none", "none", "none",
				); err != nil {
					return fmt.Errorf(
						"failed creating ipv%s filter %s chain: %s",
						addr.Version, chainName, err,
					)
				}
			}

			if err := utils.CreateJumpRule(
				addr.Version,
				p.filterTableName,
				p.forwardFilterChainName,
				chainName,
			); err != nil {
				return fmt.Errorf(
					"failed creating jump rule to ipv%s filter %s chain: %s",
					addr.Version, chainName, err,
				)
			}

			if err := utils.AddFilterForwardRules(
				addr.Version,
				p.filterTableName,
				chainName,
				addr,
				bridgeIntfName,
			); err != nil {
				return fmt.Errorf(
					"failed creating filter rules in ipv%s %s chain of %s table: %s",
					addr.Version, chainName, p.filterTableName, err,
				)
			}

			// Add postrouting nat rules
			chainName = utils.GetChainName("npo", conf.ContainerID)
			exists, err = utils.IsChainExists(addr.Version, p.natTableName, chainName)
			if err != nil {
				return fmt.Errorf(
					"failed obtaining ipv%s postrouting %s chain info: %s",
					addr.Version, chainName, err,
				)
			}
			if !exists {
				if err := utils.CreateChain(
					addr.Version,
					p.natTableName,
					chainName,
					"none", "none", "none",
				); err != nil {
					return fmt.Errorf(
						"failed creating ipv%s postrouting %s chain: %s",
						addr.Version, chainName, err,
					)
				}
			}
			if err := utils.CreateJumpRule(
				addr.Version,
				p.natTableName,
				p.postRoutingNatChainName,
				chainName,
			); err != nil {
				return fmt.Errorf(
					"failed creating jump rule to ipv%s postrouting %s chain: %s",
					addr.Version, chainName, err,
				)
			}

			var tgtAddr net.IPNet
			if addr.Version == "4" {
				if len(conf.SnatTo4) > 0{
					tgtAddr.IP = net.ParseIP(conf.SnatTo4)
				}
			} else {
				if len(conf.SnatTo6) > 0{
					tgtAddr.IP = net.ParseIP(conf.SnatTo6)
				}
			}

			if err := utils.AddPostRoutingRules(
				map[string]interface{}{
					"version":          addr.Version,
					"table":            p.natTableName,
					"chain":            chainName,
					"bridge_interface": bridgeIntfName,
					"ip_address":       addr,
					"tgt_address":      tgtAddr,
				},
			); err != nil {
				return fmt.Errorf(
					"failed creating postrouting rules in ipv%s %s chain of %s table: %s",
					addr.Version, chainName, p.natTableName, err,
				)
			}
		}
	}

	return nil
}

func (p *Plugin) execCheck(conf *Config, prevResult *current.Result) error {
	if err := p.validateInput(prevResult); err != nil {
		return fmt.Errorf("failed validating input: %s", err)
	}

	for v := range p.targetIPVersions {
		exists, err := utils.IsTableExist(v, p.filterTableName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s filter table %s info: %s", v, p.filterTableName, err)
		}
		if !exists {
			return fmt.Errorf("ipv%s filter table %s does not exist", v, p.filterTableName)
		}
		exists, err = utils.IsChainExists(v, p.filterTableName, p.forwardFilterChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining ipv%s forward chain %s info: %s",
				v, p.forwardFilterChainName, err,
			)
		}
		if !exists {
			return fmt.Errorf(
				"ipv%s chain %s in filter table %s does not exist",
				v, p.forwardFilterChainName, p.filterTableName,
			)
		}
	}

	for _, targetInterface := range p.targetInterfaces {
		for _, addr := range targetInterface.addrs {
			chainName := utils.GetChainName("ffw", conf.ContainerID)
			exists, err := utils.IsChainExists(addr.Version, p.filterTableName, chainName)
			if err != nil {
				return fmt.Errorf(
					"failed obtaining ipv%s filter %s chain info: %s",
					addr.Version, chainName, err,
				)
			}
			if !exists {
				return fmt.Errorf(
					"ipv%s filter %s chain does not exist in %s table",
					addr.Version, chainName, p.filterTableName,
				)
			}

			// check postrouting nat rules
			chainName = utils.GetChainName("npo", conf.ContainerID)
			exists, err = utils.IsChainExists(addr.Version, p.natTableName, chainName)
			if err != nil {
				return fmt.Errorf(
					"failed obtaining ipv%s filter %s chain info: %s",
					addr.Version, chainName, err,
				)
			}
			if !exists {
				return fmt.Errorf(
					"ipv%s filter %s chain does not exist in %s table",
					addr.Version, chainName, p.natTableName,
				)
			}

		}
	}
	return nil
}

func (p *Plugin) execDelete(conf *Config, prevResult *current.Result) error {
	if err := p.validateInput(prevResult); err != nil {
		return fmt.Errorf("failed validating input: %s", err)
	}

	for v := range p.targetIPVersions {
		exists, err := utils.IsTableExist(v, p.filterTableName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s filter table %s info: %s", v, p.filterTableName, err)
		}
		if !exists {
			continue
		}
		exists, err = utils.IsChainExists(v, p.filterTableName, p.forwardFilterChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining ipv%s forward chain %s info: %s",
				v, p.forwardFilterChainName, err,
			)
		}
		if exists {
			for _, targetInterface := range p.targetInterfaces {
				for _, addr := range targetInterface.addrs {
					if v != addr.Version {
						continue
					}
					chainName := utils.GetChainName("ffw", conf.ContainerID)
					if err := utils.DeleteJumpRule(addr.Version, p.filterTableName, p.forwardFilterChainName, chainName); err != nil {
						return err
					}
					// delete postrouting nat jump rule
					chainName = utils.GetChainName("npo", conf.ContainerID)
					if err := utils.DeleteJumpRule(addr.Version, p.natTableName, p.postRoutingNatChainName, chainName); err != nil {
						return err
					}

				}
			}
		}
	}

	for _, targetInterface := range p.targetInterfaces {
		for _, addr := range targetInterface.addrs {
			chainName := utils.GetChainName("ffw", conf.ContainerID)
			exists, err := utils.IsChainExists(addr.Version, p.filterTableName, chainName)
			if err != nil {
				continue
			}
			if exists {
				if err := utils.DeleteChain(addr.Version, p.filterTableName, chainName); err != nil {
					return err
				}
			}
			// delete postrouting nat rules
			chainName = utils.GetChainName("npo", conf.ContainerID)
			exists, err = utils.IsChainExists(addr.Version, p.natTableName, chainName)
			if err != nil {
				continue
			}
			if exists {
				if err := utils.DeleteChain(addr.Version, p.natTableName, chainName); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
