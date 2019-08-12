package dhclient

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/raw"
)

const responseTimeout = time.Second * 5

// Callback is a function called on certain events
type Callback func(*Lease)

// Client is a DHCP client instance
type Client struct {
	clientName string // for loging

	Hostname    string
	Iface       func() *net.Interface
	Lease       *Lease           // The current lease
	OnBound     Callback         // On renew or rebound
	DHCPOptions []Option         // List of options to send on discovery and requests
	HWAddr      net.HardwareAddr // client's hardware address

	conn      *raw.Conn // Raw socket
	xid       uint32    // Transaction ID
	rebind    bool
	isEnabled bool
	isDied    bool
	notify    chan struct{}
	c         *sync.Cond
}

// Lease is an assignment by the DHCP server
type Lease struct {
	ServerID     net.IP
	FixedAddress net.IP
	Netmask      net.IPMask
	NextServer   net.IP
	Broadcast    net.IP
	Router       []net.IP
	DNS          []net.IP
	TimeServer   []net.IP
	DomainName   string
	MTU          uint16

	// Other options
	OtherOptions []Option

	Bound  time.Time
	Renew  time.Time
	Rebind time.Time
	Expire time.Time
}

// DefaultParamsRequestList is a list of params to be requested from the server
var DefaultParamsRequestList = []layers.DHCPOpt{
	layers.DHCPOptSubnetMask,   // Subnet Mask
	layers.DHCPOptRouter,       // Router
	layers.DHCPOptTimeServer,   // Time Server
	layers.DHCPOptDNS,          // Domain Name Server
	layers.DHCPOptDomainName,   // Domain Name
	layers.DHCPOptInterfaceMTU, // Interface MTU
	layers.DHCPOptNTPServers,   // Network Time Protocol Servers
}

// AddOption adds an DHCP option
func (client *Client) AddOption(optType layers.DHCPOpt, data []byte) {
	client.DHCPOptions = append(client.DHCPOptions, Option{optType, data})
}

// AddParamRequest adds an parameter to parameter request list, if not included yet.
func (client *Client) AddParamRequest(dhcpOpt layers.DHCPOpt) {

	// search for existing parameter request list
	for i := range client.DHCPOptions {
		if client.DHCPOptions[i].Type == layers.DHCPOptParamsRequest {
			// extend existing list
			client.DHCPOptions[i].AddByte(byte(dhcpOpt))
			return
		}
	}

	// option not added yet
	client.AddOption(layers.DHCPOptParamsRequest, []byte{byte(dhcpOpt)})
}

// NewClient -
func NewClient(clientName string, HWAddr net.HardwareAddr, getIface func() *net.Interface, OnBound Callback) *Client {
	mx := sync.Mutex{}
	mx.Lock()

	client := &Client{
		clientName: clientName,
		Iface:      getIface,
		HWAddr:     HWAddr,
		OnBound:    OnBound,
		notify:     make(chan struct{}),
		c:          sync.NewCond(&mx),
	}

	// Add default DHCP options if none added yet.
	for _, param := range DefaultParamsRequestList {
		client.AddParamRequest(param)
	}

	// client.wg.Add(1)
	go client.run()

	return client
}

// Enable starts the client
func (client *Client) Enable() {
	log.Printf("dhclient [%s]: start", client.clientName)

	if client.isEnabled {
		client.Rebind()
		return
	}

	client.isEnabled = true
	client.c.Signal()
}

// Disable stops the client
func (client *Client) Disable() {
	log.Printf("dhclient [%s]: stop", client.clientName)

	client.isEnabled = false
	client.sendNotify()
}

// Destroy -
func (client *Client) Destroy() {
	log.Printf("dhclient [%s]: destroy", client.clientName)

	client.isDied = true
	client.sendNotify()
	client.c.Signal()
}

func (client *Client) sendNotify() {
	select {
	case client.notify <- struct{}{}:
	default:
	}
}

// Renew triggers the renewal of the current lease
func (client *Client) Renew() {
	log.Printf("dhclient [%s]: renew", client.clientName)

	client.sendNotify()
}

// Rebind forgets the current lease and triggers acquirement of a new one
func (client *Client) Rebind() {
	client.rebind = true
	client.Lease = nil
	client.sendNotify()
}

func (client *Client) run() {
	for !client.isDied {
		if client.isEnabled {
			client.runOnce()
			continue
		}

		client.c.Wait()
	}
}

func (client *Client) runOnce() {
	var err error
	if client.Lease == nil || client.rebind {
		// request new lease
		err = client.withConnection(client.discoverAndRequest)
		if err == nil {
			// try to renew the lease in the future
			client.rebind = false
		}
	} else {
		// renew existing lease
		err = client.withConnection(client.renew)
	}

	if err != nil {
		log.Printf("dhclient [%s]: error: %s", client.clientName, err)
		// delay for a second
		select {
		case <-client.notify:
		case <-time.After(time.Second):
		}
		if client.Lease == nil {
			return
		}
	}

	select {
	case <-client.notify:
		return
	case <-time.After(time.Until(client.Lease.Expire)):
		// remove lease and request a new one
		client.unbound()
	case <-time.After(time.Until(client.Lease.Rebind)):
		// keep lease and request a new one
		client.rebind = true
	case <-time.After(time.Until(client.Lease.Renew)):
		// renew the lease
	}
}

// unbound removes the lease
func (client *Client) unbound() {
	client.Lease = nil
}

func (client *Client) withConnection(f func(ifi *net.Interface) error) error {
	ifi := client.Iface()
	if ifi == nil {
		return fmt.Errorf("Interface not found")
	}

	conn, err := raw.ListenPacket(ifi, uint16(layers.EthernetTypeIPv4), nil)
	if err != nil {
		return err
	}
	client.conn = conn
	client.xid = rand.Uint32()

	defer func() {
		client.conn.Close()
		client.conn = nil
	}()

	return f(ifi)
}

func (client *Client) discoverAndRequest(ifi *net.Interface) error {
	lease, err := client.discover(ifi)
	if err != nil {
		return err
	}
	return client.request(ifi, lease)
}

func (client *Client) renew(ifi *net.Interface) error {
	return client.request(ifi, client.Lease)
}

func (client *Client) discover(ifi *net.Interface) (*Lease, error) {
	err := client.sendPacket(ifi, layers.DHCPMsgTypeDiscover, client.DHCPOptions)

	if err != nil {
		return nil, err
	}

	_, lease, err := client.waitForResponse(layers.DHCPMsgTypeOffer)
	if err != nil {
		return nil, err
	}

	return lease, nil
}

func (client *Client) request(ifi *net.Interface, lease *Lease) error {
	err := client.sendPacket(ifi, layers.DHCPMsgTypeRequest, append(client.DHCPOptions,
		Option{layers.DHCPOptRequestIP, []byte(lease.FixedAddress)},
		Option{layers.DHCPOptServerID, []byte(lease.ServerID)},
	))

	if err != nil {
		return err
	}

	msgType, lease, err := client.waitForResponse(layers.DHCPMsgTypeAck, layers.DHCPMsgTypeNak)
	if err != nil {
		return err
	}

	switch msgType {
	case layers.DHCPMsgTypeAck:
		if lease.Expire.IsZero() {
			err = errors.New("expire value is zero")
			break
		}
		// support DHCP servers that do not send option 58 and 59
		// this is using the Microsoft suggested defaults
		if lease.Renew.IsZero() {
			lease.Renew = lease.Bound.Add(lease.Expire.Sub(lease.Bound) / 2)
		}
		if lease.Rebind.IsZero() {
			lease.Rebind = lease.Bound.Add(lease.Expire.Sub(lease.Bound) / 1000 * 875)
		}

		client.Lease = lease

		// call the handler
		if cb := client.OnBound; cb != nil {
			cb(lease)
		}
	case layers.DHCPMsgTypeNak:
		err = errors.New("received NAK")
		client.unbound()
	default:
		err = fmt.Errorf("dhclient [%s]: unexpected response: %s", client.clientName, msgType.String())
	}

	return err
}

// sendPacket creates and sends a DHCP packet
func (client *Client) sendPacket(ifi *net.Interface, msgType layers.DHCPMsgType, options []Option) error {
	log.Printf("dhclient [%s]: sending %s", client.clientName, msgType)
	return client.sendMulticast(ifi, client.newPacket(ifi, msgType, options))
}

// newPacket creates a DHCP packet
func (client *Client) newPacket(ifi *net.Interface, msgType layers.DHCPMsgType, options []Option) *layers.DHCPv4 {
	hwAddr := client.HWAddr
	if hwAddr == nil {
		hwAddr = ifi.HardwareAddr
	}
	packet := layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		ClientHWAddr: hwAddr,
		Xid:          client.xid, // Transaction ID
		Flags:        0x8000,     // Broadcast
	}

	packet.Options = append(packet.Options, layers.DHCPOption{
		Type:   layers.DHCPOptMessageType,
		Data:   []byte{byte(msgType)},
		Length: 1,
	})

	// append DHCP options
	for _, option := range options {
		packet.Options = append(packet.Options, layers.DHCPOption{
			Type:   option.Type,
			Data:   option.Data,
			Length: uint8(len(option.Data)),
		})
	}

	return &packet
}

func (client *Client) sendMulticast(ifi *net.Interface, dhcp *layers.DHCPv4) error {
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       ifi.HardwareAddr,
		DstMAC:       layers.EthernetBroadcast,
	}
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    []byte{0, 0, 0, 0},
		DstIP:    []byte{255, 255, 255, 255},
		Protocol: layers.IPProtocolUDP,
	}
	udp := layers.UDP{
		SrcPort: 68,
		DstPort: 67,
	}

	// Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	udp.SetNetworkLayerForChecksum(&ip)
	err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, dhcp)
	if err != nil {
		return err
	}

	// Send packet
	_, err = client.conn.WriteTo(buf.Bytes(), &raw.Addr{HardwareAddr: eth.DstMAC})
	return err
}

// waitForResponse waits for a DHCP packet with matching transaction ID and the given message type
func (client *Client) waitForResponse(msgTypes ...layers.DHCPMsgType) (layers.DHCPMsgType, *Lease, error) {
	client.conn.SetReadDeadline(time.Now().Add(responseTimeout))

	recvBuf := make([]byte, 1500)
	for {
		_, _, err := client.conn.ReadFrom(recvBuf)

		if err != nil {
			return 0, nil, err
		}

		packet := parsePacket(recvBuf)
		if packet == nil {
			continue
		}

		if packet.Xid == client.xid && packet.Operation == layers.DHCPOpReply {
			msgType, res := newLease(packet)

			// do we have the expected message type?
			for _, t := range msgTypes {
				if t == msgType {
					log.Printf("dhclient [%s]: received %s", client.clientName, msgType)
					return msgType, &res, nil
				}
			}
		}
	}
}
