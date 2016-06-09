package arppoisoning

import (
	"testing"
	"net"
	"github.com/google/gopacket/pcap"
	"time"
	"fmt"
	"log"
	"errors"
	"bytes"
)

var (
	ip1 = net.ParseIP("192.168.56.104")
	mac1 = net.HardwareAddr{0x08, 0x00, 0x27, 0x75, 0xf2, 0x22}
	ip2 = net.ParseIP("192.168.56.103")
	mac2 = net.HardwareAddr{0x08, 0x00, 0x27, 0x19, 0x9a, 0x54}
	myip = net.ParseIP("192.168.56.102")
	mymac = net.HardwareAddr{0x08, 0x00, 0x27, 0xea, 0x5f, 0x0d}
	handle *pcap.Handle
)

func init() {
	var err error
	handle, err = pcap.OpenLive(`\Device\NPF_{1A4AF5C3-5B04-4669-97F4-4A467E5E15F8}`, 65536, true, 3* time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}
}

func TestArpPoisoning(t *testing.T) {
	//SendAFakeArpReply(handle, ip1, myip, mac1, mymac)
	stop := make(chan bool)
	go ArpPoisoning(handle, myip, ip1, ip2, mymac, mac1, mac2, stop)
	time.Sleep(5 * time.Second)
	close(stop)

	//SendAFakeArpRequest(handle, ip1, myip, broadcastMac, mymac)
	//time.Sleep(400 * time.Second)

}
func TestSendAFakeArpRquest(t *testing.T) {
	SendAFakeArpRequest(handle, ip1, myip, broadcastMac, mymac)
}

func TestGetMacs(t *testing.T){
	macs,err:= getMacsFromArpWithIp(handle,[]net.IP{ip1,ip2},myip,mymac)
	if err!=nil{
		t.Error(err)
	}
	fmt.Println(macs)
}
func TestFindHandleWithIp(t *testing.T) {
	ip:=net.ParseIP("192.168.56.103")
	handle,_,err:= FindInterfaceWithIp(ip)
	if err!=nil{
		t.Error(err)
	}
	t.Log(handle)
}
func TestGetMyMacFromIp(t *testing.T) {
	ip:=net.ParseIP("192.168.56.1")
	mac,_:=net.ParseMAC("0A-00-27-00-00-1D")
	mymac,err:=GetMyMacFromIp(ip)
	if err!=nil{
		t.Error(err)
	}
	if !bytes.Equal(mac,mymac[:len(mac)]){
		t.Errorf("found mac:%s,it should be %s",mymac,mac)
	}
}
func localfunc()(int,error){
	return 3,errors.New("error")
}
func TestArg(t *testing.T){
	var err error=nil
	if true{
		ti,err:=localfunc()
		fmt.Println(ti,err)
	}
	fmt.Println(err)

}
func TestArpPoisoningWithIP(t *testing.T) {
	ip1:=net.ParseIP("192.168.56.104")
	ip2:=net.ParseIP("192.168.56.103")
	stop:=make(chan bool)
	ArpPoisoningWithIP(ip1,ip2,stop)
	time.Sleep(30*time.Second)
	close(stop)
}