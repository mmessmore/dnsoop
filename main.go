package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var iface = flag.String("i", "eth0", "Network interface to capture on")
var verbose = flag.Bool("v", false, "Verbose mode")
var snapLen int32 = 65535
var filter = "udp and dst port 53"

func hasDNSLayer(packet *gopacket.Packet) bool {
	hasDNS := false
	p := *packet

	for _, l := range p.Layers() {
		if l.LayerType().String() == "DNS" {
			hasDNS = true
		}
	}
	return hasDNS
}

func getHost(packet *gopacket.Packet) (string, error) {
	p := *packet

	if !hasDNSLayer(packet) {
		return "", errors.New("Not a dns packet")
	}

	dnsLayer := p.Layer(layers.LayerTypeDNS).(*layers.DNS)

	if dnsLayer.OpCode != layers.DNSOpCodeQuery {
		return "", errors.New("Not a dns query")
	}

	for _, question := range dnsLayer.Questions {
		if question.Type != layers.DNSTypeA {
			continue
		}
		return string(question.Name), nil
	}

	return "", errors.New("No A record query")
}

func dumpCounts(queryCnt *map[string]int) {
	maxWidth := 40
	for k, v := range *queryCnt {
		spaces := maxWidth - len(k) - len(strconv.Itoa(v))
		fmt.Printf("%s%s%d\n", k, strings.Repeat(" ", spaces), v)
	}
}

func main() {
	var handle *pcap.Handle
	var err error

	var queryCnt = make(map[string]int)

	// handle sigterm and print counts
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT)
	go func() {
		sig := <-sigs
		log.Printf("Caught signal %v", sig)
		dumpCounts(&queryCnt)
		os.Exit(0)
	}()

	flag.Parse()

	log.Printf("Starting capure on interface %q", *iface)
	handle, err = pcap.OpenLive(*iface, snapLen, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)

	for {
		select {
		case packet := <-packets:
			host, err := getHost(&packet)
			if err != nil {
				continue
			}

			if _, ok := queryCnt[host]; ok {
				queryCnt[host] += 1
			} else {
				queryCnt[host] = 1
			}

		case <-ticker:
			log.Println("A minute")
			dumpCounts(&queryCnt)
		}
	}
}
