package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
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
var width = flag.Int("w", 80, "Terminal column width for printing tables")
var onlyHostname = flag.String("H", "", "Count sources for a hostname, vs hostname counts")
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

func getSrc(packet *gopacket.Packet, hostname *string) (string, error) {
	p := *packet
	src := "none"

	if ipv4 := p.Layer(layers.LayerTypeIPv4); ipv4 != nil {
		layer := ipv4.(*layers.IPv4)
		src = layer.SrcIP.String()
	} else {
		return "", errors.New("Not an IPv4 packet")
	}

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
		if string(question.Name) != *hostname {
			return "", errors.New("No the hostname we were looking for")
		}
	}

	return src, nil
}

func dumpCounts(queryCnt *map[string]int) {

	// Jump through hoops to sort the map by value into a slice for odering
	type kv struct {
		Key   string
		Value int
	}
	var ss []kv
	for k, v := range *queryCnt {
		ss = append(ss, kv{k, v})
	}
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})

	// Walk through the sorted slice and print them all pretty-like
	maxWidth := *width
	for _, item := range ss {
		spaces := maxWidth - len(item.Key) - len(strconv.Itoa(item.Value))
		if spaces < 0 {
			spaces = 10
		}
		fmt.Printf("%s%s%d\n", item.Key, strings.Repeat(" ", spaces), item.Value)
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
		host := "none"
		select {
		case packet := <-packets:
			if *onlyHostname == "" {
				host, err = getHost(&packet)
			} else {
				host, err = getSrc(&packet, onlyHostname)
			}

			if err != nil {
				continue
			}

			if _, ok := queryCnt[host]; ok {
				queryCnt[host]++
			} else {
				queryCnt[host] = 1
			}

		case <-ticker:
			log.Println("A minute")
			dumpCounts(&queryCnt)
		}
	}
}
