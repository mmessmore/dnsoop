package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/olekukonko/tablewriter"
)

var iface = flag.String("i", "eth0", "Network interface to capture on")
var interval = flag.Int("I", 60, "Number of seconds to wait before printing interval output")
var verbose = flag.Bool("v", false, "Verbose mode")
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

func dumpCounts(queryCnt *map[string][]int, start time.Time, total bool) {

	now := time.Now()
	timeDelta := now.Sub(start)
	totalMinutes := timeDelta.Minutes()

	// Jump through hoops to sort the map by value into a slice for odering
	type kv struct {
		Key      string
		Total    int
		Interval int
	}
	var ss []kv
	for k, v := range *queryCnt {
		ss = append(ss, kv{k, v[0], v[1]})
		q := *queryCnt
		q[k][1] = 0
	}
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Total > ss[j].Total
	})

	fmt.Printf("\nQueries from %s to %s\n\n",
		start.Format("2006-01-02 15:04:05"),
		now.Format("2006-01-02 15:04:05"))

	// Walk through the sorted slice and create a table to print
	var data [][]string
	for _, item := range ss {
		if total {
			rate := float64(item.Total) / totalMinutes
			data = append(data,
				[]string{item.Key,
					fmt.Sprintf("%d", item.Total),
					fmt.Sprintf("%.2f", rate)})
		} else {
			rate := float64(item.Interval) / totalMinutes
			data = append(data,
				[]string{item.Key,
					fmt.Sprintf("%d", item.Total),
					fmt.Sprintf("%d", item.Interval),
					fmt.Sprintf("%.2f", rate)})
		}
	}

	table := tablewriter.NewWriter(os.Stdout)
	if total {
		table.SetHeader([]string{"Host", "Total Count", "Rate/Min"})
	} else {
		table.SetHeader([]string{"Host", "Total Count", "Interval Count", "Rate/Min"})
	}
	table.SetBorder(false)
	table.AppendBulk(data)
	table.Render()
}

func main() {
	var handle *pcap.Handle
	var err error

	var queryCnt = make(map[string][]int)

	// keep track of time
	// for total rate tracking
	startTime := time.Now()
	// init incremental rate tracking
	lastTime := startTime

	// handle sigterm, sigint and print counts
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT)
	signal.Notify(sigs, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.Printf("Caught signal %v", sig)
		fmt.Println("TOTALS FOR RUN")
		dumpCounts(&queryCnt, startTime, true)
		os.Exit(0)
	}()

	flag.Parse()

	fmt.Printf("Starting capure on interface %q\n", *iface)
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
	// you have to make the int interval a Duration to make the types match
	// this seems counter to the docs, where a bare number works, but
	// it gets magically cast for you.  It just looks weird to me since
	// interval is not in fact a Duration of any kind
	ticker := time.Tick(time.Second * time.Duration(*interval))

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

			if len(queryCnt[host]) < 1 {
				queryCnt[host] = []int{1, 1}
			} else {
				queryCnt[host][0]++
				queryCnt[host][1]++
			}

		case <-ticker:
			dumpCounts(&queryCnt, lastTime, false)
			lastTime = time.Now()
		}
	}
}
