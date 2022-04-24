package main

import (
	"flag"
	"fmt"
	"os"
	"sniffminer/file"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/buger/goterm"
)

var (
	pcapInputFile  string
	pcapOutputFile string
	deviceName     string
	timeout        time.Duration
	snapshotLen    uint32 = 65535
)

var (
	packetCount uint64
	pcapFile    *file.Pcap
)

func init() {
	flag.StringVar(&pcapInputFile, "f", "", "pcap input file")
	flag.StringVar(&pcapOutputFile, "o", "", "pcap output file")
	flag.StringVar(&deviceName, "i", "", "dev")
	flag.DurationVar(&timeout, "t", -1*time.Second, "timeout")
}

func Stats() {
	goterm.Clear()
	goterm.MoveCursor(1, 1)
	goterm.Println("Packets:", packetCount)
	goterm.Flush()
}

func Loop(packets <-chan gopacket.Packet) {
	ticker := time.NewTicker(time.Second)

	for {
		select {
		case packet, ok := <-packets:
			if !ok {
				return
			}
			if pcapFile != nil {
				pcapFile.Write(packet)
			}
			packetCount++
		case <-ticker.C:
			Stats()
		}
	}
}

func main() {
	flag.Parse()

	handle, err := InitHandle()
	if err != nil {
		fmt.Printf("Error opening input %v\n", err)
		os.Exit(1)
	}
	if handle == nil {
		fmt.Println("No input specified")
		os.Exit(1)
	}
	defer handle.Close()

	if pcapOutputFile == "" && deviceName != "" {
		pcapOutputFile = time.Now().Format("20060102_150405") + ".pcap"
	}

	if pcapOutputFile != "" {
		pcapFile = file.NewPcap(pcapOutputFile, snapshotLen)
		defer pcapFile.Close()
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	Stats()
	Loop(packetSource.Packets())
	Stats()
}

func InitHandle() (handle *pcap.Handle, err error) {
	if pcapInputFile != "" {
		handle, err = pcap.OpenOffline(pcapInputFile)
		return
	}

	if deviceName != "" {
		handle, err = pcap.OpenLive(deviceName, int32(snapshotLen), true, timeout)
		return
	}

	return
}
