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
	err         error
	pcapFile    *file.Pcap
	handle      *pcap.Handle
)

func init() {
	flag.StringVar(&pcapInputFile, "f", "", "pcap input file")
	flag.StringVar(&pcapOutputFile, "o", "", "pcap output file")
	flag.StringVar(&deviceName, "i", "", "dev")
	flag.DurationVar(&timeout, "t", -1*time.Second, "timeout")
}

func main() {
	flag.Parse()

	if !InitHandle() {
		fmt.Println("No input specified")
		os.Exit(1)
	}
	defer handle.Close()

	if InitOutput() {
		defer pcapFile.Close()
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packets := packetSource.Packets()

    Stats()
	Loop(packets)
	Stats()
}

func InitOutput() bool {
	if pcapOutputFile != "" {
		pcapFile = file.NewPcap(pcapOutputFile, snapshotLen)
		return true
	}
	return false
}

func InitHandle() bool {
	if pcapInputFile != "" {
		handle, err = pcap.OpenOffline(pcapInputFile)
		if err != nil {
			fmt.Println("Cannot open file:", pcapFile, err)
			os.Exit(1)
		}
	} else if deviceName != "" {
		if pcapOutputFile == "" {
			pcapOutputFile = time.Now().Format("20060102_150405") + ".pcap"
		}
		handle, err = pcap.OpenLive(deviceName, int32(snapshotLen), true, timeout)
		if err != nil {
			fmt.Printf("Error opening device %s: %v\n", deviceName, err)
			os.Exit(1)
		}
	} else {
		return false
	}
	return true
}

func Loop(packets <-chan gopacket.Packet) {
	ticker := time.NewTicker(time.Second)

	for {
		select {
		case packet, ok := <-packets:
			if !ok {
				return
			}
			packetCount++
			if pcapFile != nil {
				pcapFile.Write(packet)
			}
		case <-ticker.C:
			Stats()
		}
	}
}

func Stats() {
    goterm.Clear()
	goterm.MoveCursor(1, 1)
	goterm.Println("Packets:", packetCount)
	goterm.Flush()
}
