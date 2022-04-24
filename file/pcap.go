package file

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type Pcap struct {
	f *os.File
	w *pcapgo.Writer
}

func NewPcap(fileName string, snapshotLen uint32) *Pcap {
	f, err := os.Create(fileName)
	if err != nil {
		fmt.Println("Cannot create file:", err)
		os.Exit(1)
	}

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet); err != nil {
		fmt.Println("Cannot write file:", err)
		os.Exit(1)
	}
	return &Pcap{f: f, w: w}
}

func (p *Pcap) Write(packet gopacket.Packet) {
	if err := p.w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
		fmt.Println("Cannot write file:", err)
		os.Exit(1)
	}
}

func (p *Pcap) Close() {
	p.f.Close()
}
