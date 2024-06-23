package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Captura o tempo inicial
	startTime := time.Now()

	targetIP := net.IP{45, 33, 32, 156}
	targetPort := layers.TCPPort(80)
	srcIP := net.IP{192, 168, 18, 83}
	srcPort := layers.TCPPort(443)

	// Configurar a interface e criar um handle
	iface := "wlp1s0" // Substitua pela sua interface de rede
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Erro ao abrir handle: %v", err)
	}
	defer handle.Close()

	// Filtrar apenas pacotes TCP
	filter := fmt.Sprintf("tcp and dst host %s and dst port %d", targetIP.String(), targetPort)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("Erro ao definir filtro BPF: %v", err)
	}

	// Preparar pacote SYN
	synPacket := prepareSYNPacket(srcIP, targetIP, srcPort, targetPort)

	// Enviar pacote SYN
	if err := handle.WritePacketData(synPacket); err != nil {
		log.Fatalf("Erro ao enviar pacote SYN: %v", err)
	}
	fmt.Println("Pacote SYN enviado")

	// Receber pacotes até encontrar o SYN/ACK
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.SYN && tcp.ACK && tcp.DstPort == targetPort && tcp.SrcPort == srcPort {
				fmt.Println("Pacote SYN/ACK recebido")

				// Enviar pacote RST
				rstPacket := prepareRSTPacket(srcIP, targetIP, srcPort, targetPort, tcp.Ack, tcp.Seq+1)
				if err := handle.WritePacketData(rstPacket); err != nil {
					log.Fatalf("Erro ao enviar pacote RST: %v", err)
				}
				fmt.Println("Pacote RST enviado")
				break
			}
		}
	}

	// Captura o tempo final
	endTime := time.Now()
	// Calcula a duração total
	duration := endTime.Sub(startTime)
	// Imprime o tempo de execução
	fmt.Printf("Tempo de execução: %s\n", duration)
}

// Função para preparar um pacote SYN TCP
func prepareSYNPacket(srcIP, dstIP net.IP, srcPort, dstPort layers.TCPPort) []byte {
	ipLayer := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		SYN:     true,
		Window:  14600,
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		ipLayer,
		tcpLayer,
	); err != nil {
		log.Fatalf("Erro ao serializar pacote SYN: %v", err)
	}
	return buffer.Bytes()
}

// Função para preparar um pacote RST TCP
func prepareRSTPacket(srcIP, dstIP net.IP, srcPort, dstPort layers.TCPPort, ack, seq uint32) []byte {
	ipLayer := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		RST:     true,
		Ack:     ack,
		Seq:     seq,
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		ipLayer,
		tcpLayer,
	); err != nil {
		log.Fatalf("Erro ao serializar pacote RST: %v", err)
	}
	return buffer.Bytes()
}
