package packages

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"syscall"
	// "time"
)

// Função para calcular a soma de verificação
func checksum(data []byte) uint16 {
	var sum uint32
	n := len(data)
	for i := 0; i < n-1; i += 2 {
		sum += uint32(data[i])<<8 + uint32(data[i+1])
	}
	if n%2 == 1 {
		sum += uint32(data[n-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(^sum)
}

// Converte uma estrutura para bytes
func toBytes(data interface{}) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, data)
	if err != nil {
		log.Fatalf("Erro ao converter para bytes: %v", err)
	}
	return buf.Bytes()
}

func Synconnection(targetIP string, targetPort int, portService string) {

	srcPort := uint16(443)

	srcAddr := net.ParseIP("192.168.18.83").To4()
	dstAddr := net.ParseIP(targetIP).To4()

	// Criar socket raw
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalf("Socket create error: %v", err)
	}
	defer syscall.Close(fd)

	// Cria o pacote
	fullPacket := FullPacket{
		IPHeader: IPHeader{
			VersionIHL:    (4 << 4) | 5,
			TOS:           0,
			Length:        20 + 20, // Tamanho do cabeçalho IP + TCP
			Id:            54321,
			FlagsFragment: 0,
			TTL:           64,
			Protocol:      syscall.IPPROTO_TCP,
			SrcAddr:       [4]byte{srcAddr[0], srcAddr[1], srcAddr[2], srcAddr[3]},
			DstAddr:       [4]byte{dstAddr[0], dstAddr[1], dstAddr[2], dstAddr[3]},
		},
		TCPHeader: TCPHeader{
			SrcPort: srcPort,
			DstPort: uint16(targetPort),
			SeqNum:  1105024978,
			AckNum:  0,
			DataOff: 5 << 4,
			Flags:   2, // SYN flag
			WinSize: 14600,
			UrgPtr:  0,
		},
	}
	// Calcula o checksum do IPHeader
	fullPacket.IPHeader.Checksum = checksum(toBytes(fullPacket.IPHeader))

	// Calcular pseudo-header para o checksum TCP
	pseudoHeader := append([]byte{
		srcAddr[0], srcAddr[1], srcAddr[2], srcAddr[3],
		dstAddr[0], dstAddr[1], dstAddr[2], dstAddr[3],
		0, syscall.IPPROTO_TCP,
		byte(20 >> 8), byte(20 & 0xff),
	}, toBytes(fullPacket.TCPHeader)...)
	// Calcula o checksum do TCPHeader
	fullPacket.TCPHeader.Checksum = checksum(pseudoHeader)

	// Converte o pacote para bytes
	packet := toBytes(fullPacket)

	// Enviar pacote SYN
	destAddr := syscall.SockaddrInet4{
		Port: targetPort,
		Addr: [4]byte{dstAddr[0], dstAddr[1], dstAddr[2], dstAddr[3]},
	}
	err = syscall.Sendto(fd, packet, 0, &destAddr)
	if err != nil {
		log.Fatalf("Error sending package: %v", err)
	}

	// Criar socket raw para receber pacotes
	rfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalf("Raw socket create error: %v", err)
	}
	defer syscall.Close(rfd)

	// Configurar timeout para o socket
	timeout := syscall.Timeval{Sec: 2, Usec: 0}
	syscall.SetsockoptTimeval(rfd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)

	// Receber pacotes
	for {
		buf := make([]byte, 4096)
		n, _, err := syscall.Recvfrom(rfd, buf, 0)
		if err != nil {
			// log.Fatalf("Erro ao receber pacote: %v", err)
			fmt.Printf("Port %d is filtred or timeout\n", targetPort)
			break
		}

		// Verificar se o pacote é um SYN/ACK
		if n > 0 {
			ipHeaderLen := int((buf[0] & 0x0f) * 4)
			if tcpLayer := buf[ipHeaderLen:]; len(tcpLayer) >= 20 {
				tcp := TCPHeader{
					SrcPort:  binary.BigEndian.Uint16(tcpLayer[0:2]),
					DstPort:  binary.BigEndian.Uint16(tcpLayer[2:4]),
					SeqNum:   binary.BigEndian.Uint32(tcpLayer[4:8]),
					AckNum:   binary.BigEndian.Uint32(tcpLayer[8:12]),
					DataOff:  tcpLayer[12] >> 4,
					Flags:    tcpLayer[13],
					WinSize:  binary.BigEndian.Uint16(tcpLayer[14:16]),
					Checksum: binary.BigEndian.Uint16(tcpLayer[16:18]),
					UrgPtr:   binary.BigEndian.Uint16(tcpLayer[18:20]),
				}

				// Se o pacote for SYN/ACK
				if tcp.Flags&0x12 == 0x12 && tcp.DstPort == srcPort && tcp.SrcPort == uint16(targetPort) {
					fmt.Printf("Port %d is open ........... %s\n", targetPort, portService)
					break
				}
				// Verificar se o pacote é um RST/ACK
				if tcp.Flags&0x14 == 0x14 && tcp.DstPort == srcPort && tcp.SrcPort == uint16(targetPort) {
					// fmt.Printf("Port %d is closed\n", targetPort)
					break
				}
			}
		}
	}
}
