package packages

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"syscall"
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

// Função para fragmentar um pacote IP
func fragmentPacket(pkt FullPacket, fragSize int) [][]byte {
	var fragments [][]byte
	ipHeaderBytes := toBytes(pkt.IPHeader)
	tcpHeaderBytes := toBytes(pkt.TCPHeader)

	totalLength := len(ipHeaderBytes) + len(tcpHeaderBytes)

	// Fragmentar o pacote de acordo com o tamanho especificado
	for offset := 0; offset < totalLength; offset += fragSize {
		end := offset + fragSize
		if end > totalLength {
			end = totalLength
		}

		fmt.Printf("offset: %v\n", offset)
		fmt.Printf("end: %v\n", end)
		fmt.Printf("fragSize: %v de %v\n", fragSize, totalLength)

		fmt.Printf("ip: %v\n", ipHeaderBytes)
		// Atualiza o cabeçalho de fragmento IPv4 para este fragmento
		fragmentOffset := uint16(offset) // testar o end qualquer coisa
		ipHeaderBytes[6] = byte(2<<5) | byte(fragmentOffset>>8)
		ipHeaderBytes[7] = byte(fragmentOffset & 0xFF)

		// Criar fragmento
		// ipHeader := pkt.IPHeader
		// ipHeader.Length = uint16(len(ipHeaderBytes) + len(tcpHeaderBytes) - offset) // Atualizar o tamanho do IPHeader
		// if end < totalLength {
		// 	ipHeader.FlagsFragment = uint16((offset/8)<<13) | 0x2000 // Definir o bit More Fragments
		// } else {
		// 	ipHeader.FlagsFragment = 0
		// }
		// ipHeader.Checksum = 0 // Reiniciar checksum para recalcular
		// ipHeader.Checksum = checksum(toBytes(ipHeader))

		// // Montar fragmento completo
		// fragment := make([]byte, end-offset) // Cria slice com tamanho correto
		// copy(fragment, ipHeaderBytes[offset:end])
		// fragment = append(fragment, tcpHeaderBytes...) // Adicionar cabeçalho TCP

		// // Adicionar fragmento à lista
		// fragments = append(fragments, fragment)
	}

	return fragments
}

func Synconnection(targetIP string, targetPort int) {

	srcPort := uint16(51012)

	srcAddr := net.ParseIP("192.168.18.83").To4()
	dstAddr := net.ParseIP(targetIP).To4()

	// Configurar cabeçalho IP
	ipHeader := IPHeader{
		VersionIHL:    (4 << 4) | 5,
		TOS:           0,
		Length:        20 + 20, // Tamanho do cabeçalho IP + TCP
		Id:            54321,
		FlagsFragment: 0,
		TTL:           64,
		Protocol:      syscall.IPPROTO_TCP,
		SrcAddr:       [4]byte{srcAddr[0], srcAddr[1], srcAddr[2], srcAddr[3]},
		DstAddr:       [4]byte{dstAddr[0], dstAddr[1], dstAddr[2], dstAddr[3]},
	}

	// Configurar cabeçalho TCP
	tcpHeader := TCPHeader{
		SrcPort: srcPort,
		DstPort: uint16(targetPort),
		SeqNum:  1105024978,
		AckNum:  0,
		DataOff: 5 << 4,
		Flags:   2, // SYN flag
		WinSize: 14600,
		UrgPtr:  0,
	}

	// Calcular pseudo-header para o checksum TCP
	pseudoHeader := append([]byte{
		srcAddr[0], srcAddr[1], srcAddr[2], srcAddr[3],
		dstAddr[0], dstAddr[1], dstAddr[2], dstAddr[3],
		0, syscall.IPPROTO_TCP,
		byte(20 >> 8), byte(20 & 0xff),
	}, toBytes(tcpHeader)...)
	// Calcula o checksum do TCPHeader
	tcpHeader.Checksum = checksum(pseudoHeader)

	// Pacote completo
	fullPacket := FullPacket{
		IPHeader:  ipHeader,
		TCPHeader: tcpHeader,
	}

	// Fragmentar o pacote
	fragments := fragmentPacket(fullPacket, 14) // Tamanho do fragmento em bytes

	// Criar socket raw
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalf("Erro ao criar socket raw: %v", err)
	}
	defer syscall.Close(fd)

	// Enviar cada fragmento
	for i, frag := range fragments {
		fmt.Printf("Fragmento %d:\n", i+1)
		fmt.Printf("%v\n", frag)
		destAddr := syscall.SockaddrInet4{
			Port: targetPort,
			Addr: [4]byte{dstAddr[0], dstAddr[1], dstAddr[2], dstAddr[3]},
		}
		err := syscall.Sendto(fd, frag, 0, &destAddr)
		if err != nil {
			log.Fatalf("Erro ao enviar fragmento: %v", err)
		}
	}

	fmt.Printf("Pacotes SYN enviados para %s:%d\n", targetIP, targetPort)

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
					fmt.Printf("Port %d is open\n", targetPort)
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
