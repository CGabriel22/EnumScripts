// https://github.com/liamg/furious/blob/master/scan/scan-device.go
// Crie o cabeçalho IP:
// Crie o cabeçalho TCP:
// Calcule as somas de verificação:
// Envie o pacote:
// Receba o pacote de resposta:

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
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

// Estrutura do cabeçalho IP
type IPHeader struct {
	VersionIHL    uint8
	TOS           uint8
	Length        uint16
	Id            uint16
	FlagsFragment uint16
	TTL           uint8
	Protocol      uint8
	Checksum      uint16
	SrcAddr       [4]byte
	DstAddr       [4]byte
}

// Estrutura do cabeçalho TCP
type TCPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	SeqNum   uint32
	AckNum   uint32
	DataOff  uint8
	Flags    uint8
	WinSize  uint16
	Checksum uint16
	UrgPtr   uint16
}

func main() {
	// Captura o tempo inicial
	startTime := time.Now()

	targetIP := "45.33.32.156"
	targetPort := uint16(80)
	srcIP := "192.168.18.83"
	srcPort := uint16(443)

	srcAddr := net.ParseIP(srcIP).To4()
	dstAddr := net.ParseIP(targetIP).To4()

	// Criar socket raw
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalf("Erro ao criar socket: %v", err)
	}
	defer syscall.Close(fd)

	// Construir cabeçalho IP
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
	ipHeader.Checksum = checksum(toBytes(ipHeader))

	// Construir cabeçalho TCP
	tcpHeader := TCPHeader{
		SrcPort: srcPort,
		DstPort: targetPort,
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
	tcpHeader.Checksum = checksum(pseudoHeader)

	// Construir pacote completo
	packet := append(toBytes(ipHeader), toBytes(tcpHeader)...)

	// Enviar pacote SYN
	destAddr := syscall.SockaddrInet4{
		Port: int(targetPort),
		Addr: [4]byte{dstAddr[0], dstAddr[1], dstAddr[2], dstAddr[3]},
	}
	err = syscall.Sendto(fd, packet, 0, &destAddr)
	if err != nil {
		log.Fatalf("Erro ao enviar pacote: %v", err)
	}
	fmt.Println("Pacote SYN enviado")

	// Criar socket raw para receber pacotes
	rfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalf("Erro ao criar socket: %v", err)
	}
	defer syscall.Close(rfd)

	// Configurar timeout para o socket
	timeout := syscall.Timeval{Sec: 2, Usec: 0}
	err = syscall.SetsockoptTimeval(rfd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)
	if err != nil {
		log.Fatalf("Erro ao configurar timeout: %v", err)
	}

	// Receber pacotes
	for {
		buf := make([]byte, 4096)
		n, _, err := syscall.Recvfrom(rfd, buf, 0)
		if err != nil {
			log.Fatalf("Erro ao receber pacote: %v", err)
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

				// Se o pacote for SYN/ACK, enviar RST
				if tcp.Flags&0x12 == 0x12 && tcp.DstPort == srcPort && tcp.SrcPort == targetPort {
					fmt.Println("Pacote SYN/ACK recebido")
					break
				}
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

// Converte uma estrutura para bytes
func toBytes(data interface{}) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, data)
	if err != nil {
		log.Fatalf("Erro ao converter para bytes: %v", err)
	}
	return buf.Bytes()
}
