package packages

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
)

const (
	IPv4HeaderLength     = 20 // Tamanho do cabeçalho IPv4 em bytes
	IPv4FragHeaderLength = 8  // Tamanho do cabeçalho de fragmento IPv4 em bytes
	SocketProtocolIPv4   = syscall.IPPROTO_RAW
	TCPHeaderLength      = 20 // Tamanho do cabeçalho TCP em bytes
	FragmentSize         = 8  // Tamanho de cada fragmento em bytes (deve ser múltiplo de 8)
)

func Synconnection(targetIP string, targetPort int) {
	// Definindo o endereço IPv4 de origem e destino
	srcIP := net.ParseIP("192.168.18.83").To4()
	dstIP := net.ParseIP(targetIP).To4()

	fmt.Printf("Endereço de origem: %s\n", srcIP)
	fmt.Printf("Endereço de destino: %s\n", dstIP)

	// Configurando o socket raw IPv4
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, SocketProtocolIPv4)
	if err != nil {
		fmt.Println("Erro ao criar o socket:", err)
		os.Exit(1)
	}
	defer syscall.Close(fd)

	fmt.Println("Socket raw IPv4 criado com sucesso.")

	// Construindo o cabeçalho IPv4 base
	ipv4Header := make([]byte, IPv4HeaderLength)
	ipv4Header[0] = 0x45                             // Versão IPv4 (4) e IHL (5 palavras de 32 bits)
	ipv4Header[1] = 0                                // Tipo de serviço
	ipID := uint16(0x0701)                           // ID do pacote (mesmo para todos os fragmentos)
	binary.BigEndian.PutUint16(ipv4Header[4:], ipID) // Identificação
	ipv4Header[8] = 64                               // TTL (Time to Live)
	ipv4Header[9] = 0x06                             // Protocolo TCP
	copy(ipv4Header[12:], srcIP)                     // Endereço de origem
	copy(ipv4Header[16:], dstIP)                     // Endereço de destino

	// Construindo o cabeçalho TCP
	tcpHeader := make([]byte, TCPHeaderLength)
	binary.BigEndian.PutUint16(tcpHeader[0:], 51012)              // Porta de origem (51012)
	binary.BigEndian.PutUint16(tcpHeader[2:], uint16(targetPort)) // Porta de destino
	binary.BigEndian.PutUint32(tcpHeader[4:], 1)                  // Número de sequência
	binary.BigEndian.PutUint32(tcpHeader[8:], 0)                  // Número de confirmação
	tcpHeader[12] = 5 << 4                                        // Comprimento do cabeçalho TCP em palavras de 32 bits
	tcpHeader[13] = 2                                             // Flags TCP (apenas SYN)
	binary.BigEndian.PutUint16(tcpHeader[14:], 1024)              // Tamanho da janela

	// Calculando o checksum do cabeçalho TCP
	checksum := checksumTCP(srcIP, dstIP, tcpHeader)
	binary.BigEndian.PutUint16(tcpHeader[16:], checksum) // Checksum

	fmt.Println("Pacote SYN TCP construído:")
	fmt.Printf("%X\n", tcpHeader)

	// Dividindo o pacote em fragmentos
	packet := append(ipv4Header, tcpHeader...)
	totalLength := len(tcpHeader)
	offset := 0

	for i := 0; i < 3; i++ {
		end := offset + FragmentSize
		if end > totalLength {
			end = totalLength
		}
		fragment := packet[IPv4HeaderLength+offset : IPv4HeaderLength+end]
		fragmentHeader := make([]byte, IPv4HeaderLength)
		copy(fragmentHeader, ipv4Header)
		binary.BigEndian.PutUint16(fragmentHeader[2:], uint16(len(fragment)+IPv4HeaderLength))
		// Definindo flags e offset para fragmentos
		offsetField := (offset / 8)
		if end < totalLength {
			offsetField |= 0x2000 // Mais fragmentos a seguir
		}
		binary.BigEndian.PutUint16(fragmentHeader[6:], uint16(offsetField))

		// Criando o pacote fragmentado
		fragmentPacket := append(fragmentHeader, fragment...)

		// Enviando o fragmento
		saddr := &syscall.SockaddrInet4{
			Port: 0,
			Addr: [4]byte{dstIP[0], dstIP[1], dstIP[2], dstIP[3]},
		}

		fmt.Printf("Enviando pacote fragmentado %d...\n", i+1)
		err := syscall.Sendto(fd, fragmentPacket, 0, saddr)
		if err != nil {
			fmt.Println("Erro ao enviar pacote fragmentado:", err)
			os.Exit(1)
		}
		fmt.Printf("Pacote fragmentado %d enviado com sucesso!\n", i+1)

		offset += FragmentSize
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
				if tcp.Flags&0x12 == 0x12 && tcp.DstPort == uint16(51012) && tcp.SrcPort == uint16(targetPort) {
					fmt.Printf("Port %d is open\n", targetPort)
					break
				}
				// Verificar se o pacote é um RST/ACK
				if tcp.Flags&0x14 == 0x14 && tcp.DstPort == uint16(51012) && tcp.SrcPort == uint16(targetPort) {
					// fmt.Printf("Port %d is closed\n", targetPort)
					break
				}
			}
		}
	}
}

// Função para calcular o checksum TCP
func checksumTCP(srcIP, dstIP net.IP, tcpHeader []byte) uint16 {
	var (
		sum    uint32
		length = uint32(len(tcpHeader))
	)

	// Pseudo header para o checksum TCP
	pseudo := make([]byte, 12)
	copy(pseudo[0:], srcIP)
	copy(pseudo[4:], dstIP)
	pseudo[9] = 0x06 // Protocolo TCP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(length))

	// Calculando a soma do pseudo header
	for i := 0; i < 12; i += 2 {
		sum += uint32(pseudo[i])<<8 | uint32(pseudo[i+1])
	}

	// Calculando a soma do cabeçalho TCP
	for i := 0; i < len(tcpHeader); i += 2 {
		sum += uint32(tcpHeader[i])<<8 | uint32(tcpHeader[i+1])
	}

	// Lidando com byte ímpar no cabeçalho
	if len(tcpHeader)%2 != 0 {
		sum += uint32(tcpHeader[len(tcpHeader)-1]) << 8
	}

	// Dobrando a soma de 32 bits para 16 bits
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// Complemento de um
	return uint16(^sum)
}
