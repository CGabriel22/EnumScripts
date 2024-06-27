package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"syscall"
)

// IPHeader representa o cabeçalho IP
type IPHeader struct {
	VersionIHL    uint8
	TOS           uint8
	Length        uint16
	Id            uint16
	FlagsFragment uint16
	TTL           uint8
	Protocol      uint8
	SrcAddr       [4]byte
	DstAddr       [4]byte
}

// TCPHeader representa o cabeçalho TCP
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

// FullPacket representa o pacote completo
type FullPacket struct {
	IPHeader  IPHeader
	TCPHeader TCPHeader
}

// Função para fragmentar o pacote em partes de 8 bytes
func fragmentPacket(fullPacket FullPacket) [][]byte {
	var fragments [][]byte

	// Converter FullPacket para bytes
	packetBytes := toBytes(fullPacket)

	// Tamanho máximo de cada fragmento em bytes
	fragmentSize := 8

	// Calcular quantos fragmentos serão necessários
	numFragments := (len(packetBytes) + fragmentSize - 1) / fragmentSize

	// Criar os fragmentos
	for i := 0; i < numFragments; i++ {
		start := i * fragmentSize
		end := start + fragmentSize
		if end > len(packetBytes) {
			end = len(packetBytes)
		}
		fragment := make([]byte, end-start)
		copy(fragment, packetBytes[start:end])

		// Configurar cabeçalho do fragmento IPv6
		if i == numFragments-1 {
			// Último fragmento
			nextHeader := fullPacket.IPHeader.Protocol
			reserved := uint8(0)
			fragmentOffset := uint16(i) * uint16(fragmentSize/8)
			identification := fullPacket.IPHeader.Id

			// Montar o cabeçalho do fragmento
			fragmentHeader := make([]byte, 8)
			fragmentHeader[0] = nextHeader
			fragmentHeader[1] = reserved
			binary.BigEndian.PutUint16(fragmentHeader[2:4], fragmentOffset)
			binary.BigEndian.PutUint16(fragmentHeader[4:6], identification)

			// Adicionar o cabeçalho ao início do fragmento
			fragment = append(fragmentHeader, fragment...)
		}

		fragments = append(fragments, fragment)
	}

	return fragments
}

// Função auxiliar para converter a estrutura FullPacket em bytes
func toBytes(fp FullPacket) []byte {
	ipBytes := make([]byte, 20)
	ipBytes[0] = fp.IPHeader.VersionIHL
	ipBytes[1] = fp.IPHeader.TOS
	binary.BigEndian.PutUint16(ipBytes[2:4], fp.IPHeader.Length)
	binary.BigEndian.PutUint16(ipBytes[4:6], fp.IPHeader.Id)
	binary.BigEndian.PutUint16(ipBytes[6:8], fp.IPHeader.FlagsFragment)
	ipBytes[8] = fp.IPHeader.TTL
	ipBytes[9] = fp.IPHeader.Protocol
	copy(ipBytes[12:], fp.IPHeader.SrcAddr[:])
	copy(ipBytes[16:], fp.IPHeader.DstAddr[:])

	tcpBytes := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpBytes[0:2], fp.TCPHeader.SrcPort)
	binary.BigEndian.PutUint16(tcpBytes[2:4], fp.TCPHeader.DstPort)
	binary.BigEndian.PutUint32(tcpBytes[4:8], fp.TCPHeader.SeqNum)
	binary.BigEndian.PutUint32(tcpBytes[8:12], fp.TCPHeader.AckNum)
	tcpBytes[12] = fp.TCPHeader.DataOff
	tcpBytes[13] = fp.TCPHeader.Flags
	binary.BigEndian.PutUint16(tcpBytes[14:16], fp.TCPHeader.WinSize)
	binary.BigEndian.PutUint16(tcpBytes[16:18], fp.TCPHeader.Checksum)
	binary.BigEndian.PutUint16(tcpBytes[18:20], fp.TCPHeader.UrgPtr)

	return append(ipBytes, tcpBytes...)
}

func main() {
	// Exemplo de uso
	ipHeader := IPHeader{
		VersionIHL:    (4 << 4) | 5,
		TOS:           0,
		Length:        40, // Tamanho do cabeçalho IP + TCP
		Id:            54321,
		FlagsFragment: 0,
		TTL:           64,
		Protocol:      6,                         // IPPROTO_TCP
		SrcAddr:       [4]byte{192, 168, 18, 83}, // IP de origem
		DstAddr:       [4]byte{45, 33, 32, 156},  // IP de destino
	}

	tcpHeader := TCPHeader{
		SrcPort:  51012, // Porta de origem
		DstPort:  22,    // Porta de destino
		SeqNum:   1105024978,
		AckNum:   0,
		DataOff:  5 << 4,
		Flags:    2, // SYN flag
		WinSize:  14600,
		Checksum: 0, // Será calculado posteriormente
		UrgPtr:   0,
	}

	fullPacket := FullPacket{
		IPHeader:  ipHeader,
		TCPHeader: tcpHeader,
	}

	fragments := fragmentPacket(fullPacket)

	// Socket para enviar os pacotes
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalf("Erro ao criar socket: %v", err)
	}
	defer syscall.Close(fd)

	// Configurar IP_HDRINCL para incluir o cabeçalho IP personalizado
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		log.Fatalf("Erro ao configurar IP_HDRINCL: %v", err)
	}

	// Exibindo os fragmentos gerados
	for i, frag := range fragments {
		fmt.Printf("Fragmento %d:\n", i+1)
		fmt.Printf("%v\n", frag)

		// Configurar o endereço de destino
		destAddr := syscall.SockaddrInet4{
			Port: 22,                       // Porta de destino
			Addr: [4]byte{45, 33, 32, 156}, // Endereço IP de destino
		}

		// Enviar o fragmento
		err := syscall.Sendto(fd, frag, 0, &destAddr)
		if err != nil {
			log.Fatalf("Erro ao enviar fragmento: %v", err)
		}
	}
}
