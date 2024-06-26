package packages

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

type FullPacket struct {
	IPHeader  IPHeader
	TCPHeader TCPHeader
}
