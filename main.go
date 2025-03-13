package main

import (
	"machine"
	"time"
)

// MFRC522 Registers
const (
	CommandReg      = 0x01
	ComIEnReg       = 0x02
	DivIEnReg       = 0x03
	ComIrqReg       = 0x04
	DivIrqReg       = 0x05
	ErrorReg        = 0x06
	Status1Reg      = 0x07
	Status2Reg      = 0x08
	FIFODataReg     = 0x09
	FIFOLevelReg    = 0x0A
	ControlReg      = 0x0C
	BitFramingReg   = 0x0D
	ModeReg         = 0x11
	TxControlReg    = 0x14
	CRCResultRegMSB = 0x21
	CRCResultRegLSB = 0x22
	VersionReg      = 0x37

	TxModeReg   = 0x12 // defines transmission data rate and framing
	RxModeReg   = 0x13
	ModWidthReg = 0x24
)

var spi = machine.SPI0
var rfidCS = machine.GPIO17
var rfidRST = machine.GPIO20

func writeRegister(addr, val uint8) {
	rfidCS.Low()
	//spi.Transfer(addr & 0x7E)
	spi.Transfer(addr << 1)
	spi.Transfer(val)
	rfidCS.High()
}

func readRegister(addr uint8) uint8 {
	rfidCS.Low()
	spi.Transfer((addr << 1) | 0x80)
	val, _ := spi.Transfer(0x00)
	rfidCS.High()
	return val
}

func reset() {
	writeRegister(CommandReg, 0x0F)
	time.Sleep(50 * time.Millisecond)
}

func initRFID() {
	rfidCS.Configure(machine.PinConfig{Mode: machine.PinOutput})
	rfidRST.Configure(machine.PinConfig{Mode: machine.PinOutput})
	spi.Configure(machine.SPIConfig{Frequency: 1_000_000, Mode: 0})

	rfidRST.High()
	time.Sleep(50 * time.Millisecond)

	reset()
	writeRegister(TxControlReg, 0x03) // Enable the antenna
}

// func IsNewCard() bool {
// 	//bufferATQA := make([]byte, 2)
// 	//bufferSize := len(bufferATQA)

// 	writeRegister(TxModeReg, 0x00)
// 	writeRegister(RxModeReg, 0x00)
// 	writeRegister(ModWidthReg, 0x26)

// }

func main() {
	initRFID()
	time.Sleep(500 * time.Millisecond)
	version := readRegister(VersionReg)
	println(version)

	//Valid Write
	writeRegister(CommandReg, 0x00)
	println(readRegister(CommandReg))
	writeRegister(CommandReg, 0xC)
	println(readRegister(CommandReg))
	writeRegister(CommandReg, 0x00)
	println(readRegister(CommandReg))

	// for {
	// 	status := readRegister(Status1Reg)
	// 	if status&0x01 == 0 {
	// 		println("No card detected")
	// 	} else {
	// 		println("Card detected!")
	// 	}
	// 	time.Sleep(500 * time.Millisecond)
	// }
}
