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

type RFID struct {
	spi    *machine.SPI
	csPin  machine.Pin
	rstPin machine.Pin
}

func (rf *RFID) writeRegister(addr, val uint8) {
	rf.csPin.Low()
	//spi.Transfer(addr & 0x7E)
	rf.spi.Transfer(addr << 1)
	rf.spi.Transfer(val)
	rf.csPin.High()
}

func (rf *RFID) readRegister(addr uint8) uint8 {
	rf.csPin.Low()
	rf.spi.Transfer((addr << 1) | 0x80)
	val, _ := rf.spi.Transfer(0x00)
	rf.csPin.High()
	return val
}

func (rf *RFID) reset() {
	rf.writeRegister(CommandReg, 0x0F)
	time.Sleep(50 * time.Millisecond)
}

func initRFID() RFID {
	rf := RFID{spi: machine.SPI0, csPin: machine.GPIO17, rstPin: machine.GPIO20}
	rf.csPin.Configure(machine.PinConfig{Mode: machine.PinOutput})
	rf.rstPin.Configure(machine.PinConfig{Mode: machine.PinOutput})
	print(rf.spi.Configure(machine.SPIConfig{Frequency: 1_000_000, Mode: 0}))

	rf.rstPin.High()
	time.Sleep(50 * time.Millisecond)

	rf.reset()
	rf.writeRegister(TxControlReg, 0x03) // Enable the antenna

	return rf
}

// func IsNewCard() bool {
// 	//bufferATQA := make([]byte, 2)
// 	//bufferSize := len(bufferATQA)

// 	writeRegister(TxModeReg, 0x00)
// 	writeRegister(RxModeReg, 0x00)
// 	writeRegister(ModWidthReg, 0x26)

// }
var rfid RFID

func main() {
	time.Sleep(500 * time.Millisecond)
	rfid = initRFID()

	version := rfid.readRegister(VersionReg)
	println(version)

	//Valid Write
	rfid.writeRegister(CommandReg, 0x00)
	println(rfid.readRegister(CommandReg))
	rfid.writeRegister(CommandReg, 0xC)
	println(rfid.readRegister(CommandReg))
	rfid.writeRegister(CommandReg, 0x00)
	println(rfid.readRegister(CommandReg))

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
