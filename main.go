package main

import (
	"machine"
	"strconv"
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

	TxModeReg         = 0x12 // defines transmission data rate and framing
	RxModeReg         = 0x13
	ModWidthReg       = 0x24
	CollReg           = 0x0E
	TModeReg          = 0x2A // defines settings for the internal timer
	TPrescalerReg     = 0x2B // the lower 8 bits of the TPrescaler value. The 4 high bits are in TModeReg.
	TReloadRegH       = 0x2C // defines the 16-bit timer reload value
	TReloadRegL       = 0x2D
	TCounterValueRegH = 0x2E // shows the 16-bit timer value
	TCounterValueRegL = 0x2F
	TxASKReg          = 0x15
)

// PCD_Command :
const (
	PCD_Idle             = 0x00 // no action, cancels current command execution
	PCD_Mem              = 0x01 // stores 25 bytes into the internal buffer
	PCD_GenerateRandomID = 0x02 // generates a 10-byte random ID number
	PCD_CalcCRC          = 0x03 // activates the CRC coprocessor or performs a self-test
	PCD_Transmit         = 0x04 // transmits data from the FIFO buffer
	PCD_NoCmdChange      = 0x07 // no command change, can be used to modify the CommandReg register bits without affecting the command, for example, the PowerDown bit
	PCD_Receive          = 0x08 // activates the receiver circuits
	PCD_Transceive       = 0x0C // transmits data from FIFO buffer to antenna and automatically activates the receiver after transmission
	PCD_MFAuthent        = 0x0E // performs the MIFARE standard authentication as a reader
	PCD_SoftReset        = 0x0F // resets the MFRC522
)

const (
	// The commands used by the PCD to manage communication with several PICCs (ISO 14443-3, Type A, section 6.4)
	PICC_CMD_REQA    = 0x26 // REQuest command Type A. Invites PICCs in state IDLE to go to READY and prepare for anticollision or selection. 7 bit frame.
	PICC_CMD_WUPA    = 0x52 // Wake-UP command Type A. Invites PICCs in state IDLE and HALT to go to READY(*) and prepare for anticollision or selection. 7 bit frame.
	PICC_CMD_CT      = 0x88 // Cascade Tag. Not really a command but used during anti collision.
	PICC_CMD_SEL_CL1 = 0x93 // Anti collision/Select Cascade Level 1
	PICC_CMD_SEL_CL2 = 0x95 // Anti collision/Select Cascade Level 2
	PICC_CMD_SEL_CL3 = 0x97 // Anti collision/Select Cascade Level 3
	PICC_CMD_HLTA    = 0x50 // HaLT command Type A. Instructs an ACTIVE PICC to go to state HALT.
	PICC_CMD_RATS    = 0xE0 // Request command for Answer To Reset.
	// The commands used for MIFARE Classic (from http://www.mouser.com/ds/2/302/MF1S503x-89574.pdf Section 9)
	// Use PCD_MFAuthent to authenticate access to a sector then use these commands to read/write/modify the blocks on the sector.
	// The read/write commands can also be used for MIFARE Ultralight.
	PICC_CMD_MF_AUTH_KEY_A = 0x60 // Perform authentication with Key A
	PICC_CMD_MF_AUTH_KEY_B = 0x61 // Perform authentication with Key B
	PICC_CMD_MF_READ       = 0x30 // Reads one 16 byte block from the authenticated sector of the PICC. Also used for MIFARE Ultralight.
	PICC_CMD_MF_WRITE      = 0xA0 // Writes one 16 byte block to the authenticated sector of the PICC. Called "COMPATIBILITY WRITE" for MIFARE Ultralight.
	PICC_CMD_MF_DECREMENT  = 0xC0 // Decrements the contents of a block and stores the result in the internal data register.
	PICC_CMD_MF_INCREMENT  = 0xC1 // Increments the contents of a block and stores the result in the internal data register.
	PICC_CMD_MF_RESTORE    = 0xC2 // Reads the contents of a block into the internal data register.
	PICC_CMD_MF_TRANSFER   = 0xB0 // Writes the contents of the internal data register to a block.
	// The commands used for MIFARE Ultralight (from http://www.nxp.com/documents/data_sheet/MF0ICU1.pdf, Section 8.6)
	// The PICC_CMD_MF_READ and PICC_CMD_MF_WRITE can also be used for MIFARE Ultralight.
	PICC_CMD_UL_WRITE = 0xA2 // Writes one 4 byte page to the PICC.
)

type StatusCode byte

const (
	STATUS_OK StatusCode = iota
	STATUS_ERROR
	STATUS_COLLISION
	STATUS_TIMEOUT
	STATUS_NO_ROOM
	STATUS_INTERNAL_ERROR
	STATUS_INVALID
	STATUS_CRC_WRONG
	STATUS_MIFARE_NACK StatusCode = 0xFF // Explicit value for NACK
)

type RFID struct {
	spi    *machine.SPI
	csPin  machine.Pin
	rstPin machine.Pin
}

func (rf *RFID) writeRegister(addr byte, val byte) {
	rf.csPin.Low()
	//spi.Transfer(addr & 0x7E)
	// rf.spi.Transfer(addr << 1)
	// rf.spi.Transfer(val)
	gg := []byte{val}
	data := append([]byte{addr << 1}, gg...)
	rf.spi.Tx(data, nil)
	rf.csPin.High()
}

func (rf *RFID) readRegister(addr byte) byte {
	rf.csPin.Low()
	// rf.spi.Transfer((addr << 1) | 0x80)
	// val, _ := rf.spi.Transfer(0x00)
	data := make([]byte, 0, 2)
	data = append(data, 0x80|addr<<1)
	data = append(data, 0)
	// {addr,0}
	result := make([]byte, len(data))
	rf.spi.Tx(data, result) //run insturction

	rf.csPin.High()
	return result[1:][0]
}
func (rf *RFID) ReadRegisterBytes(reg uint8, readLen int) ([]byte, error) {
	rf.csPin.Low()
	if readLen < 1 {
		return nil, nil
	}

	data := make([]byte, 0, readLen+1)
	for range readLen {
		data = append(data, 0x80|reg<<1)
	}
	data = append(data, 0)

	res := make([]byte, len(data))
	if err := rf.spi.Tx(data, res); err != nil {
		return nil, err
	}
	rf.csPin.High()
	return res[1:], nil
}

// func (rf *RFID) ReadRegisterBytes(reg uint8, count int, values []byte, rxAlign byte) {
// 	// if readLen < 1 {
// 	// 	return nil, nil
// 	// }
// 	// rf.csPin.Low()
// 	// data := make([]byte, 0, readLen+1)
// 	// for range readLen {
// 	// 	data = append(data, 0x80|reg)
// 	// }
// 	// data = append(data, 0)
// 	// // var gg []byte
// 	// // m.spi.Tx(data, gg)
// 	// // print(gg)

// 	// res := make([]byte, len(data))
// 	// if err := rf.spi.Tx(data, res); err != nil {
// 	// 	return nil, err
// 	// }
// 	// rf.csPin.High()
// 	// return res[1:], nil

// 	if count == 0 {
// 		return
// 	}
// 	//Serial.print(F("Reading ")); 	Serial.print(count); Serial.println(F(" bytes from register."));
// 	address := 0x80 | reg // MSB == 1 is for reading. LSB is not used in address. Datasheet section 8.1.2.3.
// 	index := 0            // Index in values array.

// 	rf.csPin.Low()           // Select slave
// 	count--                  // One read is performed outside of the loop
// 	rf.spi.Transfer(address) // Tell MFRC522 which address we want to read
// 	if rxAlign != 0 {        // Only update bit positions rxAlign..7 in values[0]
// 		// Create bit mask for bit positions rxAlign..7
// 		var mask byte
// 		mask = (0xFF << rxAlign) & 0xFF
// 		// Read value and tell that we want to read the same address again.
// 		value, _ := rf.spi.Transfer(address)
// 		// Apply mask to both current value of values[0] and the new data in value.
// 		values[0] = (values[0] & ^mask) | (value & mask)
// 		index++
// 	}
// 	for {
// 		if index < count {
// 			break
// 		}
// 		values[index], _ = rf.spi.Transfer(address) // Read value and tell that we want to read the same address again.
// 		index++
// 	}
// 	values[index], _ = rf.spi.Transfer(0) // Read the final byte. Send 0 to stop reading.
// 	rf.csPin.High()                       // Release slave again

// }

func (rf *RFID) writeRegisterBytes(
	reg uint8, ///< The register to write to. One of the PCD_Register enums.
	count int, ///< The number of bytes to write to the register
	values []byte, ///< The values to write. Byte array.
) {
	rf.csPin.Low()               // Select slave
	rf.spi.Transfer(reg)         // MSB == 0 is for writing. LSB is not used in address. Datasheet section 8.1.2.3.
	for i := 0; i < count; i++ { // Loop using count
		rf.spi.Transfer(values[i])
	}
	rf.csPin.High() // Release slave again

} // End PCD_WriteRegister()

func (rf *RFID) PCD_SetRegisterBitMask(
	reg uint8, ///< The register to update. One of the PCD_Register enums.
	mask byte, ///< The bits to set.
) {
	var tmp byte
	tmp = rf.readRegister(reg)
	tmp = tmp | mask
	rf.writeRegister(reg, tmp) // set bit mask
} // End PCD_SetRegisterBitMask()

func (rf *RFID) PCD_ClearRegisterBitMask(reg uint8, mask byte) {
	tmp := rf.readRegister(reg)
	tmp = tmp & ^mask
	rf.writeRegister(reg, tmp) // Clear the specified bits
}

func (rf *RFID) reset() {
	rf.writeRegister(CommandReg, 0x0F)
	time.Sleep(50 * time.Millisecond)
}

func (rf *RFID) IsNewCard() bool {
	bufferATQA := make([]byte, 2)
	bufferSize := len(bufferATQA)

	rf.writeRegister(TxModeReg, 0x00)
	rf.writeRegister(RxModeReg, 0x00)
	rf.writeRegister(ModWidthReg, 0x26)
	result := rf.PICC_RequestA(bufferATQA, bufferSize)
	//println(444444444)
	//println(result)
	return result == STATUS_OK
}

func (rf *RFID) PICC_RequestA(
	bufferATQA []byte,
	bufferSize int,
) StatusCode {
	return rf.PICC_REQA_or_WUPA(PICC_CMD_REQA, bufferATQA, bufferSize)
}

func (rf *RFID) PICC_REQA_or_WUPA(
	command byte,
	bufferATQA []byte,
	bufferSize int,
) StatusCode {
	if bufferATQA == nil || bufferSize < 2 { // ATQA response must be 2 bytes
		return STATUS_NO_ROOM
	}

	rf.PCD_ClearRegisterBitMask(CollReg, 0x80) // Clear collision bits

	validBits := byte(7) // REQA & WUPA use short frame format (7 bits)

	status := rf.PCD_TransceiveData(&command, 1, bufferATQA, bufferSize, &validBits, byte(0))
	if status != STATUS_OK {
		return status
	}
	//println(22222222)
	//println(bufferSize, validBits)
	if bufferSize != 2 || validBits != 0 { // ATQA must be exactly 16 bits
		//println(8080804)
		return STATUS_ERROR
	}

	return STATUS_OK
}

func (rf *RFID) PrintBit(in int) {
	println(strconv.FormatInt(int64(in), 2))
}

func (rf *RFID) PCD_TransceiveData(
	sendData *byte, ///< Pointer to the data to transfer to the FIFO.
	sendLen int, ///< Number of bytes to transfer to the FIFO.
	backData []byte, ///< nullptr or pointer to buffer if data should be read back after executing the command.
	backLen int, ///< In: Max number of bytes to write to *backData. Out: The number of bytes returned.
	validBits *byte, ///< In/Out: The number of valid bits in the last byte. 0 for 8 valid bits. Default nullptr.
	rxAlign byte, ///< In: Defines the bit position in backData[0] for the first bit received. Default 0.
	//checkCRC bool, ///< In: True => The last two bytes of the response is assumed to be a CRC_A that must be validated.
) StatusCode {
	var waitIRq byte
	waitIRq = 0x30 // RxIRq and IdleIRq
	return rf.PCD_CommunicateWithPICC(PCD_Transceive, waitIRq, sendData, sendLen, backData, backLen, validBits, rxAlign)
} // End PCD_TransceiveData()

func (rf *RFID) PCD_CommunicateWithPICC(
	command byte, ///< The command to execute. One of the PCD_Command enums.
	waitIRq byte, ///< The bits in the ComIrqReg register that signals successful completion of the command.
	sendData *byte, ///< Pointer to the data to transfer to the FIFO.
	sendLen int, ///< Number of bytes to transfer to the FIFO.
	backData []byte, ///< nullptr or pointer to buffer if data should be read back after executing the command.
	backLen int, ///< In: Max number of bytes to write to *backData. Out: The number of bytes returned.
	validBits *byte, ///< In/Out: The number of valid bits in the last byte. 0 for 8 valid bits.
	rxAlign byte, ///< In: Defines the bit position in backData[0] for the first bit received. Default 0.
) StatusCode {
	// Prepare values for BitFramingReg
	txLastBits := byte(0)
	if validBits != nil {
		txLastBits = *validBits
	}
	bitFraming := (rxAlign << 4) + txLastBits // RxAlign = BitFramingReg[6..4]. TxLastBits = BitFramingReg[2..0]

	rf.writeRegister(CommandReg, PCD_Idle) // Stop any active command.
	//println(rf.readRegister(CommandReg))

	rf.writeRegister(ComIrqReg, 0x7F) // Clear all seven interrupt request bits

	rf.writeRegister(FIFOLevelReg, 0x80) // FlushBuffer = 1, FIFO initialization

	//println(9901)
	//println(uint8(*sendData))

	rf.writeRegister(FIFODataReg, 0x26) // Write sendData to the FIFO

	// println(9902)
	// println(bitFraming)
	rf.writeRegister(BitFramingReg, bitFraming) // Bit adjustments

	// println(401)
	// println(rf.readRegister(Status2Reg))

	rf.writeRegister(CommandReg, command) // Execute the command
	//println(rf.readRegister(CommandReg))

	// println(402)
	// println(rf.readRegister(Status2Reg))

	if command == PCD_Transceive {
		rf.PCD_SetRegisterBitMask(BitFramingReg, 0x80) // StartSend=1, transmission of data starts
		// println(403)
		// println(rf.readRegister(Status2Reg))
	}

	// println(404)
	// println(rf.readRegister(Status2Reg))

	var irqWait byte
	irqWait = 0x30

	var completed bool
	completed = false
	completed = completed

	// println(101)
	// println(ComIrqReg)
	for range 2000 {
		val := rf.readRegister(ComIrqReg)
		//println(405)
		//println(rf.readRegister(Status2Reg))

		//println(102)
		//println(rf.readRegister(ComIrqReg))

		if val&(irqWait) != 0x00 {
			//println(406)
			//println(rf.readRegister(Status2Reg))
			//println(103)
			//println(ComIrqReg)
			completed = true
			break
		}
		//print(val)
		if val&(0x01) != 0x00 {
			//println(8080801)
			return STATUS_TIMEOUT
		}
	}
	//println(completed)
	if !completed {
		//println(8080802)
		return STATUS_TIMEOUT
	}

	rf.PCD_ClearRegisterBitMask(BitFramingReg, 0x80) // Clear collision bits

	errStatus := rf.readRegister(ErrorReg)

	//println(errStatus)

	if errStatus&0x13 != 0 {
		//println(8080803)
		return STATUS_ERROR
	}
	var _validBits byte
	_validBits = 0

	if true {
		n := rf.readRegister(FIFOLevelReg) // Number of bytes in the FIFO
		if int(n) > backLen {
			return STATUS_NO_ROOM
		}
		backLen = int(n)                                        // Number of bytes returned
		backData, _ = rf.ReadRegisterBytes(FIFODataReg, int(n)) // Get received data from FIFO
		_validBits = rf.readRegister(ControlReg)                // RxLastBits[2:0] indicates the number of valid bits in the last received byte. If this value is 000b, the whole byte is valid.
		_validBits = _validBits & 0x07
		//println(7707)
		//println(_validBits)
		if *validBits != 0x00 {
			*validBits = _validBits
		}
	}

	// if backLen > 0 {
	// level := rf.readRegister(FIFOLevelReg)
	// println(level)

	// if level == 0 {
	// 	level = 1
	// } else if level > 16 {
	// 	level = 16
	// }

	// *backLen = int(level)
	// rf.readRegisterBytes(FIFODataReg, level, backData, rxAlign)
	// _validBits := rf.readRegister(ControlReg) & 0x07
	// println(_validBits)
	// if *validBits < 0 {
	// 	*validBits = _validBits
	// }

	// level := rf.readRegister(FIFOLevelReg)

	// reg := rf.readRegister(ControlReg)

	// var dataLen int
	// if reg&0x07 != 0x00 {
	// 	dataLen = (int(level)-1)*8 + int(reg&0x07)
	// } else {
	// 	dataLen = int(level) * 8
	// }

	// if level == 0 {
	// 	level = 1
	// } else if level > 16 {
	// 	level = 16
	// }

	// res, _ := rf.ReadRegisterBytes(FIFODataReg, dataLen)

	// if len(res) > 0 {
	// 	print(123123123)
	// }
	// return STATUS_OK
	//}
	return STATUS_OK
}
func initRFID() RFID {
	rf := RFID{spi: machine.SPI0, csPin: machine.GPIO17, rstPin: machine.GPIO20}
	rf.csPin.Configure(machine.PinConfig{Mode: machine.PinOutput})
	rf.rstPin.Configure(machine.PinConfig{Mode: machine.PinOutput})
	rf.spi.Configure(machine.SPIConfig{Frequency: 1_000_000, Mode: 0})

	rf.rstPin.High()
	time.Sleep(50 * time.Millisecond)

	rf.reset()
	value := rf.readRegister(TxControlReg)

	// println(10101)
	// println(value)

	if (value & 0x03) != 0x03 {
		tmp := value | 0x03
		rf.writeRegister(TxControlReg, tmp)
		// println(10102)
		// println(tmp)
	}
	//rf.writeRegister(TxControlReg, 0x83) // Enable the antenna

	// println(10103)
	// println(rf.readRegister(TxControlReg))
	//println(0x80 | 0x03)

	// Reset baud rates
	rf.writeRegister(TxModeReg, 0x00) // Enable the antenna
	rf.writeRegister(RxModeReg, 0x00) // Enable the antenna
	// Reset ModWidthReg
	rf.writeRegister(ModWidthReg, 0x26) // Enable the antenna

	rf.writeRegister(TModeReg, 0x80)      // Enable the antenna
	rf.writeRegister(TPrescalerReg, 0xA9) // Enable the antenna
	rf.writeRegister(TReloadRegH, 0x03)   // Enable the antenna
	rf.writeRegister(TReloadRegL, 0xE8)   // Enable the antenna

	rf.writeRegister(TxASKReg, 0x40) // Enable the antenna
	rf.writeRegister(ModeReg, 0x3D)  // Enable the antenna
	return rf
}

var rfid RFID

func main() {
	time.Sleep(500 * time.Millisecond)
	rfid = initRFID()

	version := rfid.readRegister(VersionReg)
	println(20201)
	println(version)

	// rfid.writeRegister(ComIrqReg, 0x7F) // Clear all seven interrupt request bits
	// println(rfid.readRegister(ComIrqReg))

	// rfid.PrintBit(int(rfid.readRegister(FIFOLevelReg)))

	// //rfid.writeRegister(FIFODataReg, uint8(*sendData)) // Write sendData to the FIFO

	// rfid.PrintBit(int(rfid.readRegister(FIFODataReg)))

	// //Valid Write
	// rfid.writeRegister(CommandReg, 0x00)
	// println(rfid.readRegister(CommandReg))
	// rfid.writeRegister(CommandReg, 0xC)
	// println(rfid.readRegister(CommandReg))
	// //rfid.writeRegister(CommandReg, 0x00)

	// rfid.writeRegister(BitFramingReg, byte(7)) // Bit adjustments

	// println(rfid.readRegister(ComIrqReg))
	// rfid.PCD_SetRegisterBitMask(BitFramingReg, 0x80) // StartSend=1, transmission of data starts
	// print("-------\n")
	// for {
	// 	println(rfid.readRegister(ComIrqReg))
	// 	time.Sleep(500 * time.Millisecond)
	// }

	for {
		if !rfid.IsNewCard() {
			continue
		}
		println("success")
		time.Sleep(50 * time.Millisecond)
	}

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
