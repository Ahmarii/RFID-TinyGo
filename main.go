package main

import (
	"machine"
	"strconv"
	"time"
)

// By Nathakorn J
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
	CRCResultRegH     = 0x21 // shows the MSB and LSB values of the CRC calculation
	CRCResultRegL     = 0x22
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
	uid    Uid
}

type Uid struct {
	size    byte // Number of bytes in the UID. 4, 7 or 10.
	uidByte [10]byte
	sak     byte // The SAK (Select acknowledge) byte returned from the PICC after successful selection.
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
	rf.spi.Transfer(reg << 1)    // MSB == 0 is for writing. LSB is not used in address. Datasheet section 8.1.2.3.
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
	var bufferSize int
	var bufferSizePtr *int = &bufferSize
	*bufferSizePtr = len(bufferATQA)

	rf.writeRegister(TxModeReg, 0x00)
	rf.writeRegister(RxModeReg, 0x00)
	rf.writeRegister(ModWidthReg, 0x26)
	result := rf.PICC_RequestA(bufferATQA, bufferSizePtr)
	//println(444444444)
	//println(result)
	return result == STATUS_OK
}

func (rf *RFID) PICC_RequestA(
	bufferATQA []byte,
	bufferSize *int,
) StatusCode {
	return rf.PICC_REQA_or_WUPA(PICC_CMD_REQA, bufferATQA, bufferSize)
}

func (rf *RFID) PICC_REQA_or_WUPA(
	command byte,
	bufferATQA []byte,
	bufferSize *int,
) StatusCode {
	if bufferATQA == nil || *bufferSize < 2 { // ATQA response must be 2 bytes
		return STATUS_NO_ROOM
	}

	rf.PCD_ClearRegisterBitMask(CollReg, 0x80) // Clear collision bits

	validBits := byte(7) // REQA & WUPA use short frame format (7 bits)

	var commandSingle []byte
	commandSingle = append(commandSingle, command)
	status := rf.PCD_TransceiveData(commandSingle, 1, bufferATQA, bufferSize, &validBits, byte(0), false)
	if status != STATUS_OK {
		return status
	}
	//println(22222222)
	//println(bufferSize, validBits)
	if *bufferSize != 2 || validBits != 0 { // ATQA must be exactly 16 bits
		//println(8080804)
		return STATUS_ERROR
	}

	return STATUS_OK
}

func (rf *RFID) PrintBit(in int) {
	println(strconv.FormatInt(int64(in), 2))
}

func (rf *RFID) PCD_TransceiveData(
	sendData []byte, ///< Pointer to the data to transfer to the FIFO.
	sendLen int, ///< Number of bytes to transfer to the FIFO.
	backData []byte, ///< nullptr or pointer to buffer if data should be read back after executing the command.
	backLen *int, ///< In: Max number of bytes to write to *backData. Out: The number of bytes returned.
	validBits *byte, ///< In/Out: The number of valid bits in the last byte. 0 for 8 valid bits. Default nullptr.
	rxAlign byte, ///< In: Defines the bit position in backData[0] for the first bit received. Default 0.
	checkCRC bool, ///< In: True => The last two bytes of the response is assumed to be a CRC_A that must be validated.
) StatusCode {
	var waitIRq byte
	waitIRq = 0x30 // RxIRq and IdleIRq

	//println(10801)
	//for (byte i = 0; i < sendLen; i++) {
	// count := 0
	// //for(byte count = 0 ;count < bufferUsed; count++){
	// print("Send Data: ")
	// for {
	// 	if count >= sendLen {
	// 		break
	// 	}
	// 	print(sendData[count])
	// 	print(" ")
	// 	count++
	// }
	// print(" Len: " + strconv.FormatInt(int64(sendLen), 10))
	// print("\n")
	// count = 0
	// //for(byte count = 0 ;count < bufferUsed; count++){
	// print("Back Data : ")
	// for {
	// 	if count >= *backLen {
	// 		break
	// 	}
	// 	print(backData[count])
	// 	print(" ")
	// 	count++
	// }
	// print(" Len: " + strconv.FormatInt(int64(*backLen), 10))
	// print("\n")
	return rf.PCD_CommunicateWithPICC(PCD_Transceive, waitIRq, sendData, sendLen, backData, backLen, validBits, rxAlign, false)
} // End PCD_TransceiveData()

func (rf *RFID) PCD_CommunicateWithPICC(
	command byte, ///< The command to execute. One of the PCD_Command enums.
	waitIRq byte, ///< The bits in the ComIrqReg register that signals successful completion of the command.
	sendData []byte, ///< Pointer to the data to transfer to the FIFO.
	sendLen int, ///< Number of bytes to transfer to the FIFO.
	backData []byte, ///< nullptr or pointer to buffer if data should be read back after executing the command.
	backLen *int, ///< In: Max number of bytes to write to *backData. Out: The number of bytes returned.
	validBits *byte, ///< In/Out: The number of valid bits in the last byte. 0 for 8 valid bits.
	rxAlign byte, ///< In: Defines the bit position in backData[0] for the first bit received. Default 0.
	checkCRC bool,
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

	//rf.writeRegister(FIFODataReg, 0x26) // Write sendData to the FIFO single write
	rf.writeRegisterBytes(FIFODataReg, sendLen, sendData)

	// println(9902)
	// println(bitFraming)
	rf.writeRegister(BitFramingReg, bitFraming) // Bit adjustments

	//println(401)
	//println(rf.readRegister(Status2Reg))

	rf.writeRegister(CommandReg, command) // Execute the command
	//println(rf.readRegister(CommandReg))

	//println(402)
	//println(rf.readRegister(Status2Reg))

	if command == PCD_Transceive {
		rf.PCD_SetRegisterBitMask(BitFramingReg, 0x80) // StartSend=1, transmission of data starts
		//println(403)
		//println(rf.readRegister(Status2Reg))
	}

	//println(404)
	//println(rf.readRegister(Status2Reg))

	var irqWait byte
	irqWait = 0x30

	var completed bool
	completed = false
	completed = completed

	//println(101)
	//println(ComIrqReg)
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

	if *backLen != 0 {

		n := rf.readRegister(FIFOLevelReg) // Number of bytes in the FIFO
		if int(n) > *backLen {
			return STATUS_NO_ROOM
		}
		*backLen = int(n)
		// Number of bytes returned
		var toAssign []byte
		toAssign, _ = rf.ReadRegisterBytes(FIFODataReg, int(n)) // Get received data from FIFO
		for i := 0; i < *backLen; i++ {
			backData[i] = toAssign[i] // Assign values to the first 5 elements
		}
		// println("202021")
		// println(backLen)
		// print("Back Data : ")
		// count := 0
		// for {
		// 	if count >= *backLen {
		// 		break
		// 	}
		// 	print(backData[count])
		// 	print(" ")
		// 	count++
		// }
		// print(" Len: " + strconv.FormatInt(int64(*backLen), 10))
		// print("\n")

		_validBits = rf.readRegister(ControlReg) // RxLastBits[2:0] indicates the number of valid bits in the last received byte. If this value is 000b, the whole byte is valid.
		_validBits = _validBits & 0x07
		//println(7707)
		//println(_validBits)
		if *validBits != 0x00 {
			*validBits = _validBits
		}
	}

	if errStatus&0x08 != 0 { // CollErr
		return STATUS_COLLISION
	}

	if (len(backData) != 0) && (*backLen != 0) && checkCRC {
		// In this case a MIFARE Classic NAK is not OK.
		if *backLen == 1 && _validBits == 4 {
			return STATUS_MIFARE_NACK
		}
		// We need at least the CRC_A value and all 8 bits of the last byte must be received.
		if *backLen < 2 || _validBits != 0 {
			return STATUS_CRC_WRONG
		}
		// Verify CRC_A - do our own calculation and store the control in controlBuffer.
		var controlBuffer [2]byte
		var status StatusCode
		status = rf.PCD_CalculateCRC(backData[0:1], byte(*backLen-2), controlBuffer[0:1])
		if status != STATUS_OK {
			return status
		}
		if (backData[*backLen-2] != controlBuffer[0]) || (backData[*backLen-1] != controlBuffer[1]) {
			return STATUS_CRC_WRONG
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
	//println("Transceive_OK")
	return STATUS_OK
}

func (rf *RFID) PICC_ReadCardSerial() bool { //@audit-info PICC_ReadCardSerial
	var result StatusCode
	result = rf.PICC_Select(&rf.uid, 0)
	//println(701)
	//println(result)
	return (result == STATUS_OK)
} // End

func PrintBuffer(buffer []byte, bufferUsed byte) {
	count := 0
	//for(byte count = 0 ;count < bufferUsed; count++){
	for {
		if count >= int(bufferUsed) {
			break
		}
		print(buffer[count])
		print(" ")
		count++
	}
	print("Size ")
	print(bufferUsed)
	print("\n")
}

func (rf *RFID) PICC_Select(
	uid *Uid, ///< Pointer to Uid struct. Normally output, but can also be used to supply a known UID.
	validBits byte, ///< The number of known UID bits supplied in *uid. Normally 0. If set you must also supply uid->size.
) StatusCode {
	//println("SC----------------------")
	var uidComplete bool
	var selectDone bool
	var useCascadeTag bool
	var cascadeLevel byte // defalut 1
	cascadeLevel = 1
	var result StatusCode
	var count byte
	var checkBit byte
	var index byte
	var uidIndex byte             // The first index in uid->uidByte[] that is used in the current Cascade Level.
	var currentLevelKnownBits int // The number of known UID bits in the current Cascade Level.
	var buffer [9]byte            // The SELECT/ANTICOLLISION commands uses a 7 byte standard frame + 2 bytes CRC_A
	var bufferUsed byte           // The number of bytes used in the buffer, ie the number of bytes to transfer to the FIFO.
	//println(10802)
	//PrintBuffer(buffer[:], 9)
	var rxAlign byte    // Used in BitFramingReg. Defines the bit position for the first bit received.
	var txLastBits byte // Used in BitFramingReg. The number of valid bits in the last transmitted byte.
	var responseBuffer []byte
	var responseLength int
	var responseLengthPtr *int = &responseLength

	// Description of buffer structure:
	//		Byte 0: SEL 				Indicates the Cascade Level: PICC_CMD_SEL_CL1, PICC_CMD_SEL_CL2 or PICC_CMD_SEL_CL3
	//		Byte 1: NVB					Number of Valid Bits (in complete command, not just the UID): High nibble: complete bytes, Low nibble: Extra bits.
	//		Byte 2: UID-data or CT		See explanation below. CT means Cascade Tag.
	//		Byte 3: UID-data
	//		Byte 4: UID-data
	//		Byte 5: UID-data
	//		Byte 6: BCC					Block Check Character - XOR of bytes 2-5
	//		Byte 7: CRC_A
	//		Byte 8: CRC_A
	// The BCC and CRC_A are only transmitted if we know all the UID bits of the current Cascade Level.
	//
	// Description of bytes 2-5: (Section 6.5.4 of the ISO/IEC 14443-3 draft: UID contents and cascade levels)
	//		UID size	Cascade level	Byte2	Byte3	Byte4	Byte5
	//		========	=============	=====	=====	=====	=====
	//		 4 bytes		1			uid0	uid1	uid2	uid3
	//		 7 bytes		1			CT		uid0	uid1	uid2
	//						2			uid3	uid4	uid5	uid6
	//		10 bytes		1			CT		uid0	uid1	uid2
	//						2			CT		uid3	uid4	uid5
	//						3			uid6	uid7	uid8	uid9

	// Sanity checks
	if validBits > 80 {
		return STATUS_INVALID
	}

	// Prepare MFRC522
	rf.PCD_ClearRegisterBitMask(CollReg, 0x80) // ValuesAfterColl=1 => Bits received after collision are cleared.

	// Repeat Cascade Level loop until we have a complete UID.
	uidComplete = false

	//while (!uidComplete) {//@audit loop
	for {
		if uidComplete {
			break
		}
		// Set the Cascade Level in the SEL byte, find out if we need to use the Cascade Tag in byte 2.
		switch cascadeLevel {
		case 1:
			buffer[0] = PICC_CMD_SEL_CL1
			uidIndex = 0
			useCascadeTag = validBits != 0 && uid.size > 4 // When we know that the UID has more than 4 bytes
			break

		case 2:
			buffer[0] = PICC_CMD_SEL_CL2
			uidIndex = 3
			useCascadeTag = validBits != 0 && uid.size > 7 // When we know that the UID has more than 7 bytes
			break

		case 3:
			buffer[0] = PICC_CMD_SEL_CL3
			uidIndex = 6
			useCascadeTag = false // Never used in CL3.
			break

		default:
			//println(702)
			return STATUS_INTERNAL_ERROR
			//break;
		}
		//println(10803)
		//PrintBuffer(buffer[:], 9)
		// How many UID bits are known in this Cascade Level?
		currentLevelKnownBits = int(validBits - (8 * uidIndex))
		if currentLevelKnownBits < 0 {
			currentLevelKnownBits = 0
		}
		// Copy the known bits from uid->uidByte[] to buffer[]
		index = 2 // destination index in buffer[]
		if useCascadeTag {
			buffer[index] = PICC_CMD_CT
			index++
		}

		var bytesToCopy byte
		var bytesToCopyTmp int

		if currentLevelKnownBits%8 != 0 {
			bytesToCopyTmp = 1
		} else {
			bytesToCopyTmp = 0
		}
		bytesToCopy = byte(currentLevelKnownBits/8 + bytesToCopyTmp) // The number of bytes needed to represent the known bits for this level.

		if bytesToCopy != 0 {
			var maxBytes byte
			if useCascadeTag {
				maxBytes = 3
			} else {
				maxBytes = 4
			}

			// Max 4 bytes in each Cascade Level. Only 3 left if we use the Cascade Tag

			if bytesToCopy > maxBytes {
				bytesToCopy = maxBytes
			}
			//println(10811)
			//PrintBuffer(buffer[:], 9)
			var bufferCount int
			bufferCount = 0
			//for (count = 0; count < bytesToCopy; count++) {//@audit loop
			for {
				if bufferCount > int(bytesToCopy) {
					break
				}
				bufferCount++

				buffer[index] = uid.uidByte[uidIndex+count]
				index++
			}
		}
		// Now that the data has been copied we need to include the 8 bits in CT in currentLevelKnownBits
		if useCascadeTag {
			currentLevelKnownBits += 8
		}
		//println(10804)
		//PrintBuffer(buffer[:], 9)
		// Repeat anti collision loop until we can transmit all UID bits + BCC and receive a SAK - max 32 iterations.
		selectDone = false
		//while (!selectDone) { //@audit for loop
		for {
			if selectDone {
				break
			}
			// Find out how many bits and bytes to send and receive.
			if currentLevelKnownBits >= 32 { // All UID bits in this Cascade Level are known. This is a SELECT.
				//Serial.print(F("SELECT: currentLevelKnownBits=")); Serial.println(currentLevelKnownBits, DEC);

				//println(10805)
				//PrintBuffer(buffer[:], 9)
				buffer[1] = 0x70 // NVB - Number of Valid Bits: Seven whole bytes

				// Calculate BCC - Block Check Character
				buffer[6] = buffer[2] ^ buffer[3] ^ buffer[4] ^ buffer[5]

				// Calculate CRC_A
				result = rf.PCD_CalculateCRC(buffer[:], 7, buffer[7:]) // Convert array to slice
				//println(801)
				//println(result)
				if result != STATUS_OK {
					return result
				}
				//println(803)
				txLastBits = 0 // 0 => All 8 bits are valid.
				bufferUsed = 9
				// Store response in the last 3 bytes of buffer (BCC and CRC_A - not needed after tx)
				responseBuffer = buffer[6:]
				responseLength = 3
				//println(10806)
				//PrintBuffer(buffer[:], 9)
			} else { // This is an ANTICOLLISION.
				//println(10807)
				//PrintBuffer(buffer[:], 9)
				//Serial.print(F("ANTICOLLISION: currentLevelKnownBits=")); Serial.println(currentLevelKnownBits, DEC);
				txLastBits = byte(currentLevelKnownBits % 8)
				count = byte(currentLevelKnownBits / 8) // Number of whole bytes in the UID part.
				index = 2 + count                       // Number of whole bytes: SEL + NVB + UIDs
				buffer[1] = (index << 4) + txLastBits   // NVB - Number of Valid Bits

				var txLastBitsTmp int
				if txLastBits != 0x00 {
					txLastBitsTmp = 1
				} else {
					txLastBitsTmp = 0
				}

				bufferUsed = index + byte(txLastBitsTmp)
				// Store response in the unused part of buffer
				responseBuffer = buffer[index:]
				responseLength = len(buffer) - int(index)
				//println(10808)
				//PrintBuffer(buffer[:], 9)
			}

			// Set bit adjustments
			rxAlign = txLastBits                                     // Having a separate variable is overkill. But it makes the next line easier to read.
			rf.writeRegister(BitFramingReg, (rxAlign<<4)+txLastBits) // RxAlign = BitFramingReg[6..4]. TxLastBits = BitFramingReg[2..0]
			//println("------------------")
			//println("PCD_TransceiveData")
			//println(10809)
			//PrintBuffer(buffer[:], 9)
			//PrintBuffer(responseBuffer, byte(responseLength))
			// Transmit the buffer and receive the response.
			//responseBuffertmp := make([]byte, responseLength)
			result = rf.PCD_TransceiveData(buffer[:], int(bufferUsed), responseBuffer, responseLengthPtr, &txLastBits, rxAlign, false)
			//println(10810)
			//PrintBuffer(responseBuffer, byte(responseLength))
			//PrintBuffer(buffer[:], 9)
			//println("------------------")
			if result == STATUS_COLLISION { // More than one PICC in the field => collision.
				var valueOfCollReg byte
				valueOfCollReg = rf.readRegister(CollReg) // CollReg[7..0] bits are: ValuesAfterColl reserved CollPosNotValid CollPos[4:0]
				if (valueOfCollReg & 0x20) != 0x00 {      // CollPosNotValid
					return STATUS_COLLISION // Without a valid collision position we cannot continue
				}
				var collisionPos byte
				collisionPos = valueOfCollReg & 0x1F // Values 0-31, 0 means bit 32.

				if collisionPos == 0 {
					collisionPos = 32
				}

				if collisionPos <= byte(currentLevelKnownBits) { // No progress - should not happen
					return STATUS_INTERNAL_ERROR
				}

				// Choose the PICC with the bit set.
				currentLevelKnownBits = int(collisionPos)
				count = byte(currentLevelKnownBits % 8) // The bit to modify
				checkBit = byte((currentLevelKnownBits - 1) % 8)

				var countTmp int
				if count != 0x00 {
					countTmp = 1
				} else {
					countTmp = 0
				}

				index = byte(1 + (currentLevelKnownBits / 8) + countTmp) // First byte is index 0.
				buffer[index] |= (1 << checkBit)

			} else if result != STATUS_OK {

				return result

			} else { // STATUS_OK

				if currentLevelKnownBits >= 32 { // This was a SELECT.
					selectDone = true // No more anticollision
					// We continue below outside the while.

				} else { // This was an ANTICOLLISION.
					// We now have all 32 bits of the UID in this Cascade Level
					currentLevelKnownBits = 32
					// Run loop again to do the SELECT.
				}
			}
		} // End of while (!selectDone)

		// We do not check the CBB - it was constructed by us above.

		// Copy the found UID bytes from buffer[] to uid->uidByte[]

		if buffer[2] == PICC_CMD_CT {
			index = 3
			bytesToCopy = 3
		} else {
			index = 2
			bytesToCopy = 4
		}

		// index			= (buffer[2] == PICC_CMD_CT) ? 3 : 2; // source index in buffer[]
		// bytesToCopy		= (buffer[2] == PICC_CMD_CT) ? 3 : 4;
		var bytesToCopyCount int
		bytesToCopyCount = 0
		//for (count = 0; count < bytesToCopy; count++) {
		//println(10815)
		//println(index, bytesToCopy, uidIndex)
		for {
			if bytesToCopyCount >= int(bytesToCopy) {
				break
			}

			uid.uidByte[int(uidIndex)+bytesToCopyCount] = buffer[index]
			bytesToCopyCount++
			index++
			//println(10812)
			//PrintBuffer(buffer[:], 9)
			//PrintBuffer(uid.uidByte[:], bytesToCopy)
		}

		// Check response SAK (Select Acknowledge)
		if responseLength != 3 || txLastBits != 0 { // SAK must be exactly 24 bits (1 byte + CRC_A).
			return STATUS_ERROR
		}
		// Verify CRC_A - do our own calculation and store the control in buffer[2..3] - those bytes are not needed anymore.
		result = rf.PCD_CalculateCRC(responseBuffer, 1, buffer[2:4]) // Pass a slice, not a pointer
		//println(802)
		//println(result)
		if result != STATUS_OK {
			return result
		}
		if (buffer[2] != responseBuffer[1]) || (buffer[3] != responseBuffer[2]) {
			return STATUS_CRC_WRONG
		}
		if (responseBuffer[0] & 0x04) != 0x00 { // Cascade bit set - UID not complete yes
			cascadeLevel++
		} else {
			uidComplete = true
			uid.sak = responseBuffer[0]
		}
	} // End of while (!uidComplete)

	// Set correct uid->size
	uid.size = 3*cascadeLevel + 1

	return STATUS_OK
} // End PICC_Select()

func (rf *RFID) PCD_CalculateCRC(
	data []byte, ///< In: Pointer to the data to transfer to the FIFO for CRC calculation.
	length byte, ///< In: The number of bytes to transfer.
	result []byte, ///< Out: Pointer to result buffer. Result is written to result[0..1], low byte first.
) StatusCode {
	rf.writeRegister(CommandReg, PCD_Idle)                // Stop any active command.
	rf.writeRegister(DivIrqReg, 0x04)                     // Clear the CRCIRq interrupt request bit
	rf.writeRegister(FIFOLevelReg, 0x80)                  // FlushBuffer = 1, FIFO initialization
	rf.writeRegisterBytes(FIFODataReg, int(length), data) // Write data to the FIFO
	rf.writeRegister(CommandReg, PCD_CalcCRC)             // Start the calculation

	// Wait for the CRC calculation to complete. Check for the register to
	// indicate that the CRC calculation is complete in a loop. If the
	// calculation is not indicated as complete in ~90ms, then time out
	// the operation.
	deadline := uint32(time.Now().UnixMilli()) + 89 // Set deadline (current time + 89ms)

	for {
		// Read the DivIrqReg register
		n := rf.readRegister(DivIrqReg)
		//println(703)
		//println(n)
		//println(n & 0x04)
		CheckCRCIRq := n & 0x04
		if CheckCRCIRq != 0 { // Check if CRCIRq bit is set (calculation done)
			rf.writeRegister(CommandReg, PCD_Idle) // Stop CRC calculation
			//println(704)
			// Read CRC result from registers
			result[0] = rf.readRegister(CRCResultRegL)
			result[1] = rf.readRegister(CRCResultRegH)

			return STATUS_OK
		}

		// Check deadline condition
		if uint32(time.Now().UnixMilli()) >= deadline {
			break
		}
	}

	return STATUS_TIMEOUT
} // End PCD_CalculateCRC()

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
		//tmp := value | 0x03
		rf.writeRegister(TxControlReg, value|0x03)
		// println(10102)
		// println(tmp)
	}
	//rf.writeRegister(TxControlReg, 0x83) // Enable the antenna

	// println(10103)
	//println(rf.readRegister(TxControlReg))
	//println(uint8(0x80) | uint8(0x03))

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

func byteToHex(b byte) string {
	hexChars := "0123456789ABCDEF"
	return string([]byte{hexChars[b>>4], hexChars[b&0x0F]})
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

		//time.Sleep(2 * time.Second)
		if !rfid.IsNewCard() {
			//println("NC----------------------")
			continue
		}
		//println("\033[2J\033[H")
		//println("NewCard at " + time.Now().Format("15:04:05.000000"))
		//println("----------")
		serial := rfid.PICC_ReadCardSerial()
		if !serial {
			continue
		}

		//println("ReadCardSerial at " + time.Now().Format("15:04:05.000000"))
		currentUID := ""
		//print("Card UID:")
		for i := 0; i < int(rfid.uid.size); i++ {
			if rfid.uid.uidByte[i] < 0x10 {
				//print((" 0"))
				currentUID = " 0"
			} else {
				//print((" "))
				currentUID += " "
			}

			//printf("%02X",rfid.uid.uidByte[i])
			//print(byteToHex(rfid.uid.uidByte[i]))
			currentUID += byteToHex(rfid.uid.uidByte[i])
		}
		//println()
		currentUID += "\n"
		machine.Serial.Write([]byte(currentUID))
		//println("NC----------------------")
		time.Sleep(200 * time.Millisecond)
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
