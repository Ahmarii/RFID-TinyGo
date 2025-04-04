# RFID-TinyGo

A lightweight and custom-built **MFRC522 RFID library** for [TinyGo](https://tinygo.org/), designed to work with microcontrollers like the **Raspberry Pi Pico** over **SPI**.

This project enables basic RFID card detection and UID reading using the **MFRC522** module—commonly used in hobbyist and embedded systems.

---

## 📦 Features

- ✅ Detect RFID cards in range
- ✅ Read card UID (Unique Identifier)
- ✅ Communicate with MFRC522 via SPI
- ✅ Written in TinyGo from scratch
- ✅ Inspired by the Arduino MFRC522 C++ library

---

## 🛠️ Hardware Requirements

- **Raspberry Pi Pico** (or any TinyGo-compatible microcontroller)
- **MFRC522 RFID Module**
- **Jumper Wires**
- Breadboard (optional)

---

## 📚 Getting Started

### 🧪 Install TinyGo

Follow the instructions on the official site:  
🔗 https://tinygo.org/getting-started/

### 🧰 Wiring Diagram

| MFRC522 | Raspberry Pi Pico |
|---------|-------------------|
| SDA     | GP17 (customizable) |
| SCK     | GP18               |
| MOSI    | GP19               |
| MISO    | GP16               |
| RST     | GP20               |
| GND     | GND                |
| VCC     | 3.3V               |

> ⚠️ Only use 3.3V on MFRC522 when working with the Pico.

---

### 🔧 Flashing the Firmware

```bash
tinygo flash -target=pico main.go
```

You should see output via serial when a card is detected.

---

## 💡 Example Output

When a card is placed near the reader, the UID is read and printed via serial:

```
Card UID: 04 A3 1F 22
```

---

## 📂 Project Structure

- `mfrc522.go` – Main library file with register-level control
- `main.go` – Sample usage on how to detect cards and read UID
- `registers.go` – MFRC522 register definitions

---

## 📄 Reference

- [MFRC522 Datasheet (NXP)](https://www.nxp.com/docs/en/data-sheet/MFRC522.pdf)
- [Arduino MFRC522 Library](https://github.com/miguelbalboa/rfid)

---

## 📃 License

This project is licensed under the **MIT License**.

---

## 🙌 Acknowledgments

Created as part of my **POSCashier** project to support hardware integration on embedded devices using TinyGo.

> Made with 🧠 and ❤️ by [Ahmarii](https://github.com/Ahmarii)
```

---
