// =====================================================================
//  RFID card UID reader  —  RC522 + Arduino Uno (or ESP32)   v2
//  Prints each card's UID ready to paste into the project code.
//  v2: maximum antenna gain, "still alive" dots, re-checks the reader
//      every 10 s, and says when a card is seen but can't be read.
//
//  Library: MFRC522 (by GithubCommunity / miguelbalboa)
//  Serial Monitor: 115200 baud, then press RESET on the board.
// =====================================================================
#include <SPI.h>
#include <MFRC522.h>

#if defined(ESP32)
  // ESP32 (same wiring as the v4 Board 1 project):
  //   SDA->D5  SCK->D18  MOSI->D23  MISO->D19  RST->3V3  3.3V->3V3  GND->GND
  const uint8_t PIN_SS = 5, PIN_SCK = 18, PIN_MISO = 19, PIN_MOSI = 23;
  MFRC522 rfid(PIN_SS, MFRC522::UNUSED_PIN);
#else
  // Arduino Uno / Nano:
  //   SDA->D10  SCK->D13  MOSI->D11  MISO->D12  RST->D9  3.3V->3.3V (NOT 5V)  GND->GND
  const uint8_t PIN_SS = 10, PIN_RST = 9;
  MFRC522 rfid(PIN_SS, PIN_RST);
#endif

unsigned long lastDot = 0, lastCheck = 0;
byte lastVersion = 0;

void startReader() {
  rfid.PCD_Init();
  delay(50);
  rfid.PCD_SetAntennaGain(rfid.RxGain_max);   // strongest receive gain (helps clone boards)
}

void describeVersion(byte v) {
  Serial.print(F("Reader chip version: 0x"));
  Serial.print(v, HEX);
  switch (v) {
    case 0x91: case 0x92: Serial.println(F("  -> genuine RC522, OK")); break;
    case 0x88:            Serial.println(F("  -> FM17522 clone, usually works")); break;
    case 0x00: case 0xFF: Serial.println(F("  -> NO REPLY: check SDA, SCK, MOSI, MISO, 3.3V, GND")); break;
    default:              Serial.println(F("  -> unexpected value: loose/long wires or unsoldered header pins?")); break;
  }
}

void setup() {
  Serial.begin(115200);
  delay(500);
#if defined(ESP32)
  SPI.begin(PIN_SCK, PIN_MISO, PIN_MOSI, PIN_SS);
#else
  SPI.begin();
#endif
  startReader();
  Serial.println();
  Serial.println(F("=== RFID card UID reader v2 ==="));
  lastVersion = rfid.PCD_ReadRegister(MFRC522::VersionReg);
  describeVersion(lastVersion);
  Serial.println(F("Hold a card FLAT on the reader (1-2 cm) for 2 seconds."));
  Serial.println(F("A dot appears every 2 s while waiting."));
}

void printUid() {
  Serial.println();
  Serial.println(F("----------------------------------------"));
  Serial.print(F("Card UID : "));
  for (byte i = 0; i < rfid.uid.size; i++) {
    if (rfid.uid.uidByte[i] < 0x10) Serial.print('0');
    Serial.print(rfid.uid.uidByte[i], HEX);
    if (i + 1 < rfid.uid.size) Serial.print(' ');
  }
  Serial.println();
  MFRC522::PICC_Type type = rfid.PICC_GetType(rfid.uid.sak);
  Serial.print(F("Type     : "));
  Serial.println(rfid.PICC_GetTypeName(type));
  Serial.print(F("Paste    : {"));
  for (byte i = 0; i < rfid.uid.size; i++) {
    Serial.print(F("0x"));
    if (rfid.uid.uidByte[i] < 0x10) Serial.print('0');
    Serial.print(rfid.uid.uidByte[i], HEX);
    if (i + 1 < rfid.uid.size) Serial.print(F(", "));
  }
  Serial.print(F("}   (length "));
  Serial.print(rfid.uid.size);
  Serial.println(F(")"));
}

void loop() {
  unsigned long now = millis();

  // Every 10 s: re-check the chip and re-initialise it (clone boards can "freeze").
  if (now - lastCheck > 10000) {
    lastCheck = now;
    byte v = rfid.PCD_ReadRegister(MFRC522::VersionReg);
    if (v != lastVersion) {
      Serial.println();
      Serial.print(F("! Version changed - wiring is unstable. "));
      describeVersion(v);
      lastVersion = v;
    }
    startReader();
  }

  if (now - lastDot > 2000) { lastDot = now; Serial.print('.'); }

  if (!rfid.PICC_IsNewCardPresent()) return;
  if (!rfid.PICC_ReadCardSerial()) {
    Serial.println();
    Serial.println(F("Card detected but UID read failed - hold it flat and still, closer to the reader."));
    return;
  }
  printUid();
  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
  delay(1000);
}
