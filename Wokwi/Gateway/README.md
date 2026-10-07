# Testing the gateway online (two Wokwi tabs)

Wokwi can't do ESP-NOW between boards. In simulation mode (`WOKWI_SIM 1`), both boards send **the same signed packets** over **MQTT** instead: a public message server (`broker.hivemq.com`) reached through Wokwi's simulated Wi-Fi. Signing, replay protection, ACKs, timeouts and log forwarding are the same code as on the real boards; only the radio layer is swapped. On the real boards (`WOKWI_SIM 0`) ESP-NOW is used as normal.

```
 Tab 1: Board 1 (Wokwi)  ──publish /ctrl──►  broker.hivemq.com  ──►  Tab 2: Gateway (Wokwi)
                         ◄──── /gw (ACK) ───                     ◄──
```

## 1. Update your Board 1 Wokwi project (the one that already works)

Replace or add these, then **Save**:

| Tab | Action |
|---|---|
| `sketch.ino` | replace with the new `sketch.ino` from this zip |
| `link_protocol.h` | **replace too**: it now holds the MQTT settings |
| `libraries.txt` | add a 4th line: **`PubSubClient`** |
| `diagram.json`, `secrets.h` | no change |

## 2. Create the gateway Wokwi project (new tab)

1. wokwi.com → **New Project → ESP32**.
2. **sketch.ino** ← paste `Gateway/sketch.ino` (single file; nothing else needed).
3. **diagram.json** ← paste `Gateway/diagram.json` (ESP32 + a blue "Controller online" LED).
4. **libraries.txt**: Library Manager → **+** → **PubSubClient** (or paste `Gateway/libraries.txt`).
5. **Save.**

## 3. Run both

1. Put the two Wokwi tabs **in separate browser windows, side by side**. Browsers slow down background tabs, and that can make the link time out.
2. Press **▶ Play on the gateway first**. Its Serial Monitor shows:
   `LINK,Gateway started (Wokwi/MQTT mode)…` then `LINK,MQTT connected - waiting for controller`
3. Press **▶ Play on Board 1**. Within a few seconds:
   - **Gateway:** `LINK,Controller online`, the blue LED turns **on**, then `STATUS,BOOT,P0,Z1-LEFT:WARMUP,…` and `LOG,…` lines.
   - **Board 1:** `[sim] MQTT connected`, then `COMM,Gateway online - PC link UP`.

Connecting to Wi-Fi + MQTT in Wokwi can take **5–15 seconds**. That's normal.

## 4. Test script

| # | Do | Gateway tab shows | Board 1 tab shows |
|---|---|---|---|
| **G1 Link up** | Start both (step 3) | `LINK,Controller online`, blue LED on, `STATUS` lines | `Gateway online - PC link UP` |
| **G2 Events reach the PC** | Board 1: Blue card → 1234 #, then motion on one PIR, then the other | `LOG,…,AUTH,Login Operator1,…,SUCCESS`, `LOG,…,P1,…Motion warning 1/3`, `LOG,…,P2,…Corroborated…`, new `STATUS` line | LEDs / buzzer / LCD as before |
| **G3 PC link lost (T09)** | **Stop** the gateway simulation (■) | — | within ~8 s: `Gateway lost - PC link DOWN`; LCD "PC link DOWN". **Alarm still works** (try a PIR) |
| | Press ▶ on the gateway again | `Gateway started…`, `Controller online` | `Gateway restarted…` + `PC link UP` |
| **G4 Controller lost** | **Stop** Board 1 | within ~8 s: `LINK,CONTROLLER LOST…`; blue LED off | — |
| | Press ▶ on Board 1 again | `LINK,Controller restarted reason=…`; log numbering starts again | — |
| **G5 Fake gateway (T08+)** | Gateway tab: change **one byte** of `SHARED_KEY` (e.g. first `0xB7` → `0xB8`), ▶ | `SEC,REJECTED,Bad signature (spoofed?)` repeating | `COMM,Bad signature (spoofed?)…REJECTED` and **PC link DOWN** |
| | Put `0xB7` back, ▶ | link returns | `PC link UP` |

G5 is your strongest evidence for the viva: a node without the shared key can't join or fake messages, even on a public server anyone can reach.

## Notes

- **Topic:** both boards use the topic `pinnacle13/p13-2d386efc` (in `link_protocol.h`). It's unique to your project. If you change it, change it in **both** tabs.
- **Public server:** anyone subscribed to that topic could see the packets. They're **signed, not encrypted**, the same as over the radio: an outsider can't fake or replay them, but can see that events happen. That's already in your residual-risk table.
- **Lost lines:** if the internet hiccups, the gateway prints `GAP,n`, meaning n log lines didn't arrive. The full log is always kept on Board 1 (maintenance key **3**).
- **"MQTT connected" never appears:** check that both projects use `WOKWI_SIM 1` and that `PubSubClient` is in `libraries.txt`, then restart the simulation. The public server is occasionally slow, so try again after a minute.
- **This doesn't test the ESP-NOW radio itself.** Do the real-hardware gateway test (G1–G5 with two ESP32s) for that.
