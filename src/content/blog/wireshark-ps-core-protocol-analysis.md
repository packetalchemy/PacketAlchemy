---
title: "Wireshark Protocol Deep Dive: GTP, Diameter, SIP, SCTP, S1AP & Advanced Tools"
description: "Master Wireshark protocol analysis for PS Core: GTP, Diameter, SIP, SCTP, S1AP, PCAP operations, tshark CLI, statistics, and troubleshooting."
pubDate: "2026-07-09"
tags: ["Wireshark", "GTP", "Diameter", "SIP", "S1AP", "PCAP", "tshark"]
---

# Wireshark Protocol Deep Dive: GTP, Diameter, SIP, SCTP, S1AP & Advanced Tools

This comprehensive guide covers every major protocol used in Packet Switched Core networks and how to analyze them with Wireshark. From GTP tunneling and Diameter charging to SIP-based IMS signaling, SCTP transport, S1AP eNodeB control, and advanced command-line tools — this is the definitive reference for PS Core engineers.

---

## GTP (GPRS Tunneling Protocol)

### Introduction

GTP is the backbone of packet‑switched mobile networks. It carries both user data (GTP‑U) and control signaling (GTP‑C) across the LTE/EPC core. Wireshark decodes GTP on **UDP ports 2123 (control) and 2152 (user)**.

---

## Diameter

### What is Diameter?

Diameter is the next‑generation AAA protocol that replaces RADIUS. In PS Core it handles:

- **Billing/Charging (Gx)** between PGW and PCRF
- **Authentication/Authorization (S6a)** between MME and HSS
- **Policy control (Rx)** between PCRF and P‑CSCF

| Application‑ID | Name | Interface |
|---------------|------|-----------|
| 0 | Diameter Base | Connection management |
| 4 | Gx (CC‑Application) | Charging |
| 16777236 | S6a | Subscription |
| 16777264 | Rx | QoS |
| 16777232 | Cx/Dx | IMS |

### Standard Ports

- **3868/TCP or SCTP** – default Diameter transport
- **5868/TCP or SCTP** – TLS‑encrypted Diameter

### Header Overview

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (8)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Message Length (24)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Flags (8)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Command Code (24)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Application‑ID (32)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Hop‑by‑Hop ID (32)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| End‑to‑End ID (32)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| AVP / Grouped AVPs ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size (bytes) | Description |
|-------|--------------|-------------|
| Version | 1 | Always 1 |
| Length | 3 | Total message length (including 20‑byte header) |
| Flags | 1 | R (request), P (proxiable), E (error), T (potentially retransmitted) |
| Command Code | 3 | Function identifier (e.g., 272 for CCR) |
| Application‑ID | 4 | Application context (e.g., 4 for Gx) |
| Hop‑by‑Hop ID | 4 | Matches request ↔ response |
| End‑to‑End ID | 4 | Correlates across peers |

### Important AVPs

| AVP Code | Name | Description |
|----------|------|-------------|
| 1 | User‑Name | IMSI or user identifier |
| 26 | Vendor‑Id | 10415 for 3GPP |
| 256 | Result‑Code | Result of the command |
| 258 | Experimental‑Result‑Code | Extended result |
| 264 | Destination‑Host |
| 265 | Destination‑Realm |
| 266 | Disconnect‑Cause |
| 263 | Session‑Id |
| 247 | CC‑Request‑Type |
| 248 | CC‑Request‑Number |
| 258 | Event‑Trigger |
| 267 | Rating‑Group |
| 271 | GPR‑QoS‑Information |
| 272 | User‑Equipment‑Info |
| 432 | Charging‑Rule‑Install |
| 433 | Charging‑Rule‑Remove |
| 437 | Charging‑Rule‑Definition |
| 438 | Charging‑Rule‑Name |
| 439 | Event‑Charging‑Rule‑Name |
| 440 | Metering‑Method |
| 441 | Offline‑Charging |
| 442 | Online‑Charging |

### Command Codes

| Code | Name | Usage |
|------|------|------|
| 257 | Capabilities‑Exchange (CER/CEA) |
| 258 | Device‑Watchdog (DWR/DWA) |
| 260 | Disconnect‑Peer (DPR/DPA) |
| 272 | Credit‑Control (CCR/CCA) – Gx |
| 268 | Authentication‑Information (AIR/AIA) – S6a |
| 274 | Session‑Termination (STR/STA) |
| 265 | AA (RAR/RAA) – Rx |
| 298 | Abort‑Session |

### Wireshark Diameter Filters

```
# Show all Diameter
Diameter

# Show all CCR‑Initial (Gx)
Diameter && diameter.cmd.code == 272 && diameter.flags.request == 1 && diameter.CC-Request-Type == 1

# Show CCR‑Update
Diameter && diameter.cmd.code == 272 && diameter.flags.request == 1 && diameter.CC-Request-Type == 2

# Show CCR‑Termination
Diameter && diameter.cmd.code == 272 && diameter.flags.request == 1 && diameter.CC-Request-Type == 3

# Show AIR (Authentication‑Information Request – S6a)
Diameter && diameter.cmd.code == 268 && diameter.flags.request == 1

# Show AIA (Authentication‑Information Answer)
Diameter && diameter.cmd.code == 268 && diameter.flags.request == 0

# Show all error responses
Diameter && diameter.flags.request == 0 && diameter.result_code != 2001

# Filter by IMSI (User‑Name AVP)
Diameter && diameter.User-Name == "9891234567890"

# Filter by APN (Called‑Station‑Id contains APN)
Diameter && diameter.Called-Station-Id contains "internet"

# Filter by Result‑Code (e.g., 5003 – Unable to Deliver)
Diameter && diameter.result_code == 5003
```

---

## SIP (Session Initiation Protocol)

### What is SIP?

SIP is the signaling protocol used in IMS for creating, modifying, and terminating multimedia sessions. It carries voice, video, and messaging over IP networks.

### IMS Architecture

```
UE → P‑CSCF → S‑CSCF → I‑CSCF → HSS
        ↕              ↕
     PCRF        Application Server
```

| Interface | Between | Purpose |
|-----------|---------|---------|
| Gm | UE ↔ P‑CSCF | Registration / Session |
| Mw | P‑CSCF ↔ S‑CSCF | Signaling |
| Mx | S‑CSCF ↔ I‑CSCF | Routing |
| Cx | S‑CSCF ↔ HSS | Subscription |

### Transport

| Transport | Port | Security |
|-----------|------|----------|
| TCP | 5060 | Unencrypted |
| UDP | 5060 | Unencrypted |
| TCP+TLS | 5061 | Encrypted |
| SCTP | 5060 | High‑reliability |

### SIP Message Structure

```
┌─────────────────────────────────────┐
│ Method Request‑URI SIP/2.0          │ ← Request Line
├─────────────────────────────────────┤
│ Header1: Value1                     │ ← Headers
│ Header2: Value2                     │
├─────────────────────────────────────┤
│                                     │ ← Empty Line
├─────────────────────────────────────┤
│ Body (SDP, etc.)                   │ ← Message Body
└─────────────────────────────────────┘
```

### Key Methods

| Method | Purpose |
|--------|---------|
| REGISTER | Register UE in IMS |
| INVITE | Start session (call) |
| ACK | Confirm INVITE |
| BYE | End session |
| CANCEL | Cancel pending INVITE |
| OPTIONS | Capability query |
| UPDATE | Update session |
| PRACK | Provisional ACK |
| SUBSCRIBE | Subscribe to events |
| NOTIFY | Notify events |
| MESSAGE | SMS over IMS |

### SIP Status Codes

| Code | Reason |
|------|--------|
| 100 | Trying |
| 180 | Ringing |
| 183 | Session Progress |
| 200 | OK |
| 403 | Forbidden |
| 404 | Not Found |
| 408 | Request Timeout |
| 486 | Busy Here |
| 487 | Request Terminated |
| 500 | Server Internal Error |
| 503 | Service Unavailable |

### IMS Headers

| Header | Description |
|--------|-------------|
| P‑Access‑Network‑Info | Access network info (e.g., `3GPP‑E‑UTRAN‑FDD`) |
| P‑Asserted‑Identity | Verified identity |
| P‑Charging‑Vector | ICID, IOI for charging |
| P‑Called‑Party‑ID | Destination party ID |
| Service‑Route | Service routing path |
| Security‑Client / Server | IPSec parameters |

### SIP + SDP (Session Description Protocol)

SDP is carried inside the SIP body and describes the media streams:

```
v=0
o=- 3845392 3845392 IN IP4 10.10.1.1
s=-
c=IN IP4 10.10.1.1
t=0 0
m=audio 49170 RTP/AVP 0 8 97
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:97 iLBC/8000
```

| Payload Type | Codec | Usage |
|--------------|-------|-------|
| 0 | PCMU (G.711 μ‑law) | Standard voice |
| 8 | PCMA (G.711 A‑law) | Standard voice |
| 97 | iLBC | Low‑bandwidth voice |
| 98 | EVS | Enhanced voice |
| 102 | H.264 | Video |
| 113 | H.265 | Advanced video |

### Wireshark SIP Filters

```
# Show all SIP
sip

# Filter by method
sip.Method == "INVITE"
sip.Method == "REGISTER"
sip.Method == "BYE"
sip.Method == "SUBSCRIBE"
sip.Method == "NOTIFY"
sip.Method == "MESSAGE"

# Filter by status code
sip.Status-Code == 200
sip.Status-Code == 100
sip.Status-Code == 403
sip.Status-Code == 503

# Filter by Call-ID
sip.Call-ID == "abc123@operator.com"

# Filter by From/To
sip.From contains "+9891234567890"
sip.To contains "+9899876543210"

# Show INVITE with SDP
sip.Method == "INVITE" && sip contains "v=0"

# Show all errors (4xx / 5xx)
sip.Status-Code >= 400 && sip.Status-Code < 600

# Show SIP for specific IMSI
sip contains "9891234567890"
```

---

## SCTP (Stream Control Transmission Protocol)

### What is SCTP?

SCTP is a transport protocol that combines features of UDP (message‑oriented) and TCP (reliable, ordered). It is used in telecom for carrying signaling protocols such as Diameter and S1AP.

| Application | Port | Transport |
|-------------|------|-----------|
| S1AP (S1‑MME) | 36412 | eNodeB ↔ MME |
| Diameter (S6a/Gx/Rx) | 3868 | MME/SGSN ↔ HSS/PCRF |
| SIGTRAN (M2UA/M3UA) | 2905/2904 | SS7 over IP |

### SCTP vs TCP

| Feature | TCP | SCTP |
|---------|-----|------|
| Multi‑homing | ✗ | ✓ |
| Multi‑streaming | ✗ | ✓ |
| Message‑oriented | ✗ (byte stream) | ✓ |
| Cookie‑based security | ✗ | ✓ (4‑way → 2‑way) |
| Ordered delivery | ✓ (per‑stream) | ✓ (per‑stream) |
| Heartbeat | ✗ (keep‑alive) | ✓ (HEARTBEAT) |

### Multi‑homing

```
┌──────────────────────────────────────┐
│ SCTP Association                     │
│                                      │
│ Endpoint A                           │
│   ├── Primary:   10.10.1.1           │
│   ├── Secondary: 10.10.2.1           │
│   └── Secondary: 192.168.1.1         │
│         ↕ (Multi‑homed paths)        │
│ Endpoint B                           │
│   ├── Primary:   10.20.1.1           │
│   ├── Secondary: 10.20.2.1           │
│   └── Secondary: 192.168.2.1         │
└──────────────────────────────────────┘
```

### Multi‑streaming

```
SCTP Association
├── Stream 0: S1AP Procedures
├── Stream 1: NAS Transport
├── Stream 2: Paging
└── Stream 3: Error Indication
```

### SCTP Header

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Source Port               | Destination Port              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Verification Tag                                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Checksum                                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Chunks ...                                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Key Chunk Types

| Type | Name | Description |
|------|------|-------------|
| 0 | DATA | User data |
| 1 | INIT | Start association |
| 2 | INIT ACK | Start response |
| 3 | SACK | Selective ACK |
| 4 | HEARTBEAT | Liveness check |
| 5 | HEARTBEAT ACK | Liveness reply |
| 6 | ABORT | Connection abort |
| 7 | SHUTDOWN | Graceful shutdown |
| 13 | ERROR | Error report |
| 14 | Cookie Echo | Security handshake |
| 15 | Cookie ACK | Cookie response |

### Wireshark SCTP Filters

```
# Show all SCTP
sctp

# Filter by port
sctp.srcport == 36412
sctp.dstport == 3868

# Filter by chunk type
sctp.chunk.type == 1   # INIT
sctp.chunk.type == 0   # DATA
sctp.chunk.type == 4   # HEARTBEAT
sctp.chunk.type == 6   # ABORT
sctp.chunk.type == 7   # SHUTDOWN

# Filter by verification tag
sctp.verification_tag == 0x12345678

# Show S1AP traffic
sctp.dstport == 36412 || sctp.srcport == 36412

# Show Diameter traffic
sctp.dstport == 3868 || sctp.srcport == 3868
```

### What is GTP?

GTP is the tunneling protocol used for carrying user data and signaling across 2G/GPRS, 3G/UMTS, and 4G/LTE networks. It comes in three variants:

- **GTPv1-C:** Control plane for 2G/3G (Gn/Gp interfaces)
- **GTPv2-C:** Control plane for 4G/LTE (S11/S5/S8 interfaces)
- **GTP-U:** User plane data transport (all generations)

### Protocol Layering

```
┌──────────────────────────┐
│       GTP Header         │
├──────────────────────────┤
│  Information Elements    │
├──────────────────────────┤
│  UDP (2123/2152)         │
├──────────────────────────┤
│  IP                      │
├──────────────────────────┤
│  Ethernet                │
└──────────────────────────┘
```

### GTP Ports

| Port | Protocol | Usage |
|------|----------|-------|
| 2123 | UDP | GTPv1-C and GTPv2-C |
| 2152 | UDP | GTP-U |

### Interfaces and GTP

| Interface | Protocol | Between |
|-----------|----------|---------|
| Gn | GTPv1-C | SGSN ↔ GGSN |
| Gp | GTPv1-C | SGSN ↔ GGSN (roaming) |
| S11 | GTPv2-C | MME ↔ SGW |
| S4 | GTPv2-C | SGSN ↔ SGW |
| S5 | GTPv2-C | SGW ↔ PGW |
| S8 | GTPv2-C | SGW ↔ PGW (roaming) |
| S1-U | GTP-U | eNodeB ↔ SGW |
| S5-U | GTP-U | SGW ↔ PGW |

### GTPv1 Header Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version |P|X|R|  Reserved   |       Message Type            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Message Length        |     Tunnel Endpoint ID        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                      GTP Data / IEs...                        |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size (bits) | Description |
|-------|-------------|-------------|
| Version | 3 | GTP version (1 for GTPv1) |
| PT (Protocol Type) | 1 | 1=GTP, 0=GTP' |
| Reserved | 1 | Reserved |
| E (Extension) | 1 | Extension Header present |
| S (Sequence) | 1 | Sequence Number present |
| PN (PDU Number) | 1 | PDU Number present |
| Message Type | 8 | Message type |
| Message Length | 16 | Message length (excluding 8-byte header) |
| TEID | 32 | Tunnel Endpoint Identifier |

### GTPv1-C Message Types

| Type | Name | Usage |
|------|------|-------|
| 1 | Echo Request | Path keepalive check |
| 2 | Echo Response | Path keepalive reply |
| 3 | Version Not Supported | Version rejection |
| 16 | Create PDP Context Request | Create PDP context |
| 17 | Create PDP Context Response | PDP context response |
| 18 | Update PDP Context Request | Update PDP context |
| 19 | Update PDP Context Response | Update response |
| 20 | Delete PDP Context Request | Delete PDP context |
| 21 | Delete PDP Context Response | Delete response |
| 26 | Error Indication | Error report |
| 27 | PDU Notification Request | PDU notification |
| 200 | G-PDU | User data |

### Key Information Elements in GTPv1

#### IEs in Create PDP Context Request

| IE Type | Name | Description |
|---------|------|-------------|
| 1 | Cause | Cause/result |
| 2 | IMSI | User IMSI |
| 3 | Recovery | Recovery number |
| 4 | APN | Access Point Name |
| 5 | GSN Address | GGSN address |
| 6 | MSISDN | MSISDN number |
| 8 | Quality of Service | QoS Profile |
| 15 | TEID Data I | Data TEID |
| 16 | TEID Control Plane | Control TEID |
| 128 | GTP-U Peer Address | GTP-U peer address |
| 133 | Charging Characteristics | Charging attributes |
| 134 | Common Flags | Common flags |
| 150 | Selection Mode | Selection mode |

#### IEs in Create PDP Context Response

| IE Type | Name | Description |
|---------|------|-------------|
| 1 | Cause | Cause (Accept=16, Duplicate=19, ...) |
| 3 | Recovery | Recovery number |
| 5 | GSN Address | GGSN address |
| 8 | Quality of Service | QoS Profile |
| 15 | TEID Data I | Data TEID |
| 128 | GTP-U Peer Address | GTP-U peer address |

### GTPv2-C Header Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version |P|T|E|S| Reserved  |       Message Type            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Message Length        | TEID (higher 32 bits)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   TEID (lower 32 bits)       |     Sequence Number           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Sequence Number (cont)      |          Spare                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                      GTP Data / IEs...                        |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size (bits) | Description |
|-------|-------------|-------------|
| Version | 3 | GTP version (2 for GTPv2) |
| PT | 1 | Always 1 |
| T (Teid Flag) | 1 | TEID present |
| E (EPC Flags) | 1 | EPC-related flags |
| S (Sequence) | 1 | Sequence Number present |
| Message Type | 8 | Message type |
| Message Length | 16 | Message length |
| TEID | 64 | Tunnel identifier (8 bytes) |
| Sequence Number | 24 | Sequence number |
| Spare | 8 | Reserved bits |

### GTPv2-C Message Types

#### Management Messages

| Type | Name | Description |
|------|------|-------------|
| 1 | Echo Request | Path management request |
| 2 | Echo Response | Path management reply |
| 3 | Version Not Supported | Version rejection |
| 4 | Peer Address Resolution | Peer address resolution |

#### Tunnel Management Messages (S11/S5)

| Type | Name | Description |
|------|------|-------------|
| 32 | Create Session Request | Session creation |
| 33 | Create Session Response | Session creation response |
| 34 | Modify Bearer Request | Bearer modification |
| 35 | Modify Bearer Response | Bearer modification response |
| 36 | Delete Session Request | Session deletion |
| 37 | Delete Session Response | Session deletion response |
| 38 | Modify Bearer Command | Downlink bearer modification |
| 39 | Modify Bearer Failure Notification | Modification failure |
| 40 | Delete Bearer Command | Bearer deletion command |
| 41 | Delete Bearer Failure Notification | Deletion failure |

#### Bearer Management Messages

| Type | Name | Description |
|------|------|-------------|
| 64 | Create Bearer Request | Create dedicated bearer |
| 65 | Create Bearer Response | Dedicated bearer response |
| 66 | Update Bearer Request | Bearer update |
| 67 | Update Bearer Response | Bearer update response |
| 68 | Delete Bearer Request | Bearer deletion |
| 69 | Delete Bearer Response | Bearer deletion response |
| 70 | Downlink Data Notification | Downlink data indication |
| 71 | DDN Acknowledge | DDN acknowledgment |

#### Handover Messages

| Type | Name | Description |
|------|------|-------------|
| 33 | Handover Request | Handover request |
| 35 | Handover Command | Handover command |
| 161 | Handover Complete | Handover completion |

### Key Information Elements in GTPv2-C

| IE Type | Name | Description |
|---------|------|-------------|
| 1 | Cause | Cause code |
| 2 | IMSI | Subscriber IMSI |
| 51 | APN | Access Point Name |
| 53 | AMBR | Aggregate Maximum Bit Rate |
| 55 | Bearer Context | Bearer context |
| 57 | Bearer QoS | Bearer quality of service |
| 61 | Charging Characteristics | Charging attributes |
| 68 | F-TEID | Fully Qualified TEID |
| 76 | MSISDN | Phone number |
| 80 | PDN Type | PDN connection type |
| 82 | RAT Type | Radio Access Technology |
| 84 | Selection Mode | Selection mode |
| 88 | ULI | User Location Information |
| 95 | UE Time Zone | UE timezone |

#### F-TEID (IE Type 68)

```
├── CHOOSE (1 bit): F-TEID selected by peer
├── IPv4 (1 bit): IPv4 address present
├── IPv6 (1 bit): IPv6 address present
├── Interface Type (4 bits):
│   ├── 0: S1-U eNodeB
│   ├── 1: S1-U SGW
│   ├── 2: S5/S8-U SGW
│   ├── 3: S5/S8-U PGW
│   ├── 4: S11-MME
│   ├── 5: S5/S8-C SGW
│   ├── 6: S5/S8-C PGW
│   └── 7: S2b-C PGW
├── TEID (4 bytes): Tunnel identifier
├── IPv4 Address (4 bytes, optional)
└── IPv6 Address (16 bytes, optional)
```

#### Cause Values (GTPv2-C)

| Value | Name | Description |
|-------|------|-------------|
| 1 | Request Accepted | Request succeeded |
| 64 | System Failure | System failure |
| 65 | No Resources Available | Resources unavailable |
| 66 | Mandatory IE Incorrect | Mandatory IE error |
| 67 | Mandatory IE Missing | Mandatory IE missing |
| 70 | Context Not Found | Context not found |
| 71 | Request Rejected | Request rejected |
| 72 | APN Access Denied (no subscription) | APN blocked |
| 76 | User Authentication Failed | Auth failure |
| 80 | Version Not Supported | Version not supported |
| 95 | Semantically Incorrect Message | Semantic error |
| 96 | Invalid Message Format | Invalid format |
| 106 | Unexpected Message | Unexpected message |

### GTP Analysis with Wireshark Filters

```
# === Basic GTPv2-C Filters ===

# Show all GTPv2-C
gtpv2

# Show Create Session Request/Response
gtpv2.message_type == 32 || gtpv2.message_type == 33

# Show Modify Bearer Request/Response
gtpv2.message_type == 34 || gtpv2.message_type == 35

# Show Delete Session Request/Response
gtpv2.message_type == 36 || gtpv2.message_type == 37

# Show Echo Request/Response
gtpv2.message_type == 1 || gtpv2.message_type == 2

# Show Dedicated Bearer operations
gtpv2.message_type == 64 || gtpv2.message_type == 65

# === TEID-Based Filters ===

# Show traffic for a specific TEID
gtpv2.teid == 0x12345678

# Show Create Session with zero TEID
gtpv2.message_type == 32 && gtpv2.teid == 0x00000000

# Show F-TEID IE by interface type
gtpv2.fteid.interfaceType == 6   # S5/S8-C PGW
gtpv2.fteid.interfaceType == 1   # S1-U SGW

# === IMSI/APN Filters ===

# Show traffic for specific IMSI
gtpv2.imsi == "9891234567890"

# Show Create Session for specific APN
gtpv2.message_type == 32 && gtpv2.apn == "internet"

# === Cause Code Filters ===

# Show rejected responses
gtpv2.flags.request == 0 && gtpv2.cause != 1

# Show specific causes
gtpv2.cause == 70   # Context not found
gtpv2.cause == 64   # System failure

# === GTP-U Filters ===

# Show GTP-U
gtpu

# Show GTP-U with specific TEID
gtpu.teid == 0xabcdef01

# Show large GTP-U (bulk data)
gtpu && frame.len > 1400
```
