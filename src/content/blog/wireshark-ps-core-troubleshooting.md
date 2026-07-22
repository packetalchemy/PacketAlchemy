---
title: "Wireshark Troubleshooting Guide for PS Core: Filters, Scenarios & Best Practices"
description: "Complete Wireshark filter reference and troubleshooting guide for PS Core — GTP, Diameter, SIP, S1AP, SCTP, practical scenarios, advanced tips, and Huawei commands."
tags: ["Wireshark", "Troubleshooting", "PS Core", "Filters", "Practical", "Telecom"]
pubDate: "2026-07-09"
---

## ۱. مقدمه و مفاهیم پایه

### ۱.۱ انواع فیلتر در Wireshark

| نوع فیلتر | محل استفاده | مثال |
|---|---|---|
| **Display Filter** | نوار فیلتر بالای پنجره اصلی | `gtpv2.msg_type == 1` |
| **Capture Filter** | هنگام شروع ضبط (libpcap) | `host 10.1.1.1 and port 2123` |
| **Read Filter** | هنگام باز کردن فایل ذخیره‌شده | `gtp | diameter | sip` |

### ۱.۲ عملگرهای مقایسه‌ای رایج

```text
==   مساوی
!=   نامساوی
>    بزرگتر
>=   بزرگتر یا مساوی
<    کوچکتر
<=   کوچکتر یا مساوی
contains   شامل بودن
matches    تطابق با regex
```

### ۱.۳ عملگرهای منطقی

```text
&&   AND (و)
||   OR (یا)
!    NOT (نه)
```

### ۱.۴ پورت‌های استاندارد در شبکه‌های هسته بسته

| پروتکل | پورت | توضیح |
|---|---|---|
| GTPv1-C | 2123 | کنترل GTP v1 (S4/S11/S5/S8) |
| GTPv1-U | 2152 | داده GTP v1 |
| GTPv2-C | 2123 | کنترل GTP v2 (S11/S5/S8/S10) |
| Diameter | 3868 | پورت استاندارد Diameter |
| SIP | 5060 | SIP بدون TLS (UDP/TCP) |
| SIP-TLS | 5061 | SIP با TLS |
| S1AP | 36422 | S1AP روی SCTP |
| X2AP | 36422 | X2AP روی SCTP |
| RADIUS | 1812/1813 | Authentication / Accounting |

---

## ۲. فیلترهای GTP (GTPv1/v2)

### ۲.۱ GTPv2-C — فیلترهای پایه

```text
gtpv2                                    → تمام پکت‌های GTPv2
gtpv2.msg_type                           → نوع پیام GTPv2
gtpv2.msg_type == 1                      → Create Session Request
gtpv2.msg_type == 2                      → Create Session Response
gtpv2.msg_type == 3                      → Modify Bearer Request
gtpv2.msg_type == 4                      → Modify Bearer Response
gtpv2.msg_type == 5                      → Delete Session Request
gtpv2.msg_type == 6                      → Delete Session Response
gtpv2.msg_type == 7                      → Change Notification Request
gtpv2.msg_type == 8                      → Change Notification Response
gtpv2.msg_type == 32                     → Modify Bearer Command (SGW→eNodeB)
gtpv2.msg_type == 33                     → Modify Bearer Failure Indication
gtpv2.msg_type == 34                     → Delete Bearer Command
gtpv2.msg_type == 35                     → Delete Bearer Failure Indication
gtpv2.msg_type == 36                     → Bearer Resource Command
gtpv2.msg_type == 37                     → Bearer Resource Failure Indication
gtpv2.msg_type == 64                     → Echo Request
gtpv2.msg_type == 65                     → Echo Response
gtpv2.msg_type == 66                     → Version Not Supported
```

### ۲.۲ GTPv2-C — فیلترهای Information Elements

```text
gtpv2.cause                                → کد علت پاسخ
gtpv2.cause == 16                          → Request Accepted (موفق)
gtpv2.cause == 64                          → Context Not Found
gtpv2.cause == 71                          → No Resources Available
gtpv2.cause == 80                          → Semantic Error in TFT
gtpv2.cause == 81                          → Syntactic Error in TFT
gtpv2.cause == 95                          → Semantically Incorrect Message
gtpv2.cause == 96                          → Mandatory IE Incorrect
gtpv2.cause == 97                          → Mandatory IE Missing
gtpv2.cause == 99                          → Optional IE Incorrect
gtpv2.cause == 100                         → Invalid Cause
gtpv2.cause == 104                         → Invalid TEID Combination
gtpv2.cause == 105                         → Invalid Peer
gtpv2.cause == 112                         → Service Not Supported
gtpv2.cause == 113                         → Unable to Page UE
gtpv2.cause == 114                         → No Subscription
gtpv2.cause == 119                         → APN Access Denied

gtpv2.imsi                                 → IMSI (شماره مشترک)
gtpv2.imsi == "98912XXXXXXX"              → فیلتر بر اساس IMSI خاص
gtpv2.imsi contains "98912"               → IMSI حاوی رشته مشخص

gtpv2.apn                                  → APN درخواستی
gtpv2.apn == "mtnirancell"                → APN خاص

gtpv2.teid                                 → TEID پیام
gtpv2.teid == 0                            → TEID صفر (پیام اولیه)
gtpv2.teid != 0                            → TEID غیرصفر

gtpv2.uli                                  → User Location Information
gtpv2.uli.eCGI                             → E-UTRAN Cell Global ID
gtpv2.uli.tai.tac == 0x0001               → TAC خاص
```

### ۲.۳ GTPv2-C — IEهای رایج

```text
gtpv2.serving_network.mcc                  → MCC
gtpv2.serving_network.mnc                  → MNC
gtpv2.bearer_qos.qci                       → QCI
gtpv2.bearer_qos.qci == 1                 → بیر VoLTE
gtpv2.bearer_qos.qci == 5                 → بیر IMS Signaling
gtpv2.bearer_qos.qci == 9                 → بیر اینترنت عمومی

gtpv2.fteid.interface_type == 0           → S1-U eNodeB (GTP-U)
gtpv2.fteid.interface_type == 1           → S1-U SGW (GTP-U)
gtpv2.fteid.interface_type == 4           → S11 MME
gtpv2.fteid.interface_type == 6           → S5/S8 SGW (GTP-C)
gtpv2.fteid.interface_type == 7           → S5/S8 PGW (GTP-C)
gtpv2.fteid.interface_type == 15          → SGi (PGW)

gtpv2.mei                                  → Mobile Equipment Identity
gtpv2.msisdn                               → MSISDN شماره تلفن
gtpv2.pdn_type == 1                       → IPv4
gtpv2.pdn_type == 2                       → IPv6
gtpv2.pdn_type == 3                       → IPv4v6
gtpv2.pdn_type == 4                       → Non-IP

gtpv2.bearer_context.ebi == 5             → EBI=5 (bearer اول)
gtpv2.ambr.uplink                         → Uplink AMBR
gtpv2.ambr.downlink                       → Downlink AMBR
```

### ۲.۴ GTPv1

```text
gtp.version == 1                           → GTPv1
gtp.version == 2                           → GTPv2

gtp.type == 1                              → Echo Request
gtp.type == 2                              → Echo Response
gtp.type == 16                             → Create PDP Context Request
gtp.type == 17                             → Create PDP Context Response
gtp.type == 18                             → Update PDP Context Request
gtp.type == 19                             → Update PDP Context Response
gtp.type == 20                             → Delete PDP Context Request
gtp.type == 21                             → Delete PDP Context Response
gtp.gpdu                                   → GPDU (GTP-U data packet)
```

### ۲.۵ فیلترهای ترکیبی GTP

```text
gtpv2.msg_type == 1 || gtpv2.msg_type == 2       # نمایش Create Session
gtpv2.msg_type == 5 || gtpv2.msg_type == 6       # نمایش Delete Session
gtpv2.msg_type >= 32 && gtpv2.msg_type <= 37      # خطاهای GTP
gtpv2.msg_type == 64 || gtpv2.msg_type == 65      # Echo (Health Check)
gtpv2.imsi == "989123456789012"                   # GTP برای IMSI خاص
gtpv2.teid == 0x12345678                          # GTP بر روی TEID خاص
gtpv2.cause != 16 && gtpv2.cause != 2             # GTP با Cause خطا
udp.port == 2123                                  # GTP روی پورت 2123
```

---

## ۳. فیلترهای Diameter

### ۳.۱ فیلترهای پایه

```text
diameter                                   → تمام پکت‌های Diameter
diameter.cmd.code                          → کد فرمان Diameter
diameter.hdr.flags.request                 → پیام Request
diameter.hdr.flags.response                → پیام Response
```

### ۳.۲ Diameter Application Codes

| کد | اپلیکیشن | رابط |
|---|---|---|
| 16777236 | S6a (MME↔HSS) | S6a |
| 16777238 | S13 (MME↔EIR) | S13 |
| 16777217 | Gx (PGW↔PCRF) | Gx |
| 16777232 | Rx (P-CSCF↔PCRF) | Rx |
| 16777233 | S9 (PCRF↔SPR) | S9 |

### ۳.۳ Diameter Commands — S6a (MME↔HSS)

```text
diameter.cmd.code == 316                    → Authentication-Information-Request (AIR)
diameter.cmd.code == 318                    → Update-Location-Request/Response (ULR/ULA)
diameter.cmd.code == 320                    → Cancel-Location-Request (CLR)
diameter.cmd.code == 321                    → Purge-UE-Request (PUR)
diameter.cmd.code == 323                    → Insert-Subscriber-Data-Request (IDR)
diameter.cmd.code == 324                    → Delete-Subscriber-Data-Request (DSR)
diameter.cmd.code == 325                    → Diameter-Notification-Request (NOR)

diameter.application_id == 16777236         → S6a Application
diameter.application_id == 16777217         → Gx Application
diameter.application_id == 16777232         → Rx Application
```

### ۳.۴ Diameter Commands — Gx (PGW↔PCRF)

```text
diameter.cmd.code == 272                    → Credit-Control-Request/Response (CCR/CCA)
diameter.cmd.code == 274                    → Re-Auth-Request (RAR)
diameter.cmd.code == 275                    → Re-Auth-Answer (RAA)
```

### ۳.۵ AVP: Result-Code

```text
diameter.result-code == 2001                → Success
diameter.result-code == 2002                → Unable to Comply
diameter.result-code == 3001                → Unable to Deliver
diameter.result-code == 4012                → Unknown Subscription
diameter.result-code == 4181                → Unknown EPS Bearer
diameter.result-code == 5001                → Unable to Fulfill Request
diameter.result-code == 5012                → APN Rate Control Exceeded
diameter.result-code == 5014                → Bearer does not exist
diameter.result-code == 5023                → User Unknown
diameter.result-code == 5030                → Service Unavailable

diameter.result-code >= 3000                → نمایش تمام پاسخ‌های خطا
```

### ۳.۶ AVP: CCR Type و Subscription

```text
diameter.CC-Request-Type == 1               → INITIAL_REQUEST
diameter.CC-Request-Type == 2               → UPDATE_REQUEST
diameter.CC-Request-Type == 3               → TERMINATION_REQUEST
diameter.CC-Request-Type == 4               → EVENT_REQUEST

diameter.CC-Request-Type == 1 && diameter.cmd.code == 272   # CCR-I
diameter.CC-Request-Type == 2 && diameter.cmd.code == 272   # CCR-U
diameter.CC-Request-Type == 3 && diameter.cmd.code == 272   # CCR-T

diameter.Subscription-Id-type == 0          → END_USER_E164 (MSISDN)
diameter.Subscription-Id-type == 1          → END_USER_IMSI
diameter.Called-Station-Id == "mtnirancell" → فیلتر بر اساس APN
diameter.QoS-Class-Identifier == 1         → QCI=1 (VoLTE)
diameter.QoS-Class-Identifier == 9         → QCI=9 (اینترنت)
```

### ۳.۷ فیلترهای ترکیبی Diameter

```text
diameter.result-code >= 3000                 → تمام پیام‌های خطا
diameter.application_id == 16777217 && diameter.hdr.flags.request  → Gx Requests
diameter.cmd.code == 272 && diameter.CC-Request-Type == 3          → CCR-T
tcp.port == 3868 && diameter               → Diameter روی پورت خاص
diameter.Charging-Rule-Name contains "volte" → قاعده شارژینگ VoLTE
```

---

## ۴. فیلترهای SIP

### ۴.۱ فیلترهای پایه

```text
sip                                        → تمام پکت‌های SIP
sip.Method == "INVITE"                     → درخواست برقراری تماس
sip.Method == "ACK"                        → تأیید درخواست
sip.Method == "BYE"                        → پایان تماس
sip.Method == "CANCEL"                     → لغو درخواست در حال برقراری
sip.Method == "REGISTER"                   → ثبت‌نام
sip.Method == "OPTIONS"                    → تست قابلیت
sip.Method == "PRACK"                      → Provisional Response ACK
sip.Method == "UPDATE"                     → بروزرسانی تماس
sip.Method == "REFER"                      → انتقال تماس
sip.Method == "NOTIFY"                     → اطلاع‌رسانی
sip.Method == "SUBSCRIBE"                  → اشتراک رویداد
sip.Method == "MESSAGE"                    → پیام کوتاه IMS
sip.Method == "INFO"                       → اطلاعات اضافی

sip.Status-Code == 100                     → Trying
sip.Status-Code == 180                     → Ringing
sip.Status-Code == 183                     → Session Progress (Early Media)
sip.Status-Code == 200                     → OK (موفق)
sip.Status-Code == 403                     → Forbidden
sip.Status-Code == 404                     → Not Found
sip.Status-Code == 408                     → Request Timeout
sip.Status-Code == 480                     → Temporarily Unavailable
sip.Status-Code == 486                     → Busy Here
sip.Status-Code == 487                     → Request Terminated
sip.Status-Code == 488                     → Not Acceptable Here
sip.Status-Code == 500                     → Server Internal Error
sip.Status-Code == 503                     → Service Unavailable
sip.Status-Code == 603                     → Decline
```

### ۴.۲ فیلترهای هدر SIP

```text
sip.From contains "+98912"                 → فرستنده با MSISDN خاص
sip.To contains "+98901"                   → گیرنده با MSISDN خاص
sip.Call-ID == "unique-call-id"            → تماس خاص
sip.CSeq.method == "INVITE"                → CSeq مربوط به INVITE
sip.Expires                                → مدت اعتبار (REGISTER)
sip.P-Asserted-Identity contains "+98912"  → Caller ID واقعی در IMS
```

### ۴.۳ فیلترهای SDP

```text
sdp.rtpmap.codec == "AMR"                  → کدک AMR (صدا)
sdp.rtpmap.codec == "AMR-WB"              → کدک AMR-WB (صدای با کیفیت)
sdp.rtpmap.codec == "opus"                → کدک Opus
```

### ۴.۴ فیلترهای VoLTE/IMS

```text
sip.Method == "INVITE" && sdp.rtpmap.codec == "AMR"   # VoLTE call
sip.Method == "REGISTER"                                # IMS Registration
sip.Method == "MESSAGE"                                 # SMS روی IMS
sip.Status-Code == 403 || sip.Status-Code == 486 || sip.Status-Code == 603  # تماس‌های رد شده
sip.Method == "REGISTER" && sip.Expires == 0            # Deregistration
udp.port == 5060 && sip                                 # SIP روی UDP
tcp.port == 5060 && sip                                 # SIP روی TCP
```

---

## ۵. فیلترهای S1AP

### ۵.۱ فیلترهای پایه

```text
s1ap                                        → تمام پکت‌های S1AP
s1ap.procedureCode                          → کد رویه S1AP
s1ap.cause                                  → علت
s1ap.criticality                            → حیاتی بودن
```

### ۵.۲ S1AP Procedure Codes

```text
s1ap.procedureCode == 0                     → InitialUEMessage
s1ap.procedureCode == 1                     → DownlinkNASTransport
s1ap.procedureCode == 2                     → UplinkNASTransport
s1ap.procedureCode == 3                     → InitialContextSetupRequest
s1ap.procedureCode == 4                     → InitialContextSetupResponse
s1ap.procedureCode == 5                     → InitialContextSetupFailure
s1ap.procedureCode == 6                     → Paging
s1ap.procedureCode == 7                     → HandoverRequest
s1ap.procedureCode == 8                     → HandoverRequestAcknowledge
s1ap.procedureCode == 9                     → HandoverNotify
s1ap.procedureCode == 10                    → PathSwitchRequest
s1ap.procedureCode == 11                    → PathSwitchRequestAcknowledge
s1ap.procedureCode == 12                    → HandoverCancel
s1ap.procedureCode == 15                    → ErabReleaseCommand
s1ap.procedureCode == 18                    → ErabSetupRequest
s1ap.procedureCode == 19                    → ErabSetupResponse
s1ap.procedureCode == 20                    → ErabSetupFailure
s1ap.procedureCode == 28                    → UEContextReleaseCommand
s1ap.procedureCode == 32                    → S1SetupRequest
s1ap.procedureCode == 33                    → S1SetupResponse
s1ap.procedureCode == 55                    → OverloadStart
s1ap.procedureCode == 56                    → OverloadStop
s1ap.procedureCode == 65                    → HandoverRequired
s1ap.procedureCode == 66                    → HandoverCommand
s1ap.procedureCode == 67                    → HandoverFailure
s1ap.procedureCode == 68                    → HandoverPreparationFailure
```

### ۵.۳ S1AP Cause Values

```text
s1ap.cause == 1                             → unspecified
s1ap.cause == 2                             → txNearerToRAN (MME overloaded)
s1ap.cause == 3                             → txNearerToCore (eNB overloaded)
s1ap.cause == 4                             → resourcesUnavailable
s1ap.cause == 5                             → maintenance
s1ap.cause == 8                             → unknown or target eNB not responding
```

### ۵.۴ فیلترهای ترکیبی S1AP

```text
s1ap.procedureCode == 7 || s1ap.procedureCode == 8 || s1ap.procedureCode == 9   # Handover
s1ap.procedureCode == 0                                                      # InitialUEMessage
s1ap.procedureCode == 32 || s1ap.procedureCode == 33                         # S1 Setup
s1ap.procedureCode >= 15 && s1ap.procedureCode <= 24                         # E-RAB Operations
s1ap.procedureCode == 28 || s1ap.procedureCode == 29 || s1ap.procedureCode == 30  # UE Context Release
s1ap.procedureCode == 6                                                      # Paging
s1ap.procedureCode == 55 || s1ap.procedureCode == 56                         # Overload
```

---

## ۶. فیلترهای SCTP

### ۶.۱ فیلترهای پایه و Chunk Type

```text
sctp                                         → تمام پکت‌های SCTP
sctp.srcport == 36422                        → پورت مبدأ S1AP/X2AP
sctp.dstport == 36422                        → پورت مقصد S1AP/X2AP

sctp.chunk.type == 0                         → DATA Chunk
sctp.chunk.type == 1                         → INIT Chunk
sctp.chunk.type == 2                         → INIT ACK Chunk
sctp.chunk.type == 3                         → SACK Chunk
sctp.chunk.type == 4                         → ABORT Chunk
sctp.chunk.type == 5                         → SHUTDOWN Chunk
sctp.chunk.type == 7                         → ERROR Chunk
sctp.chunk.type == 8                         → COOKIE ECHO Chunk
```

### ۶.۲ فیلترهای ترکیبی SCTP + S1AP

```text
sctp && s1ap                                              # تمام S1AP روی SCTP
sctp.chunk.type == 4                                       # قطع ارتباط SCTP
sctp.chunk.type == 1 && sctp.dstport == 36422             # ارتباط SCTP جدید (INIT)
sctp.chunk.type == 0 && sctp.association.id == 1          # DATA Chunks در ارتباط خاص
```

---

## ۷. فیلترهای TCP/UDP برای تلکام

### ۷.۱ فیلترهای پورت و جریان

```text
tcp.port == 3868                             → Diameter
udp.port == 2123                             → GTPv1-C / GTPv2-C
udp.port == 2152                             → GTP-U (داده)
udp.port == 5060                             → SIP
udp.port == 5061                             → SIP-TLS
udp.port == 1812                             → RADIUS Authentication
udp.port == 1813                             → RADIUS Accounting

ip.addr == 10.100.1.1                       → هاست خاص
tcp.stream == 0                              → اولین ارتباط TCP

tcp.port == 3868 || udp.port == 2123 || udp.port == 2152 || udp.port == 5060  # پورت‌های تلکام
```

### ۷.۲ فیلترهای تحلیل TCP

```text
tcp.analysis.retransmission                  → انتقال مجدد (ReTX)
tcp.analysis.duplicate_ack                   → ACK تکراری
tcp.analysis.zero_window                     → پنجره صفر (گلوگاه)
tcp.analysis.lost_segment                    → بسته گمشده
tcp.analysis.out_of_order                    → خارج از ترتیب
tcp.analysis.fast_retransmit                 → انتقال سریع

tcp.flags.reset == 1                         → RST (ریست اتصال)
tcp.flags.syn == 1 && tcp.flags.ack == 0     → SYN (شروع اتصال)
tcp.flags.fin == 1                           → FIN (پایان اتصال)

tcp.analysis.retransmission || tcp.analysis.zero_window || tcp.flags.reset == 1  # مشکلات TCP
```

### ۷.۳ فیلترهای GTP-U

```text
gtp.gpdu                                     → بسته‌های GPDU (داده)
gtp.gpdu && ip.addr == 1.2.3.4              → داده برای IP خاص
gtp.v1.teid == 0x00001234                   → فیلتر بر اساس TEID
udp.port == 2152                            → پورت GTP-U
!gtp.gpdu && gtpv2                          → جدا کردن کنترل از داده
```

---

## ۸. سناریوهای عملی عیب‌یابی

### ۸.۱ سناریو: Attach Failure (عدم توانایی اتصال)

```text
مرحله ۱: بررسی S1AP InitialUEMessage (Attach Request)
  s1ap.procedureCode == 0

مرحله ۲: بررسی انتقال NAS و پاسخ
  s1ap.procedureCode == 0 || s1ap.procedureCode == 1 || s1ap.procedureCode == 2

مرحله ۳: بررسی S6a (Authentication, Location Update)
  diameter.application_id == 16777236
  diameter.cmd.code == 316 || diameter.cmd.code == 318

مرحله ۴: بررسی خطا در HSS
  diameter.application_id == 16777236 && diameter.result-code != 2001

مرحله ۵: بررسی GTP Create Session
  gtpv2.msg_type == 1 || gtpv2.msg_type == 2

مرحله ۶: بررسی خطا در Create Session
  gtpv2.msg_type == 2 && gtpv2.cause != 16

فیلتر جامع سناریو:
  (s1ap.procedureCode == 0 || s1ap.procedureCode == 1 || s1ap.procedureCode == 2) || (diameter.application_id == 16777236) || (gtpv2.msg_type == 1 || gtpv2.msg_type == 2)
```

### ۸.۲ سناریو: قطع تماس VoLTE

```text
مرحله ۱: بررسی SIP INVITE
  sip.Method == "INVITE"

مرحله ۲: بررسی پاسخ‌های SIP خطا
  sip.Status-Code >= 300

مرحله ۳: بررسی Rx Diameter (QoS Authorization)
  diameter.application_id == 16777232

مرحله ۴: بررسی Gx (Bearer Setup با QCI=1)
  diameter.application_id == 16777217 && diameter.CC-Request-Type == 1

مرحله ۵: بررسی QCI=1 در GTP
  gtpv2.bearer_qos.qci == 1

مرحله ۶: بررسی E-RAB Setup در S1AP
  s1ap.procedureCode == 18 || s1ap.procedureCode == 19

فیلتر جامع VoLTE:
  sip || (diameter.application_id == 16777232) || (diameter.application_id == 16777217 && diameter.CC-Request-Type == 1) || (gtpv2.bearer_qos.qci == 1) || (s1ap.procedureCode == 18 || s1ap.procedureCode == 19)
```

### ۸.۳ سناریو: مشکل Handover

```text
مرحله ۱: Handover Required (eNB → MME)
  s1ap.procedureCode == 65

مرحله ۲: Handover Request (MME → Target eNB)
  s1ap.procedureCode == 7

مرحله ۳: Handover Request Acknowledge
  s1ap.procedureCode == 8

مرحله ۴: Handover Notify (Target eNB → MME)
  s1ap.procedureCode == 9

مرحله ۵: لغو Handover
  s1ap.procedureCode == 12

مرحله ۶: Path Switch
  s1ap.procedureCode == 10 || s1ap.procedureCode == 11

مرحله ۷: Forward Relocation در GTP
  gtpv2.msg_type == 160 || gtpv2.msg_type == 161

فیلتر جامع Handover:
  (s1ap.procedureCode >= 7 && s1ap.procedureCode <= 13) || (s1ap.procedureCode == 65 || s1ap.procedureCode == 66) || (gtpv2.msg_type == 160 || gtpv2.msg_type == 161)
```

### ۸.۴ سناریو: مشکل شارژینگ (Charging)

```text
مرحله ۱: CCR-I (Initial)
  diameter.cmd.code == 272 && diameter.CC-Request-Type == 1

مرحله ۲: CCR-U (Update)
  diameter.cmd.code == 272 && diameter.CC-Request-Type == 2

مرحله ۳: CCR-T (Termination)
  diameter.cmd.code == 272 && diameter.CC-Request-Type == 3

مرحله ۴: پاسخ‌های خطا
  diameter.cmd.code == 272 && diameter.result-code >= 3000

مرحله ۵: Re-Auth از PCRF
  diameter.cmd.code == 274

مرحله ۶: پاسخ Re-Auth
  diameter.cmd.code == 275

فیلتر جامع شارژینگ:
  diameter.application_id == 16777217 && (diameter.cmd.code == 272 || diameter.cmd.code == 274 || diameter.cmd.code == 275)
```

### ۸.۵ سناریو: مشکل Bearer Setup

```text
مرحله ۱: E-RAB Setup Request
  s1ap.procedureCode == 18

مرحله ۲: E-RAB Setup Response
  s1ap.procedureCode == 19

مرحله ۳: E-RAB Setup Failure
  s1ap.procedureCode == 20

مرحله ۴: Modify Bearer در GTP
  gtpv2.msg_type == 3 || gtpv2.msg_type == 4

مرحله ۵: QCI
  gtpv2.bearer_qos.qci

مرحله ۶: QoS در Gx
  diameter.QoS-Class-Identifier

فیلتر جامع Bearer:
  (s1ap.procedureCode >= 15 && s1ap.procedureCode <= 24) || (gtpv2.msg_type == 3 || gtpv2.msg_type == 4) || diameter.QoS-Class-Identifier
```

### ۸.۶ سناریو: مشکل PDN Connectivity

```text
مرحله ۱: فیلتر بر اساس APN
  gtpv2.apn == "apn-name-here"

مرحله ۲: Create Session با APN
  gtpv2.msg_type == 1 && gtpv2.apn == "apn-name-here"

مرحله ۳: بررسی پاسخ
  gtpv2.msg_type == 2 && gtpv2.apn == "apn-name-here"

مرحله ۴: بررسی علت خطا
  gtpv2.apn == "apn-name-here" && gtpv2.cause != 16

مرحله ۵: بررسی PDN Type
  gtpv2.apn == "apn-name-here" && gtpv2.pdn_type

مرحله ۶: بررسی Delete Session
  gtpv2.apn == "apn-name-here" && (gtpv2.msg_type == 5 || gtpv2.msg_type == 6)
```

### ۸.۷ سناریو: Overload

```text
s1ap.procedureCode == 55 || s1ap.procedureCode == 56       # Overload در S1AP
diameter.result-code == 3002                                # Overload در Diameter
gtpv2.cause == 71                                           # Overload در GTP

فیلتر جامع:
  s1ap.procedureCode == 55 || diameter.result-code == 3002 || gtpv2.cause == 71
```

### ۸.۸ سناریو: Session Timeout

```text
gtpv2.msg_type == 64 || gtpv2.msg_type == 65               # GTPv2 Echo (Health Check)
diameter.cmd.code == 280                                    # Diameter DWR/DWA (Device-Watchdog)
gtp.type == 1 || gtp.type == 2                              # GTPv1 Echo
```

### ۸.۹ سناریو: تحلیل کامل یک مشترک IMSI خاص

```text
gtpv2.imsi == "989123456789012"                            # IMSI در GTP
diameter.User-Name == "989123456789012"                     # IMSI در Diameter
sip.From contains "+989****7890"                            # MSISDN در SIP
sip.To contains "+989****7890"

فیلتر جامع مشترک:
  gtpv2.imsi == "989123456789012" || diameter.User-Name == "989123456789012" || sip.From contains "+989****7890" || sip.To contains "+989****7890"
```

---

## ۹. IO Graphs برای تحلیل زمان‌بندی Signaling

### ۹.۱ دسترسی

**مسیر:** `Statistics → IO Graphs` یا `Ctrl+Shift+G`

### ۹.۲ تنظیم IO Graph برای تحلیل ترافیک تلکام

| Graph | فیلتر | رنگ | سبک |
|---|---|---|---|
| GTP | `gtp` | آبی | Line |
| Diameter | `diameter` | سبز | Line |
| SIP | `sip` | قرمز | Line |
| S1AP | `s1ap` | زرد | Line |

**Interval:** 1.0 sec — **Scale:** Packets/Tick

### ۹.۳ IO Graph برای عیب‌یابی

```text
تشخیص Retransmission:
  Filter: tcp.analysis.retransmission
  Style: Bar | Color: قرمز | Interval: 0.5 sec

تشخیص Handover Success/Failure:
  Filter 1 (Success): s1ap.procedureCode == 9
  Filter 2 (Cancel):  s1ap.procedureCode == 12

تشخیص Error Rate Diameter:
  Filter 1 (All):    diameter
  Filter 2 (Errors):  diameter.result-code >= 3000
```

---

## ۱۰. Follow TCP/Stream

### ۱۰.۱ روش استفاده

- روی پکت مورد نظر **کلیک راست** کنید
- گزینه **Follow → TCP Stream** (برای Diameter)
- یا **Follow → UDP Stream** (برای GTP)
- یا **Follow → TLS Stream** (برای SIP-TLS)

### ۱۰.۲ استفاده از فیلتر بعد از Follow

```text
tcp.stream eq 12                                → فقط ارتباط TCP مربوطه
tcp.stream eq 12 && diameter                    → فقط Diameter در آن stream
```

---

## ۱۱. Expert Information و هشدارها

### ۱۱.۱ دسترسی

**مسیر:** `Analyze → Expert Information` یا `Ctrl+Shift+E`

### ۱۱.۲ سطوح هشدار

| سطح | رنگ | توضیح |
|---|---|---|
| **Error** | قرمز | خطاهای جدی |
| **Warning** | زرد | هشدار — مشکل احتمالی |
| **Note** | آبی | اطلاعات — ممکن است مهم باشد |
| **Chat** | سبز | اطلاعات عادی |

### ۱۱.۳ فیلترهای Expert برای PS Core

```text
expert.severity == 2                                                  → فقط خطاها
expert.severity == 3                                                  → فقط هشدارها
expert.message contains "retransmission"                              → انتقال مجدد
expert.message contains "RST"                                         → TCP Reset
expert.severity <= 3 && (tcp.analysis.retransmission || tcp.flags.reset == 1 || tcp.analysis.zero_window)  # مشکلات TCP
```

### ۱۱.۴ معنی کدهای Expert

```text
[TCP Previous segment not captured]     → بسته‌ای قبلی دریافت نشده
[TCP Out-Of-Order]                     → بسته خارج از ترتیب
[TCP Retransmission]                   → انتقال مجدد
[TCP Duplicate ACK]                    → ACK تکراری
[TCP Zero Window]                      → پنجره دریافت صفر
[TCP Spurious Retransmission]          → انتقال مجدد بی‌مورد
[SCTP ABORT]                           → قطع ارتباط SCTP
[GTPv2 Bad]                            → پیام GTPv2 نادرست
[Diameter Malformed AVP]               → AVP Diameter خراب
```

---

## ۱۲. تنظیم ستون‌های سفارشی

### ۱۲.۱ دسترسی

**مسیر:** `View → Column Preferences` یا `Ctrl+Shift+X`

### ۱۲.۲ ستون‌های تلکامی پیشنهادی

| نام ستون | فیلتر فیلد | توضیح |
|---|---|---|
| TEID | `gtpv2.teid` | GTP TEID |
| GTPv2 Msg | `gtpv2.msg_type` | نوع پیام GTPv2 |
| GTP Cause | `gtpv2.cause` | علت GTP |
| Diameter Code | `diameter.cmd.code` | کد فرمان Diameter |
| Diameter Result | `diameter.result-code` | کد نتیجه |
| CC-Req-Type | `diameter.CC-Request-Type` | نوع CCR |
| SIP Method | `sip.Method` | روش SIP |
| SIP Status | `sip.Status-Code` | کد وضعیت SIP |
| S1AP Proc | `s1ap.procedureCode` | کد رویه S1AP |
| QoS Info | `gtpv2.bearer_qos.qci` | QCI |

### ۱۲.۳ پروفایل ستون‌ها

**برای GTP:** `No. | Time | Source | Destination | GTPv2 Msg | TEID | GTP Cause | APN | Info`
**برای Diameter:** `No. | Time | Source | Destination | Diameter Code | Diameter Result | CC-Req-Type | Info`
**برای SIP/VoLTE:** `No. | Time | Source | Destination | SIP Method | SIP Status | Call-ID | Info`
**برای S1AP/LTE:** `No. | Time | Source | Destination | S1AP Proc | S1AP Cause | TEID | Info`

---

## ۱۳. پروفایل PS Core در Wireshark

### ۱۳.۱ ایجاد پروفایل سفارشی

**مسیر:** `Edit → Preferences → Profiles → +`

### ۱۳.۲ Color Rules

```text
Color Rule 1: gtp || gtpv2                    → آبی تیره
Color Rule 2: diameter                        → سبز
Color Rule 3: sip                             → قرمز
Color Rule 4: s1ap                            → نارنجی
Color Rule 5: sctp                            → بنفش
Color Rule 6: tcp.analysis.retransmission     → قرمز روشن
Color Rule 7: expert.severity == 2            → قرمز
Color Rule 8: expert.severity == 3            → زرد
```

### ۱۳.۳ تنظیمات مهم پروتکل‌ها

```text
GTP:      ☑ Decode GTPv2 messages  ☑ Decode GTPv1 messages  ☑ Show GTP-U payloads
Diameter: ☑ Load custom dictionary  ☑ Show all AVPs
SIP:      ☑ Show SIP message body  ☑ Decode SDP  ☑ Highlight SIP packets
TCP:      ☑ Allow Subdissector  ☑ Reassemble TCP segments
```

### ۱۳.۴ Decode As

| پورت | پروتکل |
|---|---|
| 2123 | GTPv2-C |
| 3868 | DIAMETER |
| 5060 | SIP |
| 36422 | S1AP (روی SCTP) |
| 2152 | GTP-U |

---

## ۱۴. کدهای خطای رایج و معنی آن‌ها

### ۱۴.۱ GTP-C — Create Session Response

| Cause | معنی | اقدام |
|---|---|---|
| 1 | Request accepted | ✅ موفق |
| 6 | Request rejected, system not ready | بررسی بار سیستم |
| 9 | UE temporarily not authorized | بررسی HSS |
| 13 | Request not accepted | بررسی تنظیمات PGW |
| 19 | IMSI not known in HSS | بررسی USN/HSS |
| 22 | No resources available | افزایش ظرفیت |
| 26 | Peer response timeout | بررسی اتصال شبکه |
| 40 | No EPS bearer context activated | Re-attach UE |

### ۱۴.۲ GTP-C — Forward Relocation (Handover)

| Cause | معنی | اقدام |
|---|---|---|
| 128 | Handover Successful | ✅ موفق |
| 129 | Handover Target Unknown | بررسی eNB مقصد |
| 130 | Handover Failure, target not responding | بررسی اتصال MME-eNB |
| 131 | Handover Failure, target rejected resources | بررسی منابع eNB |

### ۱۴.۳ Diameter — Result-Code

| کد | معنی | اقدام |
|---|---|---|
| 2001 | Success | ✅ موفق |
| 4001 | Unable to Deliver | بررسی مسیریابی |
| 4012 | Unable to Comply | بررسی ظرفیت |
| 5001 | Permanent Failure | بررسی سیستم |
| 5012 | Unknown Subscriber | بررسی USN/HSS |
| 5014 | Bearer Not Activated | بررسی PDN |
| 5021 | Invalid Auth-Session-State | بررسی اتصال |
| 5023 | Invalid Service-Selection | بررسی اشتراک |

### ۱۴.۴ NAS EPS — کدهای خطای رایج

| کد | معنی | اقدام |
|---|---|---|
| #2 | IMSI unknown in HSS | بررسی USN |
| #3 | Illegal UE | بررسی IMEI |
| #6 | Illegal ME | بررسی IMEI |
| #7 | EPS services not allowed | بررسی اشتراک |
| #11 | PLMN not allowed | بررسی PLMN |
| #20 | MAC failure | بررسی احراز هویت |

---

## ۱۵. تکنیک‌های پیشرفته

### ۱۵.۱ رمزنگاری TLS/SSL برای ترافیک IMS

**روش ۱: Pre-Master Secret Log**
```bash
export SSLKEYLOGFILE=~/sslkeys.log
# سپس در Wireshark: Edit → Preferences → Protocols → TLS → Pre-Master-Secret log file
```

**روش ۲: RSA Private Key (TLS < 1.3)**
```text
Wireshark → Edit → Preferences → Protocols → TLS → RSA keys list
  IP Address: <P-CSCF_IP>  |  Port: 5061  |  Protocol: tcp  |  Key file: /path/to/server.key
```

**روش ۳: TLS 1.3**
```text
فقط Pre-Master Secret Log معتبر است. TLS 1.3 از RSA key قابل رمزگشایی نیست.
```

### ۱۵.۲ فیلترها بعد از رمزگشایی TLS

```text
sip                                          → SIP بعد از رمزگشایی
sip && tls                                   → SIP IMS با TLS
diameter && tls                              → Diameter over TLS
tls.handshake.extensions_server_name contains "p-cscf"   → اتصال TLS به P-CSCF
tls.handshake.type == 1                      → Client Hello
tls.handshake.type == 2                      → Server Hello
tls.alert_message                            → TLS Alert (خطا)
```

### ۱۵.۳ Dissectorهای Lua سفارشی

Wireshark از اسکریپت‌های Lua برای دیسکشن پروتکل‌های اختصاصی پشتیبانی می‌کند. مثال‌ها:
- `huawei_custom.lua` — پروتکل اختصاصی Huawei در PS Core
- `gtp_u_latency.lua` — محاسبه تأخیر GTP-U
- `ims_registration.lua` — تحلیل رجیستر شدن IMS

**نصب:** فایل Lua را در `~/.local/lib/wireshark/plugins/` ذخیره کنید و Wireshark را ری‌استارت کنید.

### ۱۵.۴ قوانین رنگ‌بندی (Coloring Rules)

**مسیر:** `View → Coloring Rules → +`

```text
Color Rule 1: gtp || gtpv2                    → آبی تیره
Color Rule 2: diameter                        → سبز
Color Rule 3: sip                             → قرمز
Color Rule 4: s1ap                            → نارنجی
Color Rule 5: sctp                            → بنفش
Color Rule 6: tcp.analysis.retransmission     → قرمز روشن
Color Rule 7: expert.severity == 2            → قرمز
Color Rule 8: expert.severity == 3            → زرد
```

### ۱۵.۵ Time Reference برای محاسبه تأخیر

1. پکت Request را پیدا کنید
2. روی آن کلیک راست → **Set/Unset Time Reference**
3. پکت Response را پیدا کنید
4. ستون **Time Delta** نشان‌دهنده تأخیر است
5. Time Reference را با کلیک راست حذف کنید

---

## ۱۶. فیلترهای ترکیبی پیشرفته

```text
# تمام Signaling روی SGi interface
ip.addr == 10.200.1.1 && (sip || diameter || gtpv2 || gtp)

# تمام پکت‌های مشکل‌دار در کلیه پروتکل‌ها
tcp.analysis.retransmission || tcp.flags.reset == 1 || sctp.chunk.type == 4 || gtpv2.cause != 16 || diameter.result-code >= 3000 || sip.Status-Code >= 400

# تمام QoS Related
gtpv2.bearer_qos || diameter.QoS-Information || (s1ap.procedureCode >= 15 && s1ap.procedureCode <= 24)
```

---

## ۱۷. بهترین شیوه‌ها برای کپچر در شبکه‌های عملیاتی

### ۱۷.۱ محل‌های مناسب برای کپچر

| رابط | بین | پروتکل |
|---|---|---|
| S1-U | eNB ↔ SGW | GTP-U |
| S1-MME | eNB ↔ MME | S1AP |
| S5/S8 | SGW ↔ PGW | GTP-U/C |
| S6a | MME ↔ HSS/USN | Diameter |
| Gx | PGW ↔ PCRF/UPCC | Diameter |
| SGi | PGW ↔ Internet | User Traffic |
| IMS | P-CSCF ↔ S-CSCF | SIP/TLS |
| Rx | P-CSCF ↔ PCRF | Diameter |

### ۱۷.۲ قوانین کپچر

```text
规矩 ۱: حداکثر حجم کپچر
tcpdump -i eth0 -w /capture/ps_core_%Y%m%d_%H%M%S.pcap -G 300 -W 10

规矩 ۲: فیلتر در زمان کپچر
tcpdump -i eth0 -w gtpc.pcap port 2123

规矩 ۳: زمان‌بندی کپچر (Ring Buffer)
tcpdump -i eth0 -w capture.pcap -G 300 -W 12

规矩 ۴: ذخیره Metadata
echo "Date: $(date)" > capture_metadata.txt
echo "Equipment: UGW9811-01" >> capture_metadata.txt
```

### ۱۷.۳ فیلترهای Capture برای PS Core

```text
port 2123                                   # GTP-C
port 2152                                   # GTP-U
port 3868                                   # Diameter
port 5060 or port 5061                      # SIP
port 36412                                  # S1AP
port 2123 or port 2152 or port 3868 or port 5060 or port 5061 or port 36412   # تمام PS Core
host <UE_IP> and (port 2123 or port 2152)   # یک UE خاص
```

---

## ۱۸. تحلیل آماری

### ۱۸.۱ Conversations و Endpoints
- **Conversations:** `Statistics → Conversations` — شناسایی مکالمات پرترافیک
- **Endpoints:** `Statistics → Endpoints` — شناسایی IPهای فعال

### ۱۸.۲ IO Graphs و Protocol Hierarchy
- **IO Graphs:** `Statistics → IO Graphs` — نمایش الگوی ترافیک
- **Protocol Hierarchy:** `Statistics → Protocol Hierarchy` — درصد هر پروتکل

### ۱۸.۳ RTP Streams و VoIP Calls
- **RTP Streams:** `Telephony → RTP → RTP Streams` — Packet Loss, Jitter, MOS
- **VoIP Calls:** `Telephony → VoIP Calls` — MOS Score (1-5)

### ۱۸.۴ TCP Stream Graphs
- **RTT:** `Statistics → TCP Stream Graphs → Round Trip Time`
- **Throughput:** `Statistics → TCP Stream Graphs → Throughput`
- **Window Scaling:** `Statistics → TCP Stream Graphs → Window Scaling`
- **Stuffed Segments:** `Statistics → TCP Stream Graphs → Stuffed Segments`

---

## پیوست A: فیلترهای سریع (Quick Reference)

```text
# ─── GTP-C ───
gtpv2c.message_type == 32                   # Create Session Request
gtpv2c.message_type == 33                   # Create Session Response
gtpv2c.message_type == 34                   # Modify Bearer Request
gtpv2c.message_type == 35                   # Modify Bearer Response
gtpv2c.message_type == 36                   # Delete Session Request
gtpv2c.message_type == 37                   # Delete Session Response
gtpv2c.message_type == 95                   # Create Bearer Request
gtpv2c.message_type == 96                   # Create Bearer Response
gtpv2c.message_type == 99                   # Delete Bearer Request
gtpv2c.message_type == 100                  # Delete Bearer Response
gtpv2c.cause_value != 1 && gtpv2c.cause_value != 0   # خطای GTP-C
gtpv2c.imsi == "432011234567890"           # فیلتر IMSI
gtpv2c.access_point_name == "ims"           # فیلتر APN
gtpv2c.qci == 1                             # QCI = VoLTE

# ─── GTP-U ───
gtp.teid == 0x12345678                      # TEID خاص

# ─── Diameter ───
diameter.cmd.code == 318                    # AIR
diameter.cmd.code == 316                    # ULR
diameter.cmd.code == 272                    # CCR
diameter.cmd.code == 258                    # RAR
diameter.cmd.code == 280                    # DWR
diameter.cmd.code == 282                    # DPR
diameter.result_code != 2001                # خطای Diameter
diameter.imsi == "432011234567890"         # فیلتر IMSI

# ─── SIP/IMS ───
sip.Method == "INVITE"                      # SIP INVITE
sip.Method == "REGISTER"                    # SIP REGISTER
sip.Method == "BYE"                         # SIP BYE
sip.Status-Code == 200                      # 200 OK
sip.Status-Code == 403                      # 403 Forbidden
sip.Status-Code == 408                      # 408 Timeout
sip.Status-Code == 486                      # 486 Busy
sip.P-Asserted-Identity contains "98912"    # شماره خاص

# ─── NAS ───
nas_eps.emm.message_type == 0x41            # Attach Request
nas_eps.emm.message_type == 0x42            # Attach Accept
nas_eps.emm.message_type == 0x44            # Detach Request
nas_eps.emm.imsi == "432011234567890"      # IMSI

# ─── S1AP ───
s1ap.handoverRequest                        # Handover Request
s1ap.handoverRequired                       # Handover Required
s1ap.handoverNotify                         # Handover Notify

# ─── RTP/VoLTE ───
rtp                                          # تمام RTP
srtp                                         # SRTP (VoLTE)
rfc2833                                     # DTMF
amr || amr_wb                              # Codec AMR

# ─── خطاها ───
frame.flags.malformed                       # بسته معیوب
tcp.analysis.retransmission                 # TCP Retransmission
tcp.analysis.duplicate_ack                  # TCP Dup ACK
tcp.analysis.out_of_order                   # TCP Out of Order
tcp.analysis.zero_window                    # TCP Zero Window
```

---

## پیوست B: دستورات tshark پرکاربرد

```bash
# نمایش تمام IMSIها
tshark -r capture.pcap -Y "gtpv2c.imsi" -T fields -e gtpv2c.imsi | sort -u > imsi_list.txt

# شمارش تعداد GTP-C Request/Response
tshark -r capture.pcap -Y "gtpv2c" -T fields -e gtpv2c.message_type | sort | uniq -c

# شمارش خطای Diameter
tshark -r capture.pcap -Y "diameter.result_code != 2001" -T fields -e diameter.result_code | sort | uniq -c

# خروجی CSV از GTP-C
tshark -r capture.pcap -Y "gtpv2c" -T fields \
  -e frame.number \
  -e frame.time \
  -e ip.src \
  -e ip.dst \
  -e gtpv2c.message_type \
  -e gtpv2c.imsi \
  -e gtpv2c.cause_value \
  > gtpc_analysis.csv

# آمار conversations
tshark -r capture.pcap -q -z conv,ip > ip_conversations.txt

# آمار Protocol Hierarchy
tshark -r capture.pcap -q -z io,phs > protocol_hierarchy.txt

# آمار RTP
tshark -r capture.pcap -q -z rtp,streams > rtp_stats.txt

# آمار Expert Info
tshark -r capture.pcap -q -z expert > expert_info.txt

# شمارش تعداد IMSI منحصربفرد
tshark -r capture.pcap -Y "gtpv2c.imsi" -T fields -e gtpv2c.imsi | sort -u | wc -l

# تحلیل تاخیر GTP-C
tshark -r capture.pcap -Y "gtpv2c.message_type == 32 || gtpv2c.message_type == 33" \
  -T fields -e frame.number -e frame.time -e gtpv2c.message_type -e gtpv2c.imsi

# شناسایی پکت‌های معیوب
tshark -r capture.pcap -Y "frame.flags.malformed" -T fields -e frame.number -e frame.time

# آمار TCP Retransmission
tshark -r capture.pcap -Y "tcp.analysis.retransmission" -T fields -e frame.number | wc -l
```

---

## پیوست C: چک‌لیست عیب‌یابی

### Attach Failure

```text
□ آیا Attach Request وجود دارد؟
  فیلتر: nas_eps.emm.message_type == 0x41

□ آیا Authentication Request وجود دارد؟
  فیلتر: nas_eps.emm.message_type == 0x12

□ آیا Security Mode Command وجود دارد؟
  فیلتر: nas_eps.emm.message_type == 0x5e

□ آیا Attach Accept وجود دارد؟
  فیلتر: nas_eps.emm.message_type == 0x42

□ آیا Diameter ULR ارسال شده؟
  فیلتر: diameter.cmd.code == 316

□ آیا Diameter ULA با Success برگشته؟
  فیلتر: diameter.cmd.code == 316 && diameter.result_code == 2001

□ آیا Create Session Request وجود دارد؟
  فیلتر: gtpv2c.message_type == 32

□ آیا Create Session Response با Success برگشته؟
  فیلتر: gtpv2c.message_type == 33 && gtpv2c.cause_value == 1
```

### VoLTE Call Failure

```text
□ آیا IMS Registration موفق بوده؟
  فیلتر: sip.Method == "REGISTER" && sip.Status-Code == 200

□ آیا SIP INVITE ارسال شده؟
  فیلتر: sip.Method == "INVITE"

□ آیا 100 Trying وجود دارد؟
  فیلتر: sip.Status-Code == 100

□ آیا 183 Session Progress وجود دارد؟
  فیلتر: sip.Status-Code == 183

□ آیا Dedicated Bearer (QCI=1) فعال شده؟
  فیلتر: gtpv2c.message_type == 95 && gtpv2c.qci == 1

□ آیا 200 OK وجود دارد؟
  فیلتر: sip.Status-Code == 200

□ آیا RTP برقرار شده؟
  فیلتر: rtp

□ آیا MOS مناسب است؟
  Telephony → VoIP Calls → Analyze
```

### Handover Failure

```text
□ آیا Measurement Report ارسال شده؟
  فیلتر: lte-rrc.measurementReport

□ آیا Handover Required ارسال شده؟
  فیلتر: s1ap.messageType == 0

□ آیا Handover Request به eNB مقصد رسیده؟
  فیلتر: s1ap.handoverRequest

□ آیا Handover Request Acknowledge برگشته؟
  فیلتر: s1ap.messageType == 1

□ آیا Handover Command ارسال شده؟
  فیلتر: s1ap.messageType == 2

□ آیا Handover Notify دریافت شده؟
  فیلتر: s1ap.messageType == 3

□ آیا Modify Bearer انجام شده؟
  فیلتر: gtpv2c.message_type == 34
```

---

## پیوست D: دستورات خاص Huawei

```text
# در UGW
display gtp session bearer <teid>
display gtp statistics
display service-map all
display ip pool usage
display gtp session all
display session-statistic
reset gtp session teid <value>

# در UPCC/PCRF
display deep-inspection statistics
display deep-inspection rule all
display application-identification statistics
display diameter error-code-table
display gx error-statistics

# در USN/HSS
display diameter error-statistics
display hss error-log
display tls-profile all
display tls-server all

# در MME
display s1ap statistics
```

---

## پیوست E: کدک‌های QCI

| QCI | نوع ترافیک | نمونه |
|---|---|---|
| 1 | مکالمه صوتی | VoLTE Conversation |
| 2 | مکالمه ویدیویی | Video Call |
| 3 | بازی‌های آنلاین | Online Gaming |
| 4 | جریان ویدیویی لحظه‌ای | Live Video Streaming |
| 5 | سیگنالینگ IMS | IMS Signaling |
| 9 | اینترنت عمومی | Buffered Video, Internet |
| 69 | IMS Emergency | Emergency Calls |
| 70 | SMS | SMS over IMS |
| 80 | Mission Critical Push-to-Talk | MCPTT |
| 84 | Mission Critical Data | MC Data |
| 85 | Mission Critical Voice | MC Voice |

---

## پیوست F: استانداردهای مرتبط

| استاندارد | عنوان | پروتکل |
|---|---|---|
| 3GPP TS 29.272 | S6a/S6d Interface | Diameter (MME ↔ HSS) |
| 3GPP TS 29.274 | GTPv2-C | GTP Control Plane |
| 3GPP TS 29.281 | GTP-U | GTP User Plane |
| 3GPP TS 24.301 | NAS EPS | NAS Protocol |
| 3GPP TS 36.413 | S1AP | S1 Application Protocol |
| 3GPP TS 36.423 | X2AP | X2 Application Protocol |
| RFC 3261 | SIP | Session Initiation Protocol |
| RFC 3588 | Diameter | Base Protocol |

---

## میانبرهای مفید Wireshark

| میانبر | عملکرد |
|---|---|
| `Ctrl+Shift+F` | جستجوی پکت |
| `Ctrl+Shift+E` | Expert Information |
| `Ctrl+Shift+G` | IO Graphs |
| `Ctrl+Shift+X` | Column Preferences |
| `Ctrl+Shift+D` | Decode As |
| `Ctrl+Alt+Shift+T` | Follow TCP Stream |
| `Ctrl+Alt+Shift+U` | Follow UDP Stream |
| `Ctrl+.` | رفتن به پکت بعدی |
| `Ctrl+,` | رفتن به پکت قبلی |
| `Alt+←` | بازگشت به پکت قبلی |
| `Alt+→` | رفتن به پکت بعدی |
