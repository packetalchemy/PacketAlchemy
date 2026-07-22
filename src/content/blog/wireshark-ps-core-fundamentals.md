---
title: "Wireshark for PS Core Engineers: Installation, Setup & Fundamentals"
description: "A practical guide covering Wireshark basics, PS Core architecture, installation on Linux, Windows, macOS, UI overview, capture methods, display and capture filters."
pubDate: "2026-07-09"
tags: ["Wireshark", "PS Core", "Tutorial", "Packet Capture", "Telecom"]
---

## وایرشارک برای مهندسین PS Core: نصب، راه‌اندازی و مبانی

### ۱. مقدمه و مبانی وایرشارک

Wireshark (وایرشارک) قدرتمندترین ابزار متن‌باز تحلیل پروتکل‌های شبکه است. در شبکه‌های هسته بسته (PS Core) نقش حیاتی دارد:

- **تحلیل ترافیک GTP** – بررسی مسیر تونل‌های GTPv1/2 بین SGW، PGW، MME و SGSN
- **تحلیل Diameter** – درخواست‌ها/پاسخ‌های AAA برای شارژینگ و احراز هویت
- **تحلیل SIP** – سیگنالینگ IMS برای تماس‌های صوتی/ویدئویی
- **تحلیل SCTP/S1AP** – ارتباطات کنترل بین eNodeB و MME
- **عیب‌یابی** – تشخیص مشکلات اتصال، تاخیر و بسته‌های ناقص

### ۲. معماری شبکه PS Core

#### ۲.۱ ۲G/3G (GPRS/UMTS)
```
UE → RNC/BSC → SGSN → GGSN → Internet/IMSI‑GW
                 ↕
                HLR/HSS (Diameter/MAP)
```
#### ۲.۲ ۴G LTE (EPC)
```
UE → eNodeB → MME ──→ SGW → PGW → Internet
          ↕ S1‑MME ↕ S11 ↕ S5/S8
          HSS (SCTP/S1AP)  PCRF/UPCC (Diameter)
```
#### ۲.۳ ۵G (5GC)
```
UE → gNodeB → AMF → SMF → UPF → Data Network
                 ↕ ↕ ↕
                UDM  PCF  AF (Diameter)
```
**نقاط کپچر مهم** شامل رابط‌های S1‑MME, S11, S5/S8, S6a, Gx و ... هستند (گزینه‌های جدول در منبع).

### ۳. نصب و راه‌اندازی وایرشارک

#### ۳.۱ لینوکس (Debian/Ubuntu)
```bash
# به‌روزرسانی مخازن
sudo apt update

# نصب وایرشارک و ابزارهای خط فرمان
sudo apt install wireshark tshark dumpcap

# تنظیم دسترسی برای کاربر عادی
sudo dpkg-reconfigure wireshark-common   # انتخاب "Yes"
sudo usermod -aG wireshark $USER
newgrp wireshark   # یا خروج و ورود مجدد
```
#### ۳.۲ CentOS / RHEL
```bash
# نصب EPEL
sudo yum install epel-release

# نصب وایرشارک (GUI + CLI)
sudo yum install wireshark wireshark-gnome   # یا dnf در 8+

# تنظیم قابلیت‌های raw capture برای dumpcap
sudo setcap cap_net_raw,cap_net_admin=e /usr/bin/dumpcap
```
#### ۳.۳ ویندوز
1. دانلود از https://www.wireshark.org/download.html
2. نصب (فعال‌سازی **USBPcap**, **TShark**, **Editcap**, **Mergecap**)
3. نصب **Npcap** در حالت WinPcap‑compatible و فعال‌سازی loopback traffic.

#### ۳.۴ macOS
```bash
# Homebrew
brew install --cask wireshark

# یا MacPorts
sudo port install wireshark

# برای دسترسی به capture، اجرا با sudo یا تنظیم setcap (در macOS معمولاً sudo کافی است)
sudo /Applications/Wireshark.app/Contents/MacOS/Wireshark
```
#### ۳.۵ تنظیمات پس از نصب
- غیرفعال‌سازی **Name Resolution** (MAC/Network/Transport) برای سرعت در محیط مخابراتی.
- تنظیم **Relative sequence numbers** در TCP برای راحتی تحلیل.
- تعریف **Coloring Rules**: GTP – سبز تیره، Diameter – آبی تیره، SIP – بنفش، SCTP – نارنجی، S1AP – قرمز روشن.

### ۴. نمای کلی رابط کاربری وایرشارک

#### ۴.۱ نوار ابزار اصلی
- شروع/توقف کپچر
- باز/ذخیره فایل PCAP
- جستجو و ناوبری بین بسته‌ها

#### ۴.۲ نوار فیلتر نمایش (Display Filter Toolbar)
```text
Filter: [gtpv2 && ip.addr == 10.1.1.1] [Apply]
```
- فیلتر معتبر → سبز، نامعتبر → قرمز.

#### ۴.۳ پنجره لیست بسته‌ها
| ستون | توضیح |
|------|-------|
| No. | شماره ردیف |
| Time | زمان نسبی |
| Source / Destination | آدرس‌های IP |
| Protocol | نام پروتکل شناسایی‌شده |
| Length | طول بسته (بایت) |
| Info | خلاصه اطلاعات |

#### ۴.۴ پنجره جزئیات بسته
نمایش لایه‑به‑لایه (Frame → Ethernet → IP → UDP → GTP‑C …).

#### ۴.۵ منوهای مهم
- **Analyze → Decode As** – برای تعیین پروتکل پورت دلخواه.
- **Analyze → Expert Information** – برای یافتن خطاها و هشدارها.
- **Statistics → Protocol Hierarchy / Conversations / I/O Graphs** – برای تحلیل آماری.

### ۵. روش‌های کپچر بسته‌ها

#### ۵.۱ کپچر زنده (Live Capture)
1. **Capture → Options** → انتخاب اینترفیس، فعال‌سازی **Promiscuous Mode** و تنظیم فیلتر اولیه (Capture filter).
2. استفاده از **Ring buffer** برای جلوگیری از پر شدن دیسک.
3. گزینه **Stop conditions** (زمان، حجم، تعداد بسته).

#### ۵.۲ کپچر از خط فرمان
```bash
# Capture GTP‑v2‑C (S11/S5) روی eth0
dumpcap -i eth0 -f "udp port 2123" -w /tmp/gtpv2.pcap

# Capture GTP‑U (داده کاربر)
dumpcap -i eth0 -f "udp port 2152" -w /tmp/gtpu.pcap

# Capture Diameter (SCTP)
dumpcap -i eth0 -f "sctp port 3868" -w /tmp/diameter.pcap
```
#### ۵.۳ ابزارهای جایگزین
- **tcpdump** – همانند بالا، با گزینه `-C` و `-W` برای چرخش فایل.
- **ngrep** – جستجوی متن خاص داخل ترافیک (مثلاً IMSI یا APN).
- **Remote capture** – استریم از سرور راه‌دور با SSH یا rpcapd.
```bash
ssh root@10.10.1.1 "tcpdump -i eth0 -s0 -w - udp port 2123" | wireshark -k -i -
```

### ۶. فیلترهای نمایشی (Display Filters)
#### ۶.۱ پایه
- مقایسه: `==`, `!=`, `>`, `<`, `>=`, `<=`
- منطقی: `&&` (AND), `||` (OR), `!` (NOT)
- عملیات خاص: `contains`, `matches`, `in`
#### ۶.۲ مثال‌های پرکاربرد برای PS Core
```text
# تمام بسته‌های GTP‑v2‑C
gtpv2

# فقط Create Session Request/Response
gtpv2.msg_type == 32 || gtpv2.msg_type == 33

# فیلتر بر اساس IMSI
gtpv2.imsi == "9891234567890"

# فیلتر Diameter بر روی Port 3868
diameter && tcp.dstport == 3868

# فیلتر SIP INVITE با SDP
sip.Method == "INVITE" && sip contains "v=0"
```
#### ۶.۳ ترکیبی پیشرفته
```text
# جریان کامل یک کاربر IMSI خاص (GTP یا SIP یا Diameter)
gtpv2.imsi == "9891234567890" || sip contains "9891234567890" || diameter.imsi == "9891234567890"
```

### ۷. فیلترهای کپچر (Capture Filters)
- **BPF syntax** (tcpdump/wireshark).
- فیلترها پیش از ذخیره‌سازی بسته حذف می‌شوند؛ بنابراین باعث کاهش حجم فایل می‌شوند.
#### ۷.۱ نمونه‌ها
```text
# تمام GTP (v1/v2)
udp port 2123 or udp port 2152

# فقط Diameter (SCTP)
sctp port 3868

# فقط SIP (TCP/UDP)
tcp port 5060 or tcp port 5061 or udp port 5060 or udp port 5061

# ترکیبی PS Core
udp port 2123 or udp port 2152 or sctp port 3868 or sctp port 36412
```
#### ۷.۲ نکات مهم
- استفاده از **Mirror Port** روی سوئیچ برای دریافت تمام ترافیک.
- فعال‌سازی **Promiscuous Mode** برای دریافت بسته‌های غیرمقصد.
- تنظیم **Ring buffer** (`-b filesize:102400 -b files:10`) جهت جلوگیری از پر شدن دیسک.

---

*این مطلب بر پایه‌ی مستندات داخلی `psi-core-wireshark-full.md` تهیه شده و برای مهندسین PS Core اختصاصی گردیده.*