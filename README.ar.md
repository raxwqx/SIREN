<div dir="rtl" align="right">

```text
███████╗██╗██████╗ ███████╗███╗   ██╗
██╔════╝██║██╔══██╗██╔════╝████╗  ██║
███████╗██║██████╔╝█████╗  ██╔██╗ ██║
╚════██║██║██╔══██╗██╔══╝  ██║╚██╗██║
███████║██║██║  ██║███████╗██║ ╚████║
╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
```

###  قنوات DNS الخفية — مقيسة.

**يقرأ SIREN حركة DNS، ويستخرج سمات سلوكية، ويقيّم كل حزمة (عميل، نطاق، نافذة
زمنية) بثمانية كواشف قابلة للتفسير — ثم يثبت مدى جودة عمله.**

[![CI](https://github.com/raxwqx/SIREN/actions/workflows/ci.yml/badge.svg)](https://github.com/raxwqx/SIREN/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-1.85%2B-dea584?logo=rust&logoColor=white)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-2b2f3a)
![License](https://img.shields.io/badge/license-MIT-3da639)
![Precision](https://img.shields.io/badge/precision-0.99-ff4866)
![Recall](https://img.shields.io/badge/recall-0.93-58a6ff)

🇬🇧 [English](README.md) · 🇹🇷 [Türkçe](README.tr.md) · 🇷🇺 [Русский](README.ru.md) · 🇸🇦 **العربية**

</div>

---

<div dir="rtl" align="right">

## 🎯 لماذا وُجد SIREN

DNS هو البروتوكول الوحيد الذي تسمح به معظم الشبكات بالخروج إلى الإنترنت، ولهذا
بالضبط يُستخدم لتهريب البيانات. معظم أدوات «كشف تسريب DNS» العامة ليست سوى فحص
إنتروبيا واحد داخل سكربت Python: بلا اختبارات، وبلا بيانات مرجعية، وبلا أي فكرة
عن مدى نجاحها.

بُني SIREN بالعكس:

- 🔍 **قابل للتفسير بالتصميم.** كل تنبيه يعرض الإشارات التي انطلقت، والقيمة
  المقيسة، والعتبة التي تجاوزتها.
- 🧩 **تأكيد متبادل، لا حدس.** إشارة واحدة قوية لا تكفي لحكم مرتفع؛ الأوزان
  مصممة بحيث يحتاج الحكم إلى عدة إشارات مستقلة.
- 📊 **قياس، لا ادعاء.** مولّد حتمي ينتج حركة موسومة، و`siren eval` يقدّم
  الدقة والاستدعاء وF1 ومعدل الإيجابيات الكاذبة عبر العتبات. كل رقم في هذا
  الملف يمكن إعادة إنتاجه بأمرين.
- 🪶 **بلا اعتماديات أصلية.** قارئ PCAP ومحلل DNS مكتوبان بـ Rust الخالص — بلا
  libpcap، بلا Npcap، بلا صلاحيات root. يعمل نفسه على Linux وWindows وmacOS.

> ⚠️ SIREN أداة كشف وتحليل. لا يقف داخل المسار ولا يحجب الحركة.

---

##  عرض توضيحي

```console
$ siren analyze capture.pcap --window 300 --explain

  ███████╗██╗██████╗ ███████╗███╗   ██╗
  ██╔════╝██║██╔══██╗██╔════╝████╗  ██║
  ███████╗██║██████╔╝█████╗  ██╔██╗ ██║
  ╚════██║██║██╔══██╗██╔══╝  ██║╚██╗██║
  ███████║██║██║  ██║███████╗██║ ╚████║
  ╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
  DNS covert channels, measured.  ·  github.com/raxwqx/SIREN

╭─ capture ──────────────────────────────────────────────────╮
│ input             capture.pcap                             │
│ queries           17,719                                   │
│ domains           96                                       │
│ buckets           657                                      │
│ window            300s                                     │
│ suspects          184                                      │
│ critical / high   0 / 15                                   │
╰────────────────────────────────────────────────────────────╯

  findings
  RISK SEVERITY CLIENT           DOMAIN                     QPS    ENT   SIGNALS
    47 high     10.0.0.211       tunnel18.net              0.17   3.74   label-length,nxdomain,…
    45 high     10.0.0.198       tunnel6.net               0.27   3.73   label-length,qtype,…

  evidence

  10.0.0.211 · tunnel18.net · risk 47 (high)
  2023-11-14 22:10:00 → 22:15:00   50 queries   0.17 q/s   50 distinct labels
    ▪ label-length   0.90  longest label 56 chars (normal <= 20)
    ▪ nxdomain       1.00  96% NXDOMAIN responses (normal < 25%)
    ▪ qtype          0.66  76% TXT queries (normal < 30%)
    ▪ encoding       1.00  100% of labels look encoded (hex/base32/base64)
    ▪ fanout         0.15  50 distinct labels under one domain
    MITRE T1071.004, T1568.002, T1001
```

---

## 📦 التثبيت

###  المتطلبات

- 🦀 Rust **1.85+** (يُنصح بـ `rustup`)
- 🪶 بلا libpcap، بلا Npcap، بلا root

### 🐧 Linux / macOS

```bash
git clone https://github.com/raxwqx/SIREN.git
cd SIREN
cargo build --release
./target/release/siren --help
```

التثبيت في النظام:

```bash
sudo install -m 0755 target/release/siren /usr/local/bin/siren
```

###  Windows (PowerShell)

```powershell
git clone https://github.com/raxwqx/SIREN.git
cd SIREN
cargo build --release
.\target\release\siren.exe --help
```

أضفه إلى `PATH` للجلسة الحالية:

```powershell
$env:Path += ";$PWD\target\release"
siren --version
```

> يعرض Windows Terminal (أو أي طرفية تدعم VT) المخرجات الملوّنة. عند إعادة
> توجيه stdout يتحول SIREN تلقائيًا إلى نص عادي.

---

## ⚡ البدء السريع

```bash
# 1. تحليل التقاط
siren analyze capture.pcap

# 2. نافذة زمنية أضيق أو أوسع
siren analyze capture.pcap --window 300

# 3. عرض الأدلة خلف كل نتيجة
siren analyze capture.pcap --window 300 --explain

# 4. مخرجات قابلة للقراءة آليًا
siren analyze capture.pcap --format json  > findings.json
siren analyze capture.pcap --format sarif > siren.sarif

# 5. إفشال مهمة CI عند وجود حالة خطيرة
siren analyze capture.pcap --fail-on high

# 6. إعادة إنتاج التقييم في هذا الملف
siren gen --out data/eval.jsonl --seed 42
siren eval data/eval.jsonl --window 300
```

---

## 🧠 كيف يعمل

```text
   PCAP / PCAPNG*            سجلات JSONL
        │                       │
        └───────────┬───────────┘
                    ▼
            ┌───────────────┐
            │  محلل DNS     │  Ethernet · VLAN · IPv4 · IPv6 · UDP/53
            └───────┬───────┘
                    ▼
            ┌───────────────┐
            │  التجميع      │  (عميل، نطاق، نافذة)
            └───────┬───────┘
                    ▼
            ┌───────────────┐
            │   السمات      │  الإنتروبيا · طول التسمية · qps · NXDOMAIN
            └───────┬───────┘  نسبة TXT · الترميز · CV التوقيت · fanout
                    ▼
            ┌───────────────┐
            │  8 كواشف      │  كل واحد يعيد 0..1 + دليل بشري
            └───────┬───────┘
                    ▼
            ┌───────────────┐
            │   التقييم     │  risk = 100 × Σ(weight × score)
            └───────┬───────┘
                    ▼
        جدول  ·  JSON  ·  SARIF
```

\* يُكتشف PCAPNG ويُبلَّغ عنه مع تلميح تحويل من سطر واحد
(`editcap -F pcap`). الدعم الأصلي في خارطة الطريق.

### 🚦 إشارات الكشف

| 🔍 الإشارة | ⚖️ الوزن | 🚦 تُطلق عندما | 🎯 MITRE ATT&CK |
|---|---:|---|---|
| `entropy` | 0.20 | متوسط إنتروبيا التسمية **> 4.3 بت/حرف** | T1001 |
| `label-length` | 0.16 | أي تسمية **> 20 حرفًا** | T1071.004 |
| `query-rate` | 0.18 | **> 0.3 استعلام/ث** لنطاق واحد | T1048 |
| `nxdomain` | 0.11 | **> 25%** من الردود NXDOMAIN | T1568.002 |
| `qtype` | 0.09 | **> 30%** من الاستعلامات TXT | T1071.004 |
| `encoding` | 0.15 | **> 20%** من التسميات تبدو hex/base32/base64 | T1001 |
| `beaconing` | 0.07 | **CV للفواصل < 0.35** مع ≥ 6 استعلامات | T1071.004 |
| `fanout` | 0.04 | **≥ 20** تسمية مختلفة تحت نطاق واحد | T1568.002 |

`risk = 100 × Σ(الوزن × درجة الإشارة)` — إشارة واحدة لا تبلغ حكمًا مرتفعًا
بالتصميم. اطبع الجدول من الملف التنفيذي عبر `siren signals`.

---

## 📊 التقييم

يأتي SIREN بمولّد حركة حتمي: تصفح عادي، وسلبيات صعبة من CDN (تسميات hex طويلة)،
وقياسات عالية المعدل، وأنفاق مرمّزة (hex، base32، base64)، وأنفاق NXDOMAIN،
وأنفاق بطيئة عمدًا.

```bash
siren gen --out data/eval.jsonl --seed 42
siren eval data/eval.jsonl --window 60 --json
siren eval data/eval.jsonl --window 300 --json
```

مجموعة البيانات: **17,719 حدثًا**، **96 نطاقًا**، البذرة `42`، والعتبة تُختار
بأفضل F1.

| ⏱️ النافذة | 🗂️ الحزم | ✅ الموجبة | 🎯 الدقة | 🔎 الاستدعاء | 🏅 F1 | ⚠️ FPR |
|---|---:|---:|---:|---:|---:|---:|
| 60 ث | 1,717 | 157 | **1.000** | 0.790 | 0.883 | 0.000 |
| 300 ث | 657 | 98 | **0.989** | **0.929** | **0.958** | 0.002 |

💡 **اقرأ بصدق:** عند 60 ث يكون الكاشف دقيقًا لكنه أعمى عن الأنفاق البطيئة —
استعلامان في الدقيقة لا يتركان دليلًا كافيًا داخل حزمة من دقيقة. وسّع النافذة
يرتفع الاستدعاء، مقابل تأخر في الكشف وإيجابية كاذبة واحدة. هذا المقايضة هي سبب
جعل النافذة معاملًا بدل تثبيتها.

أعد إنتاجه بنفسك؛ المولّد مبذور والأرقام ثابتة.

### ⚙️ الأداء

| الحمل | الأحداث | الوقت | السرعة |
|---|---:|---:|---:|
| JSONL, release | 17,719 | 61 ms | ~290 ألف حدث/ث |
| JSONL, 5× | 88,595 | 296 ms | ~299 ألف حدث/ث |

نواة واحدة، بلا SIMD، بلا unsafe.

---

## 🛠️ مرجع سطر الأوامر

```text
siren analyze <INPUT> [OPTIONS]
siren gen     --out <PATH> [--seed N]
siren eval    <INPUT> [OPTIONS]
siren signals
```

### `siren analyze`

| الخيار | الافتراضي | الوصف |
|---|---|---|
| `--window <SECONDS>` | `60` | حجم الحزمة الزمنية |
| `--min-queries <N>` | `3` | تجاهل الحزم الأقل استعلامات |
| `--min-risk <0-100>` | `12` | أقل خطر يُبلَّغ عنه |
| `--format <table\|json\|sarif>` | `table` | صيغة الخرج |
| `--allowlist <FILE>` | — | نطاق مسموح لكل سطر |
| `--explain` | معطّل | طباعة الأدلة على مستوى الإشارة |
| `--fail-on <low\|medium\|high\|critical>` | معطّل | الخروج بالرمز `2` |
| `--no-banner` | معطّل | بلا شعار |

### `siren eval`

| الخيار | الافتراضي | الوصف |
|---|---|---|
| `--window <SECONDS>` | `60` | حجم الحزمة |
| `--min-queries <N>` | `3` | تجاهل الحزم المتناثرة |
| `--json` | معطّل | تقرير آلي |

---

##  صيغ الإدخال

### PCAP

ملفات libpcap الكلاسيكية (`0xa1b2c3d4`، ميكرو أو نانو ثانية).
أنواع الوصل المدعومة: Ethernet (مع 802.1Q/QinQ)، raw IP، Linux SLL/SLL2.
في v0.1: فقط 53/UDP.

### JSONL

كائن JSON واحد في كل سطر:

```json
{"ts":1700000000.0,"client":"10.0.0.5","qname":"a.example.com","qtype":1,"rcode":0,"size":55}
{"ts":1700000001.2,"client":"10.0.0.5","qname":"k3j4h5g6.tunnel.net","qtype":16,"rcode":3,"size":90}
```

أضف `"label": 0|1` لتشغيل `siren eval` على بياناتك المرجعية.

---

## 📤 صيغ الخرج

| الصيغة | الاستخدام |
|---|---|
| `table` | فرز بشري في الطرفية (ألوان عند TTY) |
| `json` | خطوط المعالجة والدفاتر ولوحات المعلومات |
| `sarif` | GitHub code scanning / تعليقات CI |

---

## 🧩 قرارات التصميم

1. **Windows مواطن من الدرجة الأولى.** محلل Rust خالص، بلا Npcap وبلا صلاحيات
   مدير. الملف التنفيذي نفسه على Windows وLinux وmacOS.
2. **التفسير بدل الصندوق الأسود.** لا تعلّم آلة في المسار الساخن. كل درجة
   تُعاد حسابتها يدويًا من السمات المطبوعة.
3. **التأكيد المتبادل.** صفحة تحمّل موارد من CDN بتسميات hex تبدو مريبة لفحص
   إنتروبيا ساذج. SIREN يشترط توافق المعدل والنوع والتوقيت قبل التصعيد.
4. **بحث قابل لإعادة الإنتاج.** مولّد مبذور، عتبات كثوابت، واختبار يؤكد أن
   مجموع الأوزان = 1.0.
5. **ملل حيث يلزم.** بلا unsafe، بلا حالة عامة، بلا إدخال/إخراج خفي.

---

## 🗺️ خارطة الطريق

- [ ] PCAP متدفق (ذاكرة ثابتة للالتقاطات الكبيرة)
- [ ] قارئ PCAPNG أصلي
- [ ] إعادة تجميع TCP/53
- [ ] كشف DoH / DoT
- [ ] قائمة Public Suffix الكاملة
- [ ] التقاط حي خلف ميزة `live` اختيارية
- [ ] خطوط أساس سلوكية لكل عميل (EWMA) بدل عتبات ثابتة
- [ ] ربط DNS وHTTPS عبر JA4/TLS
- [ ] تصدير قواعد بنمط Sigma
- [ ] ملفات تنفيذية جاهزة عبر GitHub Releases

---

## ❓ الأسئلة الشائعة

**هل هذا IDS؟**
لا. محلل ومحرك كشف دون اتصال. يقرأ الحركة ولا يقف داخل المسار ولا يحجب.

**هل أحتاج root أو Npcap؟**
لا. وجّهه إلى ملف. الالتقاط الحي (خارطة الطريق) يحتاج صلاحيات التقاط.

**هل يكشف DNS over HTTPS؟**
ليس بعد. تحليل DoH عمل v0.2.

**لماذا Rust وليس Python؟**
ملف تنفيذي واحد ثابت، بلا مفسّر، بلا جحيم اعتماديات على Windows، ومئات الآلاف
من الأحداث في الثانية.

**هل أستطيع استخدام وسومي؟**
نعم: `"label": 0|1` في JSONL ثم `siren eval`.

**هل التقييم حقيقي؟**
صناعي لكنه موسوم وحتمي. يقيس اتساق الكاشف الداخلي لا انتشاره في الواقع. الخطوة
التالية هي التقاطاتك الموسومة؛ وأمر `eval` موجود لهذا بالضبط.

---

## ⚖️ الجانب القانوني

استخدم SIREN فقط على حركة تملكها أو لديك إذن صريح بتحليلها. التقاط حركة الآخرين
بلا إذن غير قانوني في معظم الولايات القضائية. المؤلف غير مسؤول عن إساءة
الاستخدام.

---

## 🤝 المساهمة

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all
```

أي PR يضيف كاشفًا يجب أن يتضمن اختبار وحدة وسطرًا في جدول الإشارات. وأي PR
يغيّر التقييم يجب أن يتضمن أرقام `siren eval` قبل/بعد.

---

## 📄 الترخيص

MIT © 2026 StyxHQ — انظر [LICENSE](LICENSE).

</div>
