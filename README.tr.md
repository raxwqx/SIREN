<div align="center">

```text
███████╗██╗██████╗ ███████╗███╗   ██╗
██╔════╝██║██╔══██╗██╔════╝████╗  ██║
███████╗██║██████╔╝█████╗  ██╔██╗ ██║
╚════██║██║██╔══██╗██╔══╝  ██║╚██╗██║
███████║██║██║  ██║███████╗██║ ╚████║
╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
```

###  DNS gizli kanalları, ölçülerek.

**SIREN DNS trafiğini okur, davranışsal özellikler çıkarır ve her
(istemci, alan adı, zaman penceresi) kutusunu sekiz açıklanabilir dedektörle
puanlar — sonra bunun ne kadar iyi çalıştığını kanıtlar.**

[![CI](https://github.com/raxwqx/SIREN/actions/workflows/ci.yml/badge.svg)](https://github.com/raxwqx/SIREN/actions/workflows/ci.yml)
![Version](https://img.shields.io/badge/version-0.2.0-ff4866)
![Rust](https://img.shields.io/badge/rust-1.85%2B-dea584?logo=rust&logoColor=white)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-2b2f3a)
![License](https://img.shields.io/badge/license-MIT-3da639)
![Precision](https://img.shields.io/badge/precision-0.99-ff4866)
![Recall](https://img.shields.io/badge/recall-0.93-58a6ff)

🇬🇧 [English](README.md) · 🇹🇷 **Türkçe** · 🇷🇺 [Русский](README.ru.md) · 🇸🇦 [العربية](README.ar.md)

</div>

---

## 🎯 SIREN neden var?

DNS, neredeyse her ağın dışarı çıkmasına izin verdiği tek protokol — bu yüzden
veri kaçırmak için tam da onu kullanıyorlar. Halka açık "DNS exfiltration
detector" araçlarının çoğu tek bir entropi kontrolünden ibaret bir Python
script'i: test yok, ground truth yok, çalışıp çalışmadığına dair fikir yok.

SIREN bunun tersini yapar:

- 🔍 **Yapısı gereği açıklanabilir.** Her alarm, hangi sinyallerin tetiklendiğini,
  ölçülen değeri ve aşılan eşiği gösterir.
- 🧩 **Sezgi değil, korelasyon.** Tek başına güçlü bir sinyal yüksek bir hüküm
  üretemez; ağırlıklar bir hükmün birkaç bağımsız sinyal gerektirmesi için
  tasarlandı.
- 📊 **İddia değil, ölçüm.** Deterministik üretici etiketli trafik oluşturur ve
  `siren eval` eşikler arasında precision, recall, F1 ve FPR raporlar. Bu
  README'deki her sayı iki komutla tekrar üretilebilir.
- 🪶 **Yerel kütüphane bağımlılığı yok.** PCAP okuyucu ve DNS ayrıştırıcı saf Rust — libpcap
  yok, Npcap yok, root yok. Linux, Windows ve macOS'ta aynı çalışır.

> ⚠️ SIREN bir tespit ve analiz aracıdır. Hattın üstünde durmaz, trafiği engellemez.

---

## 🆕 0.2.0'da yenilikler

- 🧾 **`siren summary`** — puanlamadan önce yakalamaya göz at: istemciler, alan
  adları, qname'ler, sorgu tipleri, yanıt kodları, zaman aralığı ve en çok
  konuşanlar. Otomasyon için `--format json`.
- 🛡️ **Ayrıştırıcı sağlamlaştırması** — eski VLAN etiketleri
  (`0x9100`/`0x9200`), sıfır IPv4 toplam uzunluğu, bozuk UDP uzunlukları,
  desteklenmeyen link tipleri ve yeniden kullanılan DNS işlem kimlikleri artık
  doğru işleniyor.
- 🎯 **Daha dürüst NXDOMAIN puanlaması** — tek bir NXDOMAIN yanıtı artık %100
  sayılmıyor; en az üç eşleşmiş yanıt gerekiyor.
- 🧪 **Yalnızca rakamlardan oluşan etiketler** (`22222222` gibi) artık
  hex/base32 yükü sayılmıyor.
- ⚙️ Geçersiz `--window` değerleri (0, negatif, NaN, sonsuz) reddediliyor ve
  belgelenen Rust gereksinimi gerçek olanla eşleşiyor: **1.85+**.

Tam liste için [`CHANGELOG.md`](CHANGELOG.md).

---

##  Demo

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

## 🧾 Yakalama özeti

Kovaları puanlamadan önce yakalamanın hızlı bir envanterini çıkar:

```bash
siren summary capture.pcap --top 5
```

```text
╭─ capture summary ──────────────────────────────────────────╮
│ input             capture.pcap                             │
│ queries           17,719                                   │
│ responses         17,719                                   │
│ clients           237                                      │
│ domains           96                                       │
│ qnames            10,047                                   │
│ first seen        2023-11-14 22:13:20                      │
│ last seen         2023-11-14 22:23:19                      │
│ duration          10.00m                                   │
╰────────────────────────────────────────────────────────────╯

  top clients
     COUNT  CLIENT
       282  10.0.0.191
       253  10.0.0.187

  top domains
     COUNT  DOMAIN
       802  fastly.net
       525  linkedin.com

  query types
     COUNT  QTYPE
      8466  A
      4237  AAAA
      3769  TXT

  response codes
     COUNT  RCODE
     14090  NOERROR
      3629  NXDOMAIN
```

`--top` istemci/alan adı listelerini kontrol eder (1–100). Sorgu tipi ve yanıt
kodu dağılımları her zaman tamdır. Otomasyon için:

```bash
siren summary capture.pcap --format json > summary.json
```

```json
{
  "queries": 17719,
  "responses": 17719,
  "clients": 237,
  "domains": 96,
  "unique_qnames": 10047,
  "first_ts": 1700000000.0,
  "last_ts": 1700000599.9376924,
  "duration_seconds": 599.9376924037933,
  "qtypes": [{"name": "A", "count": 8466}],
  "rcodes": [{"name": "NOERROR", "count": 14090}],
  "top_clients": [{"name": "10.0.0.191", "count": 282}],
  "top_domains": [{"name": "fastly.net", "count": 802}]
}
```

---

## 📦 Kurulum

###  Gereksinimler

- 🦀 Rust **1.85+** (`rustup` önerilir)
- 🪶 libpcap yok, Npcap yok, root yok

### 🐧 Linux / macOS

```bash
git clone https://github.com/raxwqx/SIREN.git
cd SIREN
cargo build --release
./target/release/siren --help
```

Sisteme kur:

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

Oturumluk `PATH`'e ekle:

```powershell
$env:Path += ";$PWD\target\release"
siren --version
```

> Windows Terminal (veya VT destekli herhangi bir terminal) renkli çıktıyı
> gösterir. Çıktı yönlendirildiğinde SIREN otomatik olarak düz metne döner.

---

## ⚡ Hızlı başlangıç

```bash
# 1. yakalamada ne olduğunu gör
siren summary capture.pcap --top 10

# 2. bir yakalamayı incele
siren analyze capture.pcap

# 3. dar veya geniş zaman penceresi
siren analyze capture.pcap --window 300

# 4. her bulgunun arkasındaki kanıtı göster
siren analyze capture.pcap --window 300 --explain

# 5. makine tarafından okunabilir çıktı
siren analyze capture.pcap --format json  > findings.json
siren analyze capture.pcap --format sarif > siren.sarif

# 6. ciddi bir şey çıkınca CI işini düşür
siren analyze capture.pcap --fail-on high

# 7. bu README'deki değerlendirmeyi birebir üret
siren gen --out data/eval.jsonl --seed 42
siren eval data/eval.jsonl --window 300
```

---

## 🧠 Nasıl çalışır?

```text
   PCAP / PCAPNG*            JSONL logları
        │                       │
        └───────────┬───────────┘
                    ▼
            ┌───────────────┐
            │  DNS okuyucu  │  Ethernet · VLAN · IPv4 · IPv6 · UDP/53
            └───────┬───────┘
                    ▼
            ┌───────────────┐
            │   kümeleme    │  (istemci, kayıtlı alan adı, pencere)
            └───────┬───────┘
                    ▼
            ┌───────────────┐
            │   özellikler  │  entropi · etiket uzunluğu · qps · NXDOMAIN
            └───────┬───────┘  TXT oranı · kodlama · zamanlama CV · fanout
                    ▼
            ┌───────────────┐
            │  8 dedektör   │  her biri 0..1 + insan okur kanıt
            └───────┬───────┘
                    ▼
            ┌───────────────┐
            │   puanlama    │  risk = 100 × Σ(ağırlık × skor)
            └───────┬───────┘
                    ▼
        tablo  ·  JSON  ·  SARIF
```

\* PCAPNG algılanır ve tek satırlık dönüştürme ipucuyla raporlanır
(`editcap -F pcap`). Yerel PCAPNG desteği yol haritasında.

Tüm bunlardan önce `siren summary` puanlama yapmadan istemcileri, alan adlarını,
sorgu tiplerini ve yanıt kodlarını raporlar.

### 🚦 Tespit sinyalleri

| 🔍 Sinyal | ⚖️ Ağırlık | 🚦 Ne zaman tetiklenir | 🎯 MITRE ATT&CK |
|---|---:|---|---|
| `entropy` | 0.20 | ortalama etiket entropisi **> 4.3 bit/karakter** | T1001 |
| `label-length` | 0.16 | herhangi bir etiket **> 20 karakter** | T1071.004 |
| `query-rate` | 0.18 | tek alan adına **> 0.3 sorgu/sn** | T1048 |
| `nxdomain` | 0.11 | yanıtların **> %25**'i NXDOMAIN, en az 3 yanıtla | T1568.002 |
| `qtype` | 0.09 | sorguların **> %30**'u TXT | T1071.004 |
| `encoding` | 0.15 | etiketlerin **> %20**'si hex/base32/base64 | T1001 |
| `beaconing` | 0.07 | varış aralığı **CV < 0.35**, ≥ 6 sorgu | T1071.004 |
| `fanout` | 0.04 | bir alan adı altında **≥ 20** farklı etiket | T1568.002 |

`risk = 100 × Σ(ağırlık × sinyal_skoru)` — tek bir sinyal tasarım gereği
yüksek bir hükme ulaşamaz. Tabloyu binary'den yazdırmak için `siren signals`.

---

## 📊 Değerlendirme

SIREN deterministik bir trafik üreticisi ile gelir: sıradan gezinme, CDN
hard-negative'leri (uzun hex etiketler), yüksek hızlı telemetri, kodlanmış
tüneller (hex, base32, base64), NXDOMAIN ağırlıklı tüneller ve bilerek yavaş
tüneller.

```bash
siren gen --out data/eval.jsonl --seed 42
siren eval data/eval.jsonl --window 60 --json
siren eval data/eval.jsonl --window 300 --json
```

Veri kümesi: **17.719 olay**, **96 alan adı**, seed `42`, eşik sweep'te en iyi
F1'e göre seçilir.

| ⏱️ Pencere | 🗂️ Kova | ✅ Pozitif | 🎯 Precision | 🔎 Recall | 🏅 F1 | ⚠️ FPR |
|---|---:|---:|---:|---:|---:|---:|
| 60 sn | 1.717 | 157 | **1.000** | 0.790 | 0.883 | 0.000 |
| 300 sn | 657 | 98 | **0.989** | **0.929** | **0.958** | 0.002 |

💡 **Dürüst oku:** 60 sn'de dedektör keskin ama yavaş tünellere kör — dakikada iki
sorgu gönderen bir yük, bir dakikalık kovada asla yeterli kanıt bırakmaz.
Pencereyi genişletince recall yükselir; karşılığında tespit gecikmesi ve bir
yanlış pozitif gelir. Pencereyi sabitlemek yerine parametre yapmanın sebebi tam
olarak bu denge.

Kendin üret; üretici seed'li ve sayılar sabit.

### ⚙️ Performans

| İş yükü | Olay | Süre | Hız |
|---|---:|---:|---:|
| JSONL, release | 17.719 | 61 ms | ~290 bin olay/sn |
| JSONL, 5× veri | 88.595 | 296 ms | ~299 bin olay/sn |

Tek çekirdek, SIMD yok, unsafe yok.

---

## 🛠️ CLI referansı

```text
siren analyze <GİRDİ> [SEÇENEKLER]
siren summary <GİRDİ> [SEÇENEKLER]
siren gen     --out <YOL> [--seed N]
siren eval    <GİRDİ> [SEÇENEKLER]
siren signals
```

### `siren analyze`

| Seçenek | Varsayılan | Açıklama |
|---|---|---|
| `--window <SANİYE>` | `60` | Özellik çıkarımı için kova boyu |
| `--min-queries <N>` | `3` | Daha az sorgulu kovaları yok say |
| `--min-risk <0-100>` | `12` | Raporlanacak en düşük risk |
| `--format <table\|json\|sarif>` | `table` | Çıktı biçimi |
| `--allowlist <DOSYA>` | — | Satır başına bir izinli alan adı |
| `--explain` | kapalı | Sinyal düzeyinde kanıt yazdır |
| `--fail-on <low\|medium\|high\|critical>` | kapalı | Eşleşince `2` ile çık |
| `--no-banner` | kapalı | Sade çıktı |

`--window` sonlu ve sıfırdan büyük olmalıdır; `--min-risk` 0–100 aralığındadır.

### `siren summary`

| Seçenek | Varsayılan | Açıklama |
|---|---|---|
| `--top <N>` | `10` | İstemci/alan adı listesi başına satır (1–100) |
| `--format <table\|json>` | `table` | Çıktı biçimi |
| `--no-banner` | kapalı | Sade çıktı |

### `siren eval`

| Seçenek | Varsayılan | Açıklama |
|---|---|---|
| `--window <SANİYE>` | `60` | Kova boyu |
| `--min-queries <N>` | `3` | Seyrek kovaları yok say |
| `--json` | kapalı | Makine okunur rapor |

---

##  Girdi biçimleri

### PCAP

Klasik libpcap dosyaları (`0xa1b2c3d4`, mikrosaniye veya nanosaniye).
Desteklenen link tipleri: Ethernet (802.1Q/QinQ ve eski `0x9100`/`0x9200`
etiketleri dahil), raw IP, Linux SLL/SLL2. Yalnızca 53/UDP. Desteklenmeyen link
tipleri sessizce boş rapor üretmek yerine açık hata verir. Bozuk UDP uzunluk
alanları reddedilir; sıfır IPv4 toplam uzunluğu (segmentation offload) yakalanan
baytlara geri düşer.

### JSONL

Satır başına bir JSON nesnesi — elinde DNS logu varsa doğrudan kullan:

```json
{"ts":1700000000.0,"client":"10.0.0.5","qname":"a.example.com","qtype":1,"rcode":0,"size":55}
{"ts":1700000001.2,"client":"10.0.0.5","qname":"k3j4h5g6.tunnel.net","qtype":16,"rcode":3,"size":90}
```

Kendi ground truth'unla `siren eval` çalıştırmak için olaylara `"label": 0|1`
ekle.

---

## 📤 Çıktı biçimleri

| Biçim | Kullanım |
|---|---|
| `table` | Terminalde insan triyajı (TTY'de renkli) |
| `json` | Pipeline, notebook, dashboard |
| `sarif` | GitHub code scanning / CI anotasyonları |

SARIF bulguları istemci, alan adı, risk, sinyal listesi ve MITRE tekniklerini
`properties` içinde taşır.

---

## 🧩 Tasarım kararları

1. **Windows birinci sınıf.** Saf Rust ayrıştırıcı, Npcap kurulumu ve yönetici
   izni gerektirmez. Aynı binary Windows, Linux ve macOS'ta çalışır.
2. **Kara kutu değil, açıklama.** Sıcak yolda ML yok. Her skor, yazdırılan
   özelliklerden elle yeniden hesaplanabilir.
3. **Korelasyon.** Hex etiketli bir CDN'den kaynak yükleyen sayfa, naif entropi
   kontrolüne şüpheli görünür. SIREN yükseltmeden önce hız/tip/zamanlama
   uyumu arar.
4. **Tekrarlanabilir araştırma.** Seed'li üretici, sabit eşikler, ağırlıkların
   toplamının 1.0 olduğunu doğrulayan testler.
5. **Önemli yerde sıkıcı.** Unsafe yok, global state yok, gizli I/O yok.

---

## 🗺️ Yol haritası

- [ ] Akışlı PCAP (çok GB'lık yakalamalar için sabit bellek)
- [ ] Yerel PCAPNG okuyucu
- [ ] TCP/53 yeniden birleştirme
- [ ] DoH / DoT tespiti ve çözümleme yolu analizi
- [ ] Tam Public Suffix List
- [ ] Opsiyonel `live` özelliğiyle canlı yakalama
- [ ] Sabit eşikler yerine istemci başına davranışsal baseline (EWMA)
- [ ] DNS ve HTTPS oturumlarını bağlamak için JA4/TLS korelasyonu
- [ ] Sigma tarzı kural dışa aktarımı
- [ ] GitHub Releases ile Linux/Windows/macOS hazır binary

---

## ❓ SSS

**Bu bir IDS mi?**
Hayır. Çevrimdışı analizör ve tespit motoru. Trafiği okur; hatta durmaz,
engellemez.

**Root veya Npcap gerekli mi?**
Hayır. Dosyayı göster. Canlı yakalama (yol haritası) yakalama yetkisi ister.

**DNS over HTTPS'i tespit ediyor mu?**
Henüz değil. DoH/DoT analizi yol haritasında; yakalamada DoH DNS olarak
görünmez.

**Neden Python değil Rust?**
Tek statik binary, yorumlayıcı yok, Windows'ta bağımlılık cehennemi yok ve
saniyede yüz binlerce olayı işleyecek kadar hızlı.

**Kendi etiketlerimi bağlayabilir miyim?**
Evet: JSONL olaylarına `"label": 0|1` ekle ve `siren eval` çalıştır.

**Değerlendirme gerçek mi?**
Sentetik ama etiketli ve deterministik. Dedektörün iç tutarlılığını ölçer,
gerçek dünya yaygınlığını değil. Kendi etiketli yakalamalarınla yapılan test
bir sonraki adım — `eval` komutu tam bunun için var.

---

## ⚖️ Yasal

SIREN'i yalnızca sahibi olduğun veya analiz için açık iznin bulunan trafikte
kullan. Başkalarının trafiğini izinsiz yakalamak çoğu ülkede suçtur. Yazar
kötüye kullanımdan sorumluluk kabul etmez.

---

## 🤝 Katkı

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all
```

Dedektör ekleyen PR'lar bir birim testi ve sinyal tablosuna giriş içermelidir.
Puanlamayı değiştiren PR'lar öncesi/sonrası `siren eval` sayılarını içermelidir.

Güvenlik bildirimleri: [`SECURITY.md`](SECURITY.md). Sürüm geçmişi:
[`CHANGELOG.md`](CHANGELOG.md).

---

## 📄 Lisans

MIT © 2026 StyxHQ — bkz. [LICENSE](LICENSE).
