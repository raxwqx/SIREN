# Security Policy / Güvenlik Politikası

## Supported versions / Desteklenen sürümler

Security fixes are applied to the latest release on the `main` branch.

Güvenlik düzeltmeleri `main` dalındaki en son sürüme uygulanır.

| Version | Supported |
|---|---|
| 0.2.x | ✅ |
| < 0.2 | ❌ |

## Reporting a vulnerability / Güvenlik açığı bildirme

Please **do not** open a public issue for a security problem. Do not attach real
packet captures, credentials, customer domain names, or other sensitive network
data.

Güvenlik sorunları için lütfen **herkese açık issue açma**. Gerçek paket
yakalamaları, kimlik bilgileri, müşteri alan adları veya diğer hassas ağ
verilerini ekleme.

Use GitHub private vulnerability reporting:

- <https://github.com/raxwqx/SIREN/security/advisories/new>

Please include:

- affected version or commit,
- a minimal reproducer (synthetic PCAP/JSONL if possible),
- steps to reproduce,
- expected and actual behavior,
- impact assessment,
- whether SIREN crashes, hangs, allocates unbounded memory, or misattributes
  DNS responses.

Lütfen şunları ekle:

- etkilenen sürüm veya commit,
- mümkünse sentetik bir PCAP/JSONL ile en küçük yeniden üretim,
- yeniden üretme adımları,
- beklenen ve gerçek davranış,
- etki değerlendirmesi,
- SIREN'in çöküp çökmediği, takılıp kalmadığı, sınırsız bellek ayırıp
  ayırmadığı veya DNS yanıtlarını yanlış eşleştirip eşleştirmediği.

## Scope / Kapsam

Relevant reports include:

- out-of-bounds reads or panics while parsing malformed PCAP/DNS input,
- unbounded allocations from crafted length fields or capture counts,
- denial-of-service conditions in the JSONL or PCAP readers,
- incorrect response correlation that changes scoring or attribution,
- unsafe handling of allowlist files or output paths.

İlgili bildirimler şunları içerir:

- bozuk PCAP/DNS girdisi ayrıştırılırken sınır dışı okuma veya panic,
- hazırlanmış uzunluk alanlarından veya yakalama sayılarından sınırsız bellek
  ayırma,
- JSONL veya PCAP okuyucularında hizmet reddi koşulları,
- puanlamayı veya atfı değiştiren yanlış yanıt eşleştirmesi,
- izin listesi dosyalarının veya çıktı yollarının güvensiz işlenmesi.

## Authorized use / Yetkili kullanım

SIREN is an offline analysis tool. It reads captures and logs that you provide;
it does not capture live traffic, inject packets, or block traffic. Only analyze
traffic that you own or are explicitly authorized to inspect. Capturing or
inspecting third-party traffic without permission may be illegal.

SIREN çevrimdışı bir analiz aracıdır. Yalnızca sağladığınız yakalamaları ve
günlükleri okur; canlı trafik yakalamaz, paket enjekte etmez veya trafiği
engellemez. Yalnızca sahibi olduğunuz veya açıkça inceleme izniniz bulunan
trafiği analiz edin. Üçüncü taraf trafiğini izinsiz yakalamak veya incelemek
yasa dışı olabilir.
