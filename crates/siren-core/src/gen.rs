//! Deterministic synthetic traffic generator.
//!
//! The point is not realism for its own sake: it gives every run a ground
//! truth, so `siren eval` reports numbers instead of vibes.

use crate::model::DnsEvent;

const BASE_TS: f64 = 1_700_000_000.0;

const BENIGN_DOMAINS: &[&str] = &[
    "google.com",
    "youtube.com",
    "github.com",
    "cloudflare.com",
    "amazon.com",
    "wikipedia.org",
    "microsoft.com",
    "apple.com",
    "netflix.com",
    "spotify.com",
    "reddit.com",
    "stackoverflow.com",
    "x.com",
    "linkedin.com",
    "instagram.com",
    "whatsapp.com",
    "telegram.org",
    "discord.com",
    "twitch.tv",
    "paypal.com",
    "trendyol.com",
    "hepsiburada.com",
    "sahibinden.com",
    "yandex.com",
    "mail.ru",
    "bbc.co.uk",
    "nytimes.com",
    "medium.com",
    "gitlab.com",
    "npmjs.com",
    "godaddy.com",
    "wordpress.com",
    "adobe.com",
    "dropbox.com",
    "zoom.us",
    "slack.com",
    "notion.so",
    "figma.com",
    "canva.com",
    "pinterest.com",
];

const NORMAL_SUBS: &[&str] = &[
    "www", "api", "mail", "cdn", "static", "img", "login", "app", "m", "docs", "shop", "news",
    "auth", "sso", "help", "assets", "media", "edge",
];

const CDN_DOMAINS: &[&str] = &[
    "cloudfront.net",
    "akamaiedge.net",
    "fastly.net",
    "azureedge.net",
    "googleusercontent.com",
    "fbcdn.net",
    "ttvnw.net",
    "sndcdn.com",
    "cloudflare.net",
    "edgekey.net",
];

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn range(&mut self, low: usize, high: usize) -> usize {
        if high <= low {
            return low;
        }
        low + (self.next_u64() as usize % (high - low + 1))
    }

    fn pick<'a>(&mut self, items: &'a [&'a str]) -> &'a str {
        items[self.range(0, items.len() - 1)]
    }

    fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }
}

fn event(
    ts: f64,
    client: &str,
    qname: String,
    qtype: u16,
    rcode: Option<u8>,
    size: u32,
    label: u8,
) -> DnsEvent {
    DnsEvent {
        ts,
        client: client.into(),
        qname,
        qtype,
        rcode,
        size,
        label: Some(label),
    }
}

fn hex(rng: &mut Rng, len: usize) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdef";
    (0..len)
        .map(|_| ALPHABET[rng.range(0, 15)] as char)
        .collect()
}

fn base32(rng: &mut Rng, len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    (0..len)
        .map(|_| ALPHABET[rng.range(0, 31)] as char)
        .collect()
}

fn base64ish(rng: &mut Rng, len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s: String = (0..len)
        .map(|_| ALPHABET[rng.range(0, 63)] as char)
        .collect();
    // Guarantee the detector's alphabet test: at least one upper and one digit.
    s.replace_range(0..1, "Q");
    s.replace_range(1..2, "7");
    s
}

fn client_for(id: u32) -> String {
    format!("10.0.{}.{}", (id / 250) % 250, id % 250 + 1)
}

pub fn generate(seed: u64) -> Vec<DnsEvent> {
    let mut rng = Rng::new(seed);
    let mut events = Vec::new();
    let mut client_id = 1u32;

    // 1) Ordinary browsing: low rate, human labels, valid answers.
    for _ in 0..160 {
        let client = client_for(client_id);
        client_id += 1;
        let domain = rng.pick(BENIGN_DOMAINS);
        let count = rng.range(15, 90);
        for _ in 0..count {
            let sub = rng.pick(NORMAL_SUBS);
            let qtype = if rng.chance(0.6) { 1 } else { 28 };
            let rcode = Some(if rng.chance(0.04) { 3 } else { 0 });
            events.push(event(
                BASE_TS + rng.unit() * 600.0,
                &client,
                format!("{sub}.{domain}"),
                qtype,
                rcode,
                55,
                0,
            ));
        }
    }

    // 2) Hard negatives: CDN hashes. Long and hex-looking, but slow.
    for _ in 0..25 {
        let client = client_for(client_id);
        client_id += 1;
        let domain = rng.pick(CDN_DOMAINS);
        let count = rng.range(20, 120);
        for _ in 0..count {
            let label = {
                let len = rng.range(16, 24);
                hex(&mut rng, len)
            };
            events.push(event(
                BASE_TS + rng.unit() * 600.0,
                &client,
                format!("{label}.{domain}"),
                if rng.chance(0.5) { 1 } else { 28 },
                Some(0),
                70,
                0,
            ));
        }
    }

    // 3) Hard negatives at high rate: telemetry with hashed labels.
    for _ in 0..6 {
        let client = client_for(client_id);
        client_id += 1;
        let domain = rng.pick(CDN_DOMAINS);
        let count = rng.range(180, 320);
        for _ in 0..count {
            let label = {
                let len = rng.range(16, 20);
                hex(&mut rng, len)
            };
            events.push(event(
                BASE_TS + rng.unit() * 300.0,
                &client,
                format!("{label}.{domain}"),
                1,
                Some(0),
                64,
                0,
            ));
        }
    }

    // 4) Tunnels: encoded labels, payload record types, NXDOMAIN, beacon timing.
    for index in 0..40 {
        let client = client_for(client_id);
        client_id += 1;
        let domain = format!("tunnel{index}.net");
        let count = rng.range(80, 260);
        let duration = rng.range(90, 200) as f64;
        let interval = duration / count as f64;
        let jitter = rng.unit() * 0.12;
        let nx_prob = 0.2 + rng.unit() * 0.6;
        let front_nx = rng.chance(0.2);

        for i in 0..count {
            let kind = index % 3;
            let len = match kind {
                0 => rng.range(32, 56),
                1 => rng.range(32, 52),
                _ => rng.range(40, 60),
            };
            let label = match kind {
                0 => hex(&mut rng, len),
                1 => base32(&mut rng, len),
                _ => base64ish(&mut rng, len),
            };
            let qtype = if rng.chance(0.6) {
                16
            } else if rng.chance(0.5) {
                1
            } else {
                10
            };
            // A tunnel often starts with NXDOMAINs, then the C2 answers.
            let rcode = if (front_nx && i < count / 4) || rng.chance(nx_prob) {
                3
            } else {
                0
            };
            let ts = BASE_TS + 50.0 + i as f64 * interval * (1.0 + (rng.unit() - 0.5) * jitter);
            events.push(event(
                ts,
                &client,
                format!("{label}.{domain}"),
                qtype,
                Some(rcode),
                90,
                1,
            ));
        }
    }

    // 5) Low-and-slow tunnels: deliberately hard, some will be missed.
    for index in 40..46 {
        let client = client_for(client_id);
        client_id += 1;
        let domain = format!("tunnel{index}.net");
        let count = rng.range(20, 40);
        for i in 0..count {
            let label = {
                let len = rng.range(28, 40);
                base32(&mut rng, len)
            };
            let ts = BASE_TS + i as f64 * (600.0 / count as f64);
            events.push(event(
                ts,
                &client,
                format!("{label}.{domain}"),
                16,
                Some(0),
                80,
                1,
            ));
        }
    }

    events.sort_by(|a, b| a.ts.partial_cmp(&b.ts).unwrap_or(std::cmp::Ordering::Equal));
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let a = generate(42);
        let b = generate(42);
        assert_eq!(a.len(), b.len());
        assert_eq!(a.first().unwrap().qname, b.first().unwrap().qname);
    }

    #[test]
    fn both_classes_are_present() {
        let events = generate(7);
        assert!(events.iter().any(|e| e.label == Some(0)));
        assert!(events.iter().any(|e| e.label == Some(1)));
        assert!(events.len() > 5_000);
    }
}
