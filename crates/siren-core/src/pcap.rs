//! Classic PCAP reader (magic-level, no external crate) and DNS event extraction.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::dns;
use crate::model::DnsEvent;

pub struct Packet {
    pub ts: f64,
    pub data: Vec<u8>,
}

pub struct Capture {
    pub linktype: u32,
    pub packets: Vec<Packet>,
}

pub fn is_pcap(path: &Path) -> bool {
    let mut magic = [0u8; 4];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && matches!(
            magic,
            [0xd4, 0xc3, 0xb2, 0xa1]
                | [0xa1, 0xb2, 0xc3, 0xd4]
                | [0x4d, 0x3c, 0xb2, 0xa1]
                | [0xa1, 0xb2, 0x3c, 0x4d]
                | [0x0a, 0x0d, 0x0d, 0x0a]
        )
}

pub fn read(path: &Path) -> Result<Capture, String> {
    let mut file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut head = [0u8; 24];
    file.read_exact(&mut head)
        .map_err(|e| format!("{}: pcap başlığı okunamadı: {e}", path.display()))?;

    let magic = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    let (le, nano) = match magic {
        0xa1b2_c3d4 => (true, false),
        0xa1b2_3c4d => (true, true),
        0xd4c3_b2a1 => (false, false),
        0x4d3c_b2a1 => (false, true),
        0x0a0d_0d0a => {
            return Err(
                "PCAPNG algılandı. Şununla çevir: editcap -F pcap in.pcapng out.pcap".into(),
            )
        }
        _ => return Err("bilinmeyen pcap magic; dosya bozuk veya pcap değil".into()),
    };

    let u32_at = |b: &[u8], off: usize| -> u32 {
        let a = [b[off], b[off + 1], b[off + 2], b[off + 3]];
        if le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        }
    };

    let linktype = u32_at(&head, 20);
    let mut packets = Vec::new();
    let mut hdr = [0u8; 16];
    let mut reader = BufReader::new(file);

    loop {
        match reader.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("pcap paket başlığı: {e}")),
        }
        let ts_sec = u32_at(&hdr, 0) as f64;
        let ts_frac = u32_at(&hdr, 4) as f64;
        let incl_len = u32_at(&hdr, 8) as usize;
        if incl_len > 262_144 {
            return Err(format!("şüpheli paket boyu: {incl_len} bayt"));
        }
        let mut data = vec![0u8; incl_len];
        if let Err(e) = reader.read_exact(&mut data) {
            // Truncated trailing packet: keep what we have.
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(format!("pcap paket verisi: {e}"));
        }
        let frac = if nano {
            ts_frac / 1_000_000_000.0
        } else {
            ts_frac / 1_000_000.0
        };
        packets.push(Packet {
            ts: ts_sec + frac,
            data,
        });
    }

    Ok(Capture { linktype, packets })
}

/// Turn a capture into DNS query events, correlating responses by (client, txid)
/// so `rcode` (and therefore NXDOMAIN ratio) can be computed.
pub fn events(path: &Path) -> Result<Vec<DnsEvent>, String> {
    let capture = read(path)?;
    let mut events: Vec<DnsEvent> = Vec::new();
    let mut pending: std::collections::HashMap<(String, u16), usize> =
        std::collections::HashMap::new();

    for packet in capture.packets {
        let Some(dns) = dns::extract(capture.linktype, &packet.data) else {
            continue;
        };
        if dns.is_response {
            if let Some(&idx) = pending.get(&(dns.dst.clone(), dns.id)) {
                events[idx].rcode = Some(dns.rcode);
            }
            continue;
        }
        let idx = events.len();
        pending.insert((dns.src.clone(), dns.id), idx);
        events.push(DnsEvent {
            ts: packet.ts,
            client: dns.src,
            qname: dns.qname,
            qtype: dns.qtype,
            rcode: None,
            size: dns.size,
            label: None,
        });
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn build_pcap() -> Vec<u8> {
        let dns = {
            let mut b = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            for label in ["k3j4h5g6", "tunnel", "example", "com"] {
                b.push(label.len() as u8);
                b.extend_from_slice(label.as_bytes());
            }
            b.push(0);
            b.extend_from_slice(&[0, 16, 0, 1]);
            b
        };
        let udp_len = 8 + dns.len();
        let ip_len = 20 + udp_len;
        let mut frame = Vec::new();
        // Ethernet
        frame.extend_from_slice(&[0xaa; 6]);
        frame.extend_from_slice(&[0xbb; 6]);
        frame.extend_from_slice(&[0x08, 0x00]);
        // IPv4
        frame.push(0x45);
        frame.push(0);
        frame.extend_from_slice(&(ip_len as u16).to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.push(64);
        frame.push(17);
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&[10, 0, 0, 5]);
        frame.extend_from_slice(&[10, 0, 0, 1]);
        // UDP
        frame.extend_from_slice(&50000u16.to_be_bytes());
        frame.extend_from_slice(&53u16.to_be_bytes());
        frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&dns);

        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&frame);
        out
    }

    #[test]
    fn reads_a_synthetic_capture() {
        let path = std::env::temp_dir().join(format!("siren-test-{}.pcap", std::process::id()));
        let mut f = File::create(&path).unwrap();
        f.write_all(&build_pcap()).unwrap();
        drop(f);

        assert!(is_pcap(&path));
        let events = events(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].client, "10.0.0.5");
        assert_eq!(events[0].qname, "k3j4h5g6.tunnel.example.com");
        assert_eq!(events[0].qtype, 16);
        assert!((events[0].ts - 1_700_000_000.0).abs() < f64::EPSILON);
    }
}
