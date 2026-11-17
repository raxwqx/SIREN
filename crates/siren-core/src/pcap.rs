//! Classic PCAP reader (magic-level, no external crate) and DNS event extraction.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::dns;
use crate::model::DnsEvent;

#[derive(Debug)]
pub struct Packet {
    pub ts: f64,
    pub data: Vec<u8>,
}

#[derive(Debug)]
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
        .map_err(|e| format!("{}: cannot read pcap header: {e}", path.display()))?;

    let magic = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    let (le, nano) = match magic {
        0xa1b2_c3d4 => (true, false),
        0xa1b2_3c4d => (true, true),
        0xd4c3_b2a1 => (false, false),
        0x4d3c_b2a1 => (false, true),
        0x0a0d_0d0a => {
            return Err(
                "PCAPNG detected. Convert it first: editcap -F pcap in.pcapng out.pcap".into(),
            )
        }
        _ => return Err("unknown pcap magic; the file is corrupt or not a pcap".into()),
    };

    let u32_at = |b: &[u8], off: usize| -> Option<u32> {
        let bytes = b.get(off..off + 4)?;
        let a = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Some(if le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    };

    let linktype = u32_at(&head, 20).ok_or("pcap header is truncated")?;
    if !matches!(linktype, 1 | 101 | 113 | 276) {
        return Err(format!(
            "unsupported pcap link type {linktype}; supported: Ethernet (1), raw IP (101), Linux SLL (113), Linux SLL2 (276)"
        ));
    }
    let mut packets = Vec::new();
    let mut hdr = [0u8; 16];
    let mut reader = BufReader::new(file);

    loop {
        match reader.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("pcap packet header: {e}")),
        }
        let ts_sec = u32_at(&hdr, 0).ok_or("pcap packet header is truncated")? as f64;
        let ts_frac = u32_at(&hdr, 4).ok_or("pcap packet header is truncated")? as f64;
        let incl_len = u32_at(&hdr, 8).ok_or("pcap packet header is truncated")? as usize;
        if incl_len > 262_144 {
            return Err(format!("suspicious packet length: {incl_len} bytes"));
        }
        let mut data = vec![0u8; incl_len];
        if let Err(e) = reader.read_exact(&mut data) {
            // Truncated trailing packet: keep what we have.
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(format!("pcap packet data: {e}"));
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

/// Turn a capture into DNS query events, correlating responses by
/// (client, txid) so `rcode` (and therefore NXDOMAIN ratio) can be computed.
///
/// Transaction IDs are only 16 bits and clients reuse them quickly, so one
/// `(client, txid)` key can map to several in-flight queries. Keep a queue per
/// key and prefer the response whose echoed question matches the query.
pub fn events(path: &Path) -> Result<Vec<DnsEvent>, String> {
    let capture = read(path)?;
    let mut events: Vec<DnsEvent> = Vec::new();
    let mut pending: std::collections::HashMap<(String, u16), Vec<usize>> =
        std::collections::HashMap::new();

    for packet in capture.packets {
        let Some(dns) = dns::extract(capture.linktype, &packet.data) else {
            continue;
        };
        if dns.is_response {
            let key = (dns.dst.clone(), dns.id);
            if let Some(indices) = pending.get_mut(&key) {
                let position = if dns.qname.is_empty() {
                    // No question echoed: only safe when the mapping is unique.
                    (indices.len() == 1).then_some(0)
                } else {
                    indices
                        .iter()
                        .position(|&idx| events[idx].qname.eq_ignore_ascii_case(&dns.qname))
                        .or_else(|| (indices.len() == 1).then_some(0))
                };
                if let Some(position) = position {
                    let idx = indices.remove(position);
                    events[idx].rcode = Some(dns.rcode);
                }
                if indices.is_empty() {
                    pending.remove(&key);
                }
            }
            continue;
        }
        let idx = events.len();
        pending
            .entry((dns.src.clone(), dns.id))
            .or_default()
            .push(idx);
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
    use std::path::PathBuf;

    fn dns_message(id: u16, name: &str, qtype: u16, response: bool, rcode: u8) -> Vec<u8> {
        let flags: u16 = if response {
            0x8000 | (rcode as u16 & 0x0f)
        } else {
            0x0100
        };
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&flags.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&[0, 1]);
        b
    }

    fn frame(
        id: u16,
        name: &str,
        qtype: u16,
        response: bool,
        rcode: u8,
        client: [u8; 4],
        server: [u8; 4],
    ) -> Vec<u8> {
        let dns = dns_message(id, name, qtype, response, rcode);
        let udp_len = 8 + dns.len();
        let ip_len = 20 + udp_len;
        let (src, dst, sport, dport) = if response {
            (server, client, 53u16, 50000u16)
        } else {
            (client, server, 50000u16, 53u16)
        };
        let mut out = Vec::new();
        // Ethernet
        out.extend_from_slice(&[0xaa; 6]);
        out.extend_from_slice(&[0xbb; 6]);
        out.extend_from_slice(&[0x08, 0x00]);
        // IPv4
        out.push(0x45);
        out.push(0);
        out.extend_from_slice(&(ip_len as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.push(64);
        out.push(17);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&src);
        out.extend_from_slice(&dst);
        // UDP
        out.extend_from_slice(&sport.to_be_bytes());
        out.extend_from_slice(&dport.to_be_bytes());
        out.extend_from_slice(&(udp_len as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&dns);
        out
    }

    fn capture(linktype: u32, packets: &[(f64, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&linktype.to_le_bytes());
        for (ts, data) in packets {
            let secs = *ts as u32;
            let frac = ((*ts - secs as f64) * 1_000_000.0) as u32;
            out.extend_from_slice(&secs.to_le_bytes());
            out.extend_from_slice(&frac.to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    fn write_temp(tag: &str, bytes: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!("siren-{tag}-{}.pcap", std::process::id()));
        let mut f = File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path
    }

    #[test]
    fn reads_a_synthetic_capture() {
        let query = frame(
            0x1234,
            "k3j4h5g6.tunnel.example.com",
            16,
            false,
            0,
            [10, 0, 0, 5],
            [10, 0, 0, 1],
        );
        let path = write_temp("read", &capture(1, &[(1_700_000_000.0, query)]));

        assert!(is_pcap(&path));
        let events = events(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].client, "10.0.0.5");
        assert_eq!(events[0].qname, "k3j4h5g6.tunnel.example.com");
        assert_eq!(events[0].qtype, 16);
        assert!((events[0].ts - 1_700_000_000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn correlates_reused_transaction_ids_by_question() {
        let client = [10, 0, 0, 5];
        let server = [10, 0, 0, 1];
        let packets = vec![
            (
                1_700_000_000.0,
                frame(0x1234, "a.example.com", 1, false, 0, client, server),
            ),
            (
                1_700_000_000.1,
                frame(0x1234, "b.example.com", 1, false, 0, client, server),
            ),
            (
                1_700_000_000.2,
                frame(0x1234, "b.example.com", 1, true, 3, client, server),
            ),
            (
                1_700_000_000.3,
                frame(0x1234, "a.example.com", 1, true, 0, client, server),
            ),
        ];
        let path = write_temp("correlate", &capture(1, &packets));
        let events = events(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].qname, "a.example.com");
        assert_eq!(events[0].rcode, Some(0));
        assert_eq!(events[1].qname, "b.example.com");
        assert_eq!(events[1].rcode, Some(3));
    }

    #[test]
    fn rejects_unsupported_link_types() {
        let path = write_temp("linktype", &capture(999, &[]));
        let error = read(&path).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(error.contains("unsupported pcap link type"), "{error}");
    }
}
