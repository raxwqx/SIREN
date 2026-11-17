//! Minimal, dependency-free DNS message parser.
//!
//! Only what SIREN needs: the question (qname/qtype), the transaction id,
//! the response bit and the response code. Answers, EDNS0 options and DNS over
//! TCP are intentionally out of scope for v0.1.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub src: String,
    pub dst: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub id: u16,
    pub is_response: bool,
    pub rcode: u8,
    pub qname: String,
    pub qtype: u16,
    /// DNS payload size in bytes.
    pub size: u32,
}

struct Message {
    id: u16,
    is_response: bool,
    rcode: u8,
    qname: String,
    qtype: u16,
}

/// Extract a DNS packet from a link-layer frame, if it is DNS over UDP/53.
pub fn extract(linktype: u32, frame: &[u8]) -> Option<DnsPacket> {
    let (ethertype, l3) = link_layer(linktype, frame)?;
    let (src, dst, proto, l4) = match ethertype {
        0x0800 => ipv4(l3)?,
        0x86dd => ipv6(l3)?,
        _ => return None,
    };
    // UDP only. TCP DNS needs stream reassembly and is a roadmap item.
    if proto != 17 {
        return None;
    }
    let (sp, dp, payload) = udp(l4)?;
    if sp != 53 && dp != 53 {
        return None;
    }
    let msg = parse_dns(payload)?;
    Some(DnsPacket {
        src,
        dst,
        src_port: sp,
        dst_port: dp,
        id: msg.id,
        is_response: msg.is_response,
        rcode: msg.rcode,
        qname: msg.qname,
        qtype: msg.qtype,
        size: payload.len() as u32,
    })
}

fn link_layer(linktype: u32, frame: &[u8]) -> Option<(u16, &[u8])> {
    match linktype {
        // Ethernet, with optional 802.1Q / QinQ tags.
        1 => {
            if frame.len() < 14 {
                return None;
            }
            let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            let mut off = 14;
            // 802.1Q, 802.1ad (QinQ) and the legacy 0x9100/0x9200 tags that
            // still appear in captures from older switches.
            while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100 | 0x9200) {
                if frame.len() < off + 4 {
                    return None;
                }
                ethertype = u16::from_be_bytes([frame[off + 2], frame[off + 3]]);
                off += 4;
            }
            Some((ethertype, &frame[off..]))
        }
        // Raw IP.
        101 => {
            let version = (*frame.first()?) >> 4;
            Some((if version == 6 { 0x86dd } else { 0x0800 }, frame))
        }
        // Linux cooked capture v1 / v2.
        113 => {
            if frame.len() < 16 {
                return None;
            }
            Some((u16::from_be_bytes([frame[14], frame[15]]), &frame[16..]))
        }
        276 => {
            if frame.len() < 20 {
                return None;
            }
            Some((u16::from_be_bytes([frame[0], frame[1]]), &frame[20..]))
        }
        _ => None,
    }
}

fn ipv4(b: &[u8]) -> Option<(String, String, u8, &[u8])> {
    if b.len() < 20 || (b[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((b[0] & 0x0f) as usize) * 4;
    if ihl < 20 || b.len() < ihl {
        return None;
    }
    let proto = b[9];
    let total = u16::from_be_bytes([b[2], b[3]]) as usize;
    // A total length of 0 is what some capture stacks leave behind for
    // segmentation offload; fall back to the bytes actually captured.
    let end = if total == 0 {
        b.len()
    } else {
        total.min(b.len())
    };
    if end < ihl {
        return None;
    }
    let src = Ipv4Addr::new(b[12], b[13], b[14], b[15]).to_string();
    let dst = Ipv4Addr::new(b[16], b[17], b[18], b[19]).to_string();
    Some((src, dst, proto, &b[ihl..end]))
}

fn ipv6(b: &[u8]) -> Option<(String, String, u8, &[u8])> {
    if b.len() < 40 {
        return None;
    }
    let mut next = b[6];
    let mut off = 40;
    // Walk extension headers: hop-by-hop, routing, fragment, destination options.
    while matches!(next, 0 | 43 | 44 | 60) {
        if b.len() < off + 8 {
            return None;
        }
        let hlen = (b[off + 1] as usize + 1) * 8;
        next = b[off];
        off += hlen;
    }
    if b.len() < off {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).ok()?).to_string();
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&b[24..40]).ok()?).to_string();
    Some((src, dst, next, &b[off..]))
}

fn udp(b: &[u8]) -> Option<(u16, u16, &[u8])> {
    if b.len() < 8 {
        return None;
    }
    let sp = u16::from_be_bytes([b[0], b[1]]);
    let dp = u16::from_be_bytes([b[2], b[3]]);
    let len = u16::from_be_bytes([b[4], b[5]]) as usize;
    // The UDP header is eight bytes; a smaller length field is malformed and
    // must not silently turn into "use the rest of the buffer".
    if len < 8 {
        return None;
    }
    // Truncated captures are common (snaplen); trust the captured bytes but
    // never read past them.
    let end = len.min(b.len());
    Some((sp, dp, &b[8..end]))
}

fn parse_dns(buf: &[u8]) -> Option<Message> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let is_response = flags & 0x8000 != 0;
    let rcode = (flags & 0x000f) as u8;

    if qdcount == 0 {
        return Some(Message {
            id,
            is_response,
            rcode,
            qname: String::new(),
            qtype: 0,
        });
    }

    let (qname, off) = read_name(buf, 12)?;
    if off + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
    Some(Message {
        id,
        is_response,
        rcode,
        qname,
        qtype,
    })
}

fn read_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut off = start;
    let mut end = start;
    let mut jumped = false;
    let mut depth = 0u8;

    loop {
        let len = *buf.get(off)? as usize;
        if len == 0 {
            if !jumped {
                end = off + 1;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            let lo = *buf.get(off + 1)? as usize;
            let ptr = ((len & 0x3f) << 8) | lo;
            if !jumped {
                end = off + 2;
                jumped = true;
            }
            depth += 1;
            if depth > 8 || ptr >= buf.len() {
                return None;
            }
            off = ptr;
            continue;
        }
        if len > 63 || off + 1 + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[off + 1..off + 1 + len]).into_owned());
        off += 1 + len;
    }
    Some((labels.join("."), end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut b = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&[0, 1]);
        b
    }

    fn ipv4_udp(dns: &[u8], total: Option<u16>) -> Vec<u8> {
        let udp_len = 8 + dns.len();
        let ip_len = 20 + udp_len;
        let mut b = Vec::new();
        b.push(0x45);
        b.push(0);
        b.extend_from_slice(&total.unwrap_or(ip_len as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.push(64);
        b.push(17);
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&[10, 0, 0, 5]);
        b.extend_from_slice(&[10, 0, 0, 1]);
        b.extend_from_slice(&50000u16.to_be_bytes());
        b.extend_from_slice(&53u16.to_be_bytes());
        b.extend_from_slice(&(udp_len as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(dns);
        b
    }

    fn tagged_frame(vlan: u16, l3: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&vlan.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01]); // priority / VLAN id
        frame.extend_from_slice(&[0x08, 0x00]); // IPv4
        frame.extend_from_slice(l3);
        frame
    }

    #[test]
    fn parses_all_supported_vlan_tags() {
        for vlan in [0x8100u16, 0x88a8, 0x9100, 0x9200] {
            let frame = tagged_frame(vlan, &ipv4_udp(&query("a.example.com", 1), None));
            let packet = extract(1, &frame).unwrap_or_else(|| panic!("VLAN {vlan:#06x} failed"));
            assert_eq!(packet.qname, "a.example.com");
        }
    }

    #[test]
    fn falls_back_when_ipv4_total_length_is_zero() {
        let frame = tagged_frame(0x8100, &ipv4_udp(&query("a.example.com", 1), Some(0)));
        let packet = extract(1, &frame).unwrap();
        assert_eq!(packet.qname, "a.example.com");
    }

    #[test]
    fn rejects_udp_length_below_the_header() {
        let mut datagram = vec![0u8; 16];
        datagram[0..2].copy_from_slice(&50000u16.to_be_bytes());
        datagram[2..4].copy_from_slice(&53u16.to_be_bytes());
        datagram[4..6].copy_from_slice(&7u16.to_be_bytes());
        assert!(udp(&datagram).is_none());
    }

    #[test]
    fn parses_a_question() {
        let m = parse_dns(&query("k3j4h5g6.tunnel.example.com", 16)).unwrap();
        assert_eq!(m.id, 0x1234);
        assert!(!m.is_response);
        assert_eq!(m.qname, "k3j4h5g6.tunnel.example.com");
        assert_eq!(m.qtype, 16);
    }

    #[test]
    fn parses_a_response_without_question() {
        let msg = [0x12, 0x34, 0x81, 0x83, 0, 0, 0, 0, 0, 0, 0, 0];
        let m = parse_dns(&msg).unwrap();
        assert!(m.is_response);
        assert_eq!(m.rcode, 3);
        assert!(m.qname.is_empty());
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(parse_dns(&[0, 0, 0]).is_none());
        assert!(parse_dns(&query("a.b", 1)[..13]).is_none());
    }

    #[test]
    fn follows_compression_pointers() {
        let mut b = vec![0u8; 60];
        // Question at offset 12: label "a" then a pointer to offset 40.
        b[12] = 1;
        b[13] = b'a';
        b[14] = 0xc0;
        b[15] = 40;
        // Target at offset 40: "example.com".
        b[40..53].copy_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        let (name, end) = read_name(&b, 12).unwrap();
        assert_eq!(name, "a.example.com");
        assert_eq!(end, 16);
    }
}
