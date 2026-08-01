// Fast ASN lookup over the vendored ip2asn tables (binary search on sorted ranges).
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub struct AsnDb {
    v4: Vec<(u32, u32, String)>,   // (start, end, org) sorted by start
    v6: Vec<(u128, u128, String)>,
}

impl AsnDb {
    pub fn load() -> Self {
        let v4 = Self::load_v4("data/static/asn_v4.tsv");
        let v6 = Self::load_v6("data/static/asn_v6.tsv");
        eprintln!("[panopticon] ASN db loaded: {} v4 ranges, {} v6 ranges", v4.len(), v6.len());
        AsnDb { v4, v6 }
    }

    fn load_v4(path: &str) -> Vec<(u32, u32, String)> {
        let mut v: Vec<(u32, u32, String)> = std::fs::read_to_string(path)
            .unwrap_or_default().lines().filter_map(|l| {
                let mut it = l.split('\t');
                let s = it.next()?.parse::<u32>().ok()?;
                let e = it.next()?.parse::<u32>().ok()?;
                let org = it.next()?.to_string();
                Some((s, e, org))
            }).collect();
        v.sort_by_key(|r| r.0);
        v
    }

    fn load_v6(path: &str) -> Vec<(u128, u128, String)> {
        let mut v: Vec<(u128, u128, String)> = std::fs::read_to_string(path)
            .unwrap_or_default().lines().filter_map(|l| {
                let mut it = l.split('\t');
                let s = u128::from(Ipv6Addr::from_str(it.next()?).ok()?);
                let e = u128::from(Ipv6Addr::from_str(it.next()?).ok()?);
                let org = it.next()?.to_string();
                Some((s, e, org))
            }).collect();
        v.sort_by_key(|r| r.0);
        v
    }

    pub fn lookup(&self, ip: &str) -> Option<String> {
        if ip.contains(':') {
            let v = u128::from(Ipv6Addr::from_str(ip).ok()?);
            // binary search: find the last range whose start <= v, check it contains v
            let idx = self.v6.partition_point(|r| r.0 <= v);
            if idx > 0 {
                let (s, e, org) = &self.v6[idx - 1];
                if v >= *s && v <= *e { return Some(org.clone()); }
            }
            None
        } else {
            let v = u32::from(Ipv4Addr::from_str(ip).ok()?);
            let idx = self.v4.partition_point(|r| r.0 <= v);
            if idx > 0 {
                let (s, e, org) = &self.v4[idx - 1];
                if v >= *s && v <= *e { return Some(org.clone()); }
            }
            None
        }
    }
}
