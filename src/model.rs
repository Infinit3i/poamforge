//! Parsing (Nessus CSV, Defender inventory CSV, CISA KEV), pain score, asset matching.

use chrono::NaiveDate;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::Path;

// ---------------------------------------------------------------- FedRAMP rules

pub const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// Rev5 "Open POA&M Items" columns, in template order.
pub const POAM_COLUMNS: [&str; 31] = [
    "POAM ID", "Controls", "Weakness Name", "Weakness Description",
    "Weakness Detector Source", "Weakness Source Identifier", "Asset Identifier",
    "Point of Contact", "Resources Required", "Overall Remediation Plan",
    "Original Detection Date", "Scheduled Completion Date", "Planned Milestones",
    "Milestone Changes", "Status Date", "Vendor Dependency", "Last Vendor Check-in Date",
    "Vendor Dependent Product Name", "Original Risk Rating", "Adjusted Risk Rating",
    "Risk Adjustment", "False Positive", "Operational Requirement", "Deviation Rationale",
    "Supporting Documents", "Comments", "Auto-Approve",
    "Binding Operational Directive 22-01 tracking",
    "Binding Operational Directive 22-01 Due Date", "CVE", "Service Name",
];

/// Integrated Inventory Workbook (SSP Attachment 13) columns, in template order.
pub const INVENTORY_COLUMNS: [&str; 24] = [
    "UNIQUE ASSET IDENTIFIER", "IPv4 or IPv6 Address", "Virtual", "Public", "DNS Name or URL",
    "NetBIOS Name", "MAC Address", "Authenticated Scan", "Baseline Configuration Name",
    "OS Name and Version", "Location", "Asset Type", "Hardware Make/Model", "In Latest Scan",
    "Software/Database Vendor", "Software/Database Name & Version", "Patch Level",
    "Diagram Label", "Comments", "Serial #/Asset Tag#", "VLAN/Network ID",
    "System Administrator/Owner", "Application Administrator/Owner", "Function",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Risk {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Risk {
    pub const ALL: [Risk; 5] = [Risk::None, Risk::Low, Risk::Medium, Risk::High, Risk::Critical];

    fn parse(s: &str) -> Risk {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" | "4" => Risk::Critical,
            "high" | "3" => Risk::High,
            "medium" | "2" => Risk::Medium,
            "low" | "1" => Risk::Low,
            _ => Risk::None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Risk::Critical => "Critical",
            Risk::High => "High",
            Risk::Medium => "Medium",
            Risk::Low => "Low",
            Risk::None => "None",
        }
    }

    /// Critical is rolled into High.
    pub fn fedramp(self) -> &'static str {
        match self {
            Risk::Critical | Risk::High => "High",
            Risk::Medium => "Moderate",
            _ => "Low",
        }
    }

    /// FedRAMP ConMon remediation window in days from detection.
    pub fn remediation_days(self) -> i64 {
        match self.fedramp() {
            "High" => 30,
            "Moderate" => 90,
            _ => 180,
        }
    }

    fn fallback_score(self) -> f64 {
        match self {
            Risk::Critical => 10.0,
            Risk::High => 8.0,
            Risk::Medium => 5.5,
            Risk::Low => 2.5,
            Risk::None => 0.0,
        }
    }
}

// ---------------------------------------------------------------- pain score

// Pain = how much this finding is going to hurt: risk + exploitability + spread + effort + age.
// Each bucket is capped at its weight; total is 0-100. Tune here.
pub const PAIN_WEIGHTS: [(&str, f64); 5] =
    [("severity", 35.0), ("exploit", 25.0), ("spread", 15.0), ("effort", 15.0), ("age", 10.0)];
const SPREAD_SATURATION: f64 = 50.0; // host count that maxes out the spread bucket
const AGE_SATURATION_DAYS: f64 = 365.0; // vuln age that maxes out the age bucket

// ---------------------------------------------------------------- model

#[derive(Clone, Debug)]
pub struct Item {
    pub key: String,
    pub plugin_id: String,
    pub name: String,
    pub risk: Risk,
    pub synopsis: String,
    pub description: String,
    pub solution: String,
    pub see_also: String,
    pub cvss3: Option<f64>,
    pub cvss2: Option<f64>,
    pub vpr: Option<f64>,
    pub epss: Option<f64>,
    pub exploit_available: bool,
    pub vuln_pub: Option<NaiveDate>,
    pub patch_pub: Option<NaiveDate>,
    pub cves: BTreeSet<String>,
    pub endpoints: BTreeSet<(String, String, String)>, // (host, proto, port)
    pub assets: BTreeSet<String>,                      // rendered Asset Identifier lines
    pub kev_due: Option<NaiveDate>,
    pub pain: u32,
    pub pain_parts: [f64; 5],
}

impl Item {
    pub fn in_kev(&self) -> bool {
        self.kev_due.is_some()
    }

    pub fn compute_pain(&mut self, today: NaiveDate) {
        let w = |i: usize| PAIN_WEIGHTS[i].1;
        let base = [self.cvss3, self.cvss2, self.vpr, Some(self.risk.fallback_score())]
            .into_iter()
            .flatten()
            .fold(0.0, f64::max);
        let sev = w(0) * base.min(10.0) / 10.0;

        let mut exp = 0.0;
        if self.in_kev() {
            exp = w(1);
        } else {
            if self.exploit_available {
                exp += w(1) * 0.6;
            }
            if let Some(e) = self.epss {
                let e = if e <= 1.0 { e } else { e / 100.0 };
                exp += w(1) * 0.4 * e.min(1.0);
            }
        }
        exp = exp.min(w(1));

        let n = self.assets.len() as f64;
        let spread = w(2) * ((1.0 + n).log2() / (1.0 + SPREAD_SATURATION).log2()).min(1.0);

        let sol = self.solution.to_lowercase();
        let name = self.name.to_lowercase();
        let mut effort: f64 = 0.0;
        if name.contains("unsupported") || name.contains("end of life") || name.split_whitespace().any(|t| t == "eol") {
            effort += 1.0; // platform migration, not a patch
        }
        if self.patch_pub.is_none() || sol.contains("no known solution") || sol.is_empty() || sol == "n/a" {
            effort += 0.6; // nothing to just install -> vendor dependency / workaround
        }
        if sol.contains("upgrade") {
            effort += 0.3; // version jump, regression testing
        }
        if ["reboot", "restart", "kernel", "firmware", "bios"].iter().any(|k| sol.contains(k)) {
            effort += 0.2; // downtime window
        }
        let effort = w(3) * effort.min(1.0);

        let age = self
            .vuln_pub
            .map(|d| w(4) * ((today - d).num_days().max(0) as f64 / AGE_SATURATION_DAYS).min(1.0))
            .unwrap_or(0.0);

        self.pain_parts = [sev, exp, spread, effort, age];
        self.pain = self.pain_parts.iter().sum::<f64>().min(100.0).round() as u32;
    }

    pub fn search_text(&self) -> String {
        let mut s = format!("{} {} {}", self.name, self.plugin_id, self.risk.label());
        for c in &self.cves {
            s.push(' ');
            s.push_str(c);
        }
        for a in &self.assets {
            s.push(' ');
            s.push_str(a);
        }
        s.to_lowercase()
    }
}

/// A host as Nessus saw it.
#[derive(Clone, Debug, Default)]
pub struct ScanHost {
    pub host: String,
    pub ip: String,
    pub fqdn: String,
    pub netbios: String,
    pub credentialed: Option<bool>,
}

/// A row of the Integrated Inventory Workbook.
#[derive(Clone, Debug, Default)]
pub struct Asset {
    pub name: String,
    pub source: String,
    pub id: String,
    pub ips: Vec<String>,
    pub fqdn: String,
    pub netbios: String,
    pub os: String,
    pub patch: String,
    pub kind: String,
    pub location: String,
    pub virtual_: String,
    pub public: String,
    pub mac: String,
    pub make: String,
    pub function: String,
    pub notes: Vec<String>,
    pub scanned: bool,
    pub credentialed: Option<bool>,
}

// ---------------------------------------------------------------- helpers

pub fn norm(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase()
}

fn num(v: Option<&String>) -> Option<f64> {
    v.and_then(|s| s.trim().parse().ok())
}

pub fn parse_date(v: &str) -> Option<NaiveDate> {
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    let head: String = v.chars().take(10).collect();
    for s in [v, head.as_str()] {
        for fmt in ["%Y/%m/%d", "%Y-%m-%d", "%m/%d/%Y", "%b %d, %Y"] {
            if let Ok(d) = NaiveDate::parse_from_str(s, fmt) {
                return Some(d);
            }
        }
    }
    None
}

/// Every usable IP in a free-form field (comma lists, JSON blobs, ...).
pub fn ips_in(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tok in s.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '.')) {
        let tok = tok.trim_matches(|c| c == '.' || c == ':');
        let Ok(ip) = tok.parse::<IpAddr>() else { continue };
        let skip = ip.is_loopback()
            || ip.is_unspecified()
            || match ip {
                IpAddr::V4(v4) => v4.is_link_local(),
                IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
            };
        let s = ip.to_string();
        if !skip && !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

fn truthy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "yes" | "1" | "y")
}

fn short(name: &str) -> String {
    name.to_lowercase().split('.').next().unwrap_or("").to_string()
}

/// Read a CSV into (headers, rows) tolerating BOMs and non-UTF-8 bytes.
fn read_csv(path: &Path) -> Result<(Vec<String>, Vec<Vec<String>>), String> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let headers = rdr
        .byte_headers()
        .map_err(|e| format!("{}: {e}", path.display()))?
        .iter()
        .map(|h| String::from_utf8_lossy(h).trim_start_matches('\u{feff}').to_string())
        .collect();
    let mut rows = Vec::new();
    for rec in rdr.byte_records() {
        let rec = rec.map_err(|e| format!("{}: {e}", path.display()))?;
        rows.push(rec.iter().map(|f| String::from_utf8_lossy(f).trim().to_string()).collect());
    }
    Ok((headers, rows))
}

/// Map each row to {attribute: value} using an alias table; repeated attributes are space-joined.
fn mapped_rows(headers: &[String], rows: Vec<Vec<String>>, alias: fn(&str) -> Option<&'static str>)
    -> (Vec<Option<&'static str>>, Vec<HashMap<&'static str, String>>) {
    let colmap: Vec<Option<&'static str>> = headers.iter().map(|h| alias(&norm(h))).collect();
    let out = rows
        .into_iter()
        .map(|row| {
            let mut m: HashMap<&'static str, String> = HashMap::new();
            for (i, v) in row.into_iter().enumerate() {
                if let Some(Some(attr)) = colmap.get(i) {
                    if !v.is_empty() {
                        let e = m.entry(attr).or_default();
                        if !e.is_empty() {
                            e.push(' ');
                        }
                        e.push_str(&v);
                    }
                }
            }
            m
        })
        .collect();
    (colmap, out)
}

// ---------------------------------------------------------------- file sniffing

#[derive(Debug, PartialEq, Eq)]
pub enum FileKind {
    Nessus,
    Inventory,
    Kev,
    Unknown,
}

pub fn sniff(path: &Path) -> FileKind {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    if ext == "json" {
        return FileKind::Kev;
    }
    let Ok((headers, _)) = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .and_then(|mut r| r.byte_headers().map(|h| (h.clone(), ())))
    else {
        return FileKind::Unknown;
    };
    let norms: Vec<String> = headers.iter().map(|h| norm(&String::from_utf8_lossy(h))).collect();
    if norms.iter().any(|h| h == "pluginid") {
        FileKind::Nessus
    } else if norms.iter().any(|h| matches!(inventory_alias(h), Some("name") | Some("id"))) {
        FileKind::Inventory
    } else {
        FileKind::Unknown
    }
}

// ---------------------------------------------------------------- Nessus parsing

fn nessus_alias(h: &str) -> Option<&'static str> {
    Some(match h {
        "pluginid" => "plugin_id",
        "cve" => "cve",
        "risk" | "severity" => "risk",
        "host" => "host",
        "ipaddress" => "ip",
        "protocol" => "protocol",
        "port" => "port",
        "name" | "pluginname" => "name",
        "synopsis" => "synopsis",
        "description" => "description",
        "solution" => "solution",
        "seealso" => "see_also",
        "pluginoutput" => "output",
        "cvssv30basescore" | "cvssv31basescore" | "cvssv3basescore" => "cvss3",
        "cvssv20basescore" | "cvss" => "cvss2",
        "vprscore" => "vpr",
        "epss" | "epssscore" => "epss",
        "exploitavailable" => "exploit_available",
        "vulnerabilitypublicationdate" | "vulnpublicationdate" => "vuln_pub",
        "patchpublicationdate" => "patch_pub",
        "pluginpublicationdate" => "plugin_pub",
        "netbiosname" => "netbios",
        "dnsname" | "fqdn" => "fqdn",
        _ => return None,
    })
}

/// "Nessus Scan Information" - carries "Credentialed checks : yes/no".
const SCAN_INFO_PLUGIN: &str = "19506";

pub fn load_findings(paths: &[impl AsRef<Path>], include_info: bool, per_host: bool)
    -> Result<(Vec<Item>, BTreeMap<String, ScanHost>), String> {
    let mut items: BTreeMap<String, Item> = BTreeMap::new();
    let mut hosts: BTreeMap<String, ScanHost> = BTreeMap::new();
    for p in paths {
        let p = p.as_ref();
        let (headers, rows) = read_csv(p)?;
        let (colmap, rows) = mapped_rows(&headers, rows, nessus_alias);
        if !colmap.contains(&Some("plugin_id")) {
            return Err(format!("{}: no 'Plugin ID' column - is this a Nessus CSV export?", p.display()));
        }
        for r in rows {
            let g = |k: &str| r.get(k).cloned().unwrap_or_default();
            let Some(plugin_id) = r.get("plugin_id").cloned() else { continue };
            let host = ["host", "ip", "fqdn", "netbios"]
                .iter()
                .find_map(|k| r.get(k).cloned())
                .unwrap_or_else(|| "unknown".into());

            let sh = hosts.entry(host.clone()).or_insert_with(|| ScanHost { host: host.clone(), ..Default::default() });
            if sh.ip.is_empty() {
                sh.ip = r.get("ip").cloned().unwrap_or_else(|| if ips_in(&host).is_empty() { String::new() } else { host.clone() });
            }
            if sh.fqdn.is_empty() {
                sh.fqdn = r.get("fqdn").cloned().unwrap_or_else(|| {
                    if ips_in(&host).is_empty() && host.contains('.') { host.clone() } else { String::new() }
                });
            }
            if sh.netbios.is_empty() {
                sh.netbios = g("netbios");
            }
            if plugin_id == SCAN_INFO_PLUGIN {
                let out = g("output");
                if let Some(pos) = out.find("Credentialed checks") {
                    let rest = out[pos..].splitn(2, ':').nth(1).unwrap_or("");
                    let word = rest.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
                    if !word.is_empty() {
                        sh.credentialed = Some(word == "yes");
                    }
                }
            }

            let risk = Risk::parse(&g("risk"));
            if risk == Risk::None && !include_info {
                continue;
            }
            let key = if per_host { format!("{plugin_id}|{host}") } else { plugin_id.clone() };
            let it = items.entry(key.clone()).or_insert_with(|| Item {
                key,
                plugin_id: plugin_id.clone(),
                name: g("name"),
                risk,
                synopsis: g("synopsis"),
                description: g("description"),
                solution: g("solution"),
                see_also: g("see_also"),
                cvss3: None,
                cvss2: None,
                vpr: None,
                epss: None,
                exploit_available: false,
                vuln_pub: None,
                patch_pub: None,
                cves: BTreeSet::new(),
                endpoints: BTreeSet::new(),
                assets: BTreeSet::new(),
                kev_due: None,
                pain: 0,
                pain_parts: [0.0; 5],
            });
            it.risk = it.risk.max(risk);
            for (slot, k) in [(&mut it.cvss3, "cvss3"), (&mut it.cvss2, "cvss2"), (&mut it.vpr, "vpr"), (&mut it.epss, "epss")] {
                if let Some(v) = num(r.get(k)) {
                    if slot.map_or(true, |cur| v > cur) {
                        *slot = Some(v);
                    }
                }
            }
            if truthy(&g("exploit_available")) {
                it.exploit_available = true;
            }
            if it.vuln_pub.is_none() {
                it.vuln_pub = parse_date(&g("vuln_pub")).or_else(|| parse_date(&g("plugin_pub")));
            }
            if it.patch_pub.is_none() {
                it.patch_pub = parse_date(&g("patch_pub"));
            }
            for c in g("cve").split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
                let c = c.to_ascii_uppercase();
                if c.starts_with("CVE-") {
                    it.cves.insert(c);
                }
            }
            it.endpoints.insert((host, g("protocol"), g("port")));
        }
    }
    Ok((items.into_values().collect(), hosts))
}

pub fn parse_kev(json: &str) -> Result<HashMap<String, NaiveDate>, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("KEV json: {e}"))?;
    let today = chrono::Local::now().date_naive();
    let list = v.get("vulnerabilities").and_then(|x| x.as_array()).ok_or("KEV json: no 'vulnerabilities' array")?;
    Ok(list
        .iter()
        .filter_map(|e| {
            let id = e.get("cveID")?.as_str()?.to_ascii_uppercase();
            let due = e.get("dueDate").and_then(|d| d.as_str()).and_then(parse_date).unwrap_or(today);
            Some((id, due))
        })
        .collect())
}

/// Download the KEV catalog; on success also write the raw JSON to `cache` for offline starts.
pub fn fetch_kev(cache: Option<&Path>) -> Result<HashMap<String, NaiveDate>, String> {
    let body = ureq::get(KEV_URL)
        .timeout(std::time::Duration::from_secs(30))
        .call()
        .map_err(|e| format!("KEV download: {e}"))?
        .into_string()
        .map_err(|e| format!("KEV download: {e}"))?;
    let kev = parse_kev(&body)?;
    if let Some(c) = cache {
        if let Some(d) = c.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = std::fs::write(c, &body);
    }
    Ok(kev)
}

// ---------------------------------------------------------------- Defender inventory parsing

// Covers the Defender for Endpoint device list export (security.microsoft.com > Assets > Devices),
// Advanced Hunting DeviceInfo exports, and the Defender for Cloud / Azure Resource Graph inventory CSV.
fn inventory_alias(h: &str) -> Option<&'static str> {
    Some(match h {
        "devicename" | "computerdnsname" | "resourcename" | "name" | "hostname" => "name",
        "deviceid" | "machineid" | "resourceid" | "id" => "id",
        "deviceips" | "ipaddresses" | "ipaddress" | "lastipaddress" | "privateip" | "privateipaddress"
        | "privateipaddresses" => "ips",
        "publicip" | "publicipaddress" | "publicips" | "lastexternalipaddress" => "public_ip",
        "osplatform" | "os" | "operatingsystem" | "ostype" => "os1",
        "osdistribution" => "os2",
        "osversion" | "windows10version" | "osversioninfo" => "os3",
        "osbuild" => "patch",
        "devicetype" | "devicecategory" | "resourcetype" | "type" => "type",
        "location" | "region" => "location",
        "subscription" | "subscriptionname" | "subscriptionid" => "subscription",
        "resourcegroup" => "rg",
        "tags" | "devicetags" => "tags",
        "group" | "machinegroup" | "devicegroup" => "group",
        "isinternetfacing" | "internetfacing" => "internet",
        "macaddress" => "mac",
        "domain" => "domain",
        "devicerole" | "devicesubtype" => "role",
        "vendor" | "devicemanufacturer" | "manufacturer" => "make",
        "model" | "devicemodel" => "model",
        "onboardingstatus" => "onboarding",
        "healthstatus" => "health",
        _ => return None,
    })
}

/// Returns assets plus one summary line per file.
pub fn load_inventory(paths: &[impl AsRef<Path>]) -> Result<(Vec<Asset>, Vec<String>), String> {
    let mut assets = Vec::new();
    let mut log = Vec::new();
    for p in paths {
        let p = p.as_ref();
        let (headers, rows) = read_csv(p)?;
        let norms: BTreeSet<String> = headers.iter().map(|h| norm(h)).collect();
        let (colmap, rows) = mapped_rows(&headers, rows, inventory_alias);
        if !colmap.contains(&Some("name")) && !colmap.contains(&Some("id")) {
            return Err(format!("{}: no Device Name / Resource name column - is this a Defender inventory export?", p.display()));
        }
        let cloud = ["resourcetype", "resourceid", "resourcegroup", "subscriptionid", "subscription"]
            .iter()
            .any(|h| norms.contains(*h));
        let source = if cloud { "Defender for Cloud" } else { "Defender for Endpoint" };
        let mut n = 0;
        for r in rows {
            let g = |k: &str| r.get(k).cloned().unwrap_or_default();
            let rid = g("id");
            let name = if r.contains_key("name") {
                g("name")
            } else {
                rid.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string()
            };
            if name.is_empty() {
                continue;
            }
            let mut os_parts: Vec<String> = Vec::new();
            for k in ["os1", "os2", "os3"] {
                let v = g(k);
                if !v.is_empty() && !os_parts.join(" ").to_lowercase().contains(&v.to_lowercase()) {
                    os_parts.push(v);
                }
            }
            let domain = g("domain");
            let fqdn = if name.contains('.') && ips_in(&name).is_empty() {
                name.clone()
            } else if domain.contains('.') {
                format!("{name}.{domain}")
            } else {
                String::new()
            };
            let public_ips = ips_in(&g("public_ip"));
            let mut ips = ips_in(&g("ips"));
            ips.extend(public_ips.iter().cloned());
            let kind = g("type");
            let make = [g("make"), g("model")].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
            let mut a = Asset {
                name,
                source: source.into(),
                id: rid,
                ips,
                fqdn,
                os: os_parts.join(" "),
                patch: g("patch"),
                location: g("location"),
                mac: g("mac"),
                function: g("role"),
                ..Default::default()
            };
            if cloud || format!("{kind}{make}").to_lowercase().contains("virtual") {
                a.virtual_ = "Yes".into();
            }
            let internet = g("internet");
            if !internet.is_empty() {
                a.public = if truthy(&internet) { "Yes" } else { "No" }.into();
            } else if !public_ips.is_empty() {
                a.public = "Yes".into();
            }
            for (label, k) in [("Subscription", "subscription"), ("Resource group", "rg"), ("Device group", "group"),
                               ("Tags", "tags"), ("Onboarding", "onboarding"), ("Health", "health")] {
                let v = g(k);
                if !v.is_empty() {
                    a.notes.push(format!("{label}: {v}"));
                }
            }
            a.kind = kind;
            a.make = make;
            assets.push(a);
            n += 1;
        }
        log.push(format!("{}: {n} asset(s) from {source}", p.file_name().unwrap_or_default().to_string_lossy()));
    }
    Ok((assets, log))
}

pub struct InventoryIndex {
    by: HashMap<String, usize>,
}

impl InventoryIndex {
    pub fn new(assets: &[Asset]) -> Self {
        let mut by = HashMap::new();
        for (i, a) in assets.iter().enumerate() {
            let mut keys: Vec<String> = a.ips.clone();
            keys.extend([a.name.to_lowercase(), short(&a.name), a.fqdn.to_lowercase(), short(&a.fqdn)]);
            for k in keys {
                if !k.is_empty() {
                    by.entry(k).or_insert(i); // first wins: MDE exports can carry stale duplicates
                }
            }
        }
        Self { by }
    }

    pub fn find(&self, sh: &ScanHost) -> Option<usize> {
        [sh.ip.clone(), sh.host.to_lowercase(), sh.fqdn.to_lowercase(), short(&sh.fqdn), sh.netbios.to_lowercase(), short(&sh.host)]
            .into_iter()
            .filter(|k| !k.is_empty())
            .find_map(|k| self.by.get(&k).copied())
    }
}

/// Render Asset Identifier lines; with an inventory, lead with the inventory's asset name.
pub fn label_assets(items: &mut [Item], hosts: &BTreeMap<String, ScanHost>, assets: &[Asset], inv: Option<&InventoryIndex>) {
    for it in items.iter_mut() {
        it.assets.clear();
        for (host, proto, port) in &it.endpoints {
            let svc = if !port.is_empty() && port != "0" { format!("{proto}/{port}") } else { String::new() };
            let sh = &hosts[host];
            let label = match inv.and_then(|ix| ix.find(sh)) {
                Some(i) => {
                    let ip = if sh.ip.is_empty() { host.as_str() } else { sh.ip.as_str() };
                    let detail = [ip, svc.as_str()].iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().join(" ");
                    format!("{} ({detail})", assets[i].name)
                }
                None if !svc.is_empty() => format!("{host} ({svc})"),
                None => host.clone(),
            };
            it.assets.insert(label);
        }
    }
}

#[cfg(test)]
mod kev_tests {
    /// KEV_LIVE=path: download the real catalog and cache it there.
    #[test]
    fn live_fetch() {
        let Ok(p) = std::env::var("KEV_LIVE") else { return };
        let k = super::fetch_kev(Some(std::path::Path::new(&p))).unwrap();
        println!("{} KEV CVEs", k.len());
        assert!(k.len() > 1000 && std::path::Path::new(&p).exists());
    }
}
