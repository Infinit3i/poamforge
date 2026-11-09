//! POA&M and Integrated Inventory Workbook writers (fresh sheet or append into an official template).

use crate::model::{norm, Asset, InventoryIndex, Item, ScanHost, INVENTORY_COLUMNS, POAM_COLUMNS};
use chrono::{Duration, NaiveDate};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use umya_spreadsheet::{self as us, VerticalAlignmentValues, Workbook, Worksheet};

const EXCEL_CELL_MAX: usize = 32000;

/// A named system/environment and the POAM ID prefix its POA&M uses (e.g. "V-PROD-").
#[derive(Clone, PartialEq)]
pub struct Env {
    pub name: String,
    pub prefix: String,
}

#[derive(Clone)]
pub struct Settings {
    pub scan_date: String,
    pub controls: String,
    pub detector: String,
    pub poc: String,
    pub resources: String,
    pub service: String,
    pub envs: Vec<Env>,
    pub env: usize,
    pub start_id: u32,
    pub id_width: usize,
    pub per_host: bool,
    pub include_info: bool,
    pub poam_template: Option<PathBuf>,
    pub poam_sheet: String,
    pub inv_template: Option<PathBuf>,
    pub inv_sheet: String,
    pub baseline: String,
    pub location: String,
    pub owner: String,
    pub app_owner: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            scan_date: chrono::Local::now().date_naive().format("%Y-%m-%d").to_string(),
            controls: "RA-5, SI-2".into(),
            detector: "Tenable Nessus".into(),
            poc: String::new(),
            resources: String::new(),
            service: String::new(),
            envs: vec![Env { name: "Default".into(), prefix: "V-".into() }],
            env: 0,
            start_id: 1,
            id_width: 4,
            per_host: false,
            include_info: false,
            poam_template: None,
            poam_sheet: "Open POA&M Items".into(),
            inv_template: None,
            inv_sheet: "Inventory".into(),
            baseline: String::new(),
            location: String::new(),
            owner: String::new(),
            app_owner: String::new(),
        }
    }
}

impl Settings {
    pub fn prefix(&self) -> &str {
        self.envs.get(self.env).map_or("V-", |e| e.prefix.as_str())
    }
}

/// Split "V-PROD-0042" into ("V-PROD-", Some(42)).
fn split_id(pid: &str) -> (String, Option<u32>) {
    let pid = pid.trim();
    let head = pid.trim_end_matches(|c: char| c.is_ascii_digit());
    (head.to_string(), pid[head.len()..].parse().ok())
}

/// POAM ID prefix -> (row count, highest number) over the data rows of a POA&M sheet.
fn prefix_stats(ws: &Worksheet, header_row: u32, id_col: u32) -> BTreeMap<String, (usize, u32)> {
    let mut out: BTreeMap<String, (usize, u32)> = BTreeMap::new();
    for r in header_row + 1..=ws.highest_row() {
        let pid = ws.value((id_col, r));
        if pid.trim().is_empty() {
            continue;
        }
        let (head, n) = split_id(&pid);
        let e = out.entry(head.to_ascii_uppercase()).or_default();
        e.0 += 1;
        e.1 = e.1.max(n.unwrap_or(0));
    }
    out
}

/// Which configured environment an existing POA&M belongs to, judged by its POAM ID prefixes.
/// Returns (best env index if any rows match one, human summary of the prefixes found).
pub fn detect_env(template: &Path, st: &Settings) -> Result<(Option<usize>, String), String> {
    let (wb, sheet, header_row, cols) = open_sheet(Some(template), &st.poam_sheet, &POAM_COLUMNS)?;
    let ws = wb.sheet_by_name(&sheet).map_err(|e| e.to_string())?;
    let stats = prefix_stats(ws, header_row, cols["POAM ID"]);
    let summary = if stats.is_empty() {
        "no existing POAM IDs".to_string()
    } else {
        stats.iter().map(|(p, (n, _))| format!("{p}* x{n}")).collect::<Vec<_>>().join(", ")
    };
    let best = st.envs.iter().enumerate()
        .filter_map(|(i, e)| stats.get(&e.prefix.trim().to_ascii_uppercase()).map(|(n, _)| (i, *n)))
        .max_by_key(|(_, n)| *n)
        .map(|(i, _)| i);
    Ok((best, summary))
}

enum Val {
    S(String),
    D(NaiveDate),
}

fn s(v: impl Into<String>) -> Val {
    Val::S(v.into())
}

fn clip(mut v: String) -> String {
    if v.len() > EXCEL_CELL_MAX {
        let mut cut = EXCEL_CELL_MAX;
        while !v.is_char_boundary(cut) {
            cut -= 1;
        }
        v.truncate(cut);
    }
    v
}

/// Every column gets a value: anything not known/applicable is N/A.
fn fill_na(columns: &[&'static str], mut row: HashMap<&'static str, Val>) -> Vec<(&'static str, Val)> {
    columns
        .iter()
        .map(|c| match row.remove(c) {
            Some(Val::S(v)) if !v.trim().is_empty() => (*c, Val::S(clip(v))),
            Some(Val::D(d)) => (*c, Val::D(d)),
            _ => (*c, s("N/A")),
        })
        .collect()
}

fn find_header(ws: &Worksheet, columns: &[&'static str]) -> Option<(u32, HashMap<&'static str, u32>)> {
    let want: Vec<(String, &'static str)> = columns.iter().map(|c| (norm(c), *c)).collect();
    let anchor = columns[0];
    for r in 1..=ws.highest_row().min(30) {
        let mut found: HashMap<&'static str, u32> = HashMap::new();
        for c in 1..=ws.highest_column() {
            let h = norm(&ws.value((c, r)));
            if h.is_empty() {
                continue;
            }
            if let Some((_, col)) = want.iter().find(|(nk, col)| !found.contains_key(col) && (h == *nk || h.starts_with(nk.as_str()))) {
                found.insert(col, c);
            }
        }
        if found.contains_key(anchor) && found.len() >= 5 {
            return Some((r, found));
        }
    }
    None
}

/// Workbook, sheet name, header row, {column: index} - from a template or a fresh styled sheet.
fn open_sheet(template: Option<&Path>, sheet: &str, columns: &[&'static str])
    -> Result<(Workbook, String, u32, HashMap<&'static str, u32>), String> {
    if let Some(t) = template {
        let wb = us::reader::xlsx::read(t).map_err(|e| format!("{}: {e}", t.display()))?;
        let mut names: Vec<String> = wb.sheet_collection().iter().map(|w| w.name().to_string()).collect();
        if let Some(i) = names.iter().position(|n| n == sheet) {
            let n = names.remove(i);
            names.insert(0, n);
        }
        for n in names {
            let ws = wb.sheet_by_name(&n).map_err(|e| e.to_string())?;
            if let Some((row, cols)) = find_header(ws, columns) {
                return Ok((wb, n, row, cols));
            }
        }
        return Err(format!("{}: could not find a header row containing '{}'", t.display(), columns[0]));
    }
    let mut wb = us::new_file();
    let ws = wb.sheet_mut(0).map_err(|e| e.to_string())?;
    ws.set_name(sheet);
    let wide: HashSet<&str> = ["Weakness Description", "Overall Remediation Plan", "Asset Identifier", "Planned Milestones",
        "Comments", "Supporting Documents", "OS Name and Version", "Serial #/Asset Tag#"].into();
    let mut cols = HashMap::new();
    for (i, c) in columns.iter().enumerate() {
        let ci = i as u32 + 1;
        cols.insert(*c, ci);
        ws.cell_mut((ci, 1)).set_value(*c);
        let st = ws.style_mut((ci, 1));
        st.font_mut().set_bold(true);
        st.font_mut().color_mut().set_argb_str("FFFFFFFF");
        st.set_background_color("FF1F3864");
        st.alignment_mut().set_wrap_text(true);
        st.alignment_mut().set_vertical(VerticalAlignmentValues::Top);
        ws.column_dimension_mut(&us::helper::coordinate::string_from_column_index(ci))
            .set_width(if wide.contains(c) { 40.0 } else { 18.0 });
    }
    Ok((wb, sheet.to_string(), 1, cols))
}

fn excel_serial(d: NaiveDate) -> f64 {
    (d - NaiveDate::from_ymd_opt(1899, 12, 30).unwrap()).num_days() as f64
}

fn put_row(ws: &mut Worksheet, row: u32, cols: &HashMap<&'static str, u32>, values: Vec<(&'static str, Val)>) {
    for (col, val) in values {
        let Some(&c) = cols.get(col) else { continue };
        match val {
            Val::S(v) => {
                ws.cell_mut((c, row)).set_value_string(v);
            }
            Val::D(d) => {
                ws.cell_mut((c, row)).set_value_number(excel_serial(d));
                ws.style_mut((c, row)).number_format_mut().set_format_code("mm/dd/yyyy");
            }
        }
        let al = ws.style_mut((c, row)).alignment_mut();
        al.set_wrap_text(true);
        al.set_vertical(VerticalAlignmentValues::Top);
    }
}

fn last_used_row(ws: &Worksheet, header_row: u32, col: u32) -> u32 {
    (header_row + 1..=ws.highest_row()).filter(|&r| !ws.value((col, r)).trim().is_empty()).max().unwrap_or(header_row)
}

pub fn detection_date(st: &Settings) -> Result<NaiveDate, String> {
    NaiveDate::parse_from_str(st.scan_date.trim(), "%Y-%m-%d").map_err(|_| format!("scan date '{}' is not YYYY-MM-DD", st.scan_date))
}

fn build_row(it: &Item, poam_id: String, st: &Settings, detect: NaiveDate, today: NaiveDate) -> Vec<(&'static str, Val)> {
    let mut due = detect + Duration::days(it.risk.remediation_days());
    if let Some(k) = it.kev_due {
        if k < due {
            due = k.max(detect);
        }
    }
    let test_by = detect + Duration::days((due - detect).num_days() / 2);
    let vendor_dep = if it.patch_pub.is_none() && it.solution.to_lowercase().contains("no known solution") { "Yes" } else { "No" };
    let mut desc = it.synopsis.clone();
    if !it.description.is_empty() {
        desc.push_str("\n\n");
        desc.push_str(&it.description);
    }
    let parts = crate::model::PAIN_WEIGHTS
        .iter()
        .zip(it.pain_parts)
        .map(|((k, _), v)| format!("{k} {v:.0}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut comments = format!("Pain score {}/100 ({parts}). Nessus risk: {}.", it.pain, it.risk.label());
    if let Some(v) = it.cvss3 {
        comments += &format!(" CVSSv3 {v:.1}.");
    }
    if let Some(v) = it.vpr {
        comments += &format!(" VPR {v:.1}.");
    }
    let refs = it.see_also.split_whitespace().collect::<Vec<_>>().join("\n");

    let mut row: HashMap<&'static str, Val> = HashMap::new();
    row.insert("POAM ID", s(poam_id));
    row.insert("Controls", s(&st.controls));
    row.insert("Weakness Name", s(&it.name));
    row.insert("Weakness Description", s(desc));
    row.insert("Weakness Detector Source", s(&st.detector));
    row.insert("Weakness Source Identifier", s(&it.plugin_id));
    row.insert("Asset Identifier", s(it.assets.iter().cloned().collect::<Vec<_>>().join("\n")));
    row.insert("Point of Contact", s(&st.poc));
    row.insert("Resources Required", s(&st.resources));
    row.insert("Overall Remediation Plan", s(&it.solution));
    row.insert("Original Detection Date", Val::D(detect));
    row.insert("Scheduled Completion Date", Val::D(due));
    row.insert("Planned Milestones", s(format!(
        "1) {}: Validate finding, test remediation in non-production.\n2) {}: Deploy remediation to production and verify with rescan.",
        test_by.format("%m/%d/%Y"), due.format("%m/%d/%Y"))));
    row.insert("Status Date", Val::D(today));
    row.insert("Vendor Dependency", s(vendor_dep));
    row.insert("Original Risk Rating", s(it.risk.fedramp()));
    row.insert("Risk Adjustment", s("No"));
    row.insert("False Positive", s("No"));
    row.insert("Operational Requirement", s("No"));
    row.insert("Supporting Documents", s(refs));
    row.insert("Comments", s(comments));
    row.insert("Auto-Approve", s("No"));
    row.insert("Binding Operational Directive 22-01 tracking", s(if it.in_kev() { "Yes" } else { "No" }));
    if let Some(k) = it.kev_due {
        row.insert("Binding Operational Directive 22-01 Due Date", Val::D(k));
    }
    row.insert("CVE", s(it.cves.iter().cloned().collect::<Vec<_>>().join(", ")));
    row.insert("Service Name", s(&st.service));
    fill_na(&POAM_COLUMNS, row)
}

fn first_token(s: &str) -> String {
    s.split(' ').next().unwrap_or("").to_string()
}

pub fn write_poam(items: &[&Item], st: &Settings, out: &Path) -> Result<String, String> {
    let today = chrono::Local::now().date_naive();
    let detect = detection_date(st)?;
    let (mut wb, sheet, header_row, cols) = open_sheet(st.poam_template.as_deref(), &st.poam_sheet, &POAM_COLUMNS)?;
    let ws = wb.sheet_by_name_mut(&sheet).map_err(|e| e.to_string())?;

    // find last used row + existing IDs / plugin IDs so appends don't collide
    let id_col = cols["POAM ID"];
    let src_col = cols.get("Weakness Source Identifier").copied();
    let asset_col = cols.get("Asset Identifier").copied();
    let prefix = st.prefix().trim().to_string();
    let stats = prefix_stats(ws, header_row, id_col);
    if !stats.is_empty() && !stats.contains_key(&prefix.to_ascii_uppercase()) {
        let found: Vec<&str> = stats.keys().map(String::as_str).collect();
        return Err(format!(
            "Wrong environment? The template's POAM IDs use {} but the selected environment's prefix is '{prefix}'. \
             Pick the matching environment or a different template.", found.join(", ")));
    }
    let mut max_num = stats.get(&prefix.to_ascii_uppercase()).map_or(0, |s| s.1).max(st.start_id.saturating_sub(1));
    let mut last = header_row;
    let mut existing: HashSet<(String, String)> = HashSet::new();
    for r in header_row + 1..=ws.highest_row() {
        if ws.value((id_col, r)).trim().is_empty() {
            continue;
        }
        last = r;
        if let Some(sc) = src_col {
            let asset = if st.per_host { asset_col.map(|ac| first_token(&ws.value((ac, r)))).unwrap_or_default() } else { String::new() };
            existing.insert((ws.value((sc, r)), asset));
        }
    }

    let mut sorted: Vec<&&Item> = items.iter().collect();
    sorted.sort_by(|a, b| b.pain.cmp(&a.pain));
    let (mut written, mut skipped) = (0, 0);
    for it in sorted {
        let asset = if st.per_host { it.assets.iter().next().map(|a| first_token(a)).unwrap_or_default() } else { String::new() };
        if existing.contains(&(it.plugin_id.clone(), asset)) {
            skipped += 1;
            continue;
        }
        max_num += 1;
        last += 1;
        let id = format!("{}{:0w$}", prefix, max_num, w = st.id_width);
        put_row(ws, last, &cols, build_row(it, id, st, detect, today));
        written += 1;
    }
    us::writer::xlsx::write(&wb, out).map_err(|e| format!("{}: {e}", out.display()))?;
    let kev = items.iter().filter(|i| i.in_kev()).count();
    let mut msg = format!("Wrote {written} POA&M item(s) to {}", out.display());
    if skipped > 0 {
        msg += &format!(", skipped {skipped} already present");
    }
    if kev > 0 {
        msg += &format!(", {kev} on CISA KEV");
    }
    Ok(msg)
}

pub fn write_inventory(assets: &[Asset], hosts: &BTreeMap<String, ScanHost>, st: &Settings, out: &Path) -> Result<String, String> {
    // tie Nessus hosts to inventory rows; anything Nessus saw that Defender doesn't know about is a gap
    let mut assets: Vec<Asset> = assets.to_vec();
    let index = InventoryIndex::new(&assets);
    let mut unmanaged: Vec<Asset> = Vec::new();
    for sh in hosts.values() {
        match index.find(sh) {
            Some(i) => {
                let a = &mut assets[i];
                a.scanned = true;
                if let Some(c) = sh.credentialed {
                    a.credentialed = Some(a.credentialed.unwrap_or(false) || c);
                }
                if a.netbios.is_empty() {
                    a.netbios = sh.netbios.clone();
                }
            }
            None => unmanaged.push(Asset {
                name: [&sh.fqdn, &sh.netbios, &sh.host].into_iter().find(|s| !s.is_empty()).cloned().unwrap_or_default(),
                source: "Nessus".into(),
                ips: if sh.ip.is_empty() { vec![] } else { vec![sh.ip.clone()] },
                fqdn: sh.fqdn.clone(),
                netbios: sh.netbios.clone(),
                scanned: true,
                credentialed: sh.credentialed,
                notes: vec!["Seen by Nessus but NOT in Defender inventory - onboard or document".into()],
                ..Default::default()
            }),
        }
    }

    let (mut wb, sheet, header_row, cols) = open_sheet(st.inv_template.as_deref(), &st.inv_sheet, &INVENTORY_COLUMNS)?;
    let ws = wb.sheet_by_name_mut(&sheet).map_err(|e| e.to_string())?;
    let mut last = last_used_row(ws, header_row, cols["UNIQUE ASSET IDENTIFIER"]);

    assets.sort_by_key(|a| a.name.to_lowercase());
    let unmanaged_n = unmanaged.len();
    let (mut not_scanned, mut total) = (0, 0);
    for mut a in assets.into_iter().chain(unmanaged) {
        if !a.scanned {
            not_scanned += 1;
            if !hosts.is_empty() {
                a.notes.push("In Defender inventory but NOT in latest Nessus scan".into());
            }
        }
        let auth = match (a.scanned, a.credentialed) {
            (true, Some(true)) => "Yes",
            (true, Some(false)) => "No",
            _ => "N/A",
        };
        let mut row: HashMap<&'static str, Val> = HashMap::new();
        row.insert("UNIQUE ASSET IDENTIFIER", s(&a.name));
        row.insert("IPv4 or IPv6 Address", s(a.ips.join("\n")));
        row.insert("Virtual", s(&a.virtual_));
        row.insert("Public", s(&a.public));
        row.insert("DNS Name or URL", s(&a.fqdn));
        row.insert("NetBIOS Name", s(&a.netbios));
        row.insert("MAC Address", s(&a.mac));
        row.insert("Authenticated Scan", s(auth));
        row.insert("Baseline Configuration Name", s(&st.baseline));
        row.insert("OS Name and Version", s(&a.os));
        row.insert("Location", s(if a.location.is_empty() { &st.location } else { &a.location }));
        row.insert("Asset Type", s(&a.kind));
        row.insert("Hardware Make/Model", s(&a.make));
        row.insert("In Latest Scan", s(if a.scanned { "Yes" } else { "No" }));
        row.insert("Patch Level", s(&a.patch));
        let mut notes = vec![format!("Source: {}", a.source)];
        notes.extend(a.notes.iter().cloned());
        row.insert("Comments", s(notes.join("\n")));
        row.insert("Serial #/Asset Tag#", s(&a.id));
        row.insert("System Administrator/Owner", s(&st.owner));
        row.insert("Application Administrator/Owner", s(&st.app_owner));
        row.insert("Function", s(&a.function));
        last += 1;
        put_row(ws, last, &cols, fill_na(&INVENTORY_COLUMNS, row));
        total += 1;
    }
    us::writer::xlsx::write(&wb, out).map_err(|e| format!("{}: {e}", out.display()))?;
    let mut msg = format!("Wrote {total} inventory row(s) to {}", out.display());
    if unmanaged_n > 0 {
        msg += &format!(", {unmanaged_n} scanned host(s) missing from Defender");
    }
    if !hosts.is_empty() && not_scanned > 0 {
        msg += &format!(", {not_scanned} Defender asset(s) not in scan");
    }
    Ok(msg)
}
