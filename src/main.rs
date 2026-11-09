// No console window behind the GUI on Windows release builds.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

//! PoamForge - Nessus CSV (+ Microsoft Defender inventory) -> FedRAMP Rev5 POA&M and Inventory Workbook.

mod model;
mod xlsx;

use chrono::NaiveDate;
use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use model::{Asset, FileKind, InventoryIndex, Item, Risk, ScanHost};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use xlsx::{Env, Settings};

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("PoamForge - Nessus to FedRAMP POA&M")
            .with_inner_size([1400.0, 860.0])
            .with_min_inner_size([900.0, 600.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    // files given on the command line (or dropped onto the .exe in Explorer) load at start
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    eframe::run_native("PoamForge", options, Box::new(move |cc| {
        let mut app = App::default();
        if let Some(envs) = load_envs() {
            app.st.envs = envs;
        }
        // cached KEV first so it works offline, then refresh it in the background
        app.load_kev_cache();
        app.update_kev(&cc.egui_ctx);
        if !args.is_empty() {
            app.add_files(args);
        }
        Ok(Box::new(app))
    }))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Pain,
    Risk,
    Plugin,
    Hosts,
    Name,
}

struct App {
    nessus_files: Vec<PathBuf>,
    inv_files: Vec<PathBuf>,
    kev: HashMap<String, NaiveDate>,
    kev_label: String,
    kev_rx: Option<Receiver<Result<HashMap<String, NaiveDate>, String>>>,
    st: Settings,

    items: Vec<Item>,
    hosts: BTreeMap<String, ScanHost>,
    assets: Vec<Asset>,
    matched_hosts: usize,

    selected: HashSet<String>,
    current: Option<String>,
    filter: String,
    min_risk: Risk,
    min_pain: u32,
    sort: SortKey,
    sort_desc: bool,
    status: String,
    status_err: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            nessus_files: vec![],
            inv_files: vec![],
            kev: HashMap::new(),
            kev_label: "not loaded".into(),
            kev_rx: None,
            st: Settings::default(),
            items: vec![],
            hosts: BTreeMap::new(),
            assets: vec![],
            matched_hosts: 0,
            selected: HashSet::new(),
            current: None,
            filter: String::new(),
            min_risk: Risk::Low,
            min_pain: 0,
            sort: SortKey::Pain,
            sort_desc: true,
            status: "Drop Nessus CSVs, Defender inventory CSVs, or the CISA KEV .json anywhere on this window.".into(),
            status_err: false,
        }
    }
}

fn risk_color(r: Risk) -> Color32 {
    match r {
        Risk::Critical => Color32::from_rgb(200, 80, 220),
        Risk::High => Color32::from_rgb(230, 70, 70),
        Risk::Medium => Color32::from_rgb(230, 180, 40),
        Risk::Low => Color32::from_rgb(90, 180, 90),
        Risk::None => Color32::GRAY,
    }
}

fn pain_color(p: u32) -> Color32 {
    if p >= 70 {
        Color32::from_rgb(230, 70, 70)
    } else if p >= 40 {
        Color32::from_rgb(230, 180, 40)
    } else {
        Color32::from_rgb(90, 180, 90)
    }
}

fn fname(p: &PathBuf) -> String {
    p.file_name().unwrap_or_default().to_string_lossy().into_owned()
}

/// %APPDATA%\PoamForge on Windows, ~/.config/PoamForge elsewhere.
fn config_dir() -> Option<PathBuf> {
    let base = std::env::var_os("APPDATA").or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("PoamForge"))
}

/// Environments live in a small tab-separated file: `name<TAB>prefix` per line.
fn envs_path() -> Option<PathBuf> {
    Some(config_dir()?.join("environments.tsv"))
}

/// Last downloaded (or manually loaded) CISA KEV catalog, used at startup and when offline.
fn kev_cache() -> Option<PathBuf> {
    Some(config_dir()?.join("kev.json"))
}

fn load_envs() -> Option<Vec<Env>> {
    let text = std::fs::read_to_string(envs_path()?).ok()?;
    let envs: Vec<Env> = text.lines().filter_map(|l| {
        let (name, prefix) = l.split_once('\t')?;
        Some(Env { name: name.trim().into(), prefix: prefix.trim().into() })
    }).collect();
    (!envs.is_empty()).then_some(envs)
}

fn save_envs(envs: &[Env]) -> Result<(), String> {
    let p = envs_path().ok_or("no config directory")?;
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let body: String = envs.iter().map(|e| format!("{}\t{}\n", e.name.replace('\t', " "), e.prefix.replace('\t', ""))).collect();
    std::fs::write(&p, body).map_err(|e| format!("{}: {e}", p.display()))
}

impl App {
    fn ok(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_err = false;
    }

    fn err(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_err = true;
    }

    /// Re-parse everything; keeps selections whose key still exists.
    fn rebuild(&mut self) {
        let today = chrono::Local::now().date_naive();
        let (mut items, hosts) = match model::load_findings(&self.nessus_files, self.st.include_info, self.st.per_host) {
            Ok(v) => v,
            Err(e) => return self.err(e),
        };
        let mut log = vec![];
        self.assets = if self.inv_files.is_empty() {
            vec![]
        } else {
            match model::load_inventory(&self.inv_files) {
                Ok((a, l)) => {
                    log = l;
                    a
                }
                Err(e) => return self.err(e),
            }
        };
        let index = InventoryIndex::new(&self.assets);
        let inv = (!self.assets.is_empty()).then_some(&index);
        model::label_assets(&mut items, &hosts, &self.assets, inv);
        self.matched_hosts = inv.map_or(0, |ix| hosts.values().filter(|h| ix.find(h).is_some()).count());
        for it in &mut items {
            it.kev_due = it.cves.iter().filter_map(|c| self.kev.get(c)).min().copied();
            it.compute_pain(today);
        }
        let keys: HashSet<String> = items.iter().map(|i| i.key.clone()).collect();
        self.selected.retain(|k| keys.contains(k));
        self.items = items;
        self.hosts = hosts;
        let mut msg = format!("{} finding(s) from {} host(s)", self.items.len(), self.hosts.len());
        if !self.assets.is_empty() {
            msg += &format!("; {} inventory asset(s), {} scanned host(s) matched", self.assets.len(), self.matched_hosts);
        }
        if !log.is_empty() {
            msg += &format!("  [{}]", log.join("; "));
        }
        self.ok(msg);
    }

    fn add_files(&mut self, paths: Vec<PathBuf>) {
        let mut bad = vec![];
        let mut changed = false;
        for p in paths {
            match model::sniff(&p) {
                FileKind::Nessus if !self.nessus_files.contains(&p) => {
                    self.nessus_files.push(p);
                    changed = true;
                }
                FileKind::Inventory if !self.inv_files.contains(&p) => {
                    self.inv_files.push(p);
                    changed = true;
                }
                FileKind::Kev => {
                    self.load_kev_file(p);
                    changed = true;
                }
                FileKind::Unknown => bad.push(fname(&p)),
                _ => {}
            }
        }
        if changed {
            self.rebuild();
        }
        if !bad.is_empty() {
            self.err(format!("Not a Nessus / Defender / KEV file: {}", bad.join(", ")));
        }
    }

    /// Load a KEV json picked by the user; it also becomes the cached copy.
    fn load_kev_file(&mut self, p: PathBuf) {
        match std::fs::read_to_string(&p).map_err(|e| e.to_string()).and_then(|s| model::parse_kev(&s).map(|k| (s, k))) {
            Ok((body, k)) => {
                self.kev_label = format!("{} CVEs ({})", k.len(), fname(&p));
                self.kev = k;
                if let Some(c) = kev_cache() {
                    let _ = std::fs::create_dir_all(c.parent().unwrap());
                    let _ = std::fs::write(c, body);
                }
            }
            Err(e) => self.err(e),
        }
    }

    fn load_kev_cache(&mut self) {
        let Some(c) = kev_cache() else { return };
        let Ok(body) = std::fs::read_to_string(&c) else { return };
        if let Ok(k) = model::parse_kev(&body) {
            let when = std::fs::metadata(&c).and_then(|m| m.modified()).ok()
                .map(|t| chrono::DateTime::<chrono::Local>::from(t).format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "?".into());
            self.kev_label = format!("{} CVEs (cached {when})", k.len());
            self.kev = k;
        }
    }

    /// Download the latest KEV catalog in the background (result picked up in `ui`).
    fn update_kev(&mut self, ctx: &egui::Context) {
        if self.kev_rx.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        let cache = kev_cache();
        std::thread::spawn(move || {
            let _ = tx.send(model::fetch_kev(cache.as_deref()));
            ctx.request_repaint();
        });
        self.kev_rx = Some(rx);
    }

    fn visible(&self) -> Vec<usize> {
        let q = self.filter.to_lowercase();
        let floor = if self.st.include_info { Risk::None } else { self.min_risk };
        let mut v: Vec<usize> = (0..self.items.len())
            .filter(|&i| {
                let it = &self.items[i];
                it.risk >= floor && it.pain >= self.min_pain && (q.is_empty() || it.search_text().contains(&q))
            })
            .collect();
        let items = &self.items;
        v.sort_by(|&a, &b| {
            let (x, y) = (&items[a], &items[b]);
            let o = match self.sort {
                SortKey::Pain => x.pain.cmp(&y.pain),
                SortKey::Risk => x.risk.cmp(&y.risk).then(x.pain.cmp(&y.pain)),
                SortKey::Plugin => x.plugin_id.parse::<u64>().unwrap_or(0).cmp(&y.plugin_id.parse::<u64>().unwrap_or(0)),
                SortKey::Hosts => x.assets.len().cmp(&y.assets.len()),
                SortKey::Name => y.name.to_lowercase().cmp(&x.name.to_lowercase()),
            };
            if self.sort_desc { o.reverse() } else { o }
        });
        v
    }

    /// Switch to the environment whose prefix the chosen POA&M template's IDs use.
    fn detect_env(&mut self) {
        let Some(t) = self.st.poam_template.clone() else { return };
        match xlsx::detect_env(&t, &self.st) {
            Ok((Some(i), found)) => {
                self.st.env = i;
                self.ok(format!("{}: environment '{}' ({found})", fname(&t), self.st.envs[i].name));
            }
            Ok((None, found)) => self.err(format!(
                "{}: IDs don't match any environment's prefix ({found}). Add that environment or check the template.", fname(&t))),
            Err(e) => self.err(e),
        }
    }

    fn export_poam(&mut self) {
        let chosen: Vec<&Item> = self.items.iter().filter(|i| self.selected.contains(&i.key)).collect();
        if chosen.is_empty() {
            return self.err("Nothing selected - tick findings first.");
        }
        let Some(out) = rfd::FileDialog::new().add_filter("Excel", &["xlsx"]).set_file_name("poam.xlsx").save_file() else { return };
        match xlsx::write_poam(&chosen, &self.st, &out) {
            Ok(m) => self.ok(m),
            Err(e) => self.err(e),
        }
    }

    fn export_inventory(&mut self) {
        if self.assets.is_empty() {
            return self.err("Load a Defender inventory CSV first.");
        }
        let Some(out) = rfd::FileDialog::new().add_filter("Excel", &["xlsx"]).set_file_name("inventory.xlsx").save_file() else { return };
        match xlsx::write_inventory(&self.assets, &self.hosts, &self.st, &out) {
            Ok(m) => self.ok(m),
            Err(e) => self.err(e),
        }
    }

    // ------------------------------------------------------------ panels

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            if ui.button("➕ Nessus CSV…").clicked() {
                if let Some(p) = rfd::FileDialog::new().add_filter("CSV", &["csv"]).pick_files() {
                    self.add_files(p);
                }
            }
            if ui.button("➕ Defender inventory CSV…").on_hover_text(
                "Defender for Endpoint: security.microsoft.com > Assets > Devices > Export\n\
                 Defender for Cloud: Azure portal > Defender for Cloud > Inventory > Download CSV").clicked() {
                if let Some(p) = rfd::FileDialog::new().add_filter("CSV", &["csv"]).pick_files() {
                    self.add_files(p);
                }
            }
            ui.separator();
            ui.label(format!("CISA KEV: {}", self.kev_label));
            if ui.button("Load KEV file…").clicked() {
                if let Some(p) = rfd::FileDialog::new().add_filter("JSON", &["json"]).pick_file() {
                    self.load_kev_file(p);
                    self.rebuild();
                }
            }
            let fetching = self.kev_rx.is_some();
            if ui.add_enabled(!fetching, egui::Button::new(if fetching { "Updating…" } else { "Update KEV" }))
                .on_hover_text("Download the latest CISA Known Exploited Vulnerabilities catalog (also done at startup)").clicked() {
                self.update_kev(ui.ctx());
            }
            ui.separator();
            if ui.button("Clear all").clicked() {
                *self = App { st: self.st.clone(), kev: std::mem::take(&mut self.kev), kev_label: self.kev_label.clone(), ..Default::default() };
            }
        });
        ui.horizontal_wrapped(|ui| {
            let mut remove: Option<(bool, usize)> = None;
            ui.label(RichText::new("Nessus:").strong());
            if self.nessus_files.is_empty() {
                ui.weak("none");
            }
            for (i, p) in self.nessus_files.iter().enumerate() {
                if ui.small_button(format!("{} ✖", fname(p))).on_hover_text("remove").clicked() {
                    remove = Some((true, i));
                }
            }
            ui.separator();
            ui.label(RichText::new("Defender:").strong());
            if self.inv_files.is_empty() {
                ui.weak("none");
            }
            for (i, p) in self.inv_files.iter().enumerate() {
                if ui.small_button(format!("{} ✖", fname(p))).on_hover_text("remove").clicked() {
                    remove = Some((false, i));
                }
            }
            if let Some((nessus, i)) = remove {
                if nessus { self.nessus_files.remove(i); } else { self.inv_files.remove(i); }
                self.rebuild();
            }
        });
    }

    fn settings_panel(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("POA&M");
            let mut rebuild = false;
            egui::Grid::new("poam").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
                let st = &mut self.st;
                for (label, v, hint) in [
                    ("Scan date", &mut st.scan_date, "YYYY-MM-DD = Original Detection Date"),
                    ("Point of Contact", &mut st.poc, "name, role"),
                    ("Resources Required", &mut st.resources, ""),
                    ("Service Name", &mut st.service, ""),
                    ("Controls", &mut st.controls, ""),
                    ("Detector Source", &mut st.detector, ""),
                ] {
                    ui.label(label);
                    ui.add(egui::TextEdit::singleline(v).hint_text(hint).desired_width(170.0));
                    ui.end_row();
                }
                ui.label("First POAM #");
                ui.add(egui::DragValue::new(&mut st.start_id).range(1..=999_999));
                ui.end_row();
                ui.label("ID zero-pad");
                ui.add(egui::DragValue::new(&mut st.id_width).range(1..=8));
                ui.end_row();
            });
            self.env_editor(ui);
            rebuild |= ui.checkbox(&mut self.st.per_host, "One item per host (not per plugin)").changed();
            rebuild |= ui.checkbox(&mut self.st.include_info, "Include informational (Risk=None)").changed();
            ui.horizontal(|ui| {
                ui.label("Template:");
                if ui.button("Choose…").on_hover_text("Official FedRAMP POA&M or an existing POA&M to append to").clicked() {
                    self.st.poam_template = rfd::FileDialog::new().add_filter("Excel", &["xlsx"]).pick_file();
                    self.detect_env();
                }
                if self.st.poam_template.is_some() && ui.small_button("✖").clicked() {
                    self.st.poam_template = None;
                }
            });
            ui.weak(self.st.poam_template.as_ref().map(fname).unwrap_or_else(|| "none - new workbook".into()));

            ui.add_space(10.0);
            ui.separator();
            ui.heading("Inventory workbook");
            egui::Grid::new("inv").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
                let st = &mut self.st;
                for (label, v, hint) in [
                    ("Baseline Config", &mut st.baseline, "e.g. CIS Win2022 L1"),
                    ("Location", &mut st.location, "for non-Azure assets"),
                    ("System Owner", &mut st.owner, ""),
                    ("App Owner", &mut st.app_owner, ""),
                ] {
                    ui.label(label);
                    ui.add(egui::TextEdit::singleline(v).hint_text(hint).desired_width(170.0));
                    ui.end_row();
                }
            });
            ui.horizontal(|ui| {
                ui.label("Template:");
                if ui.button("Choose…").on_hover_text("Official Integrated Inventory Workbook to append to").clicked() {
                    self.st.inv_template = rfd::FileDialog::new().add_filter("Excel", &["xlsx"]).pick_file();
                }
                if self.st.inv_template.is_some() && ui.small_button("✖").clicked() {
                    self.st.inv_template = None;
                }
            });
            ui.weak(self.st.inv_template.as_ref().map(fname).unwrap_or_else(|| "none - new workbook".into()));

            ui.add_space(10.0);
            ui.separator();
            ui.heading("Pain score");
            for (k, w) in model::PAIN_WEIGHTS {
                ui.label(format!("{k}: up to {w:.0}"));
            }
            ui.weak("severity = max(CVSSv3, CVSSv2, VPR); exploit = KEV / public exploit / EPSS; \
                     spread = host count; effort = EOL, no patch, upgrade, reboot; age = vuln age");
            if rebuild {
                self.rebuild();
            }
        });
    }

    fn env_editor(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Environment").strong());
            let st = &mut self.st;
            st.env = st.env.min(st.envs.len().saturating_sub(1));
            let cur = st.envs.get(st.env).map(|e| format!("{} ({})", e.name, e.prefix)).unwrap_or_default();
            egui::ComboBox::from_id_salt("env").selected_text(cur).show_ui(ui, |ui| {
                for (i, e) in st.envs.iter().enumerate() {
                    ui.selectable_value(&mut st.env, i, format!("{} ({})", e.name, e.prefix));
                }
            });
        });
        let mut changed = false;
        let mut remove = None;
        egui::CollapsingHeader::new("Edit environments").id_salt("envs").show(ui, |ui| {
            ui.weak("Each environment's prefix, e.g. V-PROD- / V-GOV-. Picking a POA&M template \
                     auto-selects the environment whose prefix its IDs use.");
            egui::Grid::new("envgrid").num_columns(3).spacing([6.0, 4.0]).show(ui, |ui| {
                ui.weak("Name");
                ui.weak("POAM ID prefix");
                ui.end_row();
                let n = self.st.envs.len();
                for (i, e) in self.st.envs.iter_mut().enumerate() {
                    changed |= ui.add(egui::TextEdit::singleline(&mut e.name).desired_width(90.0)).changed();
                    changed |= ui.add(egui::TextEdit::singleline(&mut e.prefix).hint_text("V-PROD-").desired_width(110.0)).changed();
                    if n > 1 && ui.small_button("✖").on_hover_text("remove").clicked() {
                        remove = Some(i);
                    }
                    ui.end_row();
                }
            });
            if ui.button("➕ Add environment").clicked() {
                self.st.envs.push(Env { name: format!("Env {}", self.st.envs.len() + 1), prefix: "V-".into() });
                changed = true;
            }
        });
        if let Some(i) = remove {
            self.st.envs.remove(i);
            self.st.env = self.st.env.min(self.st.envs.len() - 1);
            changed = true;
        }
        if changed {
            if let Err(e) = save_envs(&self.st.envs) {
                self.err(format!("Could not save environments: {e}"));
            }
        }
    }

    fn detail_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let n = self.selected.len();
            if ui.add_enabled(n > 0, egui::Button::new(RichText::new(format!("💾 Export POA&M ({n})")).strong())).clicked() {
                self.export_poam();
            }
            if ui.add_enabled(!self.assets.is_empty(), egui::Button::new("💾 Export Inventory Workbook")).clicked() {
                self.export_inventory();
            }
            ui.separator();
            let color = if self.status_err { Color32::from_rgb(230, 90, 90) } else { ui.visuals().text_color() };
            ui.label(RichText::new(&self.status).color(color));
        });
        ui.separator();
        let Some(it) = self.current.as_ref().and_then(|k| self.items.iter().find(|i| &i.key == k)) else {
            ui.weak("Click a row for details.");
            return;
        };
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.label(RichText::new(format!("{}  (plugin {})", it.name, it.plugin_id)).strong().size(15.0));
            let parts = model::PAIN_WEIGHTS
                .iter()
                .zip(it.pain_parts)
                .map(|((k, w), v)| format!("{k} {v:.0}/{w:.0}"))
                .collect::<Vec<_>>()
                .join("   ");
            ui.label(RichText::new(format!("Pain {}   [{parts}]", it.pain)).color(pain_color(it.pain)));
            let f = |v: Option<f64>| v.map_or("-".to_string(), |x| x.to_string());
            ui.label(format!(
                "Nessus {} -> FedRAMP {}   CVSSv3 {}   CVSSv2 {}   VPR {}   EPSS {}   Exploit {}   KEV due {}",
                it.risk.label(), it.risk.fedramp(), f(it.cvss3), f(it.cvss2), f(it.vpr), f(it.epss),
                if it.exploit_available { "yes" } else { "no" },
                it.kev_due.map_or("-".into(), |d| d.to_string())
            ));
            ui.label(format!("CVE: {}", if it.cves.is_empty() { "N/A".into() } else { it.cves.iter().cloned().collect::<Vec<_>>().join(", ") }));
            ui.label(format!("Assets ({}): {}", it.assets.len(), it.assets.iter().cloned().collect::<Vec<_>>().join(", ")));
            ui.label(format!("Synopsis: {}", it.synopsis));
            ui.label(format!("Solution: {}", it.solution));
            if !it.see_also.is_empty() {
                ui.label(format!("See also: {}", it.see_also.split_whitespace().collect::<Vec<_>>().join("  ")));
            }
        });
    }

    fn table(&mut self, ui: &mut egui::Ui) {
        let vis = self.visible();
        ui.horizontal(|ui| {
            ui.label("Filter");
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("name / plugin / CVE / host").desired_width(260.0));
            ui.label("Min risk");
            egui::ComboBox::from_id_salt("minrisk").selected_text(self.min_risk.label()).show_ui(ui, |ui| {
                for r in &Risk::ALL[1..] {
                    ui.selectable_value(&mut self.min_risk, *r, r.label());
                }
            });
            ui.label("Min pain");
            ui.add(egui::Slider::new(&mut self.min_pain, 0..=100));
            if ui.button("Select shown").on_hover_text("Ctrl+A").clicked() {
                self.selected.extend(vis.iter().map(|&i| self.items[i].key.clone()));
            }
            if ui.button("Clear shown").clicked() {
                for &i in &vis {
                    self.selected.remove(&self.items[i].key);
                }
            }
            ui.label(format!("{} shown, {}/{} selected", vis.len(), self.selected.len(), self.items.len()));
            ui.separator();
            let all_btn = egui::Button::new(RichText::new(format!("☑ Export ALL {} shown → POA&M", vis.len())).strong())
                .fill(Color32::from_rgb(31, 56, 100));
            if ui.add_enabled(!vis.is_empty(), all_btn).on_hover_text("Select every finding currently shown and export").clicked() {
                self.selected.extend(vis.iter().map(|&i| self.items[i].key.clone()));
                self.export_poam();
            }
        });
        ui.separator();

        // Ctrl+A = select all shown, Ctrl+E = export selected (unless typing in a text box)
        if !ui.ctx().egui_wants_keyboard_input() {
            let (ctrl_a, ctrl_e) = ui.input_mut(|i| {
                (i.consume_key(egui::Modifiers::COMMAND, egui::Key::A), i.consume_key(egui::Modifiers::COMMAND, egui::Key::E))
            });
            if ctrl_a {
                self.selected.extend(vis.iter().map(|&i| self.items[i].key.clone()));
            }
            if ctrl_e && !self.selected.is_empty() {
                self.export_poam();
            }
        }
        let all_shown_selected = !vis.is_empty() && vis.iter().all(|&i| self.selected.contains(&self.items[i].key));
        let mut header_toggle = false;

        if self.items.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("Drop Nessus CSV exports here\n(Defender inventory CSVs and the CISA KEV .json too)").size(20.0).weak());
            });
            return;
        }

        let mut clicked: Option<String> = None;
        let mut toggled: Option<String> = None;
        let mut sort_click: Option<SortKey> = None;
        TableBuilder::new(ui)
            .striped(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::exact(24.0))
            .column(Column::exact(44.0))
            .column(Column::exact(70.0))
            .column(Column::exact(76.0))
            .column(Column::exact(70.0))
            .column(Column::exact(50.0))
            .column(Column::exact(40.0))
            .column(Column::exact(44.0))
            .column(Column::remainder())
            .header(22.0, |mut h| {
                h.col(|ui| {
                    let mut all = all_shown_selected;
                    if ui.checkbox(&mut all, "").on_hover_text("select / clear all shown").changed() {
                        header_toggle = true;
                    }
                });
                for (label, key) in [("Pain", Some(SortKey::Pain)), ("Risk", Some(SortKey::Risk)), ("FedRAMP", None),
                                     ("Plugin", Some(SortKey::Plugin)), ("Hosts", Some(SortKey::Hosts)), ("KEV", None),
                                     ("Expl", None), ("Name", Some(SortKey::Name))] {
                    h.col(|ui| {
                        let arrow = match key {
                            Some(k) if k == self.sort => if self.sort_desc { " ⏷" } else { " ⏶" },
                            _ => "",
                        };
                        let r = ui.add(egui::Label::new(RichText::new(format!("{label}{arrow}")).strong()).sense(egui::Sense::click()));
                        if let (Some(k), true) = (key, r.clicked()) {
                            sort_click = Some(k);
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, vis.len(), |mut row| {
                    let it = &self.items[vis[row.index()]];
                    let sel = self.selected.contains(&it.key);
                    row.set_selected(self.current.as_ref() == Some(&it.key));
                    row.col(|ui| {
                        let mut c = sel;
                        if ui.checkbox(&mut c, "").changed() {
                            toggled = Some(it.key.clone());
                        }
                    });
                    row.col(|ui| { ui.label(RichText::new(it.pain.to_string()).color(pain_color(it.pain)).strong()); });
                    row.col(|ui| { ui.label(RichText::new(it.risk.label()).color(risk_color(it.risk))); });
                    row.col(|ui| { ui.label(it.risk.fedramp()); });
                    row.col(|ui| { ui.label(&it.plugin_id); });
                    row.col(|ui| { ui.label(it.assets.len().to_string()); });
                    row.col(|ui| { if it.in_kev() { ui.label(RichText::new("KEV").color(Color32::from_rgb(230, 70, 70)).strong()); } });
                    row.col(|ui| { if it.exploit_available { ui.label("yes"); } });
                    row.col(|ui| { ui.label(&it.name); });
                    if row.response().clicked() {
                        clicked = Some(it.key.clone());
                    }
                    if row.response().double_clicked() {
                        toggled = Some(it.key.clone());
                    }
                });
            });

        if header_toggle {
            for &i in &vis {
                let k = &self.items[i].key;
                if all_shown_selected { self.selected.remove(k); } else { self.selected.insert(k.clone()); }
            }
        }
        if let Some(k) = toggled {
            if !self.selected.remove(&k) {
                self.selected.insert(k);
            }
        }
        if let Some(k) = clicked {
            self.current = Some(k);
        }
        if let Some(k) = sort_click {
            if k == self.sort {
                self.sort_desc = !self.sort_desc;
            } else {
                self.sort = k;
                self.sort_desc = k != SortKey::Name;
            }
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &ui.ctx().clone();
        if let Some(rx) = &self.kev_rx {
            if let Ok(res) = rx.try_recv() {
                self.kev_rx = None;
                match res {
                    Ok(k) => {
                        self.kev_label = format!("{} CVEs (downloaded {})", k.len(), chrono::Local::now().format("%Y-%m-%d"));
                        self.kev = k;
                        self.rebuild();
                    }
                    // offline with a cached copy: keep using it, just say so
                    Err(e) if !self.kev.is_empty() => self.err(format!("{e} - using {}", self.kev_label)),
                    Err(e) => self.err(e),
                }
            }
        }
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect());
        if !dropped.is_empty() {
            self.add_files(dropped);
        }

        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(4.0);
            self.top_bar(ui);
            ui.add_space(2.0);
        });
        egui::Panel::left("settings").resizable(true).default_size(330.0).show(ui, |ui| self.settings_panel(ui));
        egui::Panel::bottom("detail").resizable(true).default_size(210.0).show(ui, |ui| self.detail_panel(ui));
        egui::CentralPanel::default().show(ui, |ui| self.table(ui));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SAMPLES=dir with sample.csv, mde.csv, mdc.csv, kev.json; writes poam.xlsx + inventory.xlsx there.
    #[test]
    fn end_to_end() {
        let Ok(dir) = std::env::var("SAMPLES") else { return };
        let d = PathBuf::from(dir);
        let mut app = App::default();
        app.st.scan_date = "2026-10-28".into();
        app.add_files(vec![d.join("sample.csv"), d.join("mde.csv"), d.join("mdc.csv"), d.join("kev.json")]);
        println!("{}", app.status);
        assert_eq!(app.items.len(), 3);
        app.selected = app.items.iter().map(|i| i.key.clone()).collect();
        let chosen: Vec<&Item> = app.items.iter().collect();
        println!("{}", xlsx::write_poam(&chosen, &app.st, &d.join("rs-poam.xlsx")).unwrap());
        println!("{}", xlsx::write_inventory(&app.assets, &app.hosts, &app.st, &d.join("rs-inventory.xlsx")).unwrap());
        // append into what we just wrote: everything must be skipped as duplicate
        app.st.poam_template = Some(d.join("rs-poam.xlsx"));
        println!("{}", xlsx::write_poam(&chosen, &app.st, &d.join("rs-poam2.xlsx")).unwrap());
    }

    /// Template IDs pick the environment; appending with the other env's prefix is refused.
    #[test]
    fn env_detection() {
        let Ok(dir) = std::env::var("SAMPLES") else { return };
        let d = PathBuf::from(dir);
        let mut app = App::default();
        app.st.envs = vec![
            Env { name: "PROD".into(), prefix: "V-PROD-".into() },
            Env { name: "GOV".into(), prefix: "V-GOV-".into() },
        ];
        app.st.id_width = 2;
        app.add_files(vec![d.join("sample.csv")]);
        let chosen: Vec<&Item> = app.items.iter().collect();
        let gov = d.join("env-gov.xlsx");
        app.st.env = 1;
        xlsx::write_poam(&chosen, &app.st, &gov).unwrap();

        app.st.env = 0;
        app.st.poam_template = Some(gov.clone());
        let (best, found) = xlsx::detect_env(&gov, &app.st).unwrap();
        println!("detected {best:?}: {found}");
        assert_eq!(best, Some(1));
        let e = xlsx::write_poam(&chosen, &app.st, &d.join("env-bad.xlsx")).unwrap_err();
        println!("{e}");
        assert!(e.contains("Wrong environment"));
        app.st.env = 1;
        println!("{}", xlsx::write_poam(&chosen, &app.st, &d.join("env-ok.xlsx")).unwrap());
    }
}
