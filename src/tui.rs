use crossterm::{event::{self, Event, KeyCode}, terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}};
use ratatui::{prelude::*, widgets::*};
use std::{collections::{HashMap, HashSet}, fs, io, time::{Duration, Instant}};

fn parent(org: &str) -> &str {
    let o = org.to_lowercase();
    if o.contains("google") { "Google" } else if o.contains("meta")||o.contains("facebook") { "Meta" }
    else if o.contains("microsoft") { "Microsoft" } else if o.contains("amazon") { "Amazon" }
    else if o.contains("cloudflare") { "Cloudflare" } else if o.contains("fastly") { "Fastly" }
    else if o.contains("segment")||o.contains("twilio") { "Twilio" } else { org }
}

struct State {
    jar: HashMap<String, usize>,          // org -> #sites cookied
    live: HashMap<String, HashSet<String>>, // org -> live endpoints
    recent: Vec<String>,                  // rolling flow lines
    total_flows: usize,
    sync_edges: usize,
}

fn load() -> State {
    let mut jar: HashMap<String, usize> = HashMap::new();
    let mut sites: HashMap<String, HashSet<String>> = HashMap::new();
    for l in fs::read_to_string("data/cookies.tsv").unwrap_or_default().lines().skip(1) {
        let f: Vec<&str> = l.split('\t').collect();
        // cookies.tsv: browser(0) host(1) name(2) tracker_org(3) id_kind(4) flags(5)
        if f.len() < 6 || f[3] == "-" { continue; }
        sites.entry(parent(f[3]).into()).or_default().insert(f[1].trim_start_matches('.').into());
    }
    for (o, s) in sites { jar.insert(o, s.len()); }

    // ASN data is data/static/asn_v4.tsv + asn_v6.tsv, loaded and binary-searched by
    // AsnDb. This used to parse a data/asn_ranges.txt that nothing ever wrote, so every
    // lookup returned None and no flow was ever attributed to a company.
    let asn_db = crate::asn::AsnDb::load();
    let lookup = |ip: &str| -> Option<String> { asn_db.lookup(ip).map(|o| parent(&o).to_string()) };

    let flows = fs::read_to_string("data/flows.log").unwrap_or_default();
    let all: Vec<&str> = flows.lines().collect();
    let mut live: HashMap<String, HashSet<String>> = HashMap::new();
    for l in &all {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 5 { continue; }
        let ip = f[3].rsplit_once(':').map(|(i,_)| i).unwrap_or(f[3]);
        if let Some(org) = lookup(ip) { live.entry(org).or_default().insert(ip.into()); }
    }
    let sync_edges = fs::read_to_string("data/sync_edges.tsv")
        .map(|c| c.lines().count().saturating_sub(1)).unwrap_or(0);
    let recent = all.iter().rev().take(8).map(|s| s.to_string()).collect();
    State { jar, live, recent, total_flows: all.len(), sync_edges }
}

pub fn run() -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut out = io::stdout();
    crossterm::execute!(out, EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(out))?;
    let mut st = load();
    let mut last = Instant::now();

    loop {
        term.draw(|f| {
            let z = Layout::vertical([Constraint::Length(3), Constraint::Min(6),
                Constraint::Length(10)]).split(f.area());

            let confirmed = st.jar.keys().filter(|o| st.live.contains_key(*o)).count();
            let head = Paragraph::new(Line::from(vec![
                Span::styled(" PANOPTICON ", Style::new().bg(Color::Red).fg(Color::White).bold()),
                Span::raw(format!("  flows:{}  jar-orgs:{}  ", st.total_flows, st.jar.len())),
                Span::styled(format!("⚡ active-sharing:{confirmed} ",),
                    Style::new().fg(if confirmed>0 {Color::Red} else {Color::Green}).bold()),
                Span::styled(format!("⇄ broker-sync:{} ", st.sync_edges),
                    Style::new().fg(if st.sync_edges>0 {Color::Magenta} else {Color::Green}).bold()),
            ])).block(Block::bordered());
            f.render_widget(head, z[0]);

            let mut ordered: Vec<(&String,&usize)> = st.jar.iter().collect();
            ordered.sort_by(|a,b| {
                let (la,lb)=(st.live.contains_key(a.0), st.live.contains_key(b.0));
                lb.cmp(&la).then(b.1.cmp(a.1))
            });
            let rows: Vec<Row> = ordered.iter().map(|&(org, n)| {
                let is_live = st.live.contains_key(org);
                let (flag, col) = if is_live { ("⚡ ACTIVE", Color::Red) }
                                  else { ("· dormant", Color::DarkGray) };
                let eps = st.live.get(org).map(|s| s.len()).unwrap_or(0);
                Row::new(vec![org.clone(), format!("{n} sites"),
                    format!("{eps} live"), flag.into()]).style(Style::new().fg(col))
            }).collect();
            let tbl = Table::new(rows, [Constraint::Min(16), Constraint::Length(10),
                Constraint::Length(10), Constraint::Length(12)])
                .header(Row::new(vec!["TRACKER","IN JAR","ON WIRE","STATUS"])
                    .style(Style::new().bold().fg(Color::Yellow)))
                .block(Block::bordered().title(" who is tracking you "));
            f.render_widget(tbl, z[1]);

            let feed: Vec<Line> = st.recent.iter().map(|l| {
                let f: Vec<&str> = l.split('\t').collect();
                Line::from(format!("{:<16} {:<30} {}",
                    f.get(0).unwrap_or(&""), f.get(3).unwrap_or(&""), f.get(4).unwrap_or(&"")))
            }).collect();
            f.render_widget(Paragraph::new(feed)
                .block(Block::bordered().title(" live egress (q to quit) ")), z[2]);
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                if matches!(k.code, KeyCode::Char('q')|KeyCode::Esc) { break; }
            }
        }
        if last.elapsed() > Duration::from_secs(2) { st = load(); last = Instant::now(); }
    }
    disable_raw_mode()?;
    crossterm::execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    Ok(())
}
