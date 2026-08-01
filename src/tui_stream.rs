use crate::wire::{sock_path, FlowEvent};
use crossterm::{event::{self, Event, KeyCode}, terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}};
use ratatui::{prelude::*, widgets::*};
use std::{collections::{HashMap, HashSet, VecDeque}, fs, io::{self, BufRead, BufReader},
          os::unix::net::UnixStream, sync::mpsc, time::Duration};

fn parent(o:&str)->&str{let l=o.to_lowercase();
    if l.contains("google"){"Google"}else if l.contains("meta")||l.contains("facebook"){"Meta"}
    else if l.contains("microsoft"){"Microsoft"}else if l.contains("amazon"){"Amazon"}
    else if l.contains("cloudflare"){"Cloudflare"}else if l.contains("fastly"){"Fastly"}
    else if l.contains("segment")||l.contains("twilio"){"Twilio"}else{o}}

fn jar() -> HashMap<String, usize> {
    let mut sites: HashMap<String, HashSet<String>> = HashMap::new();
    for l in fs::read_to_string("data/cookies.tsv").unwrap_or_default().lines().skip(1) {
        let f:Vec<&str>=l.split('\t').collect();
        if f.len()<5 || f[4]=="-" {continue;}
        sites.entry(parent(f[4]).into()).or_default().insert(f[1].trim_start_matches('.').into());
    }
    sites.into_iter().map(|(k,v)|(k,v.len())).collect()
}

pub fn run() -> anyhow::Result<()> {
    let path = sock_path();
    let stream = UnixStream::connect(&path)
        .map_err(|e| anyhow::anyhow!("cannot connect {path}: {e} — is the daemon running?"))?;
    let (tx, rx) = mpsc::channel::<FlowEvent>();
    std::thread::spawn(move || {
        let rdr = BufReader::new(stream);
        for line in rdr.lines().map_while(Result::ok) {
            if let Ok(ev) = serde_json::from_str::<FlowEvent>(&line) { let _ = tx.send(ev); }
        }
    });

    let jar = jar();
    let sync_edges = fs::read_to_string("data/sync_edges.tsv")
        .map(|c| c.lines().count().saturating_sub(1)).unwrap_or(0);
    let mut live: HashMap<String, HashSet<String>> = HashMap::new();
    let mut feed: VecDeque<FlowEvent> = VecDeque::new();
    let mut total = 0usize;

    enable_raw_mode()?;
    let mut out = io::stdout();
    crossterm::execute!(out, EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(out))?;

    loop {
        // drain everything queued since last frame — this is the "instant" part
        while let Ok(ev) = rx.try_recv() {
            total += 1;
            if let Some(org) = &ev.org {
                if jar.contains_key(org) { live.entry(org.clone()).or_default().insert(ev.ip.clone()); }
            }
            feed.push_front(ev);
            if feed.len() > 12 { feed.pop_back(); }
        }

        term.draw(|f| {
            let z = Layout::vertical([Constraint::Length(3), Constraint::Min(6),
                Constraint::Length(14)]).split(f.area());
            let confirmed = jar.keys().filter(|o| live.contains_key(*o)).count();
            let head = Paragraph::new(Line::from(vec![
                Span::styled(" PANOPTICON ", Style::new().bg(Color::Red).fg(Color::White).bold()),
                Span::styled(" ●LIVE ", Style::new().fg(Color::Green).bold()),
                Span::raw(format!(" flows:{total} jar:{} ", jar.len())),
                Span::styled(format!("⚡ active:{confirmed} "),
                    Style::new().fg(if confirmed>0{Color::Red}else{Color::Green}).bold()),
                Span::styled(format!("⇄ sync:{sync_edges} "),
                    Style::new().fg(if sync_edges>0{Color::Magenta}else{Color::Green}).bold()),
            ])).block(Block::bordered());
            f.render_widget(head, z[0]);

            let mut ord:Vec<(&String,&usize)> = jar.iter().collect();
            ord.sort_by(|a,b|{let(la,lb)=(live.contains_key(a.0),live.contains_key(b.0));
                lb.cmp(&la).then(b.1.cmp(a.1))});
            let rows:Vec<Row> = ord.iter().map(|&(org,n)|{
                let on=live.contains_key(org);
                let(flag,col)=if on{("⚡ ACTIVE",Color::Red)}else{("· dormant",Color::DarkGray)};
                let eps=live.get(org).map(|s|s.len()).unwrap_or(0);
                Row::new(vec![org.clone(),format!("{n} sites"),format!("{eps} live"),flag.into()])
                    .style(Style::new().fg(col))
            }).collect();
            f.render_widget(Table::new(rows,[Constraint::Min(16),Constraint::Length(10),
                Constraint::Length(10),Constraint::Length(12)])
                .header(Row::new(vec!["TRACKER","IN JAR","ON WIRE","STATUS"])
                    .style(Style::new().bold().fg(Color::Yellow)))
                .block(Block::bordered().title(" who is tracking you ")), z[1]);

            let lines:Vec<Line> = feed.iter().map(|e|{
                let tag = e.org.as_deref().filter(|o| jar.contains_key(*o));
                let base = format!("{:<15} {:<26} {}", e.comm,
                    format!("{}:{}", e.ip, e.port),
                    if e.host!="?" {e.host.clone()} else {e.org.clone().unwrap_or("?".into())});
                if tag.is_some() { Line::from(base).style(Style::new().fg(Color::Red)) }
                else { Line::from(base).style(Style::new().fg(Color::Gray)) }
            }).collect();
            f.render_widget(Paragraph::new(lines)
                .block(Block::bordered().title(" live egress — streaming (q to quit) ")), z[2]);
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(k)=event::read()? {
                if matches!(k.code, KeyCode::Char('q')|KeyCode::Esc){break;}
            }
        }
    }
    disable_raw_mode()?;
    crossterm::execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    Ok(())
}
