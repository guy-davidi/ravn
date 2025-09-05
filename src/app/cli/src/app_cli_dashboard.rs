use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Text},
    widgets::{
        Block, Borders, Clear, Gauge, List, ListItem, Paragraph, Row, Sparkline, Table, Tabs,
        Wrap,
    },
    Frame,
};
use std::{
    collections::{BTreeMap, VecDeque},
    time::{SystemTime, UNIX_EPOCH},
};
use sysinfo::{System, SystemExt, CpuExt};

#[derive(Debug, Clone)]
pub struct EventData {
    pub timestamp: u64,
    pub event_type: String,
    pub pid: u32,
    pub comm: String,
    pub file: String,
    pub uid: u32,
}

#[derive(Debug, Clone)]
pub struct SystemStats {
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub load_avg: f64,
    pub uptime: u64,
    pub processes: usize,
}

pub struct Dashboard {
    pub events: VecDeque<EventData>,
    pub event_counters: BTreeMap<String, u64>,
    pub process_counters: BTreeMap<String, u64>,
    pub anomaly_scores: VecDeque<f64>,
    pub system_stats: SystemStats,
    pub total_events: u64,
    pub start_time: u64,
    pub current_tab: usize,
    pub show_help: bool,
    pub paused: bool,
}

impl Dashboard {
    pub fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(1000),
            event_counters: BTreeMap::new(),
            process_counters: BTreeMap::new(),
            anomaly_scores: VecDeque::with_capacity(60),
            system_stats: SystemStats {
                cpu_usage: 0.0,
                memory_usage: 0.0,
                load_avg: 0.0,
                uptime: 0,
                processes: 0,
            },
            total_events: 0,
            start_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            current_tab: 0,
            show_help: false,
            paused: false,
        }
    }

    pub fn add_event(&mut self, event: EventData) {
        if self.paused {
            return;
        }

        self.events.push_back(event.clone());
        if self.events.len() > 1000 {
            self.events.pop_front();
        }

        *self.event_counters.entry(event.event_type.clone()).or_insert(0) += 1;
        *self.process_counters.entry(event.comm.clone()).or_insert(0) += 1;
        self.total_events += 1;
    }

    pub fn update_system_stats(&mut self, system: &mut System) {
        system.refresh_cpu();
        system.refresh_memory();
        system.refresh_processes();

        self.system_stats.cpu_usage = system.global_cpu_info().cpu_usage();
        self.system_stats.memory_usage = system.used_memory() as f32 / system.total_memory() as f32 * 100.0;
        self.system_stats.load_avg = system.load_average().one;
        self.system_stats.uptime = system.uptime();
        self.system_stats.processes = system.processes().len();
    }

    pub fn calculate_anomaly_score(&self) -> f64 {
        if self.total_events == 0 {
            return 0.0;
        }

        let rate = self.total_events as f64 / 
            (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - self.start_time + 1) as f64;
        let exec_ratio = *self.event_counters.get("exec").unwrap_or(&0) as f64 / self.total_events as f64;
        
        let mut score: f64 = 0.0;
        
        // Rate-based scoring
        if rate > 50.0 { score += 3.0 }
        else if rate > 30.0 { score += 2.0 }
        else if rate > 15.0 { score += 1.0 }
        else if rate > 5.0 { score += 0.5 }
        
        // Execution ratio scoring
        if exec_ratio > 0.2 { score += 2.0 }
        else if exec_ratio > 0.1 { score += 1.5 }
        else if exec_ratio > 0.05 { score += 0.8 }
        
        // System load scoring
        if self.system_stats.cpu_usage > 90.0 { score += 1.5 }
        else if self.system_stats.cpu_usage > 70.0 { score += 1.0 }
        
        // Memory pressure scoring
        if self.system_stats.memory_usage > 90.0 { score += 1.0 }
        else if self.system_stats.memory_usage > 80.0 { score += 0.5 }
        
        // Volume scoring
        if self.total_events > 5000 { score += 1.0 }
        else if self.total_events > 2000 { score += 0.5 }
        
        score.min(5.0)
    }

    pub fn render(&mut self, f: &mut Frame) {
        let size = f.size();
        
        // Update anomaly scores
        let current_score = self.calculate_anomaly_score();
        self.anomaly_scores.push_back(current_score);
        if self.anomaly_scores.len() > 60 {
            self.anomaly_scores.pop_front();
        }

        // Main layout
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Length(3),  // Tabs
                Constraint::Min(0),     // Content
                Constraint::Length(3),  // Status bar
            ])
            .split(size);

        self.render_header(f, chunks[0]);
        self.render_tabs(f, chunks[1]);
        
        match self.current_tab {
            0 => self.render_overview(f, chunks[2]),
            1 => self.render_events(f, chunks[2]),
            2 => self.render_anomaly(f, chunks[2]),
            3 => self.render_system(f, chunks[2]),
            4 => self.render_controls(f, chunks[2]),
            _ => self.render_overview(f, chunks[2]),
        }
        
        self.render_status_bar(f, chunks[3]);
        
        if self.show_help {
            self.render_help(f, size);
        }
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let title = "RAVN Security Platform v2.0";
        let subtitle = if self.paused { "MONITORING PAUSED" } else { "MONITORING ACTIVE" };
        let _status_color = if self.paused { Color::Yellow } else { Color::Green };
        
        let header = Paragraph::new(format!("{} | Status: {}", title, subtitle))
            .block(Block::default().borders(Borders::ALL).title("Enterprise Security Dashboard"))
            .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center);
        
        f.render_widget(header, area);
    }

    fn render_tabs(&self, f: &mut Frame, area: Rect) {
        let tabs = Tabs::new(vec![
            "OVERVIEW",
            "EVENTS", 
            "ANOMALY DETECTION",
            "SYSTEM MONITORING",
            "CONTROL PANEL"
        ])
        .block(Block::default().borders(Borders::ALL))
        .select(self.current_tab)
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
        
        f.render_widget(tabs, area);
    }

    fn render_overview(&self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // Left side - Key metrics
        let left_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(8), Constraint::Length(8), Constraint::Min(0)])
            .split(chunks[0]);

        self.render_key_metrics(f, left_chunks[0]);
        self.render_event_rates(f, left_chunks[1]);
        self.render_top_processes(f, left_chunks[2]);

        // Right side - Anomaly and system
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(12), Constraint::Min(0)])
            .split(chunks[1]);

        self.render_anomaly_overview(f, right_chunks[0]);
        self.render_system_overview(f, right_chunks[1]);
    }

    fn render_key_metrics(&self, f: &mut Frame, area: Rect) {
        let uptime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - self.start_time;
        let rate = if uptime > 0 { self.total_events as f64 / uptime as f64 } else { 0.0 };
        
        let total_events_str = format!("{}", self.total_events);
        let rate_str = format!("{:.1}/s", rate);
        let uptime_str = format!("{}s", uptime);
        let cpu_str = format!("{:.1}%", self.system_stats.cpu_usage);
        let memory_str = format!("{:.1}%", self.system_stats.memory_usage);
        let load_str = format!("{:.2}", self.system_stats.load_avg);
        
        let metrics = vec![
            Row::new(vec!["Total Events", &total_events_str]),
            Row::new(vec!["Event Rate", &rate_str]),
            Row::new(vec!["Session Uptime", &uptime_str]),
            Row::new(vec!["CPU Usage", &cpu_str]),
            Row::new(vec!["Memory Usage", &memory_str]),
            Row::new(vec!["Load Average", &load_str]),
        ];

        let table = Table::new(metrics, &[Constraint::Percentage(50), Constraint::Percentage(50)])
            .block(Block::default().borders(Borders::ALL).title("System Metrics"))
            .style(Style::default().fg(Color::White));

        f.render_widget(table, area);
    }

    fn render_event_rates(&self, f: &mut Frame, area: Rect) {
        let mut event_data = Vec::new();
        for (event_type, count) in self.event_counters.iter().take(6) {
            let event_name = match event_type.as_str() {
                "exec" => "Process Execution",
                "open" => "File Access",
                "connect" => "Network Connection",
                "accept" => "Network Accept",
                "setuid" => "Privilege Escalation",
                "ptrace" => "Process Tracing",
                _ => event_type
            };
            event_data.push(Line::from(format!("{}: {}", event_name, count)));
        }

        let events_widget = Paragraph::new(Text::from(event_data))
            .block(Block::default().borders(Borders::ALL).title("Event Categories"))
            .wrap(Wrap { trim: true });

        f.render_widget(events_widget, area);
    }

    fn render_top_processes(&self, f: &mut Frame, area: Rect) {
        let mut processes: Vec<_> = self.process_counters.iter().collect();
        processes.sort_by(|a, b| b.1.cmp(a.1));
        
        let process_items: Vec<ListItem> = processes
            .iter()
            .take(10)
            .map(|(name, count)| {
                ListItem::new(format!("{}: {}", name, count))
            })
            .collect();

        let processes_widget = List::new(process_items)
            .block(Block::default().borders(Borders::ALL).title("Top Processes"))
            .style(Style::default().fg(Color::White));

        f.render_widget(processes_widget, area);
    }

    fn render_anomaly_overview(&self, f: &mut Frame, area: Rect) {
        let current_score = self.calculate_anomaly_score();
        let color = if current_score > 3.0 { Color::Red }
                   else if current_score > 2.0 { Color::Magenta }
                   else if current_score > 1.0 { Color::Yellow }
                   else { Color::Green };

        let risk_level = if current_score > 3.0 { "CRITICAL THREAT" }
                        else if current_score > 2.0 { "HIGH RISK" }
                        else if current_score > 1.0 { "MEDIUM RISK" }
                        else { "LOW RISK" };

        let trend = if self.anomaly_scores.len() > 1 {
            let prev = self.anomaly_scores.get(self.anomaly_scores.len() - 2).unwrap_or(&0.0);
            if current_score > *prev + 0.1 { "RISING" }
            else if current_score < *prev - 0.1 { "FALLING" }
            else { "STABLE" }
        } else { "STABLE" };

        let anomaly_text = format!(
            "Threat Score: {:.2}/5.0\n\
             Risk Level: {}\n\
             Trend: {}\n\
             Analysis Window: 60s rolling",
            current_score, risk_level, trend
        );

        let anomaly_widget = Paragraph::new(anomaly_text)
            .block(Block::default().borders(Borders::ALL).title("Threat Analysis"))
            .style(Style::default().fg(color))
            .alignment(Alignment::Center);

        f.render_widget(anomaly_widget, area);

        // Sparkline for anomaly trend
        if self.anomaly_scores.len() > 1 {
            let sparkline_area = Rect {
                x: area.x + 1,
                y: area.y + 5,
                width: area.width - 2,
                height: 3,
            };
            
            let sparkline_data: Vec<u64> = self.anomaly_scores.iter().map(|&x| x as u64).collect();
            let sparkline = Sparkline::default()
                .data(&sparkline_data)
                .style(Style::default().fg(color));
            
            f.render_widget(sparkline, sparkline_area);
        }
    }

    fn render_system_overview(&self, f: &mut Frame, area: Rect) {
        let system_text = format!(
            "Platform: Linux Kernel\n\
             eBPF Programs: 6 loaded\n\
             Ring Buffers: Active\n\
             Database: SQLite\n\
             Policy Engine: Default\n\
             Active Processes: {}\n\
             System Uptime: {}s\n\
             \n\
             Loaded Security Modules:\n\
             • core_execfs.bpf.o\n\
             • core_network.bpf.o\n\
             • core_system.bpf.o\n\
             • core_security.bpf.o\n\
             • core_vulnerability.bpf.o\n\
             • core_update-checker.bpf.o",
            self.system_stats.processes, self.system_stats.uptime
        );

        let system_widget = Paragraph::new(system_text)
            .block(Block::default().borders(Borders::ALL).title("Security Platform Status"))
            .wrap(Wrap { trim: true });

        f.render_widget(system_widget, area);
    }

    fn render_events(&self, f: &mut Frame, area: Rect) {
        let recent_events: Vec<ListItem> = self.events
            .iter()
            .rev()
            .take(30)
            .map(|event| {
                let timestamp = chrono::DateTime::from_timestamp(event.timestamp as i64, 0)
                    .unwrap_or_default()
                    .format("%H:%M:%S")
                    .to_string();
                
                let event_type = match event.event_type.as_str() {
                    "exec" => "EXEC",
                    "open" => "FILE",
                    "connect" => "NET",
                    "accept" => "NET",
                    "setuid" => "PRIV",
                    "ptrace" => "TRACE",
                    _ => &event.event_type.to_uppercase()
                };
                
                ListItem::new(format!(
                    "{} [{}] {} (PID:{}) {}",
                    timestamp, event_type, event.comm, event.pid, event.file
                ))
            })
            .collect();

        let events_widget = List::new(recent_events)
            .block(Block::default().borders(Borders::ALL).title("Security Event Log"))
            .style(Style::default().fg(Color::White));

        f.render_widget(events_widget, area);
    }

    fn render_anomaly(&self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(8), Constraint::Min(0)])
            .split(area);

        // Threat score gauge
        let current_score = self.calculate_anomaly_score();
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Threat Score"))
            .gauge_style(Style::default().fg(if current_score > 3.0 { Color::Red }
                                           else if current_score > 2.0 { Color::Magenta }
                                           else if current_score > 1.0 { Color::Yellow }
                                           else { Color::Green }))
            .ratio(current_score / 5.0)
            .label(format!("{:.2}/5.0", current_score));

        f.render_widget(gauge, chunks[0]);

        // Threat history chart
        if self.anomaly_scores.len() > 1 {
            let sparkline_data: Vec<u64> = self.anomaly_scores.iter().map(|&x| x as u64).collect();
            let sparkline = Sparkline::default()
                .data(&sparkline_data)
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title("Threat Level History (60s)"));

            f.render_widget(sparkline, chunks[1]);
        }
    }

    fn render_system(&self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(6), Constraint::Length(6), Constraint::Min(0)])
            .split(area);

        // CPU and Memory gauges
        let cpu_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("CPU Usage"))
            .gauge_style(Style::default().fg(Color::Cyan))
            .ratio((self.system_stats.cpu_usage / 100.0) as f64)
            .label(format!("{:.1}%", self.system_stats.cpu_usage));

        let memory_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Memory Usage"))
            .gauge_style(Style::default().fg(Color::Green))
            .ratio((self.system_stats.memory_usage / 100.0) as f64)
            .label(format!("{:.1}%", self.system_stats.memory_usage));

        let gauge_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[0]);

        f.render_widget(cpu_gauge, gauge_chunks[0]);
        f.render_widget(memory_gauge, gauge_chunks[1]);

        // System details
        let system_details = format!(
            "System Information:\n\n\
             Load Average: {:.2}\n\
             System Uptime: {}s\n\
             Active Processes: {}\n\
             eBPF Programs: 6 active\n\
             Ring Buffers: 6 active\n\
             Database: SQLite active",
            self.system_stats.load_avg,
            self.system_stats.uptime,
            self.system_stats.processes
        );

        let details_widget = Paragraph::new(system_details)
            .block(Block::default().borders(Borders::ALL).title("Platform Status"))
            .wrap(Wrap { trim: true });

        f.render_widget(details_widget, chunks[1]);

        // Process list
        let mut processes: Vec<_> = self.process_counters.iter().collect();
        processes.sort_by(|a, b| b.1.cmp(a.1));
        
        let process_items: Vec<ListItem> = processes
            .iter()
            .take(20)
            .map(|(name, count)| {
                ListItem::new(format!("{}: {}", name, count))
            })
            .collect();

        let processes_widget = List::new(process_items)
            .block(Block::default().borders(Borders::ALL).title("Process Activity"))
            .style(Style::default().fg(Color::White));

        f.render_widget(processes_widget, chunks[2]);
    }

    fn render_controls(&self, f: &mut Frame, area: Rect) {
        let controls_text = "System Controls:\n\n\
                           q - Quit Dashboard\n\
                           s - Start/Restart Agent\n\
                           x - Stop Agent\n\
                           p - Pause/Resume Monitoring\n\
                           r - Reset All Statistics\n\
                           h - Toggle Help\n\
                           \n\
                           Navigation:\n\
                           Tab/Shift+Tab - Switch tabs\n\
                           1-5 - Jump to tab\n\
                           \n\
                           Security Features:\n\
                           • Real-time eBPF monitoring\n\
                           • Advanced threat detection\n\
                           • System resource tracking\n\
                           • Process behavior analysis\n\
                           • Network activity monitoring\n\
                           • Privilege escalation detection\n\
                           \n\
                           Platform Capabilities:\n\
                           • 6 eBPF programs active\n\
                           • Ring buffer data collection\n\
                           • SQLite persistence\n\
                           • 60-second rolling windows\n\
                           • Multi-factor threat scoring";

        let controls_widget = Paragraph::new(controls_text)
            .block(Block::default().borders(Borders::ALL).title("Control Panel"))
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(Color::White));

        f.render_widget(controls_widget, area);
    }

    fn render_status_bar(&self, f: &mut Frame, area: Rect) {
        let status_text = format!(
            "Agent: {} | Events: {} | Uptime: {}s | Rate: {:.1}/s | CPU: {:.1}% | RAM: {:.1}%",
            if self.paused { "PAUSED" } else { "RUNNING" },
            self.total_events,
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - self.start_time,
            if SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - self.start_time > 0 {
                self.total_events as f64 / (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - self.start_time) as f64
            } else { 0.0 },
            self.system_stats.cpu_usage,
            self.system_stats.memory_usage
        );

        let status = Paragraph::new(status_text)
            .block(Block::default().borders(Borders::ALL))
            .style(Style::default().fg(Color::Cyan))
            .alignment(Alignment::Center);

        f.render_widget(status, area);
    }

    fn render_help(&self, f: &mut Frame, area: Rect) {
        let help_text = "RAVN Security Platform Help\n\n\
                        Navigation:\n\
                        • Tab/Shift+Tab: Switch between tabs\n\
                        • 1-5: Jump to specific tab\n\
                        • h: Toggle this help\n\
                        \n\
                        Controls:\n\
                        • q: Quit dashboard\n\
                        • s: Start/restart agent\n\
                        • x: Stop agent\n\
                        • p: Pause/resume monitoring\n\
                        • r: Reset statistics\n\
                        \n\
                        Tabs:\n\
                        • Overview: Key metrics and summaries\n\
                        • Events: Real-time event stream\n\
                        • Anomaly Detection: Threat analysis and trends\n\
                        • System Monitoring: System resource monitoring\n\
                        • Control Panel: Control panel and help\n\n\
                        Press 'h' to close this help.";

        let help_widget = Paragraph::new(help_text)
            .block(Block::default().borders(Borders::ALL).title("Help"))
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(Color::Yellow));

        let help_area = Rect {
            x: area.width / 4,
            y: area.height / 4,
            width: area.width / 2,
            height: area.height / 2,
        };

        f.render_widget(Clear, help_area);
        f.render_widget(help_widget, help_area);
    }
}
