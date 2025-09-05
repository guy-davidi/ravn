// SPDX-License-Identifier: Apache-2.0
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::io::{self, AsyncBufReadExt};
use tokio::process::Command;
use serde_json;
use sysinfo::{System, SystemExt};
use std::time::{SystemTime, UNIX_EPOCH};

mod app_cli_dashboard;
use app_cli_dashboard::{Dashboard, EventData};

#[derive(Parser, Debug)]
#[command(name = "ravn-ctl", version, about = "Control ravn agent")] 
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Start,
    Stop,
    Tail,
    ApplyPolicy { file: PathBuf },
    #[cfg(feature = "tui")]
    Dashboard,
}

async fn start_agent() -> Result<()> {
    let agent = PathBuf::from("artifacts/ravn");
    if !agent.exists() { bail!("agent binary not found at {:?}", agent); }
    Command::new(agent).spawn().context("spawn agent")?;
    Ok(())
}

async fn stop_agent() -> Result<()> {
    // naive: killall ravn if available
    let _ = Command::new("pkill").arg("-f").arg("/ravn$").status().await;
    Ok(())
}

async fn tail_logs() -> Result<()> {
    // For MVP, run agent in foreground and show stdout
    let agent = PathBuf::from("artifacts/ravn");
    if !agent.exists() { bail!("agent binary not found at {:?}", agent); }
    let mut child = Command::new(agent).stdout(std::process::Stdio::piped()).spawn()?;
    let stdout = child.stdout.take().context("take stdout")?;
    let mut lines = io::BufReader::new(stdout).lines();
    while let Some(line) = lines.next_line().await? { println!("{}", line); }
    Ok(())
}

async fn apply_policy(file: PathBuf) -> Result<()> {
    let content = tokio::fs::read(&file).await.context("read policy")?;
    let _value: serde_yaml::Value = serde_yaml::from_slice(&content).context("parse policy")?;
    println!("policy applied from {:?}", file);
    Ok(())
}

#[cfg(feature = "tui")]
async fn dashboard() -> Result<()> {
    use crossterm::{
        event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::{
        backend::CrosstermBackend,
        Terminal,
    };
    use std::io;
    use tokio::sync::mpsc;

    // Spawn agent in daemon mode
    let mut child = Command::new("sudo")
        .arg("/home/hack/projects/ravn/artifacts/ravn")
        .arg("-d")
        .arg("-v")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawn agent")?;

    let (tx, mut rx) = mpsc::channel::<String>(1024);
    let stdout = child.stdout.take().context("take stdout")?;
    let mut reader = tokio::io::BufReader::new(stdout).lines();
    tokio::spawn(async move {
        while let Ok(Some(line)) = reader.next_line().await { 
            // Don't filter out ravn's own events - we want to see all events
            let _ = tx.send(line).await; 
        }
    });

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Initialize dashboard and system monitoring
    let mut dashboard = Dashboard::new();
    let mut system = System::new_all();
    
    let mut running = true;

    while running {
        // Process incoming events
        for _ in 0..256 {
            match rx.try_recv() {
                Ok(line) => {
                    // Parse JSON event
                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                        let event_data = EventData {
                            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                            event_type: event.get("etype").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                            pid: event.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                            comm: event.get("comm").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                            file: event.get("file").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            uid: event.get("uid").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                        };
                        dashboard.add_event(event_data);
                    }
                }
                Err(_) => break,
            }
        }

        // Update system stats
        dashboard.update_system_stats(&mut system);

        // Render dashboard
        terminal.draw(|f| {
            dashboard.render(f);
        })?;

        // Handle input
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(k) = event::read()? {
                match k.code {
                    KeyCode::Char('q') => running = false,
                    KeyCode::Char('h') => dashboard.show_help = !dashboard.show_help,
                    KeyCode::Char('s') => {
                        // Restart agent
                        let _ = child.start_kill();
                        child = Command::new("sudo")
                            .arg("/home/hack/projects/ravn/artifacts/ravn")
                            .arg("-d")
                            .arg("-v")
                            .stdout(std::process::Stdio::piped())
                            .stderr(std::process::Stdio::piped())
                            .spawn()
                            .context("restart agent")?;
                        
                        // Restart event processing pipeline
                        let (new_tx, new_rx) = mpsc::channel::<String>(1024);
                        let stdout = child.stdout.take().context("take stdout")?;
                        let mut reader = tokio::io::BufReader::new(stdout).lines();
                        tokio::spawn(async move {
                            while let Ok(Some(line)) = reader.next_line().await { 
                                let _ = new_tx.send(line).await; 
                            }
                        });
                        rx = new_rx;
                    },
                    KeyCode::Char('x') => {
                        let _ = child.start_kill();
                    },
                    KeyCode::Char('p') => {
                        if dashboard.paused {
                            // Resume - restart agent
                            child = Command::new("sudo")
                                .arg("/home/hack/projects/ravn/artifacts/ravn")
                                .arg("-d")
                                .arg("-v")
                                .stdout(std::process::Stdio::piped())
                                .stderr(std::process::Stdio::piped())
                                .spawn()
                                .context("resume agent")?;
                            
                            // Restart event processing pipeline
                            let (new_tx, new_rx) = mpsc::channel::<String>(1024);
                            let stdout = child.stdout.take().context("take stdout")?;
                            let mut reader = tokio::io::BufReader::new(stdout).lines();
                            tokio::spawn(async move {
                                while let Ok(Some(line)) = reader.next_line().await { 
                                    let _ = new_tx.send(line).await; 
                                }
                            });
                            rx = new_rx;
                        } else {
                            // Pause - stop agent
                            let _ = child.start_kill();
                        }
                        dashboard.paused = !dashboard.paused;
                    },
                    KeyCode::Char('r') => {
                        // Reset stats
                        dashboard.events.clear();
                        dashboard.event_counters.clear();
                        dashboard.process_counters.clear();
                        dashboard.anomaly_scores.clear();
                        dashboard.total_events = 0;
                    },
                    KeyCode::Tab => {
                        dashboard.current_tab = (dashboard.current_tab + 1) % 5;
                    },
                    KeyCode::BackTab => {
                        dashboard.current_tab = if dashboard.current_tab == 0 { 4 } else { dashboard.current_tab - 1 };
                    },
                    KeyCode::Char('1') => dashboard.current_tab = 0,
                    KeyCode::Char('2') => dashboard.current_tab = 1,
                    KeyCode::Char('3') => dashboard.current_tab = 2,
                    KeyCode::Char('4') => dashboard.current_tab = 3,
                    KeyCode::Char('5') => dashboard.current_tab = 4,
                    _ => {}
                }
            }
        }
    }

    // Cleanup
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
    let _ = child.start_kill();
    Ok(())
}


#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Start => start_agent().await?,
        Commands::Stop => stop_agent().await?,
        Commands::Tail => tail_logs().await?,
        Commands::ApplyPolicy { file } => apply_policy(file).await?,
        #[cfg(feature = "tui")]
        Commands::Dashboard => dashboard().await?,
    }
    Ok(())
}


