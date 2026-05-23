//! # Integrity Dashboard — Multi-Tenant Operations Center
//!
//! Interactive terminal for multi-repository audit surveillance.  Two
//! operating modes:
//!
//! ## TargetSelection
//! Scans a gauntlet base directory for cloned repositories and renders them
//! as a navigable list.  Repositories with a `bounce_log.ndjson` modified
//! within the last 10 seconds are tagged `[ AUDIT ACTIVE ]` (blinking).
//!
//! Keys: `↑` / `↓` to navigate · `Enter` to select · `q` to quit.
//!
//! ## ActiveSurveillance
//! Full-screen per-repo view with three tabs:
//! - **Live Telemetry**: PR delta feed with detailed finding breakdown.
//! - **Structural Topology**: top-10 C++ compile-time silos (transitive reach).
//! - **Swarm Intelligence**: structural clone cluster detection table.
//!
//! Keys: `←` / `→` to change tab · `Esc` / `Backspace` to return · `q` to quit.

use std::{
    error::Error,
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table, Tabs,
    },
    Frame, Terminal,
};

// ─── Timing constants ─────────────────────────────────────────────────────────

/// How often the selection list rescans for new/removed repositories.
const TARGET_SCAN_INTERVAL: Duration = Duration::from_secs(2);

/// A `bounce_log.ndjson` modified within this window is considered audit-active.
const ACTIVE_STRIKE_WINDOW: Duration = Duration::from_secs(10);

/// How often to check whether `bounce_log.ndjson` has been modified.
const LOG_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How often to retry the C++ graph build while it has produced no nodes.
const GRAPH_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum time to block waiting for a terminal event on each iteration.
const TICK: Duration = Duration::from_millis(100);

// ─── PR log entry ─────────────────────────────────────────────────────────────

struct WoprEntry {
    pr_number: u64,
    slop_score: u32,
    /// True when `antipattern_details` contains `architecture:compile_time_bloat`.
    is_threat: bool,
    /// True when `antipattern_details` contains `architecture:graph_entanglement`.
    is_entangled: bool,
    /// Non-zero when a `deflation_bonus:severed=N` marker is present.
    edges_severed: usize,
    /// Backlog Pruner verdict: `SEMANTIC_NULL`, `GHOST_COLLISION`, or `UNWIRED_ISLAND`.
    necrotic_flag: Option<String>,
    /// Count of structural clone pairs (Swarm Clones).
    logic_clones_found: u32,
    /// Full antipattern detail strings for the Telemetry tab.
    antipattern_details: Vec<String>,
    /// PR numbers that share similar code structure with this PR.
    collided_pr_numbers: Vec<u32>,
}

// ─── Repository list ──────────────────────────────────────────────────────────

/// One discovered repository entry in the selection screen.
struct Target {
    /// Display name — `<owner>/<repo>` for two-level paths, bare name otherwise.
    name: String,
    /// Absolute path to the repository root.
    path: PathBuf,
    /// `true` when `bounce_log.ndjson` was modified within [`ACTIVE_STRIKE_WINDOW`].
    is_active: bool,
}

/// Returns `true` when the `bounce_log.ndjson` at `log_path` was modified
/// within [`ACTIVE_STRIKE_WINDOW`] of now.
fn log_active(log_path: &Path) -> bool {
    std::fs::metadata(log_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|d| d < ACTIVE_STRIKE_WINDOW)
        .unwrap_or(false)
}

/// Scan `base_dir` for analysed repositories (depth 1 and 2).
///
/// A directory qualifies when it contains a `.git` subdirectory (in-flight
/// clone/fetch) OR a `.janitor` subdirectory (at-rest after analysis).
/// This ensures repos are visible during active packfile fetches before the
/// hyper-drive engine has had a chance to create `.janitor/`.
/// At depth 2 (`<owner>/<repo>`) the display name includes the owner prefix.
fn scan_targets(base_dir: &Path) -> Vec<Target> {
    let mut targets = Vec::new();

    let Ok(level1) = std::fs::read_dir(base_dir) else {
        return targets;
    };

    for e1 in level1.flatten() {
        let p1 = e1.path();
        if !p1.is_dir() {
            continue;
        }

        // Depth-1 target: <base>/<repo>/ with .git or .janitor
        let has_git = p1.join(".git").exists();
        let has_janitor = p1.join(".janitor").exists();
        if has_git || has_janitor {
            let name = p1
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let log_path = p1.join(".janitor").join("bounce_log.ndjson");
            targets.push(Target {
                is_active: log_active(&log_path),
                name,
                path: p1,
            });
            continue;
        }

        // Depth-2 targets: <base>/<owner>/<repo>/ with .git or .janitor
        let Ok(level2) = std::fs::read_dir(&p1) else {
            continue;
        };
        for e2 in level2.flatten() {
            let p2 = e2.path();
            if !p2.is_dir() {
                continue;
            }
            let has_git2 = p2.join(".git").exists();
            let has_janitor2 = p2.join(".janitor").exists();
            if !has_git2 && !has_janitor2 {
                continue;
            }
            let owner = p1.file_name().unwrap_or_default().to_string_lossy();
            let repo = p2.file_name().unwrap_or_default().to_string_lossy();
            let name = format!("{owner}/{repo}");
            let log_path = p2.join(".janitor").join("bounce_log.ndjson");
            targets.push(Target {
                is_active: log_active(&log_path),
                name,
                path: p2,
            });
        }
    }

    targets.sort_by(|a, b| a.name.cmp(&b.name));
    targets
}

// ─── Selection state ──────────────────────────────────────────────────────────

/// State for the `TargetSelection` mode.
struct SelectionState {
    base_dir: PathBuf,
    targets: Vec<Target>,
    /// Ratatui stateful list cursor.
    list_state: ListState,
    /// When the repository list was last rescanned.
    last_scan: Instant,
}

impl SelectionState {
    fn new(base_dir: PathBuf) -> Self {
        let targets = scan_targets(&base_dir);
        let mut list_state = ListState::default();
        if !targets.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            base_dir,
            targets,
            list_state,
            last_scan: Instant::now(),
        }
    }

    /// Path of the currently highlighted repository, or `None` if the list is empty.
    fn selected_path(&self) -> Option<PathBuf> {
        let idx = self.list_state.selected()?;
        self.targets.get(idx).map(|t| t.path.clone())
    }

    fn move_up(&mut self) {
        if self.targets.is_empty() {
            return;
        }
        let i = self.list_state.selected().unwrap_or(0);
        let prev = if i == 0 {
            self.targets.len() - 1
        } else {
            i - 1
        };
        self.list_state.select(Some(prev));
    }

    fn move_down(&mut self) {
        if self.targets.is_empty() {
            return;
        }
        let i = self.list_state.selected().unwrap_or(0);
        self.list_state.select(Some((i + 1) % self.targets.len()));
    }

    /// Rescan the gauntlet directory, preserving cursor position by name.
    fn rescan(&mut self) {
        let current_name = self
            .list_state
            .selected()
            .and_then(|i| self.targets.get(i))
            .map(|t| t.name.clone());

        self.targets = scan_targets(&self.base_dir);
        self.last_scan = Instant::now();

        let new_idx = current_name
            .and_then(|n| self.targets.iter().position(|t| t.name == n))
            .unwrap_or(0);

        if self.targets.is_empty() {
            self.list_state.select(None);
        } else {
            self.list_state
                .select(Some(new_idx.min(self.targets.len() - 1)));
        }
    }

    /// Called every tick: rescan if the interval has elapsed.
    fn tick(&mut self) {
        if Instant::now().duration_since(self.last_scan) >= TARGET_SCAN_INTERVAL {
            self.rescan();
        }
    }
}

// ─── Surveillance state ───────────────────────────────────────────────────────

/// State for the `ActiveSurveillance` mode (single-repo view).
struct WoprState {
    path: PathBuf,
    log_path: PathBuf,
    /// Top-10 C++ silos: `(label, direct_imports, transitive_reach)`.
    ranked: Vec<(String, usize, usize)>,
    entries: Vec<WoprEntry>,
    /// `true` once the graph build produced at least one node.
    graph_ready: bool,
    log_mtime: Option<SystemTime>,
    last_log_check: Instant,
    last_graph_attempt: Instant,
    /// Currently active tab: 0=Live Telemetry, 1=Structural Topology, 2=Swarm Intelligence.
    active_tab: usize,
}

impl WoprState {
    fn new(path: PathBuf) -> Self {
        let log_path = path.join(".janitor").join("bounce_log.ndjson");
        let now = Instant::now();
        let far_past = now
            .checked_sub(LOG_POLL_INTERVAL + Duration::from_secs(1))
            .unwrap_or(now);
        Self {
            path,
            log_path,
            ranked: Vec::new(),
            entries: Vec::new(),
            graph_ready: false,
            log_mtime: None,
            last_log_check: far_past,
            last_graph_attempt: far_past,
            active_tab: 0,
        }
    }

    fn try_build_graph(&mut self) {
        self.last_graph_attempt = Instant::now();

        // Load the pre-computed silo ranking written by `janitor hyper-drive`.
        // The file is absent when hyper-drive has not yet run — poll every 5 s
        // until it appears.
        let json_path = self.path.join(".janitor").join("wopr_graph.json");
        let Ok(json_str) = std::fs::read_to_string(&json_path) else {
            return;
        };
        let Ok(ranked) = serde_json::from_str::<Vec<(String, usize, usize)>>(&json_str) else {
            return;
        };
        self.ranked = ranked;
        self.graph_ready = true;
    }

    fn poll_log(&mut self) {
        self.last_log_check = Instant::now();

        let current_mtime = std::fs::metadata(&self.log_path)
            .and_then(|m| m.modified())
            .ok();

        if current_mtime == self.log_mtime {
            return;
        }
        self.log_mtime = current_mtime;
        self.entries = load_log(&self.log_path);
    }

    fn tick(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_log_check) >= LOG_POLL_INTERVAL {
            self.poll_log();
        }
        if !self.graph_ready && now.duration_since(self.last_graph_attempt) >= GRAPH_RETRY_INTERVAL
        {
            self.try_build_graph();
        }
    }
}

// ─── Top-level mode ───────────────────────────────────────────────────────────

enum WoprMode {
    Selection(SelectionState),
    Surveillance(WoprState),
}

/// Top-level application container.
struct WoprApp {
    base_dir: PathBuf,
    mode: WoprMode,
}

impl WoprApp {
    fn new(base_dir: PathBuf) -> Self {
        let sel = SelectionState::new(base_dir.clone());
        Self {
            base_dir,
            mode: WoprMode::Selection(sel),
        }
    }

    /// Transition from Selection → Surveillance for `path`.
    fn enter_surveillance(&mut self, path: PathBuf) {
        let mut state = WoprState::new(path);
        state.try_build_graph();
        state.poll_log();
        self.mode = WoprMode::Surveillance(state);
    }

    /// Transition from Surveillance → Selection (fresh scan).
    fn return_to_selection(&mut self) {
        self.mode = WoprMode::Selection(SelectionState::new(self.base_dir.clone()));
    }
}

// ─── Public entry point ───────────────────────────────────────────────────────

/// Launch the Integrity Dashboard multi-tenant operations center.
///
/// `base_dir` is the gauntlet root (e.g. `~/dev/gauntlet/`).  The dashboard
/// opens in repository-selection mode; pressing `Enter` on a highlighted
/// repository enters per-repo surveillance mode.
pub fn draw_wopr(base_dir: &Path) -> Result<(), Box<dyn Error>> {
    let mut app = WoprApp::new(base_dir.to_path_buf());

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{err:?}");
    }

    Ok(())
}

// ─── Main event loop ──────────────────────────────────────────────────────────

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut WoprApp,
) -> io::Result<()>
where
    io::Error: From<B::Error>,
{
    loop {
        // ── Draw (mode-dispatched) ─────────────────────────────────────────────
        match &mut app.mode {
            WoprMode::Selection(sel) => draw_selection(terminal, sel)?,
            WoprMode::Surveillance(state) => draw_surveillance(terminal, state)?,
        }

        // ── Events ────────────────────────────────────────────────────────────
        if event::poll(TICK)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => return Ok(()),

                    // ── Selection navigation ───────────────────────────────────
                    KeyCode::Up => {
                        if let WoprMode::Selection(sel) = &mut app.mode {
                            sel.move_up();
                        }
                    }
                    KeyCode::Down => {
                        if let WoprMode::Selection(sel) = &mut app.mode {
                            sel.move_down();
                        }
                    }

                    // ── Tab navigation (Surveillance only) ────────────────────
                    KeyCode::Left => {
                        if let WoprMode::Surveillance(state) = &mut app.mode {
                            state.active_tab = state.active_tab.saturating_sub(1);
                        }
                    }
                    KeyCode::Right => {
                        if let WoprMode::Surveillance(state) = &mut app.mode {
                            state.active_tab = (state.active_tab + 1).min(2);
                        }
                    }

                    // ── Enter surveillance ────────────────────────────────────
                    KeyCode::Enter => {
                        let path_opt = if let WoprMode::Selection(sel) = &app.mode {
                            sel.selected_path()
                        } else {
                            None
                        };
                        if let Some(path) = path_opt {
                            app.enter_surveillance(path);
                        }
                    }

                    // ── Return to selection ───────────────────────────────────
                    KeyCode::Esc | KeyCode::Backspace => {
                        if matches!(app.mode, WoprMode::Surveillance(_)) {
                            app.return_to_selection();
                        }
                    }

                    _ => {}
                }
            }
        }

        // ── Tick (periodic refresh) ────────────────────────────────────────────
        match &mut app.mode {
            WoprMode::Selection(sel) => sel.tick(),
            WoprMode::Surveillance(state) => state.tick(),
        }
    }
}

// ─── Selection screen ─────────────────────────────────────────────────────────

fn draw_selection<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    sel: &mut SelectionState,
) -> io::Result<()>
where
    io::Error: From<B::Error>,
{
    let text_style = Style::default().fg(Color::White);
    let muted_style = Style::default().fg(Color::DarkGray);
    let border_style = Style::default().fg(Color::Cyan);
    let active_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD | Modifier::SLOW_BLINK);

    let items: Vec<ListItem> = sel
        .targets
        .iter()
        .map(|t| {
            if t.is_active {
                ListItem::new(Line::from(vec![
                    Span::styled(format!("  {}", t.name), text_style),
                    Span::styled("  [ AUDIT ACTIVE ]", active_style),
                ]))
            } else {
                ListItem::new(Line::from(Span::styled(
                    format!("  {}", t.name),
                    muted_style,
                )))
            }
        })
        .collect();

    let empty = items.is_empty();
    let list_state = &mut sel.list_state;

    terminal.draw(|f| {
        let area = f.area();

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(1),
            ])
            .split(area);

        // ── Title ─────────────────────────────────────────────────────────────
        let title = Paragraph::new(Line::from(vec![
            Span::styled(
                "  INTEGRITY DASHBOARD",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "  //  GLOBAL AUDIT SYSTEM",
                Style::default().fg(Color::Blue),
            ),
            Span::styled("  //  v7.5.1", Style::default().fg(Color::DarkGray)),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Thick)
                .border_style(border_style)
                .style(Style::default().bg(Color::Black)),
        );
        f.render_widget(title, chunks[0]);

        // ── Repository list ───────────────────────────────────────────────────
        let placeholder: Vec<ListItem> = vec![ListItem::new(Line::from(Span::styled(
            "  NO REPOSITORIES DETECTED IN GAUNTLET DIRECTORY",
            Style::default().fg(Color::DarkGray),
        )))];

        let list = List::new(if empty { placeholder } else { items })
            .block(
                Block::default()
                    .title("[ SELECT REPOSITORY ]")
                    .borders(Borders::ALL)
                    .border_type(BorderType::Thick)
                    .border_style(border_style)
                    .style(Style::default().bg(Color::Black)),
            )
            .style(text_style)
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        f.render_stateful_widget(list, chunks[1], list_state);

        // ── Footer ────────────────────────────────────────────────────────────
        let footer =
            Paragraph::new("  ↑/↓ Navigate  ·  Enter Select  ·  q Quit").style(muted_style);
        f.render_widget(footer, chunks[2]);
    })?;

    Ok(())
}

// ─── Surveillance screen ──────────────────────────────────────────────────────

fn draw_surveillance<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    state: &mut WoprState,
) -> io::Result<()>
where
    io::Error: From<B::Error>,
{
    let ranked = &state.ranked;
    let entries = &state.entries;
    let graph_ready = state.graph_ready;
    let active_tab = state.active_tab;
    let repo_name = state
        .path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    // Pre-compute swarm cluster data (entries with collision partners).
    let collision_rows: Vec<(u64, Vec<u32>, u32)> = entries
        .iter()
        .filter(|e| !e.collided_pr_numbers.is_empty())
        .map(|e| (e.pr_number, e.collided_pr_numbers.clone(), e.slop_score))
        .collect();

    terminal.draw(|f| {
        let area = f.area();

        let border_style = Style::default().fg(Color::Cyan);
        let header_style = Style::default()
            .fg(Color::Blue)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
        let text_style = Style::default().fg(Color::White);
        let muted_style = Style::default().fg(Color::DarkGray);

        // Layout: title(3) | tabs(3) | content(min) | footer(1)
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(1),
            ])
            .split(area);

        // ── Title bar ─────────────────────────────────────────────────────────
        let title = Paragraph::new(Line::from(vec![
            Span::styled(
                "  INTEGRITY DASHBOARD",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "  //  STRUCTURAL TOPOLOGY MATRIX",
                Style::default().fg(Color::Blue),
            ),
            Span::styled(
                format!("  //  REPO: {repo_name}"),
                Style::default().fg(Color::DarkGray),
            ),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Thick)
                .border_style(border_style)
                .style(Style::default().bg(Color::Black)),
        );
        f.render_widget(title, chunks[0]);

        // ── Tab selector ──────────────────────────────────────────────────────
        let tab_titles = vec![
            "  Live Telemetry  ",
            "  Structural Topology  ",
            "  Swarm Intelligence  ",
        ];
        let tabs = Tabs::new(tab_titles)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(border_style)
                    .style(Style::default().bg(Color::Black)),
            )
            .select(active_tab)
            .style(text_style)
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            );
        f.render_widget(tabs, chunks[1]);

        // ── Tab content ───────────────────────────────────────────────────────
        match active_tab {
            0 => render_telemetry(f, chunks[2], entries, border_style, text_style, muted_style),
            1 => render_topology(
                f,
                chunks[2],
                RenderTopologyParams {
                    ranked,
                    graph_ready,
                    border_style,
                    header_style,
                    text_style,
                    muted_style,
                },
            ),
            2 => render_swarm(
                f,
                chunks[2],
                &collision_rows,
                border_style,
                header_style,
                text_style,
                muted_style,
            ),
            _ => {}
        }

        // ── Footer ────────────────────────────────────────────────────────────
        let footer = Paragraph::new(
            "  ↑/↓ Navigate  ·  ←/→ Change Tab  ·  Enter Select  ·  Esc Back  ·  q Quit",
        )
        .style(muted_style);
        f.render_widget(footer, chunks[3]);
    })?;

    Ok(())
}

// ─── Tab 1: Live Telemetry ────────────────────────────────────────────────────

fn render_telemetry(
    f: &mut Frame<'_>,
    area: Rect,
    entries: &[WoprEntry],
    border_style: Style,
    text_style: Style,
    muted_style: Style,
) {
    let critical_style = Style::default().fg(Color::Red).add_modifier(Modifier::BOLD);
    let warning_style = Style::default()
        .fg(Color::Magenta)
        .add_modifier(Modifier::BOLD);
    let positive_style = Style::default()
        .fg(Color::LightGreen)
        .add_modifier(Modifier::BOLD);

    let feed_items: Vec<ListItem> = if entries.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "  AWAITING DATA ... NO BOUNCE LOG ENTRIES FOUND",
            muted_style,
        )))]
    } else {
        entries
            .iter()
            .rev()
            .take(50)
            .flat_map(|e| {
                let mut lines: Vec<Line> = Vec::new();

                // Header line: PR number and composite score.
                let header_style = if e.is_entangled {
                    warning_style
                } else if e.is_threat {
                    critical_style
                } else if e.edges_severed > 0 {
                    positive_style
                } else {
                    text_style
                };

                let mut header_spans: Vec<Span> = vec![Span::styled(
                    format!("  PR #{:<6}  score={:>4}", e.pr_number, e.slop_score),
                    header_style,
                )];
                if let Some(flag) = &e.necrotic_flag {
                    header_spans.push(Span::styled(
                        format!("  NECROTIC: {flag}"),
                        Style::default().fg(Color::Yellow),
                    ));
                }
                if e.logic_clones_found > 0 {
                    header_spans.push(Span::styled(
                        format!("  CLONES: {}", e.logic_clones_found),
                        header_style,
                    ));
                }
                if e.edges_severed > 0 {
                    header_spans.push(Span::styled(
                        format!("  DEBT REDUCED:{}", e.edges_severed),
                        positive_style,
                    ));
                }
                if !e.collided_pr_numbers.is_empty() {
                    header_spans.push(Span::styled(
                        format!(
                            "  [!] SWARM MATCH: {} PARTNERS",
                            e.collided_pr_numbers.len()
                        ),
                        Style::default().fg(Color::Magenta),
                    ));
                }

                lines.push(Line::from(header_spans));

                // Critical antipattern detail lines.
                for detail in e.antipattern_details.iter().take(3) {
                    lines.push(Line::from(Span::styled(
                        format!("    ↳ [!] {detail}"),
                        critical_style,
                    )));
                }

                lines.into_iter().map(ListItem::new)
            })
            .collect()
    };

    let feed = List::new(feed_items)
        .block(
            Block::default()
                .title("[ LIVE TELEMETRY — PR DELTA FEED ]")
                .borders(Borders::ALL)
                .border_type(BorderType::Thick)
                .border_style(border_style)
                .style(Style::default().bg(Color::Black)),
        )
        .style(text_style);
    f.render_widget(feed, area);
}

// ─── Tab 2: Structural Topology ───────────────────────────────────────────────

struct RenderTopologyParams<'a> {
    ranked: &'a [(String, usize, usize)],
    graph_ready: bool,
    border_style: Style,
    header_style: Style,
    text_style: Style,
    muted_style: Style,
}

fn render_topology(f: &mut Frame<'_>, area: Rect, params: RenderTopologyParams<'_>) {
    let RenderTopologyParams {
        ranked,
        graph_ready,
        border_style,
        header_style,
        text_style,
        muted_style,
    } = params;
    let header = Row::new(vec![
        Cell::from("HEADER PATH").style(header_style),
        Cell::from("DIRECT IMPORTS").style(header_style),
        Cell::from("TRANSITIVE BLAST RADIUS").style(header_style),
    ])
    .height(1);

    let silo_rows: Vec<Row> = if ranked.is_empty() {
        let msg = if graph_ready {
            "  NO C++ FILES DETECTED IN REPOSITORY"
        } else {
            "  AWAITING TOPOLOGY GRAPH GENERATION..."
        };
        vec![Row::new(vec![Cell::from(msg)]).style(muted_style)]
    } else {
        ranked
            .iter()
            .map(|(label, direct, blast)| {
                Row::new(vec![
                    Cell::from(label.clone()),
                    Cell::from(direct.to_string()),
                    Cell::from(blast.to_string()),
                ])
                .style(text_style)
            })
            .collect()
    };

    let table = Table::new(
        silo_rows,
        [
            Constraint::Percentage(60),
            Constraint::Percentage(15),
            Constraint::Percentage(25),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title("[ C/C++ COMPILE-TIME SILOS ]")
            .borders(Borders::ALL)
            .border_type(BorderType::Thick)
            .border_style(border_style)
            .style(Style::default().bg(Color::Black)),
    )
    .style(text_style);
    f.render_widget(table, area);
}

// ─── Tab 3: Swarm Intelligence ────────────────────────────────────────────────

fn render_swarm(
    f: &mut Frame<'_>,
    area: Rect,
    collision_rows: &[(u64, Vec<u32>, u32)],
    border_style: Style,
    header_style: Style,
    text_style: Style,
    muted_style: Style,
) {
    let header = Row::new(vec![
        Cell::from("PR NUMBER").style(header_style),
        Cell::from("COLLISION PARTNERS").style(header_style),
        Cell::from("SLOP SCORE").style(header_style),
    ])
    .height(1);

    let rows: Vec<Row> = if collision_rows.is_empty() {
        vec![Row::new(vec![
            Cell::from(""),
            Cell::from("  NO STRUCTURAL CLONE CLUSTERS DETECTED"),
            Cell::from(""),
        ])
        .style(muted_style)]
    } else {
        collision_rows
            .iter()
            .map(|(pr, partners, score)| {
                let partner_str = partners
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                Row::new(vec![
                    Cell::from(pr.to_string()),
                    Cell::from(partner_str),
                    Cell::from(score.to_string()),
                ])
                .style(text_style)
            })
            .collect()
    };

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(15),
            Constraint::Percentage(65),
            Constraint::Percentage(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title("[ SWARM INTELLIGENCE — STRUCTURAL CLONE CLUSTERS ]")
            .borders(Borders::ALL)
            .border_type(BorderType::Thick)
            .border_style(border_style)
            .style(Style::default().bg(Color::Black)),
    )
    .style(text_style);
    f.render_widget(table, area);
}

// ─── Log parsing ──────────────────────────────────────────────────────────────

fn load_log(path: &Path) -> Vec<WoprEntry> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    content.lines().filter_map(parse_log_line).collect()
}

fn parse_log_line(line: &str) -> Option<WoprEntry> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let pr_number = v["pr_number"].as_u64()?;
    let slop_score = v["slop_score"].as_u64().unwrap_or(0) as u32;
    let necrotic_flag = v["necrotic_flag"].as_str().map(String::from);
    let logic_clones_found = v["logic_clones_found"].as_u64().unwrap_or(0) as u32;

    let details = v["antipattern_details"].as_array();

    let antipattern_details: Vec<String> = details
        .map(|arr| {
            arr.iter()
                .filter_map(|d| d.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let is_threat = antipattern_details
        .iter()
        .any(|s| s.contains("architecture:compile_time_bloat"));

    let is_entangled = antipattern_details
        .iter()
        .any(|s| s.contains("architecture:graph_entanglement"));

    let edges_severed = antipattern_details
        .iter()
        .find_map(|s| {
            s.strip_prefix("deflation_bonus:severed=")
                .and_then(|n| n.parse::<usize>().ok())
        })
        .unwrap_or(0);

    let collided_pr_numbers: Vec<u32> = v["collided_pr_numbers"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|d| d.as_u64().map(|n| n as u32))
                .collect()
        })
        .unwrap_or_default();

    Some(WoprEntry {
        pr_number,
        slop_score,
        is_threat,
        is_entangled,
        edges_severed,
        necrotic_flag,
        logic_clones_found,
        antipattern_details,
        collided_pr_numbers,
    })
}
