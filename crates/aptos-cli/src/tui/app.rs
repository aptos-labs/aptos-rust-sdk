//! TUI application state and event loop.

use anyhow::{Context, Result};
use aptos_sdk::Aptos;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;
use std::time::{Duration, Instant};

use super::ui;

/// Which tab is currently selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Account,
    Move,
}

impl Tab {
    pub fn title(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Account => "Account",
            Tab::Move => "Move",
        }
    }

    pub fn all() -> &'static [Tab] {
        &[Tab::Dashboard, Tab::Account, Tab::Move]
    }

    pub fn next(self) -> Tab {
        match self {
            Tab::Dashboard => Tab::Account,
            Tab::Account => Tab::Move,
            Tab::Move => Tab::Dashboard,
        }
    }

    pub fn prev(self) -> Tab {
        match self {
            Tab::Dashboard => Tab::Move,
            Tab::Account => Tab::Dashboard,
            Tab::Move => Tab::Account,
        }
    }
}

/// Ledger data fetched from the network.
#[derive(Debug, Clone, Default)]
pub struct LedgerData {
    pub chain_id: Option<u8>,
    pub epoch: Option<String>,
    pub ledger_version: Option<String>,
    pub block_height: Option<String>,
    pub ledger_timestamp: Option<String>,
    pub node_role: Option<String>,
    pub gas_low: Option<u64>,
    pub gas_mid: Option<u64>,
    pub gas_high: Option<u64>,
}

/// Account data fetched from the network.
#[derive(Debug, Clone, Default)]
pub struct AccountData {
    pub address: String,
    pub balance: Option<String>,
    pub sequence_number: Option<String>,
    pub auth_key: Option<String>,
    pub resources: Vec<String>,
    pub error: Option<String>,
}

/// Move view function result.
#[derive(Debug, Clone, Default)]
pub struct MoveViewData {
    pub function: String,
    pub type_args: String,
    pub args: String,
    pub result: Option<String>,
    pub error: Option<String>,
}

/// The application state.
pub struct App {
    pub aptos: Aptos,
    pub network_name: String,
    pub tab: Tab,
    pub should_quit: bool,
    pub ledger: LedgerData,
    pub account: AccountData,
    pub move_view: MoveViewData,
    /// Which input field is active (for Account and Move tabs)
    pub input_mode: bool,
    /// Current input buffer text
    pub input_buffer: String,
    /// Which field is being edited on the current tab
    pub active_field: usize,
    /// Last refresh timestamp
    pub last_refresh: Instant,
    /// Status message
    pub status: String,
    /// Refresh interval
    pub refresh_interval: Duration,
}

impl App {
    pub fn new(aptos: Aptos, network_name: String) -> Self {
        Self {
            aptos,
            network_name,
            tab: Tab::Dashboard,
            should_quit: false,
            ledger: LedgerData::default(),
            account: AccountData::default(),
            move_view: MoveViewData::default(),
            input_mode: false,
            input_buffer: String::new(),
            active_field: 0,
            last_refresh: Instant::now() - Duration::from_secs(100), // force first refresh
            status: "Loading...".to_string(),
            refresh_interval: Duration::from_secs(3),
        }
    }

    /// Refresh dashboard data from the network.
    pub async fn refresh_ledger(&mut self) {
        match self.aptos.ledger_info().await {
            Ok(info) => {
                self.ledger.chain_id = Some(info.chain_id);
                self.ledger.epoch = Some(info.epoch.clone());
                self.ledger.ledger_version = Some(info.ledger_version.clone());
                self.ledger.block_height = Some(info.block_height.clone());
                self.ledger.ledger_timestamp = Some(info.ledger_timestamp.clone());
                self.ledger.node_role = Some(info.node_role.clone());
                self.status = format!("Updated at block {}", info.block_height);
            }
            Err(e) => {
                self.status = format!("Error: {e}");
            }
        }

        match self.aptos.fullnode().estimate_gas_price().await {
            Ok(gas) => {
                self.ledger.gas_low = Some(gas.data.low());
                self.ledger.gas_mid = Some(gas.data.gas_estimate);
                self.ledger.gas_high = Some(gas.data.high());
            }
            Err(e) => {
                self.status = format!("Gas error: {e}");
            }
        }

        self.last_refresh = Instant::now();
    }

    /// Fetch account data.
    pub async fn fetch_account(&mut self) {
        let addr_str = self.account.address.trim().to_string();
        if addr_str.is_empty() {
            self.account.error = Some("Enter an address".to_string());
            return;
        }

        let address = match aptos_sdk::types::AccountAddress::from_hex(&addr_str) {
            Ok(a) => a,
            Err(e) => {
                self.account.error = Some(format!("Invalid address: {e}"));
                return;
            }
        };

        self.account.error = None;
        self.status = format!("Fetching account {addr_str}...");

        // Fetch balance
        match self.aptos.get_balance(address).await {
            Ok(balance) => {
                let apt = balance as f64 / 100_000_000.0;
                self.account.balance = Some(format!("{apt:.8} APT ({balance} octas)"));
            }
            Err(e) => {
                self.account.balance = Some(format!("Error: {e}"));
            }
        }

        // Fetch account info
        match self.aptos.fullnode().get_account(address).await {
            Ok(data) => {
                self.account.sequence_number = Some(data.data.sequence_number.clone());
                self.account.auth_key = Some(data.data.authentication_key.clone());
            }
            Err(e) => {
                self.account.sequence_number = None;
                self.account.auth_key = None;
                self.account.error = Some(format!("Account error: {e}"));
                return;
            }
        }

        // Fetch resources (just type names)
        match self.aptos.fullnode().get_account_resources(address).await {
            Ok(resources) => {
                self.account.resources = resources.data.iter().map(|r| r.typ.clone()).collect();
            }
            Err(_) => {
                self.account.resources = vec![];
            }
        }

        self.status = format!("Account {addr_str} loaded");
    }

    /// Execute a view function.
    pub async fn execute_view(&mut self) {
        let function = self.move_view.function.trim().to_string();
        if function.is_empty() {
            self.move_view.error = Some("Enter a function ID".to_string());
            return;
        }

        self.move_view.error = None;
        self.move_view.result = None;
        self.status = format!("Calling {function}...");

        // Parse type args
        let type_args: Vec<String> = if self.move_view.type_args.trim().is_empty() {
            vec![]
        } else {
            self.move_view
                .type_args
                .split(',')
                .map(|s| s.trim().to_string())
                .collect()
        };

        // Parse args as JSON
        let args: Vec<serde_json::Value> = if self.move_view.args.trim().is_empty() {
            vec![]
        } else {
            self.move_view
                .args
                .split(',')
                .map(|s| {
                    let s = s.trim();
                    serde_json::from_str(s)
                        .unwrap_or_else(|_| serde_json::Value::String(s.to_string()))
                })
                .collect::<Vec<_>>()
        };

        match self.aptos.view(&function, type_args, args).await {
            Ok(result) => {
                self.move_view.result =
                    Some(serde_json::to_string_pretty(&result).unwrap_or_default());
                self.status = format!("View {function} succeeded");
            }
            Err(e) => {
                self.move_view.error = Some(format!("{e}"));
                self.status = format!("View {function} failed");
            }
        }
    }

    /// Commit the current input buffer to the appropriate field.
    fn commit_input(&mut self) {
        match self.tab {
            Tab::Account => {
                self.account.address = self.input_buffer.clone();
            }
            Tab::Move => match self.active_field {
                0 => self.move_view.function = self.input_buffer.clone(),
                1 => self.move_view.type_args = self.input_buffer.clone(),
                2 => self.move_view.args = self.input_buffer.clone(),
                _ => {}
            },
            Tab::Dashboard => {}
        }
    }

    /// Load current field value into the input buffer.
    fn load_field_into_input(&mut self) {
        self.input_buffer = match self.tab {
            Tab::Account => self.account.address.clone(),
            Tab::Move => match self.active_field {
                0 => self.move_view.function.clone(),
                1 => self.move_view.type_args.clone(),
                2 => self.move_view.args.clone(),
                _ => String::new(),
            },
            Tab::Dashboard => String::new(),
        };
    }

    fn max_fields(&self) -> usize {
        match self.tab {
            Tab::Dashboard => 0,
            Tab::Account => 1,
            Tab::Move => 3,
        }
    }
}

/// Run the TUI application.
pub async fn run_tui(aptos: Aptos, network_name: String) -> Result<()> {
    let mut terminal = ratatui::init();
    let result = run_app(&mut terminal, aptos, network_name).await;
    ratatui::restore();
    result
}

async fn run_app(terminal: &mut DefaultTerminal, aptos: Aptos, network_name: String) -> Result<()> {
    let mut app = App::new(aptos, network_name);

    // Initial data fetch
    app.refresh_ledger().await;

    loop {
        terminal
            .draw(|frame| ui::draw(frame, &app))
            .context("failed to draw")?;

        // Auto-refresh dashboard data
        if app.tab == Tab::Dashboard && app.last_refresh.elapsed() >= app.refresh_interval {
            app.refresh_ledger().await;
        }

        // Poll for events with a short timeout
        if event::poll(Duration::from_millis(100)).context("event poll failed")?
            && let Event::Key(key) = event::read().context("event read failed")?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            // Ctrl+C always quits
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                app.should_quit = true;
            }

            if app.input_mode {
                // Input mode: typing into a field
                match key.code {
                    KeyCode::Esc => {
                        app.input_mode = false;
                    }
                    KeyCode::Enter => {
                        app.commit_input();
                        app.input_mode = false;
                        // Auto-execute on Enter
                        match app.tab {
                            Tab::Account => app.fetch_account().await,
                            Tab::Move if app.active_field == 0 => {
                                app.execute_view().await;
                            }
                            _ => {}
                        }
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    KeyCode::Tab => {
                        // Move to next field
                        app.commit_input();
                        app.active_field = (app.active_field + 1) % app.max_fields().max(1);
                        app.load_field_into_input();
                    }
                    _ => {}
                }
            } else {
                // Normal mode: navigation
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        app.should_quit = true;
                    }
                    KeyCode::Tab | KeyCode::Right => {
                        app.tab = app.tab.next();
                        app.active_field = 0;
                    }
                    KeyCode::BackTab | KeyCode::Left => {
                        app.tab = app.tab.prev();
                        app.active_field = 0;
                    }
                    KeyCode::Char('1') => app.tab = Tab::Dashboard,
                    KeyCode::Char('2') => {
                        app.tab = Tab::Account;
                        app.active_field = 0;
                    }
                    KeyCode::Char('3') => {
                        app.tab = Tab::Move;
                        app.active_field = 0;
                    }
                    KeyCode::Char('r') => {
                        app.refresh_ledger().await;
                    }
                    KeyCode::Enter | KeyCode::Char('i') | KeyCode::Char('e') => {
                        if app.max_fields() > 0 {
                            app.input_mode = true;
                            app.load_field_into_input();
                        }
                        // On Dashboard, Enter triggers refresh
                        if app.tab == Tab::Dashboard {
                            app.refresh_ledger().await;
                        }
                    }
                    KeyCode::Char('x') => {
                        // Execute action on current tab
                        match app.tab {
                            Tab::Account => app.fetch_account().await,
                            Tab::Move => app.execute_view().await,
                            Tab::Dashboard => app.refresh_ledger().await,
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.max_fields() > 0 {
                            app.active_field = (app.active_field + 1) % app.max_fields().max(1);
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.max_fields() > 0 {
                            app.active_field = if app.active_field == 0 {
                                app.max_fields().saturating_sub(1)
                            } else {
                                app.active_field - 1
                            };
                        }
                    }
                    _ => {}
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}
