//! TUI rendering.

use super::app::{App, Tab};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Padding, Paragraph, Tabs, Wrap},
};

/// Main draw function.
pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title bar
            Constraint::Length(3), // Tabs
            Constraint::Min(10),   // Content
            Constraint::Length(3), // Status bar
        ])
        .split(frame.area());

    draw_title_bar(frame, app, chunks[0]);
    draw_tabs(frame, app, chunks[1]);

    match app.tab {
        Tab::Dashboard => draw_dashboard(frame, app, chunks[2]),
        Tab::Account => draw_account(frame, app, chunks[2]),
        Tab::Move => draw_move(frame, app, chunks[2]),
        Tab::Compile => draw_compile(frame, app, chunks[2]),
    }

    draw_status_bar(frame, app, chunks[3]);
}

fn draw_title_bar(frame: &mut Frame, app: &App, area: Rect) {
    let chain_id = app
        .ledger
        .chain_id
        .map_or("?".to_string(), |id| id.to_string());
    let version = app.ledger.ledger_version.as_deref().unwrap_or("...");

    let title = Line::from(vec![
        Span::styled(
            " APTOS SDK CLI ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!(" {} ", app.network_name.to_uppercase()),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("Chain ID: {chain_id}"),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw("  "),
        Span::styled(
            format!("Version: {version}"),
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(Color::DarkGray));
    let paragraph = Paragraph::new(title).block(block);
    frame.render_widget(paragraph, area);
}

fn draw_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let tab_titles: Vec<Line> = Tab::all()
        .iter()
        .enumerate()
        .map(|(i, t)| Line::from(format!(" {} {} ", i + 1, t.title())))
        .collect();

    let selected = Tab::all().iter().position(|t| *t == app.tab).unwrap_or(0);

    let tabs = Tabs::new(tab_titles)
        .select(selected)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .divider(Span::styled(" │ ", Style::default().fg(Color::DarkGray)))
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    frame.render_widget(tabs, area);
}

fn draw_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let keybinds = if app.input_mode {
        "Enter: confirm │ Esc: cancel │ Tab: next field │ Ctrl+C: quit"
    } else if app.tab == Tab::Compile {
        "Tab/←→: switch tabs │ 1-4: jump │ i: edit │ x: compile │ t: test │ r: refresh │ q: quit"
    } else {
        "Tab/←→: switch tabs │ 1-4: jump to tab │ i/Enter: edit │ x: execute │ r: refresh │ q: quit"
    };

    let status = Line::from(vec![
        Span::styled(
            format!(" {} ", app.status),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw("  "),
        Span::styled(keybinds, Style::default().fg(Color::DarkGray)),
    ]);

    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    let paragraph = Paragraph::new(status).block(block);
    frame.render_widget(paragraph, area);
}

// =============================================================================
// Dashboard tab
// =============================================================================

fn draw_dashboard(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .margin(1)
        .split(area);

    draw_ledger_info(frame, app, chunks[0]);
    draw_gas_info(frame, app, chunks[1]);
}

fn draw_ledger_info(frame: &mut Frame, app: &App, area: Rect) {
    let na = "...".to_string();

    let items = vec![
        info_row(
            "Chain ID",
            &app.ledger.chain_id.map_or(na.clone(), |id| id.to_string()),
        ),
        info_row("Epoch", app.ledger.epoch.as_ref().unwrap_or(&na)),
        info_row(
            "Ledger Version",
            app.ledger.ledger_version.as_ref().unwrap_or(&na),
        ),
        info_row(
            "Block Height",
            app.ledger.block_height.as_ref().unwrap_or(&na),
        ),
        info_row("Node Role", app.ledger.node_role.as_ref().unwrap_or(&na)),
        info_row(
            "Timestamp",
            &format_timestamp(app.ledger.ledger_timestamp.as_deref()),
        ),
    ];

    let list = List::new(items).block(
        Block::default()
            .title(Line::from(" Ledger Info ").bold().cyan())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::horizontal(1)),
    );
    frame.render_widget(list, area);
}

fn draw_gas_info(frame: &mut Frame, app: &App, area: Rect) {
    let low = app
        .ledger
        .gas_low
        .map_or("...".into(), |v| format!("{v} octas"));
    let mid = app
        .ledger
        .gas_mid
        .map_or("...".into(), |v| format!("{v} octas"));
    let high = app
        .ledger
        .gas_high
        .map_or("...".into(), |v| format!("{v} octas"));

    let items = vec![
        gas_row("Low (deprioritized)", &low, Color::Green),
        gas_row("Medium (estimate)", &mid, Color::Yellow),
        gas_row("High (prioritized)", &high, Color::Red),
    ];

    let list = List::new(items).block(
        Block::default()
            .title(Line::from(" Gas Prices ").bold().magenta())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Magenta))
            .padding(Padding::horizontal(1)),
    );
    frame.render_widget(list, area);
}

// =============================================================================
// Account tab
// =============================================================================

fn draw_account(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Address input
            Constraint::Length(7), // Account info
            Constraint::Min(3),    // Resources list
        ])
        .split(area);

    // Address input
    let input_style = if app.input_mode && app.tab == Tab::Account {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };

    let display_text = if app.input_mode && app.tab == Tab::Account {
        &app.input_buffer
    } else {
        &app.account.address
    };

    let input = Paragraph::new(display_text.as_str())
        .style(input_style)
        .block(
            Block::default()
                .title(
                    Line::from(if app.input_mode && app.tab == Tab::Account {
                        " Address (editing) "
                    } else {
                        " Address (press i to edit) "
                    })
                    .bold()
                    .cyan(),
                )
                .borders(Borders::ALL)
                .border_style(if app.input_mode && app.tab == Tab::Account {
                    Style::default().fg(Color::Yellow)
                } else if app.active_field == 0 {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        );
    frame.render_widget(input, chunks[0]);

    // Show cursor when editing
    if app.input_mode && app.tab == Tab::Account {
        frame.set_cursor_position((chunks[0].x + display_text.len() as u16 + 1, chunks[0].y + 1));
    }

    // Account info
    let info_text = if let Some(err) = &app.account.error {
        Text::from(Line::from(Span::styled(
            err.as_str(),
            Style::default().fg(Color::Red),
        )))
    } else if app.account.balance.is_some() {
        let mut lines = vec![];
        if let Some(bal) = &app.account.balance {
            lines.push(info_line("Balance", bal));
        }
        if let Some(seq) = &app.account.sequence_number {
            lines.push(info_line("Sequence Number", seq));
        }
        if let Some(auth) = &app.account.auth_key {
            // Truncate auth key for display
            let display = if auth.len() > 20 {
                format!("{}...{}", &auth[..10], &auth[auth.len() - 8..])
            } else {
                auth.clone()
            };
            lines.push(info_line("Auth Key", &display));
        }
        Text::from(lines)
    } else {
        Text::from(Line::from(Span::styled(
            "Enter an address and press Enter to look up",
            Style::default().fg(Color::DarkGray),
        )))
    };

    let info_block = Paragraph::new(info_text).block(
        Block::default()
            .title(Line::from(" Account Info ").bold().green())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green))
            .padding(Padding::horizontal(1)),
    );
    frame.render_widget(info_block, chunks[1]);

    // Resources list
    let resource_items: Vec<ListItem> = if app.account.resources.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "No resources loaded",
            Style::default().fg(Color::DarkGray),
        )))]
    } else {
        app.account
            .resources
            .iter()
            .map(|r| {
                ListItem::new(Line::from(Span::styled(
                    format!("  {r}"),
                    Style::default().fg(Color::White),
                )))
            })
            .collect()
    };

    let resources_list = List::new(resource_items).block(
        Block::default()
            .title(
                Line::from(format!(" Resources ({}) ", app.account.resources.len()))
                    .bold()
                    .yellow(),
            )
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .padding(Padding::horizontal(1)),
    );
    frame.render_widget(resources_list, chunks[2]);
}

// =============================================================================
// Move tab
// =============================================================================

fn draw_move(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Function input
            Constraint::Length(3), // Type args input
            Constraint::Length(3), // Args input
            Constraint::Min(5),    // Result
        ])
        .split(area);

    // Function ID input
    draw_input_field(
        frame,
        app,
        chunks[0],
        " Function ID (e.g. 0x1::coin::balance) ",
        &app.move_view.function,
        0,
    );

    // Type args input
    draw_input_field(
        frame,
        app,
        chunks[1],
        " Type Args (comma-separated, optional) ",
        &app.move_view.type_args,
        1,
    );

    // Args input
    draw_input_field(
        frame,
        app,
        chunks[2],
        " Args (comma-separated JSON values, optional) ",
        &app.move_view.args,
        2,
    );

    // Result
    let result_text = if let Some(err) = &app.move_view.error {
        Text::from(Line::from(Span::styled(
            err.as_str(),
            Style::default().fg(Color::Red),
        )))
    } else if let Some(result) = &app.move_view.result {
        Text::from(
            result
                .lines()
                .map(|l| {
                    Line::from(Span::styled(
                        l.to_string(),
                        Style::default().fg(Color::Green),
                    ))
                })
                .collect::<Vec<_>>(),
        )
    } else {
        Text::from(Line::from(Span::styled(
            "Enter a function ID and press Enter or x to call",
            Style::default().fg(Color::DarkGray),
        )))
    };

    let result_block = Paragraph::new(result_text)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(Line::from(" Result ").bold().green())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green))
                .padding(Padding::horizontal(1)),
        );
    frame.render_widget(result_block, chunks[3]);
}

fn draw_input_field(
    frame: &mut Frame,
    app: &App,
    area: Rect,
    title: &str,
    value: &str,
    field_index: usize,
) {
    let is_editing = app.input_mode
        && matches!(app.tab, Tab::Move | Tab::Compile)
        && app.active_field == field_index;
    let is_selected = !app.input_mode
        && matches!(app.tab, Tab::Move | Tab::Compile)
        && app.active_field == field_index;

    let display_text = if is_editing { &app.input_buffer } else { value };

    let style = if is_editing {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };

    let border_style = if is_editing {
        Style::default().fg(Color::Yellow)
    } else if is_selected {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let input = Paragraph::new(display_text).style(style).block(
        Block::default()
            .title(Line::from(title).bold().cyan())
            .borders(Borders::ALL)
            .border_style(border_style),
    );
    frame.render_widget(input, area);

    // Show cursor
    if is_editing {
        frame.set_cursor_position((area.x + display_text.len() as u16 + 1, area.y + 1));
    }
}

// =============================================================================
// Compile tab
// =============================================================================

fn draw_compile(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Package dir input
            Constraint::Length(3), // Named addresses input
            Constraint::Length(3), // Action buttons
            Constraint::Min(5),    // Output
        ])
        .split(area);

    // Package directory input
    draw_input_field(
        frame,
        app,
        chunks[0],
        " Package Directory ",
        &app.compile.package_dir,
        0,
    );

    // Named addresses input
    draw_input_field(
        frame,
        app,
        chunks[1],
        " Named Addresses (e.g. my_addr=0x1234) ",
        &app.compile.named_addresses,
        1,
    );

    // Action hints bar
    let status_indicator = match app.compile.success {
        Some(true) => Span::styled(
            " PASS ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Some(false) => Span::styled(
            " FAIL ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
        None if app.compile.is_running => Span::styled(
            " RUNNING ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        None => Span::styled(
            " READY ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
    };

    let last_action = app.compile.last_action.as_deref().unwrap_or("None");

    let action_line = Line::from(vec![
        Span::raw("  "),
        status_indicator,
        Span::raw("  "),
        Span::styled(
            format!("Last: {last_action}"),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw("    "),
        Span::styled(
            "[x] Compile",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("    "),
        Span::styled(
            "[t] Test",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let action_block = Paragraph::new(action_line).block(
        Block::default()
            .title(Line::from(" Actions ").bold().yellow())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    frame.render_widget(action_block, chunks[2]);

    // Output
    let output_lines: Vec<Line> = if app.compile.output.is_empty() {
        vec![Line::from(Span::styled(
            "Press [x] to compile or [t] to run tests",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        app.compile
            .output
            .iter()
            .map(|line| {
                let color = if line.starts_with("Error") || line.contains("error") {
                    Color::Red
                } else if line.contains("warning") {
                    Color::Yellow
                } else if line.contains("PASS")
                    || line.contains("Success")
                    || line.contains("succeeded")
                {
                    Color::Green
                } else {
                    Color::White
                };
                Line::from(Span::styled(line.clone(), Style::default().fg(color)))
            })
            .collect()
    };

    let output_block = Paragraph::new(output_lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(Line::from(" Output ").bold().green())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green))
                .padding(Padding::horizontal(1)),
        );
    frame.render_widget(output_block, chunks[3]);
}

// =============================================================================
// Helpers
// =============================================================================

fn info_row(label: &str, value: &str) -> ListItem<'static> {
    ListItem::new(Line::from(vec![
        Span::styled(
            format!("{label:>18}: "),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(value.to_string(), Style::default().fg(Color::White)),
    ]))
}

fn info_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label:>18}: "),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(value.to_string(), Style::default().fg(Color::White)),
    ])
}

fn gas_row(label: &str, value: &str, color: Color) -> ListItem<'static> {
    ListItem::new(Line::from(vec![
        Span::styled(
            format!("{label:>22}: "),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(value.to_string(), Style::default().fg(color)),
    ]))
}

fn format_timestamp(ts: Option<&str>) -> String {
    match ts {
        Some(ts_str) => {
            if let Ok(us) = ts_str.parse::<u64>() {
                let secs = us / 1_000_000;
                format!("{secs}s unix ({ts_str} us)")
            } else {
                ts_str.to_string()
            }
        }
        None => "...".to_string(),
    }
}
