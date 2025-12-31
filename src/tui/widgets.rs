//! Custom widgets for the game UI

use ratatui::{
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
    buffer::Buffer,
};

/// A progress bar widget for energy/stress
pub struct StatusBar {
    value: u8,
    max: u8,
    label: String,
    color: Color,
    warning_threshold: u8,
    danger_threshold: u8,
}

impl StatusBar {
    pub fn new(label: &str, value: u8, max: u8) -> Self {
        Self {
            value,
            max,
            label: label.to_string(),
            color: Color::Green,
            warning_threshold: 70,
            danger_threshold: 90,
        }
    }

    pub fn color(mut self, color: Color) -> Self {
        self.color = color;
        self
    }

    pub fn warning_threshold(mut self, threshold: u8) -> Self {
        self.warning_threshold = threshold;
        self
    }

    pub fn danger_threshold(mut self, threshold: u8) -> Self {
        self.danger_threshold = threshold;
        self
    }
}

impl Widget for StatusBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 3 || area.height < 1 {
            return;
        }

        // Determine color based on value
        let color = if self.value >= self.danger_threshold {
            Color::Red
        } else if self.value >= self.warning_threshold {
            Color::Yellow
        } else {
            self.color
        };

        // Calculate filled portion
        let filled = (self.value as u16 * (area.width - 2)) / self.max as u16;

        // Render label
        let label = format!("{}: {}%", self.label, self.value);
        buf.set_string(area.x, area.y, &label, Style::default().fg(color));

        // Render bar if there's room
        if area.height > 1 {
            let bar_y = area.y + 1;
            buf.set_string(area.x, bar_y, "[", Style::default());
            buf.set_string(area.x + area.width - 1, bar_y, "]", Style::default());

            for x in 0..filled {
                buf.set_string(area.x + 1 + x, bar_y, "█", Style::default().fg(color));
            }
            for x in filled..(area.width - 2) {
                buf.set_string(area.x + 1 + x, bar_y, "░", Style::default().fg(Color::DarkGray));
            }
        }
    }
}

/// A blinking alert widget
pub struct AlertIndicator {
    message: String,
    severity: crate::data::Severity,
    blink: bool,
}

impl AlertIndicator {
    pub fn new(message: &str, severity: crate::data::Severity) -> Self {
        Self {
            message: message.to_string(),
            severity,
            blink: true,
        }
    }

    pub fn blink(mut self, blink: bool) -> Self {
        self.blink = blink;
        self
    }
}

impl Widget for AlertIndicator {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let color = crate::tui::severity_color(&self.severity);
        let symbol = self.severity.symbol();

        let text = format!("{} {}", symbol, self.message);
        buf.set_string(area.x, area.y, &text, Style::default().fg(color));
    }
}

/// ASCII art box for dramatic moments
pub struct DramaticBox {
    title: String,
    content: Vec<String>,
    border_color: Color,
}

impl DramaticBox {
    pub fn new(title: &str) -> Self {
        Self {
            title: title.to_string(),
            content: Vec::new(),
            border_color: Color::Red,
        }
    }

    pub fn content(mut self, lines: Vec<String>) -> Self {
        self.content = lines;
        self
    }

    pub fn border_color(mut self, color: Color) -> Self {
        self.border_color = color;
        self
    }
}

impl Widget for DramaticBox {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Draw dramatic double-line border
        let style = Style::default().fg(self.border_color);

        // Top border
        buf.set_string(area.x, area.y, "╔", style);
        for x in 1..area.width - 1 {
            buf.set_string(area.x + x, area.y, "═", style);
        }
        buf.set_string(area.x + area.width - 1, area.y, "╗", style);

        // Title
        let title_start = (area.width as usize - self.title.len() - 2) / 2;
        buf.set_string(
            area.x + title_start as u16,
            area.y,
            format!(" {} ", self.title),
            style,
        );

        // Sides
        for y in 1..area.height - 1 {
            buf.set_string(area.x, area.y + y, "║", style);
            buf.set_string(area.x + area.width - 1, area.y + y, "║", style);
        }

        // Bottom border
        buf.set_string(area.x, area.y + area.height - 1, "╚", style);
        for x in 1..area.width - 1 {
            buf.set_string(area.x + x, area.y + area.height - 1, "═", style);
        }
        buf.set_string(area.x + area.width - 1, area.y + area.height - 1, "╝", style);

        // Content
        for (i, line) in self.content.iter().enumerate() {
            if i as u16 + 1 < area.height - 1 {
                buf.set_string(
                    area.x + 2,
                    area.y + 1 + i as u16,
                    line,
                    Style::default().fg(Color::White),
                );
            }
        }
    }
}
