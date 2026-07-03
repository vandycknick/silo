use std::fmt::Write as _;

use clap::builder::styling::{AnsiColor, Effects, Style};
use clap::builder::StyledStr;
use console::measure_text_width;

pub(crate) struct HelpDoc {
    out: StyledStr,
    has_content: bool,
}

impl HelpDoc {
    pub(crate) fn new() -> Self {
        Self {
            out: StyledStr::new(),
            has_content: false,
        }
    }

    pub(crate) fn section(mut self, title: &str) -> Self {
        if self.has_content {
            self.write("\n");
        }
        self.write_color(title, AnsiColor::Yellow.on_default() | Effects::BOLD);
        self.write(":\n");
        self.has_content = true;
        self
    }

    pub(crate) fn table(mut self, rows: &[(&str, &str)]) -> Self {
        let width = rows
            .iter()
            .map(|(left, _)| measure_text_width(left))
            .max()
            .unwrap_or(0);

        for (left, right) in rows {
            self.write("  ");
            self.write_color(left, AnsiColor::Blue.on_default() | Effects::BOLD);
            self.padding(width.saturating_sub(measure_text_width(left)) + 2);
            self.write(right);
            self.write("\n");
        }
        self.has_content = true;
        self
    }

    pub(crate) fn text(mut self, text: &str) -> Self {
        self.write("  ");
        self.write(text);
        self.write("\n");
        self.has_content = true;
        self
    }

    pub(crate) fn examples(mut self, examples: &[&str]) -> Self {
        for example in examples {
            self.write("  ");
            self.write(example);
            self.write("\n");
        }
        self.has_content = true;
        self
    }

    pub(crate) fn build(self) -> StyledStr {
        self.out
    }

    fn write(&mut self, text: &str) {
        self.out.push_str(text);
    }

    fn write_color(&mut self, text: &str, style: Style) {
        let _ = write!(
            self.out,
            "{}{}{}",
            style.render(),
            text,
            style.render_reset()
        );
    }

    fn padding(&mut self, count: usize) {
        for _ in 0..count {
            self.write(" ");
        }
    }
}

pub(crate) fn examples(examples: &[&str]) -> StyledStr {
    HelpDoc::new()
        .section("Examples")
        .examples(examples)
        .build()
}

#[cfg(test)]
mod tests {
    #[test]
    fn examples_are_styled() {
        let help = crate::help::examples(&["an example"]);
        assert!(help.ansi().to_string().contains("\u{1b}["));
        assert!(help.to_string().contains("Examples:"));
        assert!(help.to_string().contains("an example"));
    }
}
