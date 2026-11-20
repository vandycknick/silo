//! Ordered progress rows with a bounded, forward-only viewport.
//!
//! The model is terminal-independent. The renderer only owns fixed indicatif
//! line slots; application-specific events and summary wording stay with callers.

use std::time::Duration;

use console::{measure_text_width, style};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::ui::BRAILLE_TICKS;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Bar {
    pub position: u64,
    pub length: u64,
}

pub(crate) trait ListRow {
    fn label(&self) -> &str;
    fn status(&self) -> &str;
    fn is_final(&self) -> bool;
    fn is_active(&self) -> bool;
    fn is_unstarted(&self) -> bool;
    fn bar(&self) -> Option<Bar>;
    fn counts(&self) -> Option<String>;
}

/// One or two ordered slices of the original list, never reordered rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Segment {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Window {
    pub start: usize,
    pub end: usize,
    pub tail: Option<Segment>,
    pub hidden_above: usize,
    pub hidden_below: usize,
    pub slots: usize,
}

#[derive(Debug, Default)]
pub(crate) struct ListModel {
    start: usize,
    tail_start: usize,
    slots: Option<usize>,
}

impl ListModel {
    pub fn window(&mut self, rows: &[impl ListRow], terminal_rows: u16) -> Window {
        // One header, one spare terminal row. Fewer than three list slots
        // cannot accommodate a row and both hidden-range summaries.
        let available = if terminal_rows < 5 {
            0
        } else {
            usize::from(terminal_rows.saturating_sub(2)).min(rows.len())
        };
        // Freeze height once rows are known. A terminal shrink can only reduce
        // the allocation, since safety takes precedence over the frozen height.
        let slots = if rows.is_empty() {
            0
        } else {
            let slots = self.slots.get_or_insert(available);
            *slots = (*slots).min(available);
            *slots
        };
        if rows.len() <= slots {
            return Window::contiguous(0, rows.len(), slots);
        }
        let first_pending = rows
            .iter()
            .position(|row| !row.is_final())
            .unwrap_or(rows.len());
        self.start = self
            .start
            .max(first_pending.saturating_sub(1))
            .min(rows.len().saturating_sub(1));
        let contiguous = Window::contiguous(self.start, rows.len(), slots);
        if !rows.iter().skip(contiguous.end).any(ListRow::is_active) {
            return contiguous;
        }

        // Reserve top summary (if needed), gap, one tail row and bottom
        // summary. Smaller terminals retain the lowest-index active rows.
        let top = usize::from(self.start > 0);
        let head_capacity = (slots / 4).max(2).min(slots.saturating_sub(top + 3));
        if head_capacity < 2 {
            return contiguous;
        }
        let head_end = (self.start + head_capacity).min(rows.len());
        let Some(front) = rows
            .iter()
            .enumerate()
            .skip(head_end)
            .find_map(|(index, row)| (row.is_active() || row.is_unstarted()).then_some(index))
        else {
            return contiguous;
        };
        let tail_start = self.tail_start.max(front.saturating_sub(1));
        if tail_start <= head_end {
            // No gap to compress: the active rows already consume the space.
            return contiguous;
        }
        let tail_capacity = slots.saturating_sub(top + head_capacity + 1);
        let tail_end = segment_end(tail_start, rows.len(), tail_capacity);
        if tail_start >= tail_end {
            return contiguous;
        }
        self.tail_start = tail_start;
        Window {
            start: self.start,
            end: head_end,
            tail: Some(Segment {
                start: tail_start,
                end: tail_end,
            }),
            hidden_above: self.start,
            hidden_below: rows.len().saturating_sub(tail_end),
            slots,
        }
    }
}

/// Fit optional detail in priority order: status, counts, then bar.
/// The caller's status column width keeps every row's details aligned.
pub(crate) fn row_text(row: &impl ListRow, status_width: usize, width: usize) -> String {
    let base = format!(
        "     {}  {:status_width$}",
        plain_text(row.label()),
        plain_text(row.status())
    );
    let counts = row.counts().map(|counts| plain_text(&counts));
    let base_width = measure_text_width(&base);
    let mut line = base;
    if let Some(counts) = counts {
        let detail_width = base_width + 2 + measure_text_width(&counts);
        if detail_width <= width {
            if let Some(bar) = row.bar().filter(|_| width > 110) {
                let bar_width = width.saturating_sub(detail_width + 2).min(24);
                if bar_width >= 4 {
                    let filled = if bar.length == 0 {
                        0
                    } else {
                        ((u128::from(bar.position.min(bar.length)) * bar_width as u128)
                            / u128::from(bar.length)) as usize
                    };
                    line.push_str(&format!(
                        "  {}{}",
                        style("━".repeat(filled)).magenta(),
                        style("╌".repeat(bar_width - filled)).color256(238),
                    ));
                }
            }
            line.push_str("  ");
            line.push_str(&counts);
        }
    }
    let line = console::truncate_str(&line, width, "").into_owned();
    if row.is_final() {
        style(line).dim().to_string()
    } else {
        line
    }
}

pub(crate) fn fit_line(text: &str, width: usize) -> String {
    console::truncate_str(&plain_text(text), width, "").into_owned()
}

fn plain_text(text: &str) -> String {
    // User-controlled text must not inject terminal rows or cursor movements.
    console::strip_ansi_codes(text)
        .chars()
        .filter(|ch| !ch.is_control())
        .collect()
}

fn segment_end(start: usize, total: usize, capacity: usize) -> usize {
    let remaining = total.saturating_sub(start);
    let visible = if remaining <= capacity {
        remaining
    } else {
        capacity.saturating_sub(1)
    };
    start + visible
}

impl Window {
    fn contiguous(start: usize, total: usize, slots: usize) -> Self {
        let capacity = slots.saturating_sub(usize::from(start > 0));
        let end = segment_end(start, total, capacity);
        Self {
            start,
            end,
            tail: None,
            hidden_above: start,
            hidden_below: total.saturating_sub(end),
            slots,
        }
    }

    fn row_index(self, slot: usize) -> Option<usize> {
        if slot >= self.slots {
            return None;
        }
        let offset = usize::from(self.hidden_above > 0);
        let position = slot.checked_sub(offset)?;
        let head_len = self.end - self.start;
        if position < head_len {
            return Some(self.start + position);
        }
        let tail = self.tail?;
        let position = position.checked_sub(head_len + 1)?;
        (position < tail.end - tail.start).then_some(tail.start + position)
    }

    pub fn line<R: ListRow>(
        self,
        slot: usize,
        rows: &[R],
        status_width: usize,
        width: usize,
        summary: impl Fn(std::ops::Range<usize>) -> String,
    ) -> String {
        if slot >= self.slots {
            return String::new();
        }
        if let Some(index) = self.row_index(slot) {
            if let Some(row) = rows.get(index) {
                return row_text(row, status_width, width);
            }
        }
        if self.hidden_above > 0 && slot == 0 {
            return fit_line(&summary(0..self.start), width);
        }
        if let Some(tail) = self.tail {
            let gap_slot = usize::from(self.hidden_above > 0) + self.end - self.start;
            if slot == gap_slot {
                return fit_line(&summary(self.end..tail.start), width);
            }
        }
        if self.hidden_below > 0 && slot == self.slots.saturating_sub(1) {
            let end = self.tail.map_or(self.end, |tail| tail.end);
            return fit_line(&summary(end..rows.len()), width);
        }
        String::new()
    }
}

pub(crate) struct ListRenderer {
    progress: MultiProgress,
    header: ProgressBar,
    lines: Vec<ProgressBar>,
}

impl ListRenderer {
    pub fn new(progress: MultiProgress) -> Self {
        let header = progress.add(ProgressBar::new_spinner());
        header.enable_steady_tick(Duration::from_millis(80));
        Self {
            progress,
            header,
            lines: Vec::new(),
        }
    }

    pub fn draw<R: ListRow>(
        &mut self,
        header: &str,
        rows: &[R],
        window: Window,
        width: usize,
        status_width: usize,
        summary: impl Fn(std::ops::Range<usize>) -> String,
    ) {
        let (template, prefix) = if width >= 5 {
            ("   {spinner} {msg}", 5)
        } else if width > 0 {
            ("{spinner}{msg}", 1)
        } else {
            ("{msg}", 0)
        };
        self.header.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(BRAILLE_TICKS)
                .template(template)
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        self.header
            .set_message(fit_line(header, width.saturating_sub(prefix)));
        while self.lines.len() < window.slots {
            let line = self.progress.add(
                ProgressBar::new_spinner().with_style(
                    ProgressStyle::default_spinner()
                        .template("{msg}")
                        .unwrap_or_else(|_| ProgressStyle::default_spinner()),
                ),
            );
            self.lines.push(line);
        }
        while self.lines.len() > window.slots {
            if let Some(line) = self.lines.pop() {
                line.finish_and_clear();
                self.progress.remove(&line);
            }
        }
        for (slot, line) in self.lines.iter().enumerate() {
            let text = window.line(slot, rows, status_width, width, &summary);
            // A blank slot still occupies a physical row in indicatif.
            line.set_message(if text.is_empty() {
                " ".to_string()
            } else {
                text
            });
        }
    }
}

impl Drop for ListRenderer {
    fn drop(&mut self) {
        for line in &self.lines {
            line.finish_and_clear();
            self.progress.remove(line);
        }
        self.header.finish_and_clear();
        self.progress.remove(&self.header);
    }
}

#[cfg(test)]
mod tests {
    use crate::progress_list::{row_text, Bar, ListModel, ListRow, Window};

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Waiting,
        Active,
        Ready,
        Final,
    }

    struct Row {
        label: String,
        state: State,
    }

    impl ListRow for Row {
        fn label(&self) -> &str {
            &self.label
        }
        fn status(&self) -> &str {
            "Downloading"
        }
        fn is_final(&self) -> bool {
            self.state == State::Final
        }
        fn is_active(&self) -> bool {
            self.state == State::Active
        }
        fn is_unstarted(&self) -> bool {
            self.state == State::Waiting
        }
        fn bar(&self) -> Option<Bar> {
            Some(Bar {
                position: 50,
                length: 100,
            })
        }
        fn counts(&self) -> Option<String> {
            Some("50 B/100 B".into())
        }
    }

    fn rows(total: usize) -> Vec<Row> {
        (0..total)
            .map(|index| Row {
                label: format!("{index:012x}"),
                state: State::Waiting,
            })
            .collect()
    }

    fn assert_partition(window: Window, rows: &[Row]) -> Vec<usize> {
        let visible: Vec<_> = (0..window.slots)
            .filter_map(|slot| window.row_index(slot))
            .collect();
        let gap = window.tail.map_or(0, |tail| tail.start - window.end);
        assert_eq!(
            window.hidden_above + gap + window.hidden_below + visible.len(),
            rows.len()
        );
        assert!(visible.windows(2).all(|pair| pair[0] < pair[1]));
        for slot in 0..window.slots {
            let line = window.line(slot, rows, 17, 120, |range| {
                format!("hidden {}..{} ({})", range.start, range.end, range.len())
            });
            if let Some(index) = window.row_index(slot) {
                assert!(line.contains(&rows[index].label));
            } else if slot == 0 && window.hidden_above > 0 {
                assert_eq!(
                    line,
                    format!("hidden 0..{} ({})", window.start, window.hidden_above)
                );
            } else if let Some(tail) = window.tail.filter(|_| {
                slot == usize::from(window.hidden_above > 0) + window.end - window.start
            }) {
                assert_eq!(
                    line,
                    format!("hidden {}..{} ({gap})", window.end, tail.start)
                );
            } else if slot + 1 == window.slots && window.hidden_below > 0 {
                let end = window.tail.map_or(window.end, |tail| tail.end);
                assert_eq!(
                    line,
                    format!("hidden {end}..{} ({})", rows.len(), window.hidden_below)
                );
            } else {
                assert!(line.is_empty());
            }
        }
        visible
    }

    #[test]
    fn viewport_is_constant_bounded_ordered_and_forward_only_for_whole_pull() {
        for height in [0, 1, 2, 3, 4, 5, 6, 10, 20, 70, 71, 90] {
            let mut rows = rows(69);
            let mut model = ListModel::default();
            let first = model.window(&rows, height);
            let mut previous_start = 0;
            for done in 0..=69 {
                for (index, row) in rows.iter_mut().enumerate() {
                    row.state = if index < done {
                        State::Final
                    } else {
                        State::Waiting
                    };
                }
                let window = model.window(&rows, height);
                assert_eq!(window.slots, first.slots, "height {height}, done {done}");
                assert!(window.slots < usize::from(height.saturating_sub(1)).max(1));
                assert!(window.start >= previous_start);
                previous_start = window.start;
                assert_partition(window, &rows);
                assert!(window.tail.is_none());
                if height >= 71 {
                    assert_eq!((window.start, window.end), (0, 69));
                }
                if window.slots > 0 && height < 71 {
                    assert!(done.saturating_sub(window.start) <= 1);
                }
                if height < 5 {
                    assert_eq!(window.slots, 0);
                }
            }
        }
    }

    #[test]
    fn download_front_forty_rows_ahead_stays_visible_and_both_segments_only_advance() {
        for height in [11, 12, 16, 20, 30, 50, 71, 90] {
            let mut rows = rows(69);
            let mut model = ListModel::default();
            let slots = model.window(&rows, height).slots;
            let mut previous_head = 0;
            let mut previous_tail = 0;
            let mut split_seen = false;
            let mut merged = false;
            for tick in 0_usize..=109 {
                let downloaded = tick.min(69);
                let extracted = tick.saturating_sub(40).min(69);
                for (index, row) in rows.iter_mut().enumerate() {
                    row.state = if index < extracted {
                        State::Final
                    } else if (index == extracted && index < downloaded)
                        || (downloaded..(downloaded + 3).min(69)).contains(&index)
                    {
                        State::Active
                    } else if index < downloaded {
                        State::Ready
                    } else {
                        State::Waiting
                    };
                }
                let window = model.window(&rows, height);
                assert_eq!(window.slots, slots);
                assert!(window.start >= previous_head);
                previous_head = window.start;
                let visible = assert_partition(window, &rows);
                for (index, row) in rows.iter().enumerate().filter(|(_, row)| row.is_active()) {
                    assert!(
                        visible.contains(&index),
                        "height {height}, tick {tick}, missing {}",
                        row.label
                    );
                }
                if let Some(tail) = window.tail {
                    assert!(tail.start >= previous_tail);
                    previous_tail = tail.start;
                    split_seen = true;
                } else if split_seen {
                    merged = true;
                }
            }
            if height < 50 {
                assert!(split_seen && merged, "height {height}");
            }
        }
    }

    #[test]
    fn segments_merge_when_the_last_active_row_fits_the_contiguous_window() {
        let mut rows = rows(69);
        for row in rows.iter_mut().take(50) {
            row.state = State::Ready;
        }
        rows[0].state = State::Active;
        rows[50].state = State::Active;
        let mut model = ListModel::default();
        assert!(model.window(&rows, 20).tail.is_some());
        for row in rows.iter_mut().take(40) {
            row.state = State::Final;
        }
        rows[40].state = State::Active;
        let window = model.window(&rows, 20);
        assert!(window.tail.is_none());
        assert_eq!(window.start, 39);
        let visible = assert_partition(window, &rows);
        assert!(visible.contains(&40) && visible.contains(&50));
    }

    #[test]
    fn excess_active_rows_keep_lowest_indexes_and_tiny_terminals_remain_bounded() {
        for height in [0, 1, 2, 3, 4, 5, 6, 8, 10, 20] {
            let mut rows = rows(69);
            for row in &mut rows {
                row.state = State::Active;
            }
            let window = ListModel::default().window(&rows, height);
            let visible = assert_partition(window, &rows);
            assert_eq!(visible, (0..visible.len()).collect::<Vec<_>>());
            assert!(window.slots < usize::from(height.saturating_sub(1)).max(1));
        }
    }

    #[test]
    fn fitting_list_never_reassigns_row_positions() {
        let mut rows = rows(5);
        let mut model = ListModel::default();
        for done in 0..=5 {
            for (index, row) in rows.iter_mut().enumerate() {
                row.state = if index < done {
                    State::Final
                } else {
                    State::Active
                };
            }
            let window = model.window(&rows, 20);
            assert_eq!((window.start, window.end, window.slots), (0, 5, 5));
            assert_eq!(assert_partition(window, &rows), (0..5).collect::<Vec<_>>());
        }
    }

    #[test]
    fn width_fitting_drops_bar_before_counts_and_never_wraps() {
        let row = Row {
            label: "123456789abc".into(),
            state: State::Active,
        };
        for width in 0..=160 {
            assert!(console::measure_text_width(&row_text(&row, 17, width)) <= width);
        }
        assert!(row_text(&row, 17, 120).contains('━'));
        let narrow = row_text(&row, 17, 80);
        assert!(!narrow.contains('━'));
        assert!(narrow.contains("50 B/100 B"));
        assert!(!row_text(&row, 17, 40).contains("50 B/100 B"));
    }

    #[test]
    fn shrinking_terminal_reclamps_slots_and_empty_manifest_is_safe() {
        let mut model = ListModel::default();
        assert_eq!(model.window(&[] as &[Row], 20).slots, 0);
        let rows = rows(69);
        assert_eq!(model.window(&rows, 20).slots, 18);
        assert_eq!(model.window(&rows, 6).slots, 4);
        assert_eq!(model.window(&rows, 20).slots, 4);
        assert_eq!(model.window(&rows, 2).slots, 0);
    }
}
