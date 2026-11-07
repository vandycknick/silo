//! Linux kernel command-line parameters, split exactly as the kernel splits them.
//!
//! [`params`] reproduces Linux `next_arg` (`lib/cmdline.c`, unchanged from
//! v5.15 through v7.2) over the kernel `isspace` table (`lib/ctype.c`). Host
//! admission and guest init therefore see the parameter names the kernel
//! dispatches, not a guess based on ASCII whitespace or prefixes:
//!
//! ```text
//!  "rdinit=/x"      quoted parameter    -> name `rdinit`, value `/x`
//!  rdinit="/x y"    quoted value        -> name `rdinit`, value `/x y`
//!  "a rdinit=/x"    one quoted token    -> name `a rdinit`, value `/x`
//!  a<VT>rdinit=/x   VT (0x0b) and NBSP (0xa0) separate tokens
//! ```
//!
//! A NUL byte ends the command line, as it ends the kernel's C string.

/// One parameter as Linux `parse_args` dispatches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Param<'a> {
    pub name: &'a [u8],
    /// `None` without `=`; the kernel's quote stripping is already applied.
    pub value: Option<&'a [u8]>,
}

/// Parameters the trusted bootstrap and Silo `/init` own outright. Linux
/// dispatches each through `__setup("<name>=")`, so only the valued spelling
/// acts; `root` or `rdinit` without `=` is handed to init as a plain argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reserved {
    /// `root=`, `rootfstype=`, `rootflags=`: the bootstrap selects the root.
    RootSelection,
    /// `rdinit=`: Linux executes it instead of `/init`, so the bootstrap, root
    /// checks and translation setup would never run. Even an empty value
    /// discards `/init` and falls through to kernel root mounting.
    InitialExecutable,
}

const ROOT_SELECTORS: [&[u8]; 3] = [b"root", b"rootfstype", b"rootflags"];

impl Param<'_> {
    /// Linux `parameq`: `-` and `_` are interchangeable in parameter names.
    pub fn is(&self, key: &[u8]) -> bool {
        self.name.len() == key.len()
            && self
                .name
                .iter()
                .zip(key)
                .all(|(&left, &right)| dash_to_underscore(left) == dash_to_underscore(right))
    }

    pub fn reserved(&self) -> Option<Reserved> {
        if self.value.is_none() {
            None
        } else if ROOT_SELECTORS.iter().any(|selector| self.is(selector)) {
            Some(Reserved::RootSelection)
        } else if self.is(b"rdinit") {
            Some(Reserved::InitialExecutable)
        } else {
            None
        }
    }
}

/// Iterates the parameters of `cmdline` in kernel dispatch order.
pub fn params(cmdline: &[u8]) -> Params<'_> {
    Params { rest: cmdline }
}

pub struct Params<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Params<'a> {
    type Item = Param<'a>;

    /// Mirrors `skip_spaces` + `next_arg`. The kernel terminates the name at
    /// the first `=` and the token with NULs written in place; here those
    /// positions bound sub-slices instead.
    fn next(&mut self) -> Option<Param<'a>> {
        let start = self
            .rest
            .iter()
            .position(|&byte| !is_space(byte))
            .unwrap_or(self.rest.len());
        let mut args = self.rest.get(start..).unwrap_or_default();
        if matches!(args.first(), None | Some(0)) {
            self.rest = &[];
            return None;
        }
        let quoted = args.first() == Some(&b'"');
        if quoted {
            args = args.get(1..).unwrap_or_default();
        }
        let mut in_quote = quoted;
        // As in the kernel, `0` means "no `=` yet", so a leading `=` is
        // skipped and a later one still splits the token.
        let mut equals = 0;
        let mut end = 0;
        for &byte in args {
            if byte == 0 || (is_space(byte) && !in_quote) {
                break;
            }
            if equals == 0 && byte == b'=' {
                equals = end;
            }
            if byte == b'"' {
                in_quote = !in_quote;
            }
            end += 1;
        }
        self.rest = match args.get(end) {
            Some(&byte) if byte != 0 => args.get(end + 1..).unwrap_or_default(),
            _ => &[],
        };

        let value_quoted = equals != 0 && args.get(equals + 1) == Some(&b'"');
        let closing_quote = end > 0 && args.get(end - 1) == Some(&b'"');
        let terminator = if closing_quote && (value_quoted || quoted) {
            end - 1
        } else {
            end
        };
        if equals == 0 {
            return Some(Param {
                name: args.get(..terminator).unwrap_or_default(),
                value: None,
            });
        }
        let value_start = equals + 1 + usize::from(value_quoted);
        Some(Param {
            name: args.get(..equals).unwrap_or_default(),
            value: Some(
                args.get(value_start..terminator.max(value_start))
                    .unwrap_or_default(),
            ),
        })
    }
}

/// Linux `isspace`: ASCII HT, LF, VT, FF, CR, space and Latin-1 NBSP.
fn is_space(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ' | 0xa0)
}

fn dash_to_underscore(byte: u8) -> u8 {
    if byte == b'-' {
        b'_'
    } else {
        byte
    }
}

#[cfg(test)]
mod tests {
    use crate::kernel_cmdline::{params, Param, Reserved};
    use std::vec::Vec;

    fn param<'a>(name: &'a [u8], value: Option<&'a [u8]>) -> Param<'a> {
        Param { name, value }
    }

    fn assert_params(cmdline: &[u8], expected: &[Param<'_>]) {
        let mut actual = params(cmdline);
        for expected in expected {
            assert_eq!(actual.next().as_ref(), Some(expected), "{cmdline:?}");
        }
        assert_eq!(actual.next(), None, "{cmdline:?}");
    }

    // Expectations were produced by the verbatim v7.2 `next_arg` and `_ctype`
    // table compiled in isolation.
    #[test]
    fn tokens_match_linux_next_arg() {
        assert_params(
            b"  console=hvc0  loglevel=4\n",
            &[
                param(b"console", Some(b"hvc0")),
                param(b"loglevel", Some(b"4")),
            ],
        );
        assert_params(
            b"\"rdinit=/agent/silo-agent\"",
            &[param(b"rdinit", Some(b"/agent/silo-agent"))],
        );
        assert_params(
            b"rdinit=\"/agent/silo-agent\"",
            &[param(b"rdinit", Some(b"/agent/silo-agent"))],
        );
        assert_params(b"\"rdinit=\"/x\"\"", &[param(b"rdinit", Some(b"/x\""))]);
        assert_params(b"\"a rdinit=/x\"", &[param(b"a rdinit", Some(b"/x"))]);
        assert_params(b"a=\"b rdinit=/x\"", &[param(b"a", Some(b"b rdinit=/x"))]);
        assert_params(b"\"rdinit=/x y", &[param(b"rdinit", Some(b"/x y"))]);
        assert_params(b"=rdinit=/x", &[param(b"=rdinit", Some(b"/x"))]);
        assert_params(b"rd\"init\"=/x", &[param(b"rd\"init\"", Some(b"/x"))]);
        assert_params(b"\"root\"=/dev/vda", &[param(b"root\"", Some(b"/dev/vda"))]);
        assert_params(b"q\"=x\"", &[param(b"q\"", Some(b"x\""))]);
        assert_params(b"a\"=\"b", &[param(b"a\"", Some(b"b"))]);
        assert_params(b"a=b\"", &[param(b"a", Some(b"b\""))]);
        assert_params(b"\"", &[param(b"", None)]);
        assert_params(b"\"\"", &[param(b"", None)]);
        assert_params(b"a=\"", &[param(b"a", Some(b""))]);
        assert_params(b"rdinit", &[param(b"rdinit", None)]);
        assert_params(b"rdinit=", &[param(b"rdinit", Some(b""))]);
        assert_params(
            b" \"init=/sbin/my init\" silo.rootfs=\"linux-flat-overlay-v1\"",
            &[
                param(b"init", Some(b"/sbin/my init")),
                param(b"silo.rootfs", Some(b"linux-flat-overlay-v1")),
            ],
        );
        assert_params(b"", &[]);
        assert_params(b" \t\n", &[]);
    }

    #[test]
    fn kernel_whitespace_and_nul_bound_tokens() {
        for separator in [b'\t', b'\n', 0x0b, 0x0c, b'\r', b' ', 0xa0] {
            let cmdline = [
                b'x', separator, b'r', b'd', b'i', b'n', b'i', b't', b'=', b'/',
            ];
            assert_params(&cmdline, &[param(b"x", None), param(b"rdinit", Some(b"/"))]);
        }
        // U+00E0 is encoded as C3 A0; the kernel splits inside the character.
        assert_params(
            "x\u{e0}rdinit=/x".as_bytes(),
            &[param(b"x\xc3", None), param(b"rdinit", Some(b"/x"))],
        );
        assert_params(b"a\0rdinit=/x", &[param(b"a", None)]);
        assert_params(b"a=\"\0\" rdinit=/x", &[param(b"a", Some(b""))]);
    }

    #[test]
    fn reserved_parameters_require_the_kernel_recognized_spelling() {
        let reserved = |cmdline: &[u8]| {
            params(cmdline)
                .map(|param| param.reserved())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            reserved(b"rdinit=/agent/silo-agent \"rdinit=/x\" rdinit=\"/x\" rdinit="),
            [Some(Reserved::InitialExecutable); 4]
        );
        assert_eq!(
            reserved(b"root=/dev/vda \"rootfstype=ext4\" rootflags=\"ro\" root="),
            [Some(Reserved::RootSelection); 4]
        );
        assert_eq!(
            reserved(
                b"rdinit root rootwait xinit=/x \"a rdinit=/x\" rd\"init\"=/x init=/sbin/init"
            ),
            [None; 7]
        );
        assert!(params(b"page-reporting.page_reporting-order=2")
            .all(|param| param.is(b"page_reporting.page-reporting_order")));
    }
}
