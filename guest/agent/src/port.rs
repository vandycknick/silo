use protocol::parse_guest_port_args;

pub fn from_kernel_cmdline() -> u32 {
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    parse_guest_port_args(cmdline.split_whitespace())
}
