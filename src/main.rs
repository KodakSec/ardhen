use std::fs;
use std::io::{self, Write};
use std::process::Command;

fn main() {
    loop {
        print_menu();
        let choice = get_user_input();

        match choice.as_str() {
            "1" => apply_sysctl_hardening(),
            "q" => break,
            _ => println!("Invalid option. Please try again."),
        }

        println!("\nPress Enter to continue...");
        io::stdin().read_line(&mut String::new()).unwrap();
    }
}

fn print_menu() {
    println!("
╔══════════════════════════════════════════════════════════════╗
║                            ArdHen                            ║
╠══════════════════════════════════════════════════════════════╣
║ 1. Apply sysctl Hardening                                    ║
║ q. Quit                                                      ║
║ Github/KodakSec                                              ║
╚══════════════════════════════════════════════════════════════╝
");
}

fn get_user_input() -> String {
    print!("Enter your choice: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn apply_sysctl_hardening() {
    println!("Applying sysctl hardening...");
    let configs = [
        ("kernel.kptr_restrict", "2"),
        ("kernel.dmesg_restrict", "1"),
        ("kernel.unprivileged_bpf_disabled", "1"),
        ("net.core.bpf_jit_harden", "2"),
        ("kernel.yama.ptrace_scope", "2"),
        ("kernel.kexec_load_disabled", "1"),
        ("kernel.randomize_va_space", "2"),
        ("kernel.sysrq", "0"),
        ("kernel.unprivileged_userns_clone", "0"),
        ("kernel.perf_event_paranoid", "3"),
        ("kernel.modules_disabled", "1"),
        ("vm.mmap_rnd_bits", "32"),
        ("vm.mmap_rnd_compat_bits", "16"),
        ("net.ipv4.tcp_syncookies", "1"),
        ("net.ipv4.tcp_rfc1337", "1"),
        ("net.ipv4.conf.default.rp_filter", "1"),
        ("net.ipv4.conf.all.rp_filter", "1"),
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv4.conf.default.accept_redirects", "0"),
        ("net.ipv4.conf.all.secure_redirects", "0"),
        ("net.ipv4.conf.default.secure_redirects", "0"),
        ("net.ipv6.conf.all.accept_redirects", "0"),
        ("net.ipv6.conf.default.accept_redirects", "0"),
        ("net.ipv4.conf.all.send_redirects", "0"),
        ("net.ipv4.conf.default.send_redirects", "0"),
        ("net.ipv4.icmp_echo_ignore_all", "1"),
        ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
        ("net.ipv4.tcp_sack", "0"),
        ("net.ipv4.tcp_timestamps", "0"),
        ("net.ipv4.tcp_window_scaling", "0"),
        ("net.ipv4.ip_forward", "0"),
        ("net.ipv6.conf.all.forwarding", "0"),
        ("net.ipv4.conf.all.log_martians", "1"),
        ("net.ipv4.conf.default.log_martians", "1"),
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
        ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
        ("net.ipv4.tcp_max_syn_backlog", "2048"),
        ("net.ipv4.tcp_synack_retries", "2"),
        ("net.ipv4.tcp_syn_retries", "2"),
        ("net.ipv4.tcp_fin_timeout", "15"),
        ("net.ipv4.conf.all.accept_source_route", "0"),
        ("net.ipv4.conf.default.accept_source_route", "0"),
        ("net.ipv6.conf.all.accept_source_route", "0"),
        ("net.ipv6.conf.default.accept_source_route", "0"),
        ("net.ipv4.conf.all.bootp_relay", "0"),
        ("net.ipv4.conf.default.bootp_relay", "0"),
        ("net.ipv4.conf.all.mc_forwarding", "0"),
        ("net.ipv4.conf.default.mc_forwarding", "0"),
        ("net.ipv4.conf.all.proxy_arp", "0"),
        ("net.ipv4.conf.default.proxy_arp", "0"),
        ("net.ipv6.conf.all.proxy_ndp", "0"),
        ("net.ipv6.conf.default.proxy_ndp", "0"),
        ("net.ipv6.conf.all.use_tempaddr", "2"),
        ("net.ipv6.conf.default.use_tempaddr", "2"),
        ("net.ipv6.conf.all.disable_ipv6", "1"),
        ("net.ipv6.conf.default.disable_ipv6", "1"),
        ("net.ipv6.conf.lo.disable_ipv6", "1"),
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
        ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
        ("net.ipv4.icmp_ratelimit", "100"),
        ("net.ipv4.icmp_ratemask", "8191"),
        ("net.ipv4.icmp_errors_use_inbound_ifaddr", "1"),
        ("fs.protected_hardlinks", "1"),
        ("fs.protected_symlinks", "1"),
        ("fs.suid_dumpable", "0"),
        ("fs.file-max", "2097152"),
        ("kernel.core_uses_pid", "1"),
        ("kernel.core_pattern", "|/bin/false"),
        ("kernel.hung_task_timeout_secs", "0"),
        ("kernel.printk", "4 4 1 7"),
        ("kernel.panic", "10"),
        ("kernel.panic_on_oops", "1"),
    ];

    for (param, value) in configs.iter() {
        let filename = format!("/etc/sysctl.d/{}.conf", param.replace(".", "_"));
        let content = format!("{} = {}\n", param, value);
        let output = Command::new("sudo")
            .args(&["tee", &filename])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn();

        match output {
            Ok(mut child) => {
                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(content.as_bytes()).unwrap();
                }
                let output = child.wait_with_output().unwrap();
                if output.status.success() {
                    println!("Created {}", filename);
                } else {
                    eprintln!("Failed to create {}", filename);
                }
            }
            Err(e) => eprintln!("Failed to create {}: {}", filename, e),
        }
        let output = Command::new("sudo")
            .args(&["sysctl", "-w", &format!("{}={}", param, value)])
            .output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    println!("Applied setting: {} = {}", param, value);
                } else {
                    eprintln!("Failed to apply setting: {} = {}", param, value);
                }
            }
            Err(e) => eprintln!("Failed to execute sysctl: {}", e),
        }
    }

    println!("sysctl hardening completed.");
}
