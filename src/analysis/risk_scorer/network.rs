pub(super) fn analyze_network_connect(remote_addr: &str, port: u16) -> u8 {
    let mut score = 20u8;

    if is_private_ip(remote_addr) {
        score = score.saturating_sub(10u8);
    } else {
        score = score.saturating_add(25);
    }

    if is_suspicious_port(port) {
        score = score.saturating_add(60);
    }

    /*
     * These ports increase the heuristic score; they do not identify malware.
     * Common command-channel ports receive an additional weight because an
     * external connection on them deserves review even without payload data.
     */
    match port {
        4444 | 31337 => score = score.saturating_add(55),
        6667 | 6697 => score = score.saturating_add(45),
        _ => {}
    }

    score
}

pub(super) fn analyze_network_send(port: u16, bytes: u32) -> u8 {
    let mut score = 15u8;

    if bytes > 1_000_000 {
        score = score.saturating_add(40);
    } else if bytes > 100_000 {
        score = score.saturating_add(20);
    }

    if is_suspicious_port(port) {
        score = score.saturating_add(35);
    }

    score
}

fn is_private_ip(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => address.is_private() || address.is_loopback(),
        Ok(std::net::IpAddr::V6(address)) => {
            address.is_loopback()
                || address.is_unique_local()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|address| address.is_private() || address.is_loopback())
        }
        Err(_) => false,
    }
}

fn is_suspicious_port(port: u16) -> bool {
    matches!(
        port,
        4444 | 5555
            | 6666
            | 7777
            | 8888
            | 9999
            | 31337
            | 12345
            | 54321
            | 6667
            | 6697
            | 1337
            | 10000
            | 20000
            | 65535
    )
}
