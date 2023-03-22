use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    time::Duration,
};

use anyhow::{anyhow, Result};
use clap::Parser;
use dns_lookup::{AddrInfoHints, AddrInfoIter};

const ABUSEHOST: &str = "whois.abuse.net";
const ANICHOST: &str = "whois.arin.net";
const DENICHOST: &str = "whois.denic.de";
const DKNICHOST: &str = "whois.dk-hostmaster.dk";
const FNICHOST: &str = "whois.afrinic.net";
const GNICHOST: &str = "whois.nic.gov";
const IANAHOST: &str = "whois.iana.org";
const INICHOST: &str = "whois.internic.net";
const KNICHOST: &str = "whois.krnic.net";
const LNICHOST: &str = "whois.lacnic.net";
const MNICHOST: &str = "whois.ra.net";
const PDBHOST: &str = "whois.peeringdb.com";
const PNICHOST: &str = "whois.apnic.net";
const QNICHOST_TAIL: &str = ".whois-servers.net";
const RNICHOST: &str = "whois.ripe.net";
const VNICHOST: &str = "whois.verisign-grs.com";

/// Internet domain name and network number directory service
#[derive(Parser, Debug)]
//#[command(author, version, about, long_about = None, disable_help_flag = true)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Use the American Registry for Internet Numbers (ARIN) database.  It
    /// contains network numbers used in those parts of the world covered
    /// neither by APNIC, AfriNIC, LACNIC, nor by RIPE.  The query syntax
    /// is documented at https://www.arin.net/resources/whoisrws/whois_api.html#nicname
    #[arg(short = 'a')]
    use_anichost: bool,

    #[arg(short = 'A')]
    use_pnichost: bool,

    #[arg(short = 'b')]
    use_abusehost: bool,

    #[arg(short = 'c')]
    country: Option<String>,

    #[arg(short = 'f')]
    use_fnichost: bool,

    #[arg(short = 'g')]
    use_gnichost: bool,

    // TODO: should be lowercase 'h', but also get '--help' to still work
    // i.e. "disable_help_flag" makes it possible to use 'h' but breaks
    // the help / usage flag.
    #[arg(short = 'H')]
    host: Option<String>,

    #[arg(short = 'i')]
    use_inichost: bool,

    #[arg(short = 'I')]
    use_ianahost: bool,

    #[arg(short = 'k')]
    use_knichost: bool,

    #[arg(short = 'l')]
    use_lnichost: bool,

    #[arg(short = 'm')]
    use_mnichost: bool,

    #[arg(short = 'p')]
    port: Option<String>,

    #[arg(short = 'P')]
    use_pdbhost: bool,

    #[arg(short = 'Q')]
    quick: bool,

    #[arg(short = 'r')]
    use_rnichost: bool,

    #[arg(short = 'R')]
    recurse: bool,

    #[arg(short = 'S')]
    spam_me: bool,

    names: Vec<String>,
}

fn resolve_static_host(args: &Args) -> Option<&'static str> {
    if args.use_anichost {
        return Some(ANICHOST);
    }
    if args.use_pnichost {
        return Some(PNICHOST);
    }
    if args.use_abusehost {
        return Some(ABUSEHOST);
    }
    if args.use_fnichost {
        return Some(FNICHOST);
    }
    if args.use_gnichost {
        return Some(GNICHOST);
    }
    if args.use_inichost {
        return Some(INICHOST);
    }
    if args.use_ianahost {
        return Some(IANAHOST);
    }
    if args.use_knichost {
        return Some(KNICHOST);
    }
    if args.use_lnichost {
        return Some(LNICHOST);
    }
    if args.use_mnichost {
        return Some(MNICHOST);
    }
    if args.use_pdbhost {
        return Some(PDBHOST);
    }
    if args.use_rnichost {
        return Some(RNICHOST);
    }
    None
}

const CONNECT_TIMEOUT: Duration = Duration::new(180, 0);
const WRITE_TIMEOUT: Duration = Duration::new(180, 0);
const PROTOCOL_TCP: i32 = 6;
const _PROTOCOL_UDP: i32 = 17;
const IPV4_ADDR: i32 = 2;
const _IPV6_ADDR: i32 = 30;
const SOCKTYPE_TCP: i32 = 1;
const _SOCKTYPE_UDP: i32 = 2;

fn connect_first(ai_iter: AddrInfoIter) -> Result<TcpStream> {
    for ai in ai_iter {
        match ai {
            Ok(ai) => {
                if ai.address == IPV4_ADDR && ai.protocol == PROTOCOL_TCP {
                    let result = TcpStream::connect_timeout(&ai.sockaddr, CONNECT_TIMEOUT)?;
                    return Ok(result);
                }
            }
            // Skip errors in resolution
            Err(_) => (),
        }
    }
    Err(anyhow!("could not resolve address"))
}

fn build_query(hostname: &str, query: &str, spam_me: bool) -> String {
    if !spam_me
        && (hostname == DENICHOST
            || hostname == String::from("de".to_owned().clone() + QNICHOST_TAIL).as_str())
    {
        if query.contains(|c: char| !c.is_ascii()) {
            return format!("-T dn,ace {query}\r\n");
        } else {
            return format!("-T dn {query}\r\n");
        }
    } else if !spam_me
        && (hostname == DKNICHOST
            || hostname == String::from("dk".to_owned().clone() + QNICHOST_TAIL).as_str())
    {
        return format!("--show-handles {query}\r\n");
    } else if spam_me || query.contains(|c: char| c == ' ') {
        return format!("{query}\r\n");
    } else if hostname == ANICHOST {
        if query.starts_with("AS") && query[2..].contains(|c: char| c.is_ascii_digit()) {
            return format!("+ a {}\r\n", &query[2..]);
        } else {
            return format!("+ {query}\r\n");
        }
    } else if hostname == VNICHOST {
        return format!("domain {query}\r\n");
    }
    format!("{query}\r\n")
}

// TODO: put flags into a struct
fn whois(query: &str, hostname: &str, service: &str, flags: &WhoisFlags) -> Result<()> {
    let ai_canonname = 0x02;
    let hints = AddrInfoHints {
        socktype: SOCKTYPE_TCP,
        flags: ai_canonname,
        ..Default::default()
    };
    let ai_iter = match dns_lookup::getaddrinfo(Some(hostname), Some(service), Some(hints)) {
        Ok(v) => v,
        Err(err) => panic!(">> {:?}", err),
    };
    let mut connection = connect_first(ai_iter)?;
    let query = build_query(query, hostname, flags.spam_me);
    connection.set_write_timeout(Some(WRITE_TIMEOUT))?;
    connection.write(query.as_bytes())?;
    connection.flush()?;
    let buf_reader = BufReader::new(&connection);
    let mut comment = 0;
    if !flags.spam_me && (hostname == ANICHOST || hostname == RNICHOST) {
        comment = 2;
    }
    for line in buf_reader.lines() {
        let line = match line {
            Ok(v) => v,
            Err(_) => break,
        };
        if !flags.spam_me && line == "-- \r" {
            break;
        }
        if comment == 1 && line.starts_with("#") {
            break;
        } else if comment == 2 {
            if line.is_empty() || line.starts_with(|c: char| c == '#' || c == '%' || c == '\r') {
                continue
            } else {
                comment = 1;
            }
        }
        println!("{line}");
    }
    Ok(())
}

fn resolve_env_var(keys: &[&str]) -> Option<String> {
    for key in keys {
        match std::env::var(key) {
            Ok(v) => if !v.is_empty() { return Some(v) },
            Err(_) => (),
        };
    }
    None
}

fn choose_default_server(query: &str) -> String {
    if query.ends_with("-ARIN") {
        return String::from(ANICHOST);
    }
    if query.ends_with("-NICAT") {
        return format!("at{QNICHOST_TAIL}");
    }
    if query.ends_with("-NORID") {
        return format!("no{QNICHOST_TAIL}");
    }
    if query.ends_with("-RIPE") {
        return String::from(RNICHOST);
    }
    if query.ends_with(".ac.uk") {
        return format!("ac.uk{QNICHOST_TAIL}");
    }
    if query.ends_with(".gov.uk") {
        return format!("ac.uk{QNICHOST_TAIL}");
    }
    String::from(IANAHOST)
}

struct WhoisFlags {
    recurse: bool,
    quick: bool,
    spam_me: bool,
}

fn main() {
    let args = Args::parse();
    let static_host = resolve_static_host(&args);
    let host = match static_host {
        Some(v) => Some(String::from(v)),
        None => args.host.clone(),
    };
    let host = match host {
        Some(v) => Some(v),
        None => {
            match &args.country {
                Some(country) => Some(format!("{country}{QNICHOST_TAIL}")),
                None => resolve_env_var(&["WHOIS_SERVER", "RA_SERVER"]),
            }
        }
    };
    // If no host or country is specified, rely on referrals from IANA.
    let flags = WhoisFlags {
        recurse: args.recurse || !args.quick && host.is_none() && args.country.is_none(),
        quick: args.quick,
        spam_me: args.spam_me
    };
    let port = match &args.port {
        Some(v) => v.clone(),
        None => String::from("whois"),
    };
    for name in args.names {
        let host = host.clone().unwrap_or_else(|| choose_default_server(name.as_str()));
        if args.country.is_none() {
            match whois(
                name.as_str(),
                host.as_str(),
                port.as_str(),
                &flags,
            ) {
                Ok(_) => (),
                Err(err) => println!("ERROR: {err}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_de_host() {
        let q = build_query(DENICHOST, "foo.com", false);
        assert_eq!(q, "-T dn foo.com\r\n");
        let q = build_query("de.whois-servers.net", "foo.com", false);
        assert_eq!(q, "-T dn foo.com\r\n");
        let q = build_query(DENICHOST, "f·o.com", false);
        assert_eq!(q, "-T dn,ace f·o.com\r\n");
        let q = build_query("de.whois-servers.net", "f·o.com", false);
        assert_eq!(q, "-T dn,ace f·o.com\r\n");
        let q = build_query(DENICHOST, "foo.com", true);
        assert_eq!(q, "foo.com\r\n");
        let q = build_query("de.whois-servers.net", "foo.com", true);
        assert_eq!(q, "foo.com\r\n");
    }

    #[test]
    fn test_dk_host() {
        let q = build_query(DKNICHOST, "foo.com", false);
        assert_eq!(q, "--show-handles foo.com\r\n");
        let q = build_query("dk.whois-servers.net", "foo.com", false);
        assert_eq!(q, "--show-handles foo.com\r\n");
        let q = build_query(DKNICHOST, "foo.com", true);
        assert_eq!(q, "foo.com\r\n");
        let q = build_query("dk.whois-servers.net", "foo.com", true);
        assert_eq!(q, "foo.com\r\n");
    }

    #[test]
    fn test_host_with_space() {
        let q = build_query(VNICHOST, "foo.com bar.com", false);
        assert_eq!(q, "foo.com bar.com\r\n");
        let q = build_query(VNICHOST, "foo.com bar.com", true);
        assert_eq!(q, "foo.com bar.com\r\n");
    }

    #[test]
    fn test_anic_host() {
        let q = build_query(ANICHOST, "foo.com", false);
        assert_eq!(q, "+ foo.com\r\n");
        let q = build_query(ANICHOST, "AS1234", false);
        assert_eq!(q, "+ a 1234\r\n");
        let q = build_query(ANICHOST, "AP1234", false);
        assert_eq!(q, "+ AP1234\r\n");
    }

    #[test]
    fn test_vnic_host() {
        let q = build_query(VNICHOST, "foo.com", false);
        assert_eq!(q, "domain foo.com\r\n");
    }
}
