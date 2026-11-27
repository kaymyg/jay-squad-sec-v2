use jay_squad_sec::telemetry::{
    parse_netstat, parse_proc_net_tcp, parse_reg_query, parse_tasklist_csv, suspicious_path,
};

#[test]
fn parsers_return_empty_or_bounded_results_for_empty_and_header_only_input() {
    assert!(parse_proc_net_tcp("").is_empty());
    assert!(parse_tasklist_csv("").is_empty());
    assert!(parse_netstat("").is_empty());
    assert!(parse_reg_query("").is_empty());
    assert!(parse_proc_net_tcp("sl local rem st").is_empty());
}

#[test]
fn malformed_numeric_fields_are_ignored() {
    let proc = "header\n0: 0100007F:ZZZZ 08080808:01BB 01 a b c d e f nope";
    assert!(parse_proc_net_tcp(proc).is_empty());
    let netstat = "TCP 10.0.0.1:1 8.8.8.8:443 ESTABLISHED nope";
    assert!(parse_netstat(netstat).is_empty());
    let tasklist = "\"bad.exe\",\"not-a-pid\",\"Console\",\"1\",\"10 K\"";
    assert!(parse_tasklist_csv(tasklist).is_empty());
}

#[test]
fn path_heuristic_does_not_treat_unrelated_paths_as_staging_locations() {
    assert!(suspicious_path("/usr/bin/systemd").is_none());
    assert!(suspicious_path("C:\\Program Files\\Vendor\\agent.exe").is_none());
}
