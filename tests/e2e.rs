//! Behavior on real kernels and a real sing-box, in the containerlab topology
//! of `tests/e2e`.
//!
//! Not part of `cargo test`; run `cargo test --test e2e` with the topology
//! deployed by `tests/e2e/lab.sh up`. Verdicts come from what the network
//! shows: origin echoes the address a connection came from (the node itself,
//! or the relay when sing-box carried it), and the resolver behind the relay
//! answers `probe.test` differently from the one on origin.

use std::{
    io::{self, Write},
    os::{linux::net::SocketAddrExt, unix::net},
    process::{Command, Output, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

const SING_BOX_CONFIG: &str = include_str!("e2e/uta/sing-box.json");

const UTA: &str = "/home/alice/.local/bin/uta";
const ALICE_CONFIG: &str = "/home/alice/.config/uta";

const ORIGIN: &str = "http://10.0.4.2/";
const ORIGIN6: &str = "http://[fd00:4::2]/";
const RELAY: &str = "10.0.3.2";
const RELAY6: &str = "[fd00:0003:0000:0000:0000:0000:0000:0002]";
const WORKSTATION: &str = "10.0.1.2";
const CLIENT: &str = "192.168.10.2";
/// What the resolver behind the relay and the one on origin answer for
/// `probe.test`.
const PROXIED: &str = "198.18.0.2";
const DIRECT: &str = "198.18.0.1";

/// Holds the topology, which the tests share, for one test. Runners may run
/// each test in a process of its own, so the lock is a name in the abstract
/// socket namespace: the kernel frees it with the process, and unlike a file
/// lock under `target/` it does not depend on the file system, where a waiter
/// on NFS polls only every few seconds.
fn lock() -> net::UnixListener {
    let name = net::SocketAddr::from_abstract_name("uta-e2e").expect("the name is valid");
    let lock = loop {
        match net::UnixListener::bind_addr(&name) {
            Ok(lock) => break lock,
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                sleep(Duration::from_millis(100));
            }
            Err(error) => panic!("locking the topology failed: {error}"),
        }
    };
    let running = docker(&[
        "inspect",
        "-f",
        "{{.State.Running}}",
        "clab-uta-workstation",
    ]);
    assert!(
        running.status.success() && stdout(&running) == "true",
        "the topology is not running; deploy it with tests/e2e/lab.sh up"
    );
    lock
}

fn docker(args: &[&str]) -> Output {
    Command::new("docker")
        .args(args)
        .output()
        .expect("docker runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

#[derive(Clone, Copy)]
enum As {
    Root,
    Alice,
    Bob,
}

/// Runs a shell script on a node.
fn sh(node: &str, user: As, script: &str) -> Output {
    sh_with_input(node, user, script, "")
}

fn sh_with_input(node: &str, user: As, script: &str, input: &str) -> Output {
    let container = format!("clab-uta-{node}");
    let mut args = vec!["exec", "-i"];
    match user {
        As::Root => {}
        As::Alice => args.extend(["-u", "alice", "-e", "XDG_RUNTIME_DIR=/run/user/1001"]),
        As::Bob => args.extend(["-u", "bob", "-e", "XDG_RUNTIME_DIR=/run/user/1002"]),
    }
    args.extend([container.as_str(), "sh", "-c", script]);
    let mut child = Command::new("docker")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("docker runs");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(input.as_bytes())
        .expect("docker reads stdin");
    child.wait_with_output().expect("docker runs")
}

/// Runs a script that must succeed and returns its output.
fn ok(node: &str, user: As, script: &str) -> String {
    let output = sh(node, user, script);
    assert!(
        output.status.success(),
        "`{script}` on {node} failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    stdout(&output)
}

fn write(node: &str, path: &str, content: &str, owner: &str) {
    let output = sh_with_input(
        node,
        As::Root,
        &format!("cat > {path} && chown {owner} {path}"),
        content,
    );
    assert!(output.status.success(), "writing {path} on {node} failed");
}

/// The address origin saw for a TCP connection.
fn seen(node: &str, user: As, url: &str) -> String {
    stdout(&sh(node, user, &format!("curl -s --http0.9 -m 5 {url}")))
}

/// The address origin saw for a UDP datagram.
fn seen_udp(node: &str, user: As, target: &str) -> String {
    stdout(&sh(
        node,
        user,
        &format!("echo x | socat -T 3 - {target},shut-none"),
    ))
}

fn resolve(node: &str, user: As, server: &str) -> String {
    stdout(&sh(
        node,
        user,
        &format!("dig +short +time=3 +tries=1 @{server} probe.test"),
    ))
}

fn wait_until(what: &str, timeout: Duration, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < timeout, "timed out waiting until {what}");
        sleep(Duration::from_millis(200));
    }
}

fn uta(user: As, args: &str) -> Output {
    sh("workstation", user, &format!("{UTA} {args}"))
}

/// Kernel objects uta owns on a node: (tables, rules of each family, routes of
/// each family).
fn kernel_objects(node: &str) -> (usize, usize, usize) {
    let count = |script: &str| ok(node, As::Root, script).parse().unwrap_or(0);
    (
        count("nft list tables | grep -c 'inet uta$' || true"),
        count("{ ip -4 rule; ip -6 rule; } | grep -c 'proto 117' || true"),
        count(
            "{ ip -4 route show table all; ip -6 route show table all; } | grep -c 'proto 117' || \
             true",
        ),
    )
}

/// Starts uta on the workstation as alice deploys it, with `rules` and the test
/// sing-box configuration. The unit reports readiness once traffic is
/// captured, so `systemctl start` returns only then.
fn start_workstation(rules: &str) {
    start_workstation_with(rules, SING_BOX_CONFIG);
}

fn start_workstation_with(rules: &str, sing_box_config: &str) {
    stop_workstation();
    write(
        "workstation",
        &format!("{ALICE_CONFIG}/uta.toml"),
        "[singbox]\nconfig = [\"sing-box\"]\n",
        "alice:alice",
    );
    write(
        "workstation",
        &format!("{ALICE_CONFIG}/rules"),
        rules,
        "alice:alice",
    );
    write(
        "workstation",
        &format!("{ALICE_CONFIG}/sing-box/config.json"),
        sing_box_config,
        "alice:alice",
    );
    ok(
        "workstation",
        As::Alice,
        "systemctl --user reset-failed uta 2>/dev/null; systemctl --user start uta",
    );
    assert!(uta(As::Alice, "status").status.success());
}

fn stop_workstation() {
    sh("workstation", As::Alice, "systemctl --user stop uta");
    assert_eq!(
        kernel_objects("workstation"),
        (0, 0, 0),
        "stopping uta left kernel state"
    );
}

#[test]
fn captures_the_selected_user_only() {
    let _topology = lock();
    start_workstation("uid:alice\n");
    assert_eq!(seen("workstation", As::Alice, ORIGIN), RELAY);
    assert_eq!(seen("workstation", As::Alice, ORIGIN6), RELAY6);
    assert_eq!(seen_udp("workstation", As::Alice, "UDP4:10.0.4.2:9"), RELAY);
    assert_eq!(
        seen_udp("workstation", As::Alice, "UDP6:[fd00:4::2]:9"),
        RELAY6
    );
    assert_eq!(seen("workstation", As::Bob, ORIGIN), WORKSTATION);
    assert_eq!(
        seen_udp("workstation", As::Bob, "UDP4:10.0.4.2:9"),
        WORKSTATION
    );
    stop_workstation();
    assert_eq!(seen("workstation", As::Alice, ORIGIN), WORKSTATION);
}

#[test]
fn dns_of_captured_sockets_reaches_sing_box() {
    let _topology = lock();
    start_workstation("uid:alice\n");
    assert_eq!(resolve("workstation", As::Alice, "127.0.0.53"), PROXIED);
    assert_eq!(resolve("workstation", As::Alice, "10.0.4.2"), PROXIED);
    assert_eq!(resolve("workstation", As::Bob, "127.0.0.53"), DIRECT);

    // Excluding the local resolver leaves queries to it alone, but not queries
    // to others.
    start_workstation("uid:alice\n!dst:127.0.0.53\n");
    assert_eq!(resolve("workstation", As::Alice, "127.0.0.53"), DIRECT);
    assert_eq!(resolve("workstation", As::Alice, "10.0.4.2"), PROXIED);
    stop_workstation();
}

#[test]
fn conditions_narrow_capture() {
    let _topology = lock();
    start_workstation("uid:alice\n!dst:10.0.4.0/24\n");
    assert_eq!(seen("workstation", As::Alice, ORIGIN), WORKSTATION);
    assert_eq!(seen("workstation", As::Alice, ORIGIN6), RELAY6);

    start_workstation("uid:alice\n!oif:eth1\n");
    assert_eq!(seen("workstation", As::Alice, ORIGIN), WORKSTATION);

    // Every condition of a rule must hold.
    start_workstation("uid:alice port:9\n");
    assert_eq!(seen("workstation", As::Alice, ORIGIN), WORKSTATION);
    assert_eq!(seen_udp("workstation", As::Alice, "UDP4:10.0.4.2:9"), RELAY);

    start_workstation("uid:alice proto:tcp\n");
    assert_eq!(seen("workstation", As::Alice, ORIGIN), RELAY);
    assert_eq!(
        seen_udp("workstation", As::Alice, "UDP4:10.0.4.2:9"),
        WORKSTATION
    );

    // Addresses of the other family are outside a negated IPv4 network.
    start_workstation("uid:alice dst:!10.0.4.0/24\n");
    assert_eq!(seen("workstation", As::Alice, ORIGIN), WORKSTATION);
    assert_eq!(seen("workstation", As::Alice, ORIGIN6), RELAY6);

    // Origin's networks are left alone, except DNS, so its resolver is still
    // reached through sing-box.
    start_workstation("uid:alice\n!dst:10.0.4.0/24,fd00:4::/64 port:!53\n");
    assert_eq!(seen("workstation", As::Alice, ORIGIN), WORKSTATION);
    assert_ne!(seen("workstation", As::Alice, ORIGIN6), RELAY6);
    assert_eq!(resolve("workstation", As::Alice, "10.0.4.2"), PROXIED);
    stop_workstation();
}

#[test]
fn gid_selects_sockets_of_a_group() {
    let _topology = lock();
    ok("workstation", As::Root, "groupadd -f proxied");
    start_workstation("gid:proxied\n");
    let as_proxied = format!(
        "setpriv --reuid=bob --regid=proxied --clear-groups curl -s --http0.9 -m 5 {ORIGIN}"
    );
    assert_eq!(ok("workstation", As::Root, &as_proxied), RELAY);
    assert_eq!(seen("workstation", As::Bob, ORIGIN), WORKSTATION);
    stop_workstation();
}

#[test]
fn kernel_state_removed_by_another_program() {
    let _topology = lock();
    start_workstation("uid:alice\n");
    // systemd-networkd removes rules it did not configure when it starts.
    ok(
        "workstation",
        As::Root,
        "ip rule del priority 5201; ip -6 rule del priority 5201; ip route flush table 7500; ip \
         -6 route flush table 7500",
    );
    wait_until(
        "uta puts policy routing back",
        Duration::from_secs(5),
        || seen("workstation", As::Alice, ORIGIN) == RELAY,
    );
    assert!(uta(As::Alice, "status").status.success());

    ok("workstation", As::Root, "nft delete table inet uta");
    assert!(!uta(As::Alice, "status").status.success());
    stop_workstation();
}

#[test]
fn cgroup_rules_follow_units_that_restart() {
    let _topology = lock();
    start_workstation("cgroup:/system.slice/uta-probe.service\n");
    // The unit connects after a pause, as tracking a new cgroup takes a moment.
    let probe = format!(
        "systemd-run --quiet --wait --pipe --unit uta-probe -p User=bob sh -c 'sleep 1; curl -s \
         --http0.9 -m 5 {ORIGIN}'"
    );
    assert_eq!(ok("workstation", As::Root, &probe), RELAY);
    // A new run of the unit has a new cgroup.
    assert_eq!(ok("workstation", As::Root, &probe), RELAY);
    assert_eq!(seen("workstation", As::Bob, ORIGIN), WORKSTATION);
    stop_workstation();
}

#[test]
fn run_captures_one_command() {
    let _topology = lock();
    start_workstation("");
    assert_eq!(
        stdout(&uta(
            As::Alice,
            &format!("run curl -s --http0.9 -m 5 {ORIGIN}")
        )),
        RELAY
    );
    assert_eq!(seen("workstation", As::Alice, ORIGIN), WORKSTATION);
    assert_eq!(uta(As::Alice, "run sh -c 'exit 7'").status.code(), Some(7));

    // A run inside a run stays in the enclosing scope.
    let nested = stdout(&uta(
        As::Alice,
        &format!("run sh -c 'cat /proc/self/cgroup; {UTA} run cat /proc/self/cgroup'"),
    ));
    let scopes: Vec<&str> = nested.lines().collect();
    assert_eq!(scopes.len(), 2, "{nested}");
    assert_eq!(scopes[0], scopes[1]);
    assert_eq!(
        stdout(&uta(
            As::Alice,
            &format!("run {UTA} run curl -s --http0.9 -m 5 {ORIGIN}")
        )),
        RELAY
    );
    stop_workstation();
}

#[test]
fn run_with_captures_sources_until_the_command_ends() {
    let _topology = lock();
    start_workstation("");
    ok(
        "workstation",
        As::Alice,
        &format!("setsid {UTA} run --with uid:bob sleep 60 >/dev/null 2>&1 &"),
    );
    wait_until("the run is captured", Duration::from_secs(10), || {
        stdout(&uta(As::Alice, "status")).contains("with uid:bob")
    });
    assert_eq!(seen("workstation", As::Bob, ORIGIN), RELAY);
    ok("workstation", As::Root, "pkill -u alice -x sleep");
    wait_until("the run ends", Duration::from_secs(10), || {
        !stdout(&uta(As::Alice, "status")).contains("uta run:")
    });
    assert_eq!(seen("workstation", As::Bob, ORIGIN), WORKSTATION);
    stop_workstation();
}

/// Runs `uta <args>` in a terminal, typing `answer`, if any, after a second.
fn uta_in_terminal(args: &str, answer: Option<&str>) -> Output {
    let typing = answer.map_or_else(String::new, |answer| format!("echo {answer};"));
    sh(
        "workstation",
        As::Alice,
        &format!("(sleep 1; {typing} sleep 3) | script -qec '{UTA} {args}' /dev/null"),
    )
}

fn rules_file() -> String {
    ok(
        "workstation",
        As::Alice,
        &format!("cat {ALICE_CONFIG}/rules"),
    )
}

#[test]
fn add_and_del_match_rules_by_meaning() {
    let _topology = lock();
    start_workstation("uid:alice\n");
    assert!(
        uta(As::Alice, "add --yes 'port:80,9 uid:bob'")
            .status
            .success()
    );
    assert_eq!(rules_file(), "uid:alice\nuid:bob port:9,80");
    assert_eq!(seen_udp("workstation", As::Bob, "UDP4:10.0.4.2:9"), RELAY);
    assert!(
        uta(As::Alice, "del --yes 'uid:bob port:9,80,9'")
            .status
            .success()
    );
    assert_eq!(rules_file(), "uid:alice");
    stop_workstation();
}

#[test]
fn changes_to_capture_need_confirmation() {
    let _topology = lock();
    start_workstation("uid:alice\n");

    let kept = uta_in_terminal("add uid:bob", Some("y"));
    assert!(kept.status.success(), "{}", stdout(&kept));
    assert_eq!(rules_file(), "uid:alice\nuid:bob");
    assert_eq!(seen("workstation", As::Bob, ORIGIN), RELAY);

    let refused = uta_in_terminal("del uid:bob", Some("n"));
    assert!(!refused.status.success());
    assert_eq!(rules_file(), "uid:alice\nuid:bob");
    assert_eq!(seen("workstation", As::Bob, ORIGIN), RELAY);

    let expired = uta_in_terminal("del uid:bob --timeout 1", None);
    assert!(!expired.status.success());
    assert_eq!(seen("workstation", As::Bob, ORIGIN), RELAY);

    // The client goes away while the daemon waits for confirmation.
    ok(
        "workstation",
        As::Alice,
        &format!(
            "(sleep 30) | script -qec '{UTA} del uid:bob --timeout 30' /dev/null & sleep 1.5; \
             pkill -f '^{UTA} del'; sleep 1"
        ),
    );
    assert_eq!(seen("workstation", As::Bob, ORIGIN), RELAY);
    assert_eq!(rules_file(), "uid:alice\nuid:bob");

    let without_terminal = uta(As::Alice, "del uid:bob");
    assert!(!without_terminal.status.success());

    assert!(uta(As::Alice, "del uid:bob --yes").status.success());
    assert_eq!(seen("workstation", As::Bob, ORIGIN), WORKSTATION);
    stop_workstation();
}

#[test]
fn an_unwritable_rules_file_rolls_the_change_back() {
    let _topology = lock();
    start_workstation("uid:alice\n");
    ok(
        "workstation",
        As::Root,
        &format!("chmod 555 {ALICE_CONFIG}"),
    );
    let output = uta(As::Alice, "add uid:bob --yes");
    ok(
        "workstation",
        As::Root,
        &format!("chmod 755 {ALICE_CONFIG}"),
    );
    assert!(!output.status.success());
    assert_eq!(rules_file(), "uid:alice");
    assert_eq!(seen("workstation", As::Bob, ORIGIN), WORKSTATION);
    stop_workstation();
}

#[test]
fn a_pending_change_makes_other_changes_busy() {
    let _topology = lock();
    start_workstation("uid:alice\n");
    let pending = format!("(sleep 5) | script -qec '{UTA} add uid:bob --timeout 4' /dev/null");
    let script =
        format!("{pending} >/dev/null & sleep 1.5; {UTA} apply --yes 2>&1; echo \"exit $?\"; wait");
    let output = ok("workstation", As::Alice, &script);
    assert!(output.contains("the daemon is busy"), "{output}");
    assert!(output.ends_with("exit 1"), "{output}");
    stop_workstation();
}

#[test]
fn fails_open_when_sing_box_dies() {
    let _topology = lock();
    start_workstation("uid:alice\n");
    let objects = kernel_objects("workstation");
    let daemon = ok(
        "workstation",
        As::Root,
        &format!("pgrep -f '^{UTA} daemon'"),
    );
    ok("workstation", As::Root, "pkill -KILL -x sing-box");
    wait_until("traffic goes direct", Duration::from_secs(5), || {
        seen("workstation", As::Alice, ORIGIN) == WORKSTATION
    });
    // systemd restarts the daemon, which captures again.
    wait_until("capture resumes", Duration::from_secs(20), || {
        seen("workstation", As::Alice, ORIGIN) == RELAY
    });
    assert_ne!(
        ok(
            "workstation",
            As::Root,
            &format!("pgrep -f '^{UTA} daemon'")
        ),
        daemon
    );
    assert_eq!(kernel_objects("workstation"), objects);
    stop_workstation();
}

#[test]
fn a_killed_daemon_leaves_nothing_behind() {
    let _topology = lock();
    start_workstation("uid:alice\n");
    let objects = kernel_objects("workstation");
    ok(
        "workstation",
        As::Root,
        &format!("pkill -KILL -f '^{UTA} daemon'"),
    );
    wait_until("capture resumes", Duration::from_secs(20), || {
        uta(As::Alice, "status").status.success() && seen("workstation", As::Alice, ORIGIN) == RELAY
    });
    assert_eq!(kernel_objects("workstation"), objects);
    assert_eq!(ok("workstation", As::Root, "pgrep -c -x sing-box"), "1");
    stop_workstation();
}

#[test]
fn relative_paths_in_the_sing_box_configuration_resolve_against_its_directory() {
    let _topology = lock();
    write(
        "workstation",
        &format!("{ALICE_CONFIG}/rule-set.json"),
        r#"{ "version": 3, "rules": [{ "ip_cidr": ["10.0.4.0/24"] }] }"#,
        "alice:alice",
    );
    let mut config: serde_json::Value = serde_json::from_str(SING_BOX_CONFIG).unwrap();
    config["route"]["rule_set"] = serde_json::json!([
        { "type": "local", "tag": "origin", "format": "source", "path": "rule-set.json" }
    ]);
    config["route"]["rules"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({ "rule_set": "origin", "outbound": "direct" }));
    start_workstation_with("uid:alice\n", &config.to_string());
    // Captured, then sent out directly by the rule from the relative rule-set.
    assert_eq!(seen("workstation", As::Alice, ORIGIN), WORKSTATION);
    assert_eq!(seen("workstation", As::Alice, ORIGIN6), RELAY6);
    stop_workstation();
}

#[test]
fn sing_box_log_settings_cannot_hide_startup() {
    let _topology = lock();
    let mut config: serde_json::Value = serde_json::from_str(SING_BOX_CONFIG).unwrap();
    config["log"] = serde_json::json!({ "disabled": true, "output": "sing-box.log" });
    start_workstation_with("uid:alice\n", &config.to_string());
    assert_eq!(seen("workstation", As::Alice, ORIGIN), RELAY);
    stop_workstation();
}

#[test]
fn a_failed_reload_keeps_the_running_configuration() {
    let _topology = lock();
    start_workstation("uid:alice\n");
    // Passes `sing-box check`, but the local resolver holds the port.
    let mut config: serde_json::Value = serde_json::from_str(SING_BOX_CONFIG).unwrap();
    config["inbounds"] = serde_json::json!([
        { "type": "direct", "tag": "taken", "listen": "127.0.0.53", "listen_port": 53 }
    ]);
    write(
        "workstation",
        &format!("{ALICE_CONFIG}/sing-box/config.json"),
        &config.to_string(),
        "alice:alice",
    );
    let output = uta(As::Alice, "apply --yes");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("runs the previous one again"));
    assert_eq!(seen("workstation", As::Alice, ORIGIN), RELAY);
    assert!(stdout(&uta(As::Alice, "status")).contains("sing-box configuration changed"));
    stop_workstation();
}

#[test]
fn one_daemon_per_network_namespace() {
    let _topology = lock();
    start_workstation("uid:alice\n");
    let second = sh(
        "workstation",
        As::Alice,
        &format!(
            "sudo -n setpriv --reuid=1001 --regid=1001 --init-groups --inh-caps=+net_admin \
             --ambient-caps=+net_admin -- {UTA} daemon --config {ALICE_CONFIG}/uta.toml --rules \
             {ALICE_CONFIG}/rules --runtime-dir /tmp/second"
        ),
    );
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("a uta daemon is running"));
    assert_eq!(seen("workstation", As::Alice, ORIGIN), RELAY);
    stop_workstation();
}

/// Starts uta on the router as `contrib/system` deploys it, with the local
/// resolver running.
fn start_router(rules: &str) {
    // A previous test may have left sing-box holding the resolver's port.
    stop_router();
    ok("router", As::Root, "systemctl start dnsmasq");
    start_router_with(rules, SING_BOX_CONFIG);
}

fn start_router_with(rules: &str, sing_box_config: &str) {
    stop_router();
    write("router", "/etc/uta/rules", rules, "root:root");
    write(
        "router",
        "/etc/uta/sing-box/config.json",
        sing_box_config,
        "root:root",
    );
    ok(
        "router",
        As::Root,
        "systemctl reset-failed uta 2>/dev/null; systemctl start uta",
    );
    assert!(sh("router", As::Root, "uta status").status.success());
}

fn stop_router() {
    sh("router", As::Root, "systemctl stop uta");
    assert_eq!(
        kernel_objects("router"),
        (0, 0, 0),
        "stopping uta left kernel state"
    );
}

#[test]
fn captures_forwarded_traffic() {
    let _topology = lock();
    for src_valid_mark in [0, 1] {
        ok(
            "router",
            As::Root,
            &format!("sysctl -qw net.ipv4.conf.all.src_valid_mark={src_valid_mark}"),
        );
        start_router("iif:eth2\n");
        assert_eq!(
            seen("client", As::Root, ORIGIN),
            RELAY,
            "src_valid_mark={src_valid_mark}"
        );
        assert_eq!(seen("client", As::Root, ORIGIN6), RELAY6);
        assert_eq!(seen_udp("client", As::Root, "UDP4:10.0.4.2:9"), RELAY);
        assert_eq!(resolve("client", As::Root, "10.0.4.2"), PROXIED);
    }
    ok(
        "router",
        As::Root,
        "sysctl -qw net.ipv4.conf.all.src_valid_mark=0",
    );

    start_router("iif:eth2\n!oif:eth1\n");
    assert_eq!(seen("client", As::Root, ORIGIN), CLIENT);

    start_router("iif:eth2\nlocal\n");
    assert_eq!(seen("client", As::Root, ORIGIN), RELAY);
    assert_eq!(seen("router", As::Root, ORIGIN), RELAY);
    stop_router();
    assert_eq!(seen("client", As::Root, ORIGIN), CLIENT);
}

#[test]
fn forwarded_traffic_by_source() {
    let _topology = lock();
    start_router("src:192.168.10.2\n");
    assert_eq!(seen("client", As::Root, ORIGIN), RELAY);
    assert_ne!(seen("client", As::Root, ORIGIN6), RELAY6);

    start_router("iif:eth2\n!src:192.168.10.2\n");
    assert_eq!(seen("client", As::Root, ORIGIN), CLIENT);
    assert_eq!(seen("client", As::Root, ORIGIN6), RELAY6);

    let mac = ok("client", As::Root, "cat /sys/class/net/eth1/address");
    start_router(&format!("mac:{mac}\n"));
    assert_eq!(seen("client", As::Root, ORIGIN), RELAY);
    start_router("mac:02:00:5e:10:00:01\n");
    assert_eq!(seen("client", As::Root, ORIGIN), CLIENT);

    start_router("iif:eth2\n!proto:udp sport:5555\n");
    assert_eq!(
        seen_udp("client", As::Root, "UDP4:10.0.4.2:9,bind=:5555"),
        CLIENT
    );
    assert_eq!(seen_udp("client", As::Root, "UDP4:10.0.4.2:9"), RELAY);
    stop_router();
}

#[test]
fn datagrams_from_other_ports_reach_the_client_from_there() {
    let _topology = lock();
    let mut config: serde_json::Value = serde_json::from_str(SING_BOX_CONFIG).unwrap();
    config["route"]["rules"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({ "port": 10, "outbound": "direct" }));
    // With local, uta also captures the sockets of sing-box itself.
    start_router_with("iif:eth2\nlocal\n", &config.to_string());
    // Origin answers a datagram to port 10 from port 11; sing-box passes the
    // answer on from where it came. The client's datagram back to port 11
    // goes through sing-box too, instead of leaving as an answer to it.
    let answer = ok(
        "client",
        As::Root,
        r#"python3 -c '
import socket
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.settimeout(3)
client.sendto(b"x", ("10.0.4.2", 10))
_, source = client.recvfrom(64)
client.sendto(b"x", source)
seen, _ = client.recvfrom(64)
print(f"{source[0]}:{source[1]} {seen.decode()}")
'"#,
    );
    let (source, seen) = answer.split_once(' ').unwrap();
    assert_eq!(source, "10.0.4.2:11");
    assert_ne!(seen, CLIENT);
    stop_router();
}

#[test]
fn dns_of_forwarded_clients_reaches_sing_box() {
    let _topology = lock();
    start_router("iif:eth2\n");
    assert_eq!(resolve("client", As::Root, "192.168.10.1"), PROXIED);
    assert_eq!(resolve("client", As::Root, "fd00:10::1"), PROXIED);
    // Only redirected queries reach the DNS inbound.
    assert!(
        !sh(
            "client",
            As::Root,
            "dig +short +time=2 +tries=1 -p 7853 @192.168.10.1 probe.test"
        )
        .status
        .success()
    );

    start_router("iif:eth2\n!dst:192.168.10.1\n");
    assert_eq!(resolve("client", As::Root, "192.168.10.1"), DIRECT);
    stop_router();
    assert_eq!(resolve("client", As::Root, "192.168.10.1"), DIRECT);
}

#[test]
fn sing_box_can_replace_the_local_resolver() {
    let _topology = lock();
    let mut config: serde_json::Value = serde_json::from_str(SING_BOX_CONFIG).unwrap();
    // Replies to captured queries for other resolvers leave from sockets bound
    // to those resolvers' addresses and port 53, which a wildcard listener on
    // port 53 allows only with reuse_addr.
    config["inbounds"] = serde_json::json!([
        { "type": "direct", "tag": "resolver", "listen": "::", "listen_port": 53, "reuse_addr": true }
    ]);
    config["route"]["rules"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({ "inbound": "resolver", "action": "hijack-dns" }));
    stop_router();
    ok("router", As::Root, "systemctl stop dnsmasq");
    start_router_with("iif:eth2\n", &config.to_string());
    assert_eq!(resolve("client", As::Root, "192.168.10.1"), PROXIED);
    assert_eq!(resolve("client", As::Root, "10.0.4.2"), PROXIED);
    // Software on the router that uta leaves alone uses sing-box directly.
    assert_eq!(resolve("router", As::Root, "127.0.0.1"), PROXIED);
    stop_router();
    ok("router", As::Root, "systemctl start dnsmasq");
}
