use std::{
    io::Write,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;

fn run_cordis_mcp_stdio(messages: &[&str]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_catomicals"))
        .args(["mcp", "cordis-serve"])
        .env("CATOMICALS_CORDIS_BRIDGE_URL", "http://127.0.0.1:18788")
        .env("CATOMICALS_CORDIS_SESSION_TOKEN", "test-session-token")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn catomicals CLI");
    let mut stdin = child.stdin.take().expect("child stdin");
    for message in messages {
        writeln!(stdin, "{message}").expect("write MCP message");
    }
    drop(stdin);
    wait_with_timeout(child)
}

fn wait_with_timeout(mut child: Child) -> std::process::Output {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait().expect("poll catomicals CLI") {
            Some(_) => {
                return child
                    .wait_with_output()
                    .expect("read catomicals CLI output");
            }
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            None => {
                let _ = child.kill();
                let output = child.wait_with_output().expect("kill catomicals CLI");
                panic!(
                    "catomicals CLI timed out; stderr: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}

#[test]
fn cordis_mcp_has_a_separate_stdio_subcommand() {
    let output = Command::new(env!("CARGO_BIN_EXE_catomicals"))
        .args(["mcp", "cordis-serve", "--help"])
        .output()
        .expect("run catomicals CLI");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("bridge-url"));
    assert!(!stdout.contains("session-token"));
}

#[test]
fn cordis_mcp_fails_closed_without_the_bridge_url() {
    let output = Command::new(env!("CARGO_BIN_EXE_catomicals"))
        .args(["mcp", "cordis-serve"])
        .env_remove("CATOMICALS_CORDIS_BRIDGE_URL")
        .env("CATOMICALS_CORDIS_SESSION_TOKEN", "test-session-token")
        .output()
        .expect("run catomicals CLI");

    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "Error: Cordis bridge URL is not configured"
    );
}

#[test]
fn cordis_mcp_fails_closed_without_the_session_token() {
    let output = Command::new(env!("CARGO_BIN_EXE_catomicals"))
        .args(["mcp", "cordis-serve"])
        .env("CATOMICALS_CORDIS_BRIDGE_URL", "http://127.0.0.1:18788")
        .env_remove("CATOMICALS_CORDIS_SESSION_TOKEN")
        .output()
        .expect("run catomicals CLI");

    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "Error: Cordis session token is not configured"
    );
}

#[test]
fn cordis_mcp_rejects_every_bridge_url_except_a_bare_ipv4_loopback_origin() {
    for rejected in [
        "https://127.0.0.1:18788",
        "http://localhost:18788",
        "http://[::1]:18788",
        "http://127.1:18788",
        "http://2130706433:18788",
        "http://192.168.1.10:18788",
        "http://user:password@127.0.0.1:18788",
        "http://127.0.0.1",
        "http://127.0.0.1:0",
        "http://127.0.0.1:18788/prefix",
        "http://127.0.0.1:18788?query=1",
        "http://127.0.0.1:18788#fragment",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_catomicals"))
            .args(["mcp", "cordis-serve"])
            .env("CATOMICALS_CORDIS_BRIDGE_URL", rejected)
            .env("CATOMICALS_CORDIS_SESSION_TOKEN", "test-session-token")
            .output()
            .expect("run catomicals CLI");

        assert!(!output.status.success(), "accepted {rejected}");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr).trim(),
            "Error: Cordis bridge URL must be http://127.0.0.1:<non-zero-port>",
            "unexpected error for {rejected}"
        );
    }
}

#[test]
fn cordis_mcp_rejects_an_empty_session_token() {
    let output = Command::new(env!("CARGO_BIN_EXE_catomicals"))
        .args(["mcp", "cordis-serve"])
        .env("CATOMICALS_CORDIS_BRIDGE_URL", "http://127.0.0.1:18788")
        .env("CATOMICALS_CORDIS_SESSION_TOKEN", "")
        .output()
        .expect("run catomicals CLI");

    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "Error: Cordis session token is not configured"
    );
}

#[test]
fn cordis_mcp_serves_stdio_until_the_client_closes_input() {
    let output = run_cordis_mcp_stdio(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    ]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cordis_mcp_identifies_as_the_config_server() {
    let output = run_cordis_mcp_stdio(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    ]);
    assert!(output.status.success());
    let response = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value.get("id") == Some(&Value::from(1)))
        .expect("initialize response");
    assert_eq!(
        response["result"]["serverInfo"]["name"],
        "catomicals-config"
    );
}

#[test]
fn cordis_mcp_tool_surface_is_exactly_six_configuration_tools() {
    let output = run_cordis_mcp_stdio(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
    ]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value.get("id") == Some(&Value::from(2)))
        .expect("tools/list response");
    let mut names: Vec<_> = response["result"]["tools"]
        .as_array()
        .expect("tool array")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    for tool in response["result"]["tools"].as_array().expect("tool array") {
        assert_eq!(
            tool["outputSchema"]["type"], "object",
            "{} must publish an object outputSchema for strict MCP clients",
            tool["name"],
        );
    }
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "create_plugin_settings_intent",
            "list_plugins",
            "read_plugin_health",
            "read_plugin_manifest",
            "read_plugin_settings_schema",
            "validate_plugin_settings_patch",
        ]
    );
    for forbidden in ["confirm", "apply", "secret", "install", "sign", "broadcast"] {
        assert!(names.iter().all(|name| !name.contains(forbidden)));
    }
}

#[test]
fn cordis_mcp_patch_schema_is_closed_keyed_and_safely_bounded() {
    let output = run_cordis_mcp_stdio(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
    ]);
    assert!(output.status.success());
    let response = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value.get("id") == Some(&Value::from(2)))
        .expect("tools/list response");
    let tool = response["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "validate_plugin_settings_patch")
        .expect("validate tool");
    let schema = &tool["inputSchema"];
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["$defs"]["SettingsPatch"]["additionalProperties"],
        false
    );
    let changes = &schema["$defs"]["SettingsPatch"]["properties"]["changes"];
    assert_eq!(changes["minProperties"], 1);
    assert_eq!(changes["maxProperties"], 128);
    assert_eq!(
        changes["propertyNames"]["pattern"],
        "^[a-z][A-Za-z0-9]*(?:[.-][A-Za-z0-9]+)*$"
    );
    let setting_value = schema["$defs"]["SettingValue"].to_string();
    assert!(setting_value.contains("9007199254740991"));
    assert!(setting_value.contains("65536"));
    let list_tool = response["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "list_plugins")
        .expect("list tool");
    assert_eq!(list_tool["inputSchema"]["additionalProperties"], false);
}
