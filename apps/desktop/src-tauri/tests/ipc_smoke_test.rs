use boundaryx_desktop::EngineSupervisor;
use std::time::Duration;

#[tokio::test]
async fn test_desktop_ipc_to_engine_sidecar_smoke() {
    let supervisor = EngineSupervisor::new();

    // 1. Start supervisor
    eprintln!("[smoke test] Starting engine supervisor...");
    let start_res = supervisor.start().await;
    assert!(
        start_res.is_ok(),
        "Failed to launch sidecar supervisor: {:?}",
        start_res.err()
    );

    // Give process a moment to initialize
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 2. Verify process is running
    assert!(
        supervisor.is_running().await,
        "Engine sidecar should be running"
    );
    let pid = supervisor.child_pid().await;
    assert!(pid.is_some(), "Engine sidecar should have a valid PID");
    eprintln!("[smoke test] Sidecar is active with PID: {:?}", pid);

    // 3. Test ping command
    eprintln!("[smoke test] Sending ping command to sidecar...");
    let ping_res = supervisor
        .send_command("smoke-ping-1".into(), "ping".into(), serde_json::json!({}))
        .await
        .expect("Ping command failed");

    assert_eq!(
        ping_res.get("pong").and_then(|v| v.as_bool()),
        Some(true),
        "Ping should return pong: true"
    );
    assert_eq!(
        ping_res.get("engine").and_then(|v| v.as_str()),
        Some("boundaryx"),
        "Engine name should be boundaryx"
    );
    assert_eq!(
        ping_res.get("version").and_then(|v| v.as_str()),
        Some("0.1.1"),
        "Engine version should be 0.1.1"
    );
    eprintln!("[smoke test] Ping response validated: {:?}", ping_res);

    // 4. Test tools.registry command
    eprintln!("[smoke test] Sending tools.registry command to sidecar...");
    let tools_res = supervisor
        .send_command(
            "smoke-tools-2".into(),
            "tools.registry".into(),
            serde_json::json!({}),
        )
        .await
        .expect("Tools registry command failed");

    assert!(
        tools_res.is_array(),
        "tools.registry should return an array of tools"
    );
    let tools_array = tools_res.as_array().unwrap();
    assert!(
        !tools_array.is_empty(),
        "Tools registry should return at least one tool"
    );
    eprintln!(
        "[smoke test] Received {} registered tools from engine",
        tools_array.len()
    );

    // 5. Test program creation & scope evaluation
    eprintln!("[smoke test] Creating test program via IPC...");
    let prog_res = supervisor
        .send_command(
            "smoke-prog-3".into(),
            "programs.create".into(),
            serde_json::json!({
                "name": "Integration Smoke Target",
                "description": "Created during IPC supervisor integration test"
            }),
        )
        .await
        .expect("Failed to create test program");

    let prog_id = prog_res
        .get("id")
        .and_then(|v| v.as_str())
        .expect("Program should have an ID");
    eprintln!("[smoke test] Created test program with ID: {}", prog_id);

    // Add include scope rule
    eprintln!("[smoke test] Adding scope rule for example.com...");
    let rule_res = supervisor
        .send_command(
            "smoke-rule-4".into(),
            "scope.create_rule".into(),
            serde_json::json!({
                "program_id": prog_id,
                "pattern": "example.com",
                "rule_type": "include",
                "matcher_type": "domain"
            }),
        )
        .await
        .expect("Failed to create scope rule");
    assert!(rule_res.get("id").is_some());

    // Evaluate in-scope target
    eprintln!("[smoke test] Evaluating in-scope target https://example.com/api...");
    let scope_res = supervisor
        .send_command(
            "smoke-scope-5".into(),
            "scope.evaluate".into(),
            serde_json::json!({
                "program_id": prog_id,
                "target": "https://example.com/api/v1"
            }),
        )
        .await
        .expect("Scope evaluate command failed");

    assert_eq!(
        scope_res.get("is_in_scope").and_then(|v| v.as_bool()),
        Some(true),
        "example.com/api/v1 should be in scope"
    );
    assert_eq!(
        scope_res.get("status").and_then(|v| v.as_str()),
        Some("in_scope")
    );
    eprintln!("[smoke test] In-scope evaluation verified: {:?}", scope_res);

    // Evaluate out-of-scope target
    eprintln!("[smoke test] Evaluating out-of-scope target https://unauthorized-evil.com...");
    let out_res = supervisor
        .send_command(
            "smoke-scope-6".into(),
            "scope.evaluate".into(),
            serde_json::json!({
                "program_id": prog_id,
                "target": "https://unauthorized-evil.com/login"
            }),
        )
        .await
        .expect("Scope evaluate out-of-scope failed");

    assert_eq!(
        out_res.get("is_in_scope").and_then(|v| v.as_bool()),
        Some(false),
        "unauthorized-evil.com should NOT be in scope"
    );
    eprintln!("[smoke test] Out-of-scope evaluation verified: {:?}", out_res);

    // 6. Test child process shutdown & cleanup
    eprintln!("[smoke test] Triggering supervisor.shutdown()...");
    supervisor.shutdown().await;

    // Verify process is no longer running
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !supervisor.is_running().await,
        "Engine sidecar should no longer be running after shutdown"
    );
    eprintln!("[smoke test] Sidecar cleanly terminated and confirmed exited.");
}
