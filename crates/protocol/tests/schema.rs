use rusty_sand_protocol::{
    pipe_name, HookOperation, HookReady, HookRequest, HookResponse, OperationCriticality,
    EXPECTED_HOOK_COUNT, MAX_MESSAGE_SIZE, PROTOCOL_VERSION,
};
use serde_json::json;

#[test]
fn operation_messages_preserve_wire_tags_and_classification() {
    /* Literal fixtures detect wire changes that Rust-only round trips miss. */
    let operations = [
        (
            "FileCreate",
            json!({"path": "a", "access_rights": 1, "share_mode": 2, "creation_disposition": 3, "flags_and_attributes": 4}),
            false,
        ),
        ("FileWrite", json!({"path": "a", "handle": 42}), false),
        ("FileDelete", json!({"path": "a"}), false),
        ("FileRead", json!({"path": "a"}), true),
        (
            "FileMove",
            json!({"source": "a", "destination": "b"}),
            false,
        ),
        (
            "FileCopy",
            json!({"source": "a", "destination": "b"}),
            false,
        ),
        (
            "FileAttributeChange",
            json!({"path": "a", "new_attributes": 2}),
            false,
        ),
        ("FolderCreate", json!({"path": "a"}), false),
        ("FolderDelete", json!({"path": "a"}), false),
        (
            "RegistrySet",
            json!({"key": "k", "value": "v", "data_type": 1, "data_size": 8}),
            false,
        ),
        ("RegistryDelete", json!({"key": "k"}), false),
        ("RegistryRead", json!({"key": "k", "value": "v"}), true),
        (
            "RegistryOpen",
            json!({"key": "k", "access_rights": 1}),
            true,
        ),
        (
            "NetworkConnect",
            json!({"remote_addr": "127.0.0.1", "port": 443, "protocol": "Tcp"}),
            false,
        ),
        (
            "NetworkSend",
            json!({"remote_addr": "127.0.0.1", "port": 443, "bytes_to_send": 8}),
            false,
        ),
        (
            "NetworkReceive",
            json!({"remote_addr": "127.0.0.1", "port": 443, "bytes_to_receive": 8}),
            true,
        ),
        (
            "ProcessCreate",
            json!({"executable": "app.exe", "args": "--help", "creation_flags": 4}),
            false,
        ),
        (
            "ThreadCreate",
            json!({"start_address": 4096, "parameter": 0}),
            false,
        ),
        (
            "ThreadCreateRemote",
            json!({"target_process_id": 12, "start_address": 4096}),
            false,
        ),
        (
            "DllLoad",
            json!({"dll_path": "app.dll", "load_flags": 0}),
            false,
        ),
        (
            "MemoryAllocate",
            json!({"base_address": 4096, "size": 8192, "protection": 4, "allocation_type": 4096}),
            false,
        ),
        (
            "MemoryProtect",
            json!({"base_address": 4096, "size": 8192, "old_protection": 4, "new_protection": 32}),
            false,
        ),
        (
            "MemoryWrite",
            json!({"target_process_id": 12, "base_address": 4096, "bytes_to_write": 8}),
            false,
        ),
    ];

    for (tag, data, read_only) in operations {
        let wire = json!({"operation": {"type": tag, "data": data}, "pid": 12, "tid": 34});

        let request: HookRequest = serde_json::from_value(wire.clone()).unwrap();

        let criticality = match tag {
            "FileRead" | "RegistryRead" | "RegistryOpen" | "NetworkReceive" => {
                OperationCriticality::Low
            }
            "FileCreate" | "FileWrite" | "FileCopy" | "FolderCreate" | "RegistrySet"
            | "NetworkConnect" | "NetworkSend" => OperationCriticality::Medium,
            "FileDelete"
            | "FileMove"
            | "FileAttributeChange"
            | "FolderDelete"
            | "RegistryDelete"
            | "MemoryProtect" => OperationCriticality::High,
            "ProcessCreate" | "ThreadCreate" | "ThreadCreateRemote" | "DllLoad"
            | "MemoryAllocate" | "MemoryWrite" => OperationCriticality::Critical,
            _ => panic!("missing fixture classification: {tag}"),
        };

        assert_eq!(request.operation.is_read_only(), read_only, "{tag}");
        assert_eq!(request.operation.criticality(), criticality, "{tag}");
        assert_eq!(serde_json::to_value(request).unwrap(), wire, "{tag}");

        for field in data.as_object().unwrap().keys() {
            let mut missing = wire.clone();
            missing["operation"]["data"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(
                serde_json::from_value::<HookRequest>(missing).is_err(),
                "{tag}.{field}"
            );

            let mut malformed = wire.clone();
            malformed["operation"]["data"][field] = json!(false);
            assert!(
                serde_json::from_value::<HookRequest>(malformed).is_err(),
                "{tag}.{field}"
            );
        }
    }
}

#[test]
fn network_protocol_names_remain_compatible() {
    for protocol in ["Tcp", "Udp", "Tcp6", "Udp6"] {
        let wire = json!({
            "type": "NetworkConnect",
            "data": {"remote_addr": "::1", "port": 53, "protocol": protocol}
        });

        let operation: HookOperation = serde_json::from_value(wire.clone()).unwrap();

        assert_eq!(serde_json::to_value(operation).unwrap(), wire);
    }
}

#[test]
fn approval_response_preserves_denial_and_optional_reason() {
    for wire in [
        json!({"allowed": false, "reason": "policy"}),
        json!({"allowed": true, "reason": null}),
    ] {
        let response: HookResponse = serde_json::from_value(wire.clone()).unwrap();

        assert_eq!(serde_json::to_value(response).unwrap(), wire);
    }
}

#[test]
fn unknown_operation_is_rejected() {
    let wire = json!({"type": "UnknownOperation", "data": {}});

    let result = serde_json::from_value::<HookOperation>(wire);

    assert!(result.is_err());
}

#[test]
fn ready_message_is_distinct_from_operation_requests() {
    let ready = HookReady {
        version: PROTOCOL_VERSION,
        pid: 42,
        installed_hooks: EXPECTED_HOOK_COUNT,
    };
    let wire = json!({"version": 1, "pid": 42, "installed_hooks": 17});

    assert_eq!(serde_json::to_value(&ready).unwrap(), wire);
    assert_eq!(
        serde_json::from_value::<HookReady>(wire.clone()).unwrap(),
        ready
    );
    assert!(serde_json::from_value::<HookRequest>(wire.clone()).is_err());
    assert!(serde_json::from_value::<HookResponse>(wire).is_err());
    assert!(serde_json::from_value::<HookReady>(json!({
        "operation": {"type": "FileRead", "data": {"path": "a"}}, "pid": 42, "tid": 3
    }))
    .is_err());
    assert_eq!(MAX_MESSAGE_SIZE, 8192);
    assert_eq!(pipe_name(42), r"\\.\pipe\rusty_sand_hooks_42");
    assert_eq!(pipe_name(u32::MAX), r"\\.\pipe\rusty_sand_hooks_4294967295");
}

#[test]
fn malformed_envelopes_are_rejected() {
    for wire in [
        json!({}),
        json!({"operation": {"type": "FileRead", "data": {"path": "a"}}, "pid": 1}),
        json!({"operation": {"type": "FileRead", "data": {"path": "a"}}, "tid": 1}),
        json!({"operation": {"type": "FileRead", "data": {"path": "a"}}, "pid": -1, "tid": 1}),
        json!({"operation": {"type": "FileRead", "data": {"path": "a"}}, "pid": 1, "tid": 4294967296_u64}),
        json!({"operation": {"type": "FileRead"}, "pid": 1, "tid": 1}),
        json!({"operation": {"data": {"path": "a"}}, "pid": 1, "tid": 1}),
    ] {
        assert!(serde_json::from_value::<HookRequest>(wire).is_err());
    }

    for wire in [
        json!({}),
        json!({"allowed": "true"}),
        json!({"allowed": true, "reason": 1}),
    ] {
        assert!(serde_json::from_value::<HookResponse>(wire).is_err());
    }

    for wire in [
        json!({"pid": 1, "installed_hooks": 17}),
        json!({"version": 1, "installed_hooks": 17}),
        json!({"version": 1, "pid": 1}),
        json!({"version": -1, "pid": 1, "installed_hooks": 17}),
        json!({"version": 1, "pid": "1", "installed_hooks": 17}),
        json!({"version": 1, "pid": 1, "installed_hooks": 4294967296_u64}),
    ] {
        assert!(serde_json::from_value::<HookReady>(wire).is_err());
    }

    for wire in ["", "{", "null", "[]", r#"{"allowed":true} trailing"#] {
        assert!(serde_json::from_str::<HookRequest>(wire).is_err());
        assert!(serde_json::from_str::<HookResponse>(wire).is_err());
        assert!(serde_json::from_str::<HookReady>(wire).is_err());
    }
}

#[test]
fn numeric_and_protocol_boundaries_are_checked() {
    for data in [
        json!({"remote_addr": "::1", "port": 65536, "protocol": "Tcp"}),
        json!({"remote_addr": "::1", "port": -1, "protocol": "Tcp"}),
        json!({"remote_addr": "::1", "port": 443, "protocol": "tcp"}),
        json!({"remote_addr": "::1", "port": 443, "protocol": "Unknown"}),
    ] {
        assert!(serde_json::from_value::<HookOperation>(json!({
            "type": "NetworkConnect", "data": data
        }))
        .is_err());
    }

    let wire = json!({"type": "MemoryWrite", "data": {
        "target_process_id": u32::MAX, "base_address": u64::MAX, "bytes_to_write": u32::MAX
    }});
    let operation: HookOperation = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(operation).unwrap(), wire);
}
