use super::*;
use crate::ipc::NetworkProtocol;

#[test]
fn noninteractive_policy_keeps_dns_network_and_registry_independent() {
    let mut config = SandboxConfig {
        interactive_mode: false,
        allow_registry: false,
        ..SandboxConfig::default()
    };
    let connect = |port| HookOperation::NetworkConnect {
        remote_addr: "192.0.2.1".into(),
        port,
        protocol: NetworkProtocol::Tcp,
    };
    let registry = HookOperation::RegistryRead {
        key: "HKCU\\Software".into(),
        value: "Value".into(),
    };
    assert!(policy_denial(&config, &registry).is_some());
    assert!(policy_denial(&config, &connect(53)).is_some());
    assert!(policy_denial(&config, &connect(443)).is_some());
    config.allow_dns = true;
    assert!(policy_denial(&config, &connect(53)).is_none());
    assert!(policy_denial(&config, &connect(443)).is_some());
    config.allow_dns = false;
    config.allow_internet = true;
    assert!(policy_denial(&config, &connect(53)).is_some());
    assert!(policy_denial(&config, &connect(443)).is_none());
    config.allow_registry = true;
    assert!(policy_denial(&config, &registry).is_none());
}
