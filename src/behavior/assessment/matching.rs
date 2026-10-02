//! Descriptive telemetry parsing and rule predicates.

use super::schema::ActionStatus;
use crate::report::EventType;

pub(super) struct HookText<'a> {
    pub(super) status: ActionStatus,
    pub(super) caller: Option<u32>,
    pub(super) description: &'a str,
}

pub(super) fn hook_text(details: &str) -> HookText<'_> {
    let (status, rest) = if let Some(rest) = details.strip_prefix("denied hook request from pid ") {
        (ActionStatus::Denied, rest)
    } else if let Some(rest) = details.strip_prefix("allowed hook request from pid ") {
        (ActionStatus::Attempted, rest)
    } else {
        return HookText {
            status: ActionStatus::Attempted,
            caller: None,
            description: details,
        };
    };

    let Some((caller, description)) = rest.split_once(": ") else {
        return HookText {
            status,
            caller: None,
            description: "",
        };
    };

    /*
     * The monitor appends one policy-reason suffix. Removing it prevents the
     * reason from participating in path or command matching. Unknown formats
     * remain uncorrelatable rather than inventing a caller identity.
     */
    let description = description
        .strip_suffix(')')
        .and_then(|text| text.rsplit_once(" ("))
        .map_or(description, |(description, _)| description);

    HookText {
        status,
        caller: caller.parse::<u32>().ok().filter(|pid| *pid != 0),
        description,
    }
}

pub(super) fn file_target<'a>(
    event_type: &EventType,
    details: &'a str,
    request: &HookText<'a>,
) -> Option<(ActionStatus, &'a str)> {
    let path = match event_type {
        EventType::FileCreated | EventType::FileModified => {
            return Some((
                ActionStatus::Observed,
                details
                    .strip_prefix("observed filesystem change (process unattributed): ")
                    .unwrap_or(details),
            ));
        }
        EventType::HookFileCreate => request.description.strip_prefix("create file: ")?,
        EventType::HookFileWrite => request.description.strip_prefix("write to file: ")?,
        EventType::HookFileMove => {
            request
                .description
                .strip_prefix("move file: ")?
                .rsplit_once(" -> ")?
                .1
        }
        EventType::HookFileCopy => {
            request
                .description
                .strip_prefix("copy file: ")?
                .rsplit_once(" -> ")?
                .1
        }
        _ => return None,
    };

    Some((request.status, path))
}

pub(super) fn startup_registry(key: &str) -> bool {
    [
        "\\software\\microsoft\\windows\\currentversion\\run",
        "\\software\\microsoft\\windows\\currentversion\\runonce",
    ]
    .iter()
    .any(|suffix| key.ends_with(suffix))
        || key.ends_with("\\system\\currentcontrolset\\services")
        || key.contains("\\system\\currentcontrolset\\services\\")
}

pub(super) fn credential_file(path: &str) -> bool {
    let path = path.trim_matches('"').replace('/', "\\");

    [
        "\\windows\\system32\\config\\sam",
        "\\windows\\system32\\config\\security",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix))
        || path.contains("\\microsoft\\credentials\\")
        || path.contains("\\microsoft\\vault\\")
        || (path.contains("\\user data\\") && path.ends_with("\\login data"))
        || (path.contains("\\firefox\\profiles\\")
            && (path.ends_with("\\logins.json") || path.ends_with("\\key4.db")))
}

pub(super) fn command_parts(description: &str) -> Option<(&str, &str)> {
    let command = description.strip_prefix("execute: ")?.trim_start();
    let (executable, arguments) = if let Some(quoted) = command.strip_prefix('"') {
        quoted.split_once('"')?
    } else {
        command.split_once(' ').unwrap_or((command, ""))
    };
    let executable = executable.rsplit(['\\', '/']).next()?;

    Some((executable, arguments.trim_start()))
}

fn argument(arguments: &str, expected: &str) -> bool {
    arguments
        .split_whitespace()
        .any(|part| part.trim_matches('"') == expected)
}

pub(super) fn suspicious_execution(executable: &str, arguments: &str) -> bool {
    let remote = arguments.contains("http://") || arguments.contains("https://");

    match executable {
        "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe" => {
            ["-enc", "-encodedcommand", "-e"]
                .iter()
                .any(|flag| argument(arguments, flag))
                || arguments.contains("downloadstring(")
                || argument(arguments, "invoke-expression")
        }
        "mshta" | "mshta.exe" => {
            remote || arguments.contains("javascript:") || arguments.contains("vbscript:")
        }
        "regsvr32" | "regsvr32.exe" => {
            argument(arguments, "scrobj.dll")
                && (arguments.contains("/i:http://") || arguments.contains("/i:https://"))
        }
        "rundll32" | "rundll32.exe" => arguments.contains("javascript:"),
        "certutil" | "certutil.exe" => argument(arguments, "-urlcache") && remote,
        _ => false,
    }
}

pub(super) fn defense_command(executable: &str, arguments: &str) -> bool {
    match executable {
        "vssadmin" | "vssadmin.exe" => {
            argument(arguments, "delete") && argument(arguments, "shadows")
        }
        "wbadmin" | "wbadmin.exe" => {
            argument(arguments, "delete") && argument(arguments, "catalog")
        }
        "wevtutil" | "wevtutil.exe" => {
            argument(arguments, "cl") || argument(arguments, "clear-log")
        }
        "bcdedit" | "bcdedit.exe" => {
            argument(arguments, "/set")
                && argument(arguments, "recoveryenabled")
                && argument(arguments, "no")
        }
        _ => false,
    }
}

pub(super) fn injection_target(event_type: &EventType, description: &str) -> Option<u32> {
    let target = match event_type {
        EventType::HookMemoryWrite => {
            let (bytes, target) = description
                .strip_prefix("write ")?
                .split_once(" bytes to pid ")?;

            bytes.parse::<u32>().ok().filter(|bytes| *bytes != 0)?;
            target
        }
        EventType::HookThreadCreateRemote => {
            description.strip_prefix("create remote thread in pid ")?
        }
        _ => return None,
    };
    let (pid, address) = target.split_once(" at 0x")?;

    u64::from_str_radix(address, 16)
        .ok()
        .filter(|address| *address != 0)?;

    pid.parse::<u32>().ok().filter(|pid| *pid != 0)
}
