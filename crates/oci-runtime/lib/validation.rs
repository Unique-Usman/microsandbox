//! Reject requested OCI semantics that this runtime cannot enforce.

use anyhow::{Result, bail};
use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn validate_bundle(value: &Value) -> Result<()> {
    let version = value["ociVersion"].as_str().unwrap_or_default();
    if !matches!(version, "1.0.0" | "1.0.1" | "1.0.2" | "1.1.0" | "1.2.0") {
        bail!("unsupported OCI version {version}");
    }
    keys(
        value,
        "config",
        &[
            "ociVersion",
            "root",
            "process",
            "annotations",
            "linux",
            "mounts",
        ],
    )?;
    let root = &value["root"];
    keys(root, "root", &["path", "readonly"])?;
    if root["readonly"].as_bool() == Some(true) {
        bail!("unsupported OCI field root.readonly: read-only rootfs is not implemented");
    }
    validate_process(&value["process"])?;
    if let Some(linux) = value.get("linux") {
        // An empty Linux section requests no additional host or guest controls.
        keys(linux, "linux", &[])?;
    }
    if value
        .get("mounts")
        .and_then(Value::as_array)
        .is_some_and(|mounts| !mounts.is_empty())
    {
        bail!(
            "unsupported OCI field mounts: complete mount flags and host ownership semantics are not implemented"
        );
    }
    Ok(())
}

pub(crate) fn validate_process(value: &Value) -> Result<()> {
    keys(
        value,
        "process",
        &[
            "args",
            "env",
            "cwd",
            "user",
            "terminal",
            "consoleSize",
            "noNewPrivileges",
        ],
    )?;
    if value["noNewPrivileges"].as_bool() == Some(true) {
        bail!("unsupported OCI field process.noNewPrivileges");
    }
    keys(&value["user"], "process.user", &["uid", "gid"])?;
    if let Some(size) = value.get("consoleSize") {
        keys(size, "process.consoleSize", &["height", "width"])?;
    }
    Ok(())
}

fn keys(value: &Value, path: &str, supported: &[&str]) -> Result<()> {
    let Some(object) = value.as_object() else {
        bail!("invalid OCI field {path}: expected an object");
    };
    for key in object.keys() {
        if !supported.contains(&key.as_str()) {
            bail!("unsupported OCI field {path}.{key}: runmsb cannot enforce this setting");
        }
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal() -> Value {
        json!({"ociVersion":"1.2.0", "root":{"path":"rootfs"},
            "process":{"args":["/hello"],"cwd":"/","user":{"uid":0,"gid":0}}})
    }

    #[test]
    fn accepts_minimal_bundle() {
        validate_bundle(&minimal()).unwrap();
    }

    #[test]
    fn rejects_unimplemented_security_even_when_empty() {
        for (key, value) in [
            ("capabilities", json!({})),
            ("noNewPrivileges", json!(true)),
            ("apparmorProfile", json!("profile")),
            ("selinuxLabel", json!("label")),
            ("rlimits", json!([])),
            ("unknownExtension", json!(true)),
        ] {
            let mut bundle = minimal();
            bundle["process"][key] = value;
            assert!(
                validate_bundle(&bundle)
                    .unwrap_err()
                    .to_string()
                    .contains(key)
            );
        }
    }

    #[test]
    fn rejects_namespaces_resources_hooks_and_mounts() {
        for (key, value) in [
            ("linux", json!({"namespaces":[{"type":"network"}]})),
            ("linux", json!({"resources":{"pids":{"limit":16}}})),
            ("hooks", json!({})),
            ("mounts", json!([{"type":"bind"}])),
        ] {
            let mut bundle = minimal();
            bundle[key] = value;
            assert!(validate_bundle(&bundle).is_err(), "{key}");
        }
        let mut bundle = minimal();
        bundle["root"]["readonly"] = json!(true);
        assert!(validate_bundle(&bundle).is_err());
    }
}
