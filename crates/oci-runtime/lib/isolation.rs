//! OCI namespace and resource requests mapped into one guest workload domain.

use anyhow::{Result, bail, ensure};
use microsandbox_protocol::isolation::{WorkloadIsolation, WorkloadResources};
use microsandbox_runtime::oci::OciBundle;
use oci_spec::runtime::{LinuxNamespaceType, LinuxResources};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(crate) const ISOLATION_LABEL: &str = "oci.microsandbox.isolation";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn policy(bundle: &OciBundle) -> Result<WorkloadIsolation> {
    let mut policy = WorkloadIsolation::default();
    if let Some(linux) = bundle.spec.linux() {
        for namespace in linux.namespaces().as_deref().unwrap_or_default() {
            let kind = namespace.typ();
            if kind == LinuxNamespaceType::Network {
                continue;
            }
            ensure!(
                namespace.path().is_none(),
                "cannot join a host {kind} namespace from the guest kernel"
            );
            match kind {
                LinuxNamespaceType::Mount => policy.mount = true,
                LinuxNamespaceType::Pid => policy.pid = true,
                LinuxNamespaceType::Ipc => policy.ipc = true,
                LinuxNamespaceType::Uts => policy.uts = true,
                LinuxNamespaceType::Cgroup => policy.cgroup = true,
                LinuxNamespaceType::User | LinuxNamespaceType::Time => {
                    bail!("guest {kind} namespace configuration is not implemented")
                }
                LinuxNamespaceType::Network => unreachable!(),
            }
        }
        ensure!(
            linux.uid_mappings().as_ref().is_none_or(Vec::is_empty)
                && linux.gid_mappings().as_ref().is_none_or(Vec::is_empty),
            "guest user namespace ID mappings are not implemented"
        );
        if let Some(resources) = linux.resources() {
            policy.resources = resource_policy(resources)?;
        }
    }
    ensure!(
        !(policy.pid || policy.cgroup || policy.ipc) || policy.mount,
        "guest PID, IPC and cgroup namespaces require a private mount namespace"
    );
    if let Some(hostname) = bundle
        .spec
        .hostname()
        .as_ref()
        .filter(|name| !name.is_empty())
    {
        ensure!(
            policy.uts,
            "setting a workload hostname requires a guest UTS namespace"
        );
        ensure!(
            hostname.len() <= 63 && !hostname.as_bytes().contains(&0),
            "invalid workload hostname"
        );
        policy.hostname = Some(hostname.clone());
    }
    Ok(policy)
}

pub(crate) fn guest_memory_mib(resources: &WorkloadResources) -> Result<Option<u32>> {
    Ok(microsandbox_runtime::oci::cgroup::guest_memory_mib(
        resources,
    )?)
}

pub(crate) fn guest_cpus(resources: &WorkloadResources) -> Result<Option<u8>> {
    resources
        .cpu_quota
        .map(|quota| {
            let period = resources.cpu_period.unwrap_or(100_000);
            ensure!(
                (1_000..=1_000_000).contains(&period) && quota >= 1_000,
                "invalid CPU quota or period"
            );
            // The guest agent and kernel must not consume the workload's virtual CPU capacity.
            let count = quota
                .div_ceil(period)
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("guest CPU budget overflow"))?;
            Ok(u8::try_from(count)?)
        })
        .transpose()
}

fn resource_policy(resources: &LinuxResources) -> Result<WorkloadResources> {
    ensure!(
        resources.block_io().is_none()
            && resources
                .hugepage_limits()
                .as_ref()
                .is_none_or(Vec::is_empty)
            && resources.network().is_none()
            && resources
                .rdma()
                .as_ref()
                .is_none_or(|value| value.is_empty())
            && resources
                .unified()
                .as_ref()
                .is_none_or(|value| value.is_empty()),
        "guest I/O, hugepage, network, RDMA and arbitrary unified cgroup controls are not implemented"
    );
    let mut result = WorkloadResources::default();
    if let Some(cpu) = resources.cpu() {
        ensure!(
            cpu.cpus().as_ref().is_none_or(String::is_empty)
                && cpu.mems().as_ref().is_none_or(String::is_empty)
                && cpu.realtime_runtime().is_none()
                && cpu.realtime_period().is_none()
                && cpu.burst().is_none()
                && cpu.idle().is_none(),
            "guest cpuset, realtime, burst and idle CPU controls are not implemented"
        );
        result.cpu_quota = positive_limit(cpu.quota(), "CPU quota")?;
        result.cpu_period = cpu.period().filter(|value| *value != 0);
        if let Some(period) = result.cpu_period {
            ensure!((1_000..=1_000_000).contains(&period), "invalid CPU period");
        }
        if let Some(quota) = result.cpu_quota {
            ensure!(
                quota >= 1_000,
                "CPU quota must be at least 1000 microseconds"
            );
        }
        if let Some(shares) = cpu.shares().filter(|value| *value != 0) {
            ensure!(
                (2..=262_144).contains(&shares),
                "CPU shares must be between 2 and 262144"
            );
            result.cpu_weight = Some(1 + (shares - 2) * 9_999 / 262_142);
        }
    }
    if let Some(memory) = resources.memory() {
        #[allow(deprecated)]
        let kernel_limit = memory.kernel();
        ensure!(
            memory.reservation().is_none_or(|value| value == 0)
                && kernel_limit.is_none_or(|value| value == 0)
                && memory.kernel_tcp().is_none_or(|value| value == 0)
                && memory.swappiness().is_none()
                && memory.use_hierarchy() != Some(false)
                && !memory.check_before_update().unwrap_or(false)
                && !memory.disable_oom_killer().unwrap_or(false),
            "guest memory reservation, separate kernel limits, swappiness, nonhierarchical accounting, update checks and OOM-disable controls are not implemented"
        );
        result.memory_max = positive_limit(memory.limit(), "memory limit")?;
        if let Some(total) = positive_limit(memory.swap(), "memory plus swap limit")? {
            let memory = result
                .memory_max
                .ok_or_else(|| anyhow::anyhow!("swap limit requires a memory limit"))?;
            result.swap_max =
                Some(total.checked_sub(memory).ok_or_else(|| {
                    anyhow::anyhow!("memory plus swap limit is below memory limit")
                })?);
        }
    }
    if let Some(pids) = resources.pids() {
        result.pids_max = positive_limit(Some(pids.limit()), "task limit")?;
    }
    Ok(result)
}

fn positive_limit(value: Option<i64>, name: &str) -> Result<Option<u64>> {
    match value {
        None | Some(-1 | 0) => Ok(None),
        Some(value) if value > 0 => Ok(Some(value as u64)),
        _ => bail!("invalid {name}"),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_one_guest_namespace_set_and_rejects_host_paths() {
        let bundle = |namespaces: serde_json::Value, hostname: &str| OciBundle {
            path: "/bundle".into(),
            spec: serde_json::from_value(serde_json::json!({
                "ociVersion": "1.2.0", "hostname": hostname,
                "linux": {"namespaces": namespaces}
            }))
            .unwrap(),
        };
        let requested = bundle(
            serde_json::json!([
                {"type": "pid"}, {"type": "mount"}, {"type": "ipc"},
                {"type": "uts"}, {"type": "cgroup"},
                {"type": "network", "path": "/run/netns/container"}
            ]),
            "workload",
        );
        let mapped = policy(&requested).unwrap();
        assert!(mapped.pid && mapped.mount && mapped.ipc && mapped.uts && mapped.cgroup);
        assert_eq!(mapped.hostname.as_deref(), Some("workload"));
        for namespaces in [
            serde_json::json!([{"type": "mount", "path": "/proc/1/ns/mnt"}]),
            serde_json::json!([{"type": "pid"}]),
            serde_json::json!([{"type": "user"}]),
            serde_json::json!([{"type": "time"}]),
        ] {
            assert!(policy(&bundle(namespaces, "")).is_err());
        }
        assert!(policy(&bundle(serde_json::json!([]), "workload")).is_err());
    }

    #[test]
    fn maps_limits_without_subtracting_management_overhead() {
        let resources = serde_json::from_value(serde_json::json!({
            "cpu": {"quota": 150000, "period": 100000, "shares": 1024},
            "memory": {"limit": 536870912, "swap": 536870912}, "pids": {"limit": 32}
        }))
        .unwrap();
        let mapped = resource_policy(&resources).unwrap();
        assert_eq!(mapped.cpu_quota, Some(150000));
        assert_eq!(mapped.memory_max, Some(536870912));
        assert_eq!(mapped.swap_max, Some(0));
        assert_eq!(mapped.pids_max, Some(32));
        assert_eq!(guest_memory_mib(&mapped).unwrap(), Some(640));
        assert_eq!(guest_cpus(&mapped).unwrap(), Some(3));
    }

    #[test]
    fn rejects_untranslated_controls_and_invalid_limits() {
        for value in [
            serde_json::json!({"cpu": {"cpus": "2-3"}}),
            serde_json::json!({"cpu": {"quota": 1}}),
            serde_json::json!({"memory": {"limit": 1024, "swap": 512}}),
            serde_json::json!({"pids": {"limit": -2}}),
            serde_json::json!({"unified": {"memory.max": "100"}}),
        ] {
            assert!(resource_policy(&serde_json::from_value(value).unwrap()).is_err());
        }
    }
}
