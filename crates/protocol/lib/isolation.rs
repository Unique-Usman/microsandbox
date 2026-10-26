//! Explicit guest workload isolation requested by the OCI runtime.

use serde::{Deserialize, Serialize};

use crate::exec::ExecRequest;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One namespace and resource domain for the init command and subsequent execs.
///
/// This is a create-once policy, not a per-exec request to create nested containers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkloadIsolation {
    /// Create a workload PID namespace with the first command as PID 1.
    pub pid: bool,
    /// Clone the prepared mount tree once for this workload.
    pub mount: bool,
    /// Isolate System V IPC and POSIX message queues.
    pub ipc: bool,
    /// Isolate the workload hostname.
    pub uts: bool,
    /// Hide ancestor cgroups from the workload.
    pub cgroup: bool,
    /// Hostname applied only in the workload UTS namespace.
    pub hostname: Option<String>,
    /// Resource ceilings for the workload, excluding agentd.
    pub resources: WorkloadResources,
}

/// Supported cgroup-v2 workload controls, in kernel units.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkloadResources {
    /// Aggregate CPU quota in microseconds; absence means unlimited.
    pub cpu_quota: Option<u64>,
    /// CPU period in microseconds.
    pub cpu_period: Option<u64>,
    /// Cgroup-v2 CPU weight, between 1 and 10000.
    pub cpu_weight: Option<u64>,
    /// Workload memory ceiling in bytes.
    pub memory_max: Option<u64>,
    /// Additional swap ceiling in bytes, not memory plus swap.
    pub swap_max: Option<u64>,
    /// Aggregate task ceiling; Linux counts threads as well as processes.
    pub pids_max: Option<u64>,
}

/// Start the first command in a new, explicitly isolated workload domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolatedExecRequest {
    /// Ordinary process settings.
    pub process: ExecRequest,
    /// Create-once namespace and cgroup configuration.
    pub isolation: WorkloadIsolation,
}
