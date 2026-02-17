
## Clarifications

### Session 2026-02-16
- Q: How should the chart handle the `certkit-secrets` (containing `registration-key`)?
  - A: **Both**: Support creating the Secret via values (e.g., `secret.create: true`, `secret.key: "..."`) AND referencing an existing Secret (e.g., `secret.name: "my-secret"`).
- Q: Should the chart include liveness/readiness probes?
  - A: **Shell Command**: Yes, implementation MUST include standard `exec` probes (e.g., `pgrep` or similar) to ensure the process is running, as no HTTP health endpoint exists.


**Feature Branch**: `1-agent-helm-chart`  
**Created**: 2026-02-16  
**Status**: Draft  
**Input**: User description: "I'd like a configurable helmchart that can make a deployment or cronjob for the certkit agent. It should look something like what exists at kubectl describe --namespace certkit deploy/certkit-agent. Depending on the values it can use --once to do a cron or deployment for a live agent."

## User Scenarios & Testing *(mandatory)*

<!--
  IMPORTANT: User stories should be PRIORITIZED as user journeys ordered by importance.
-->

### User Story 1 - Continuous Agent Deployment (Priority: P1)

As a DevOps engineer, I want to deploy the certkit-agent as a long-running service so that it continuously monitors and manages certificates using my existing configuration (host volumes, secrets).

**Why this priority**: Ensure feature parity with existing manual deployment methods.

**Independent Test**: Can be fully tested by installing the chart with default values (or `mode: deployment`) and verifying a Deployment is created with correct volume mounts and env vars.

**Acceptance Scenarios**:

1. **Given** a Kubernetes cluster and existing `certkit-secrets`, **When** I `helm install` with `mode: deployment`, **Then** a Deployment resource is created.
2. **Given** the deployment is created, **When** I inspect the pod spec, **Then** it MUST have the configured command arguments, volume mounts, and environment variables.
3. **Given** the agent is running, **When** I check logs, **Then** it should show successful startup and certificate monitoring.

---

### User Story 2 - Scheduled Agent Execution (CronJob) (Priority: P1)

As a DevOps engineer, I want to deploy the certkit-agent as a CronJob so that it performs certificate checks on a schedule (e.g., daily) to reduce resource usage.

**Why this priority**: Provides a more resource-efficient alternative for environments that don't need continuous monitoring.

**Independent Test**: Can be tested by installing the chart with `mode: cronjob` and verifying the created resource.

**Acceptance Scenarios**:

1. **Given** a Kubernetes cluster, **When** I `helm install` with `mode: cronjob` and a specified schedule, **Then** a CronJob resource is created.
2. **Given** the CronJob is created, **When** I inspect the job template, **Then** the container command MUST include the `--once` argument.
3. **Given** the CronJob triggers, **When** the pod runs, **Then** it should perform a single check and exit.

---

### User Story 3 - Advanced Configuration (Priority: P2)

As a DevOps engineer, I want to allow flexible configuration of the agent's environment, resources, and placement rules.

**Why this priority**: Necessary for production-grade deployments in varying environments.

**Independent Test**: Install with custom values for resources, nodeSelector, and extra volumes.

**Acceptance Scenarios**:

1. **Given** a values file with `resources`, `nodeSelector`, and `tolerations`, **When** I `helm install`, **Then** the resulting Pods reflect these settings.

---

### Edge Cases

- What happens when `mode` is set to an invalid value? (Should fail validation or default to deployment)
- How does system handle missing secrets? (Pod will fail to start - standard k8s behavior)
- What if both Deployment and CronJob are somehow enabled? (Chart logic should enforce one or the other based on `mode`)

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST support a `mode` configuration value that toggles between `deployment` and `cronjob`.
- **FR-002**: When `mode` is `deployment`, the chart MUST render a Kubernetes Deployment resource.
- **FR-003**: When `mode` is `cronjob`, the chart MUST render a Kubernetes CronJob resource.
- **FR-004**: The CronJob implementation MUST automatically append the `--once` argument to the container command.
- **FR-005**: System MUST allow specification of the Docker image repository, tag, and pull policy.
- **FR-006**: System MUST allow configuration of Volumes and VolumeMounts (specifically prioritizing HostPath support for this initial version).
  - *Note: Support for PersistentVolumeClaims (PVCs) is NOT required for v1 but the design should allow for future extensibility.*
- **FR-007**: System MUST allow configuration of existing Secrets OR creation of new Secrets via values for the registration key.
- **FR-008**: System MUST allow configuration of CronJob schedule.
- **FR-009**: System MUST allow configuration of standard Pod attributes: `resources`, `nodeSelector`, `tolerations`, `affinity`.
- **FR-010**: System MUST allow overriding or extending the default command/args.
- **FR-011**: System MUST include default liveness and readiness probes using shell commands (e.g. `exec`) to verify process health.

### Key Entities *(include if feature involves data)*

- **Chart**: The Helm chart package.
- **Values**: The configuration interface for users.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Users can successfully deploy the agent matching their existing `kubectl describe` configuration using only `values.yaml`.
- **SC-002**: Users can switch from Deployment to CronJob mode by changing a single configuration value.
- **SC-003**: Generated manifests pass `helm lint` and `kubectl apply --dry-run` validation.
