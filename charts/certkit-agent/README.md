# CertKit Agent Helm Chart

The `certkit-agent` Helm chart allows you to deploy the CertKit Agent as either a long-running Deployment or a scheduled CronJob. It supports mounting existing certificates and configuration via HostPath volumes.

## Installation

### Add the Helm Repository

```bash
helm repo add certkit https://charts.certkit.io
helm repo update
```

### Install the Chart

```bash
helm install certkit certkit/certkit-agent --namespace certkit --create-namespace
```

## Configuration

### Minimal Configuration

For a basic deployment, you often need to provide your registration key (obtained from the CertKit dashboard).

```bash
helm install certkit certkit/certkit-agent \
  --namespace certkit \
  --set secret.key="YOUR_REGISTRATION_KEY"
```

If you manage your secrets externally, you can reference an existing secret instead:

```bash
helm install certkit certkit/certkit-agent \
  --namespace certkit \
  --set secret.create=false \
  --set secret.name="my-existing-secret"
```

### Deployment Mode (Default)

Running as a Deployment ensures the agent is always running to manage certificates and configuration updates.

**Example: Deployment with HostPath Volume**

This example mounts a local directory `/opt/haproxy/certs` into the container at `/etc/certkit-agent`.

```bash
helm upgrade --install certkit charts/certkit-agent --namespace certkit \
  --set 'volumes[0].name=haproxy-certs' \
  --set 'volumes[0].hostPath.path=/opt/haproxy/certs' \
  --set 'volumes[0].hostPath.type=Directory' \
  --set 'volumeMounts[0].name=haproxy-certs' \
  --set 'volumeMounts[0].mountPath=/etc/certkit-agent' \
  --set secret.key="YOUR_REGISTRATION_KEY"
```

### CronJob Mode

Running as a CronJob is useful for periodic checks without consuming resources continuously. The chart automatically appends the `--once` flag to the agent command.

**Example: CronJob with HostPath Volume**

This example schedules the agent to run daily at 2 AM, mounting `/var/lib/certs` to `/etc/certkit-agent`.

```bash
helm upgrade --install certkit-cron charts/certkit-agent --namespace certkit \
  --set mode=cronjob \
  --set cronjob.schedule="0 2 * * *" \
  --set 'volumes[0].name=app-certs' \
  --set 'volumes[0].hostPath.path=/var/lib/certs' \
  --set 'volumes[0].hostPath.type=Directory' \
  --set 'volumeMounts[0].name=app-certs' \
  --set 'volumeMounts[0].mountPath=/etc/certkit-agent' \
  --set secret.key="YOUR_REGISTRATION_KEY"
```

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `mode` | Operation mode: `deployment` or `cronjob` | `deployment` |
| `image.repository` | Docker image repository | `ghcr.io/certkit-io/certkit-agent` |
| `image.tag` | Docker image tag | `latest` |
| `secret.create` | Create a new secret for registration key | `true` |
| `secret.name` | Name of secret (created or referenced) | "" |
| `secret.key` | Registration key value | "" |
| `cronjob.schedule` | Schedule for CronJob mode | `0 0 * * *` |
| `volumes` | List of additional volumes | `[]` |
| `volumeMounts` | List of additional volume mounts | `[]` |
