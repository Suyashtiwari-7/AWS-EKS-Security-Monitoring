# AWS EKS Security Monitoring Pipeline
### Securing Kubernetes workloads with Wazuh SIEM, Falco (eBPF), and Trivy Operator

This repository contains the configuration files and deployment manifests for a secure, cost-optimized telemetry pipeline on AWS EKS. The setup monitors runtime anomalies, container image CVEs, and Kubernetes control-plane audit events, routing all logs securely to a self-hosted Wazuh SIEM VM.

> [!TIP]
> **Cost Savings:** By using **Kubernetes Event Exporter**, this pipeline bypasses expensive AWS CloudWatch ingestion fees (~90% cost savings for control-plane logs) by routing all telemetry locally through a private **Tailscale VPN** overlay network.

---

## 🗺️ System Architecture

```
                     [ AWS EKS CLUSTER ]
  ┌─────────────────────────────────────────────────────────────┐
  │                                                             │
  │  ┌─────────────────────── wazuh namespace ────────────────┐  │
  │  │                                                        │  │
  │  │  ┌────────────────── protected-nginx Pod ────────────┐  │  │
  │  │  │                                                   │  │  │
  │  │  │  ┌───────────┐         ┌───────────────────────┐  │  │  │
  │  │  │  │   nginx   │         │      wazuh-agent      │  │  │  │
  │  │  │  └─────┬─────┘         │  (collects & ships)   │  │  │  │
  │  │  │        │               └──────────▲────────────┘  │  │  │
  │  │  │        │ (access.log)             │               │  │  │
  │  │  │        ▼                          │ (Local logs)  │  │  │
  │  │  │  ┌───────────┐         ┌──────────┴────────────┐  │  │  │
  │  │  │  │ Shared    ├────────►│   falco_listener.py   │  │  │  │
  │  │  │  │  emptyDir  │         │ (syslog/http receiver)│  │  │  │
  │  │  │  └─────▲─────┘         └──────────▲────────────┘  │  │  │
  │  │  │        │                          │               │  │  │
  │  │  │        │ (reports.json)           │               │  │  │
  │  │  │  ┌─────┴─────┐         ┌──────────┴────────────┐  │  │  │
  │  │  │  │   trivy-  │         │       tailscale       │  │  │  │
  │  │  │  │  bridge   │         │   (WireGuard tunnel)  │  │  │  │
  │  │  │  └───────────┘         └──────────┬────────────┘  │  │  │
  │  │  └───────────────────────────────────┼────────────────┘  │  │
  │  │                                      │                   │  │
  │  │  ┌─────────────────────────────┐     │                   │  │
  │  │  │  kubernetes-event-exporter  ├─────┘ (HTTP Webhook)    │  │
  │  │  └─────────────────────────────┘                         │  │
  │  └──────────────────────────────────────────────────────────┘  │
  │                                                             │
  │  ┌── falco namespace ─────────┐  ┌── trivy-system ────────┐ │
  │  │                            │  │                        │ │
  │  │  ┌──────────────────────┐  │  │  ┌──────────────────┐  │ │
  │  │  │   falco (eBPF)       │  │  │  │  trivy-operator  │  │ │
  │  │  └──────────┬───────────┘  │  │  └──────────────────┘  │ │
  │  │             │              │  └────────────────────────┘ │
  │  │             ▼ (syslog/UDP) │                             │
  │  │  ┌──────────────────────┐  │                             │
  │  │  │   falcosidekick      │  │                             │
  │  │  └──────────┬───────────┘  │                             │
  │  └─────────────┼──────────────┘                             │
  │                └─────────── (Forwarded alerts)              │
  └─────────────────────────────────────────────────────────────┘
                                   │
                                   │  [ Tailscale WireGuard Tunnel ]
                                   ▼
                 ┌───────────────────────────────────┐
                 │          Wazuh Manager            │
                 │         (Self-Hosted VM)          │
                 │     (1514/TCP Ingestion Port)     │
                 └───────────────────────────────────┘
```

---

## 🔄 How the Data Flows

The pipeline is split into three main security channels. All telemetry is aggregated inside the application pod and securely shipped outbound over Tailscale VPN.

| Pipeline Channel | Source Component | How it Works | Wazuh Target Rule |
| :--- | :--- | :--- | :--- |
| **Pipeline A: Vulnerability Scanning** | **Trivy Operator** | Scans container images for CVEs -> Publishes custom Kubernetes CRDs -> `trivy-bridge` parses CRDs into JSON -> Wazuh Agent tails logs. | `100050` (CVE Alert) |
| **Pipeline B: Runtime Auditing** | **Falco (eBPF)** | DaemonSet intercepts syscalls on EKS worker nodes -> Forwards alert to `falco-falcosidekick` -> Sends UDP syslog to `falco-receiver-svc` on application pod. | `100051` (Runtime Threat) |
| **Pipeline C: Kubernetes Events** | **Kubernetes Event Exporter** | Captures EKS control-plane audit trails (pod schedules, warning events, config edits) -> POSTs HTTP payload to Python webhook listener inside the app pod. | `100060` to `100062` (EKS Audits) |

---

## 📁 Repository Structure

```
.
├── README.md                           # Documentation and setup instructions
├── Secure_Kubernetes_Telemetry_Pipeline.pdf # Project Technical Design Guide (PDF)
│
├── [ EKS Deployment Manifests ]
├── wazuh-sidecar.yaml                  # Application pod with 4 containers (Sidecar Architecture)
├── wazuh-agent-config.yaml             # ConfigMap containing agent configs and listener script
├── kubernetes-event-exporter.yaml      # Config & Deployment for API event monitoring
├── falco-values.yaml                   # Helm overrides for eBPF kernel auditing & Sidekick
├── trivy-rbac.yaml                     # RBAC rules granting the pod read access to Trivy reports
├── workload-nodepool.yaml              # Karpenter node scaling profiles (cost optimization)
├── resource-quota.yaml                 # Compute namespaces budget configurations
│
└── [ Wazuh Manager Configurations ]
    ├── manager-ossec.conf              # Main server daemon settings (Secure TCP + UDP syslog)
    ├── manager-decoders.xml            # Custom regex patterns for Trivy & Falco JSON logs
    └── manager-rules.xml               # Custom rules for threat mapping & MITRE compliance
```

---

## 🛠️ Step-by-Step Deployment

### 1. Prepare your Wazuh Manager (Ubuntu VM)
Configure your central Wazuh Manager instance to ingest the custom log streams:
1. Copy the contents of `manager-decoders.xml` into `/var/ossec/etc/decoders/local_decoder.xml`
2. Copy the contents of `manager-rules.xml` into `/var/ossec/etc/rules/local_rules.xml`
3. Copy the daemon configs from `manager-ossec.conf` to `/var/ossec/etc/ossec.conf`
4. Restart the Wazuh Manager service:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

### 2. Connect the Cluster via Tailscale VPN
Generate a one-time reusable **Tailscale Auth Key** from your admin console, then deploy it as a secret inside the Kubernetes cluster:
```bash
kubectl create namespace wazuh
kubectl create secret generic tailscale-auth --from-literal=TS_AUTHKEY=<YOUR_TS_AUTHKEY> -n wazuh
```

### 3. Deploy Security Scanners (Trivy & Falco)
Install Trivy and Falco agents into EKS via Helm:
```bash
# Install Trivy Operator (CVE scanner)
helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/
helm repo update
helm install trivy-operator aquasecurity/trivy-operator --namespace trivy-system --create-namespace
kubectl apply -f trivy-rbac.yaml

# Install Falco (eBPF runtime protection)
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install falco falcosecurity/falco --namespace falco --create-namespace -f falco-values.yaml
```

### 4. Run the Workload
Open `wazuh-agent-config.yaml` and `wazuh-sidecar.yaml` and replace the placeholder `<WAZUH_MANAGER_IP>` with your Wazuh Manager's private Tailscale IP (e.g. `100.x.x.x`).
```bash
# Apply agent logging configuration and Python listener script
kubectl apply -f wazuh-agent-config.yaml

# Launch Nginx pod along with Event Exporter
kubectl apply -f wazuh-sidecar.yaml
kubectl apply -f kubernetes-event-exporter.yaml
```

---

## 🧪 Threat Verification Runbook

Validate that the entire security pipeline is working correctly by running these verification checks:

### 1. Trigger Runtime Threat Alert (Falco)
Run an unauthorized command inside the container to trigger a Falco alert (reading sensitive system files):
```bash
kubectl exec -it deployment/protected-nginx -n wazuh -c nginx -- cat /etc/shadow
```
Check the wazuh-agent's local log. An alert should write immediately:
```bash
kubectl exec -n wazuh deployment/protected-nginx -c wazuh-agent -- tail -n 5 /var/ossec/logs/falco.log
```
*💡 **Result:** Go to the Wazuh SIEM dashboard and search `rule.id: 100051` to see the live Falco alarm.*

### 2. Verify CVE Report Log Extraction (Trivy)
Confirm the `trivy-bridge` helper container is parsing image vulnerability reports:
```bash
kubectl exec -n wazuh deployment/protected-nginx -c wazuh-agent -- cat /logs/trivy/reports.json
```
*💡 **Result:** Search `rule.id: 100050` on the Wazuh SIEM dashboard to see the mapped CVE alerts.*

### 3. Verify Control-Plane Audits (Event Exporter)
Ensure cluster configuration changes are captured and routed:
```bash
kubectl exec -n wazuh deployment/protected-nginx -c wazuh-agent -- tail -n 5 /var/ossec/logs/k8s_events.log
```
*💡 **Result:** Search `rule.id: 100060` or `100061` in the SIEM dashboard to check Kubernetes audit logs.*
