# EKS Security Monitoring Pipeline (Wazuh, Falco & Trivy)

A secure, cost-optimized Kubernetes security monitoring pipeline designed to run on AWS EKS and stream runtime alerts, control-plane audit events, and container image vulnerabilities directly to a self-hosted Wazuh SIEM. 

By leveraging **Kubernetes Event Exporter**, this architecture bypasses expensive AWS CloudWatch ingestion fees (~90% cost savings for control-plane logs) by routing all telemetry locally through a private **Tailscale VPN** tunnel.

---

## ── ARCHITECTURE OVERVIEW ──

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
  │  │  │  │   Shared  ├────────►│   falco_listener.py   │  │  │  │
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

### Main Pipeline Components:
1. **Runtime Protection (Falco):** Uses eBPF kernel probes to detect runtime anomalies (e.g. spawned shells, file permission changes) and forwards alerts via syslog UDP locally to the pod.
2. **Vulnerability Assessment (Trivy):** Continuously scans running images and publishes Custom Resource Definitions (CRDs). A lightweight `trivy-bridge` parses these findings into unified JSON logs.
3. **Audit/Control Plane logs (Event Exporter):** Replaces AWS CloudWatch. It queries EKS events and posts them directly to the pod's HTTP listener.
4. **Ingestion & Overlay (Wazuh & Tailscale):** A shared-network namespace inside the app pod aggregates all logs. The local Wazuh Agent forwards this telemetry securely over Tailscale's WireGuard mesh to your Wazuh Manager dashboard.

---

## ── REPOSITORY STRUCTURE ──

```
.
├── README.md                           # Documentation and guides
├── Secure_Kubernetes_Telemetry_Pipeline.pdf # (Place your compiled PDF here)
├── wazuh-sidecar.yaml                  # Kubernetes Deployment sidecar manifest
├── wazuh-agent-config.yaml             # Agent ConfigMap (ossec.conf & falco_listener.py)
├── kubernetes-event-exporter.yaml      # Control-plane event exporter configuration
├── falco-values.yaml                   # Helm value overrides for Falco & Sidekick
├── trivy-rbac.yaml                     # Least-privilege RBAC roles for Trivy access
├── workload-nodepool.yaml              # Karpenter Auto-scaling configuration (Cost control)
├── resource-quota.yaml                 # Compute budget and resource controls
├── manager-ossec.conf                  # Wazuh Manager main server configuration
├── manager-decoders.xml                # Custom Wazuh Decoders for JSON parsing
└── manager-rules.xml                   # Custom Wazuh Ingestion Rules (MITRE mapped)
```

---

## ── DEPLOYMENT INSTRUCTIONS ──

### 1. Configure the Wazuh Manager (Ubuntu VM)
Copy the custom rules and decoders to your central Wazuh Manager installation to parse the incoming EKS JSON streams:

```bash
# 1. Add Trivy/Falco decoders to:
/var/ossec/etc/decoders/local_decoder.xml

# 2. Add custom rules (rules 100050, 100051, 100060-100062) to:
/var/ossec/etc/rules/local_rules.xml

# 3. Restart the Wazuh Manager service:
sudo systemctl restart wazuh-manager
```

### 2. Connect EKS to the Tailscale Network
Create a Tailscale Auth Key (`TS_AUTHKEY`) from your Tailscale console and register it inside EKS so the sidecar can build the WireGuard tunnel:

```bash
kubectl create namespace wazuh
kubectl create secret generic tailscale-auth --from-literal=TS_AUTHKEY=<YOUR_TS_AUTHKEY> -n wazuh
```

### 3. Deploy the Security Agents
Run these commands in EKS to deploy the vulnerability and runtime agents:

```bash
# Deploy Trivy Operator
helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/
helm repo update
helm install trivy-operator aquasecurity/trivy-operator --namespace trivy-system --create-namespace

# Configure RBAC permissions for Trivy-Bridge
kubectl apply -f trivy-rbac.yaml

# Deploy Falco with eBPF driver
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install falco falcosecurity/falco --namespace falco --create-namespace -f falco-values.yaml
```

### 4. Deploy the Logging Engine & Workload
Open `wazuh-agent-config.yaml` and `wazuh-sidecar.yaml` and replace the placeholder `<WAZUH_MANAGER_IP>` with your Wazuh Manager's private Tailscale IP address (e.g. `100.x.x.x`).

```bash
# Apply agent configurations and python listener
kubectl apply -f wazuh-agent-config.yaml

# Deploy the application pod alongside the exporter
kubectl apply -f wazuh-sidecar.yaml
kubectl apply -f kubernetes-event-exporter.yaml
```

---

## ── THREAT VERIFICATION RUNBOOK ──

### 1. Trigger Runtime Threat Alert (Falco)
Exec into the primary Nginx container and trigger a critical Falco rule by attempting to read sensitive host files:

```bash
kubectl exec -it deployment/protected-nginx -n wazuh -c nginx -- cat /etc/shadow
```

Verify that the alarm registered instantly inside the Wazuh Agent log:

```bash
kubectl exec -n wazuh deployment/protected-nginx -c wazuh-agent -- tail -n 5 /var/ossec/logs/falco.log
```
*(Wazuh dashboard: filter search for `rule.id: 100051` to see the live alarm).*

### 2. Verify Vulnerability Scanning (Trivy)
View the extracted vulnerability stream stored in the shared emptyDir volume:

```bash
kubectl exec -n wazuh deployment/protected-nginx -c wazuh-agent -- cat /logs/trivy/reports.json
```
*(Wazuh dashboard: filter search for `rule.id: 100050` to view the parsed CVE reports).*

### 3. Verify Control-Plane Audit logs (Event Exporter)
View EKS event logs delivered to the webhook listener:

```bash
kubectl exec -n wazuh deployment/protected-nginx -c wazuh-agent -- tail -n 5 /var/ossec/logs/k8s_events.log
```
*(Wazuh dashboard: filter search for `rule.id: 100060` or `100061` to view Kubernetes events).*
