# OpenSecAgent

<p align="center">
  <strong>Autonomous Server Cybersecurity Expert Bot</strong>
</p>

<p align="center">
  A server-side security agent that continuously monitors hosts and containers, detects risky changes, recommends and executes safe remediation, and produces clear reports—all with explainable security.
</p>

---

## Overview

**OpenSecAgent** is an open-source, server-resident security agent for small/medium companies, DevOps teams, and MSPs. It reduces time-to-detect and time-to-contain incidents by:

- **Continuous monitoring** of host and container assets
- **Drift detection** for critical config files
- **Rule-based detectors** (auth failures, new admins, new ports, new containers)
- **Policy-controlled remediation** (alert-only or soft containment)
- **Audit trail** and email alerts

### One-liner

> OpenSecAgent is a server-side security expert that continuously watches your hosts and containers, explains risk in plain English, and safely contains incidents—then emails you a clean report.

---

## Current Implementation Status

| Feature | Status | Notes |
|--------|--------|-------|
| Host inventory (OS, packages, services, ports, sudo users) | ✅ Implemented | dpkg/rpm, systemd, ss/netstat |
| Docker inventory (containers, images) | ✅ Implemented | Via Docker SDK |
| Drift monitoring (critical files) | ✅ Implemented | Baseline + hash diff |
| Detectors (auth, admin, ports, containers) | ✅ Implemented | Rule-based |
| Policy engine (Tier 0/1) | ✅ Implemented | Alert-only + soft containment |
| Responder (stop container, block IP stub) | ✅ Implemented | Docker stop; IP block placeholder |
| Audit log (incidents + actions) | ✅ Implemented | JSONL append-only |
| Email (immediate + daily digest) | ✅ Implemented | SMTP |
| LLM summaries | ✅ Implemented | Optional; incident summaries only |
| **LLM agent (command loop)** | ✅ Implemented | LLM suggests commands → execute → feed back → repeat (whitelist) |
| **Full activity logging** | ✅ Implemented | Every collector, detector, command, LLM call in activity.jsonl |
| **Packaging (pip, Docker)** | ✅ Implemented | `pip install opensecagent`, Dockerfile, docker-compose |

---

## Installation

### Option A: pipx (recommended on Linux / when you see “externally-managed-environment”)

On many Linux systems (Debian, Ubuntu, etc.) the system Python is “externally managed” and `pip install` is blocked. Use **pipx** so the app runs in its own environment and the `opensecagent` command is on your PATH:

```bash
# Install pipx if needed: sudo apt install pipx && pipx ensurepath
pipx install opensecagent
opensecagent config    # interactive wizard → writes config (no path needed)
opensecagent status    # or run the daemon: opensecagent
```

### Option A2: pip in a virtual environment

If you prefer a venv (or are on macOS/Windows where `pip install` often works):

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install opensecagent
opensecagent config
opensecagent status
```

After `opensecagent config`, the config file is written to `/etc/opensecagent/config.yaml` (if writable) or `~/.config/opensecagent/config.yaml`. You never need to pass `--config` unless you use a custom path.

### Option B: From source

```bash
git clone https://github.com/DulanDias/opensecagent.git
cd opensecagent
pip install -e .
opensecagent config    # wizard → writes config
opensecagent status
```

### Option C: systemd service

```bash
# After cloning or extracting
sudo SOURCE_DIR=/path/to/opensecagent bash scripts/install.sh
sudo vi /etc/opensecagent/config.yaml   # Configure admin_emails, smtp, etc.
sudo systemctl enable opensecagent && sudo systemctl start opensecagent
sudo journalctl -u opensecagent -f
```

### Option D: Docker

```bash
# Build and run
docker build -t opensecagent .
docker run -d --name opensecagent \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc/opensecagent:/etc/opensecagent \
  -v /var/lib/opensecagent:/var/lib/opensecagent \
  -v /var/log/opensecagent:/var/log/opensecagent \
  opensecagent
```

---

## Configuration

**Easiest:** run `opensecagent config`. You answer a few questions (scan frequency, email, LLM API key, etc.) and the tool writes the YAML for you. No need to pass a config path afterward.

**Config file location** (when not using `--config`): `/etc/opensecagent/config.yaml` or `~/.config/opensecagent/config.yaml`. Override with `OPENSECAGENT_CONFIG=/path/to/config.yaml` or `opensecagent --config /path/to/config.yaml`.

| Key | Description | Default |
|-----|-------------|---------|
| `agent.data_dir` | State and drift baseline | `/var/lib/opensecagent` |
| `agent.log_dir` | Log directory | `/var/log/opensecagent` |
| `collector.host_interval_sec` | Host inventory interval | 300 |
| `collector.docker_interval_sec` | Docker inventory interval | 60 |
| `collector.drift_interval_sec` | Drift check interval | 300 |
| `collector.critical_files` | Files to monitor for drift | `/etc/passwd`, `/etc/sudoers`, etc. |
| `action_tier_max` | 0=alert only, 1=soft containment | 1 |
| `notifications.admin_emails` | Alert recipients | `[]` |
| `notifications.smtp` | SMTP host, port, user, password | — |
| `llm.enabled` | Use LLM for summaries + agent | false |
| `llm.api_key` | OpenAI (or compatible) API key | — |
| `llm_agent.enabled` | Run LLM agent loop on incidents | false |
| `llm_agent.run_on_incident` | Run agent when P1/P2 incident | true |
| `llm_agent.run_interval_sec` | Periodic agent run (0=disabled) | 0 |
| `audit.file` | Audit log path | `/var/log/opensecagent/audit.jsonl` |
| `activity.file` | Activity log path | `/var/log/opensecagent/activity.jsonl` |

---

## Setup & configuration (CLI, wizard-driven)

**Recommended: run the full wizard once** (paths → config → validate → optional systemd install):

```bash
opensecagent wizard
```

The wizard will prompt for: config/data/log directories, admin emails, SMTP, environment, action tier, LLM (optional), then validate, and optionally install the systemd service.

**Other commands** (all support interactive/wizard-style where noted):

```bash
# Setup with interactive prompts (paths + optional config wizard)
opensecagent setup --interactive

# Or non-interactive with explicit paths
opensecagent setup --config-dir /etc/opensecagent --data-dir /var/lib/opensecagent --log-dir /var/log/opensecagent

# Configure (interactive wizard)
opensecagent --config /etc/opensecagent/config.yaml config wizard

# Or set single keys
opensecagent --config /etc/opensecagent/config.yaml config set notifications.smtp.host smtp.example.com
opensecagent --config /etc/opensecagent/config.yaml config set notifications.admin_emails.0 admin@example.com

# Validate and show config
opensecagent --config /etc/opensecagent/config.yaml config validate
opensecagent --config /etc/opensecagent/config.yaml config show

# Install systemd (interactive: prompts for dirs and start service)
opensecagent install --interactive
# Or non-interactive
opensecagent install --config-dir /etc/opensecagent --no-start

# Status and uninstall
opensecagent --config /etc/opensecagent/config.yaml status
opensecagent uninstall --remove-unit
```

| Command | Description |
|---------|-------------|
| `wizard` | **Full wizard**: paths → config → validate → optional install → status |
| `setup` | Create dirs + default config; `--interactive` / `-i` prompts for paths and runs config wizard |
| `config wizard` | Interactive config (emails, SMTP, env, tier, LLM) |
| `config set KEY VALUE` | Set one key (dot notation) |
| `config show` | Print merged config as YAML |
| `config validate` | Validate config file |
| `install` | Install systemd unit; `--interactive` / `-i` prompts for dirs and start service |
| `status` | Show version, paths, daemon state |
| `uninstall` | Stop/disable service; `--remove-unit` to remove unit file |

---

## CLI (run & export)

```bash
# One-off collection (host + Docker)
opensecagent --config config/default.yaml collect

# Drift check
opensecagent --config config/default.yaml drift

# Run detectors
opensecagent --config config/default.yaml detect

# Run LLM agent loop once (scan + fix; requires llm.enabled and api_key)
opensecagent --config config/default.yaml agent

# Export audit log as JSON
opensecagent --config config/default.yaml export-audit --path /var/log/opensecagent/audit.jsonl

# Export activity log as JSON
opensecagent --config config/default.yaml export-activity --path /var/log/opensecagent/activity.jsonl
```

---

## Logging & Audit

- **Audit log** (`audit.file`): Append-only JSONL with incidents and actions. Use `export-audit` to convert to JSON.
- **Activity log** (`activity.file`): Full activity log—every collector run, detector run, policy decision, command execution, LLM call. Use `export-activity` to convert to JSON.
- **Python logging**: INFO to stdout (daemon start/stop, errors). Redirect to a file or use systemd/journal.

---

## Deployment Options

| Environment | How to deploy |
|-------------|---------------|
| **Bare metal / VPS** | systemd service via `scripts/install.sh` |
| **Docker host** | Run agent in container with Docker socket mount |
| **AWS EC2 / Lightsail** | systemd on Amazon Linux / Ubuntu |
| **GCP Compute / Azure VM** | systemd on Debian/Ubuntu |
| **Kubernetes** | DaemonSet (planned) |
| **Managed service** | Self-host on your infra; no SaaS yet |

### Where to run OpenSecAgent

- **On each server** you want to protect (agent per host)
- **Central management server** (optional control plane, planned)
- **MSP / multi-tenant**: One agent per client server; central dashboard planned

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        OpenSecAgent Daemon                        │
├─────────────────────────────────────────────────────────────────┤
│  Collectors          │  Detectors        │  Policy Engine        │
│  • Host inventory    │  • Auth failures  │  • Action tiers       │
│  • Docker inventory  │  • New admin user │  • Maintenance windows│
│  • Drift monitor     │  • New port       │                       │
│                      │  • New container  │  Responder            │
│                      │                   │  • Stop container     │
│                      │                   │  • Block IP (stub)   │
├─────────────────────────────────────────────────────────────────┤
│  Reporter: Audit (JSONL) │ Email (SMTP) │ LLM summaries (optional)│
└─────────────────────────────────────────────────────────────────┘
```

---

## Security

- **Defensive only**: No offensive scanning, exploitation, or "hacking back"
- **Policy-first**: High-impact actions require policy and (optionally) approval
- **Sensitive data**: Redacted before sending to LLM
- **Least privilege**: Run as dedicated user where possible; escalate only for specific tasks

---

## Roadmap

- [x] **LLM agent loop**: LLM suggests commands → execute → feed output back → repeat (whitelist-based)
- [x] **Full activity logging**: Every collector, detector, command in activity.jsonl
- [x] **pip package**: `pip install opensecagent`
- [x] **Docker image**: Dockerfile included
- [ ] **Kubernetes DaemonSet**: For cluster-wide deployment
- [ ] **Control plane**: Central dashboard, multi-tenant, policy management
- [ ] **Slack/Teams/PagerDuty**: Additional notification channels
- [ ] **Compliance packs**: SOC2/ISO27001 mapping reports

---

## Contributing

Contributions are welcome. Please open an issue or PR on GitHub.

1. Fork the repo
2. Create a feature branch
3. Add tests where applicable
4. Submit a pull request

---

## License

[Choose: MIT, Apache 2.0, or your preferred license]

---

## Links

- **GitHub**: https://github.com/DulanDias/opensecagent
- **Issues**: https://github.com/DulanDias/opensecagent/issues
- **Documentation**: (link when available)
