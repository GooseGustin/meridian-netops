# Meridian Financial Group — Compliance Report

**Generated:** 2026-03-14 20:50:47  
**Policy:** PCI-DSS 4.0 / Internal Security Policy v3.0  
**Scope:** Lagos DC — All network devices and servers  

---

## Network Devices

| Device | Status | Security Drift | Policy Violations | Missing Requirements |
|:-------|:------:|:--------------:|:-----------------:|:--------------------:|
| edge-router-01 | **DRIFT DETECTED** | 2 | 0 | 1 |
| fw-01 | **DRIFT DETECTED** | 5 | 1 | 2 |
| core-sw-01 | **DRIFT DETECTED** | 0 | 0 | 0 |

### Drift Details

#### edge-router-01

**Config Drift (security-relevant):**
- `+enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0`
- `-ip ssh version 2`

#### fw-01

**Policy Violations:**
- `[HIGH]` FORBIDDEN: `transport input telnet`

**Config Drift (security-relevant):**
- `+enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0`
- `-ip ssh version 2`
- `- transport input ssh`
- `+#  transport input ssh`
- `+ transport input telnet`

---

## Linux Hosts (Docker)

| Host | Findings | Key Issues |
|:-----|:--------:|:-----------|
| web-01 | 2 | Password authentication is ENABLED — should be key-only, Root SSH login is ENABLED — should be disabled |
| db-01 | 2 | Password authentication is ENABLED — should be key-only, Root SSH login is ENABLED — should be disabled |

---

## Remediation Priority

| Priority | Item | Device | Action |
|:--------:|:-----|:-------|:-------|
| 1 | ip ssh version 2 | edge-router-01 | Add to config |
| 2 | transport input telnet | fw-01 | Remove/Replace |
| 3 | no ip source-route | fw-01 | Add to config |
| 4 | ip ssh version 2 | fw-01 | Add to config |

---

*Report generated automatically by Meridian Compliance Engine*