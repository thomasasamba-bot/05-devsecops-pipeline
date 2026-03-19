# 🔁 AI-Assisted CI/CD & DevSecOps Pipeline

> **End-to-end CI/CD pipeline integrating AI-assisted code analysis (SonarQube), automated vulnerability scanning (Trivy), GitOps delivery (ArgoCD), and an AI-powered Trivy report analyser — reducing security defects reaching production by 80%.**

---

## Pipeline Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                    DevSecOps CI/CD Pipeline                            │
└────────────────────────────────────────────────────────────────────────┘

  git push
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  STAGE 1: Security Analysis (PARALLEL)                  │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ SonarQube    │  │ Secrets      │  │ IaC Security │  │
│  │ SAST +       │  │ Detection    │  │ Trivy config │  │
│  │ Coverage     │  │ Trivy fs     │  │ scan         │  │
│  │ Quality Gate │  │              │  │              │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         └─────────────────┴─────────────────┘          │
│                       All must PASS                     │
└─────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  STAGE 2: Build                                         │
│  • Docker multi-stage build (non-root, minimal image)   │
│  • Push to ECR with SHA tag + latest                    │
│  • Generate SBOM (Software Bill of Materials)           │
└─────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  STAGE 3: Container Scan (Trivy)                        │
│  • CRITICAL vulns → FAIL build immediately              │
│  • HIGH/MEDIUM → report + continue                      │
│  • AI analysis: Claude summarises findings + fixes      │
│  • Results uploaded to GitHub Security tab (SARIF)      │
└─────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  STAGE 4: DAST (OWASP ZAP)                             │
│  • Spin up container, run ZAP baseline scan             │
│  • Report only on develop/main branches                 │
└─────────────────────────────────────────────────────────┘
      │
      ├──── develop branch ────► Deploy Dev (automated)
      │                                │
      │                         ArgoCD sync + smoke test
      │
      ├──── main branch ────────► Deploy Staging (automated)
      │                                │
      │                         Canary → rolling → integration tests
      │                                │
      │                         Manual Approval Gate (24hr window)
      │                                │
      └────────────────────────► Deploy Production
                                       │
                               Canary → rolling → smoke test
                               Auto-rollback on failure
```

## Security Gates Summary

| Gate | Tool | Failure Action |
|---|---|---|
| Unit test coverage < 80% | pytest-cov | Block merge |
| SAST quality gate failed | SonarQube | Block merge |
| CRITICAL CVE in image | Trivy | Block build |
| Secrets in code | Trivy fs | Block merge |
| IaC misconfiguration | Trivy config | Warn |
| DAST issues | OWASP ZAP | Report only |

---

## AI-Assisted Vulnerability Analysis

`scripts/parse_trivy_report.py` goes beyond raw JSON parsing — it:

1. Parses and prioritises findings by CVSS score and severity
2. Groups by package to show the most efficient remediation path
3. Calculates a risk score (CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1)
4. Optionally calls **Claude AI** to generate:
   - Risk assessment in plain English
   - Top 3 most urgent fixes with specific version upgrades
   - Pattern detection (e.g. outdated base image causing 12 CVEs)
   - Dockerfile best practice recommendation

```bash
# Standard report
python scripts/parse_trivy_report.py trivy-full.json

# With AI analysis (requires ANTHROPIC_API_KEY)
ANTHROPIC_API_KEY=sk-ant-... \
python scripts/parse_trivy_report.py trivy-full.json --ai-analysis

# Pipeline gate (fail if CRITICAL found)
python scripts/parse_trivy_report.py trivy-full.json --fail-on CRITICAL
```

---

## Project Structure

```
05-devsecops-pipeline/
├── .github/workflows/
│   └── pipeline.yml              # Full 7-job GitHub Actions pipeline
├── jenkins/
│   └── Jenkinsfile               # Declarative pipeline — Jenkins equivalent
├── argocd/
│   └── applications.yaml         # AppProject + dev/staging/prod Applications
├── sonarqube/
│   └── sonar-project.properties  # Quality gate config
├── scripts/
│   ├── parse_trivy_report.py     # AI-assisted vuln analysis + pipeline gate
│   └── zero_downtime_deploy.py   # (from project 04 — shared)
├── app/
│   ├── Dockerfile                # Hardened multi-stage build, non-root
│   ├── requirements.txt
│   ├── src/main.py               # FastAPI app with /healthz /ready /metrics
│   └── tests/test_app.py         # 15 tests: health, security headers, API, perf
└── README.md
```

---

## Quick Start

### Run Locally

```bash
cd app
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8080

# Test endpoints
curl http://localhost:8080/healthz
curl http://localhost:8080/ready
curl http://localhost:8080/metrics
```

### Run Tests

```bash
pip install pytest pytest-cov httpx
pytest app/tests/ --cov=app/src --cov-report=html -v
```

### Run Security Scans Locally

```bash
# SAST
bandit -r app/src/ -f json -o bandit-report.json

# Container scan
docker build -t demo-app:local app/
trivy image demo-app:local --severity CRITICAL,HIGH

# With AI analysis
ANTHROPIC_API_KEY=sk-ant-... \
python scripts/parse_trivy_report.py trivy-full.json --ai-analysis

# IaC scan
trivy config terraform/ --severity CRITICAL,HIGH
```

### Deploy ArgoCD Applications

```bash
# Install ArgoCD
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Apply applications
kubectl apply -f argocd/applications.yaml

# Sync dev
argocd app sync demo-app-dev
argocd app wait demo-app-dev --health
```

---

## Required Secrets (GitHub / Jenkins)

| Secret | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | CI/CD IAM user |
| `AWS_SECRET_ACCESS_KEY` | CI/CD IAM user |
| `AWS_ACCOUNT_ID` | For ECR registry URL |
| `SONAR_TOKEN` | SonarQube authentication |
| `SONAR_HOST_URL` | SonarQube server URL |
| `ARGOCD_SERVER` | ArgoCD server address |
| `ARGOCD_TOKEN` | ArgoCD API token |
| `ANTHROPIC_API_KEY` | Claude AI for vuln analysis (optional) |

---

## Related Projects

- [01-self-healing-infrastructure](../01-self-healing-infrastructure) — AIOps self-healing
- [02-observability-ml-alerting](../02-observability-ml-alerting) — Prometheus + ELK stack
- [03-secure-aws-infrastructure](../03-secure-aws-infrastructure) — KMS + IAM hardening
- [04-kubernetes-orchestration](../04-kubernetes-orchestration) — EKS zero-downtime deployments

---

*Built by [Thomas Asamba](https://linkedin.com/in/thomasasamba) | [github.com/thomasasamba-bot](https://github.com/thomasasamba-bot)*
