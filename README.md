# 🍯 LLM-Based Honeypots Hub

<div align="center">

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![OpenAI](https://img.shields.io/badge/LLM-OpenAI-412991.svg)](https://openai.com/)

> **A curated collection of LLM resources and a live multi-protocol honeypot implementation** focused on designing, deploying, and analyzing intelligent, interactive honeypots.

Part of [Awesome GenAI CyberHub](https://github.com/Ashfaaq98/awesome-genai-cyberhub)

</div>

---

## 📖 Table of Contents

- [About](#-about)
- [🛠️ Tools & Frameworks](#️-tools--frameworks)
- [📜 Research Papers](#-research-papers)
- [📚 Videos & Blog Posts](#-videos--blog-posts)
- [🚀 Honeypot Implementation](#-honeypot-implementation)
  - [Architecture](#architecture)
  - [Quick Start](#quick-start)
  - [Configuration](#configuration)
  - [Dashboard](#dashboard)
- [🤝 Contributing](#-contributing)

---

## 💡 About

This project serves two purposes:

1. **Curated Resource List** — A living collection of tools, papers, and blog posts at the intersection of LLMs and honeypot technology.
2. **Live Implementation** — A fully functional multi-protocol LLM-powered honeypot (SSH · HTTP · TCP) you can deploy and study.

LLMs fundamentally change the honeypot landscape by enabling **dynamic, contextually aware responses** to attacker commands rather than static, pre-scripted replies — dramatically increasing realism and the intelligence value of captured interactions.

---

## 🛠️ Tools & Frameworks

| Tool | Protocol | Description |
|------|----------|-------------|
| [galah (GLA)](https://github.com/0x4D31/galah) | HTTP | LLM-powered web honeypot emulating web applications. Featured at DEF CON 32. |
| [shelLM](https://github.com/stratosphereips/shelLM) | SSH | LLM-based SSH honeypot. |
| [VelLMes-AI-Deception-Framework](https://github.com/stratosphereips/VelLMes-AI-Deception-Framework) | Multi | AI-driven deception framework incorporating LLMs for honeypot functionalities. |
| [DECEIVE (Splunk)](https://github.com/splunk/DECEIVE) | Multi | Framework for AI-driven deception and honeypot concepts by Splunk. |
| [beelzebub](https://github.com/mariocandela/beelzebub) | SSH/HTTP/TCP | Secure low-code honeypot framework leveraging LLMs. Supports SSH, HTTP, and TCP. |
| [honeybee](https://github.com/yaaras/honeybee) | Multi | LLM/agent-inspired deception and interaction experiments. |
| [llm-honeypot (PalisadeResearch)](https://github.com/PalisadeResearch/llm-honeypot) | SSH | Modified Cowrie SSH honeypot detecting LLM-driven hacking agents via prompt injection traps. |

---

## 📜 Research Papers

### Foundational

| Paper | Venue | Summary |
|-------|-------|---------|
| [HoneyGPT](https://www.cse.psu.edu/~sxz16/papers/HoneyGPT.pdf) | Academic | Context-aware and evasive LLM honeypot framework. |
| [LLMPot](https://arxiv.org/abs/2405.05999) | arXiv | Automated LLM-based industrial honeypot generation via prompt inversion. |
| [LLM in the Shell](https://ieeexplore.ieee.org/document/10628775) | IEEE | Generative honeypots powered by LLMs. |
| [MySQL-Pot](https://ieeexplore.ieee.org/document/10607309) | IEEE | LLM-based honeypot for MySQL threat protection. |

### Systematization & Surveys

| Paper | Venue | Summary |
|-------|-------|---------|
| [SoK: Honeypots & LLMs](https://arxiv.org/abs/2510.25939) | arXiv:2510.25939 | Systematizes LLM-powered honeypot research since late 2022. Asks whether LLMs resolve the high-fidelity vs. low-operational-risk paradox. |

### New (2025–2026)

| Paper | Venue | Summary |
|-------|-------|---------|
| [AdvancedShelLM](https://arxiv.org/abs/2606.27990) | arXiv:2606.27990 | Multi-agent, stateful SSH honeypot. Manager/Worker LLM split + persistent FS. Up to **99.02% shell-correctness pass rate**. |
| [Honeyval](https://arxiv.org/abs/2605.29963) | arXiv:2605.29963 | Evaluation framework for LLM-backed HTTP honeypots — measuring actual deception quality. |
| [Honeyquest for LLMs](https://arxiv.org/abs/2606.21037) | arXiv:2606.21037 | Tests deception hypotheses against AI attackers. 21 LLMs × 10 providers × 10,962 responses vs. 47-human baseline. |
| [LLM-Based Pentesting with Honeypots](https://arxiv.org/abs/2609.08093) | arXiv:2609.08093 | LLM attackers can reason about honeypot suspicion and use it for target selection. |
| [Towards Agentic Honeynet Configuration](https://arxiv.org/abs/2603.14122) | arXiv:2603.14122 | Agentic reasoning applied to honeynet deployment under real resource constraints. |
| [ORCAGen](https://arxiv.org/abs/2610.12415) | arXiv:2610.12415 | GenAI + RAG to build malware-specific deception playbooks; trades containment for attacker observation. |
| [HydraPoT](https://arxiv.org/abs/2610.27722) | arXiv:2610.27722 | Cost-aware routing: each attacker command → traditional emulation, lightweight LLM, or cloud LLM based on complexity policy. |
| [LLM-Sherlock](https://arxiv.org/html/2409.08234v1) | arXiv | Jailbreak/misuse assessment framework — relevant to attacks against LLM honeypots. |

---

## 📚 Videos & Blog Posts

| Resource | Type | Description |
|----------|------|-------------|
| [Deceive AI — Splunk Blog](https://www.splunk.com/en_us/blog/security/deceive-ai-honeypot-concept.html) | Blog | Splunk's concept for an AI honeypot, related to the DECEIVE GitHub project. |
| [GLA: LLM-Powered Web Honeypot — DEF CON 32](https://www.youtube.com/watch?v=XGsm4Qcc_Ag) | Video | Adel Karimi presents galah — architecture, LLM comparison, real scan captures. |

---

## 🚀 Honeypot Implementation

This repo includes a production-ready **multi-protocol LLM honeypot** built in Python.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   LLM Honeypot Hub                      │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │  SSH     │  │  HTTP    │  │  TCP     │             │
│  │ Protocol │  │ Protocol │  │ Protocol │             │
│  │ :2222    │  │ :8080    │  │ :9999    │             │
│  └────┬─────┘  └────┬─────┘  └────┬────┘             │
│       │             │             │                     │
│       └─────────────┼─────────────┘                   │
│                     ▼                                   │
│           ┌─────────────────┐                          │
│           │   LLM Engine    │  ← OpenAI GPT-4o-mini   │
│           │  (Core Router)  │                          │
│           └────────┬────────┘                          │
│                    │                                    │
│           ┌────────▼────────┐                          │
│           │  Session Store  │  ← Per-attacker context  │
│           │  + Event Logger │                          │
│           └────────┬────────┘                          │
│                    │                                    │
│           ┌────────▼────────┐                          │
│           │   Dashboard     │  ← Real-time web UI      │
│           │   :5000         │                          │
│           └─────────────────┘                          │
└─────────────────────────────────────────────────────────┘
```

### Quick Start

#### Prerequisites

- Python 3.11+
- OpenAI API key
- (Optional) Docker

#### Install

```bash
git clone https://github.com/YOUR_USERNAME/llm-honeypot-hub
cd llm-honeypot-hub
pip install -r requirements.txt
```

#### Configure

```bash
cp configs/config.example.yaml configs/config.yaml
# Edit configs/config.yaml — add your OPENAI_API_KEY
```

#### Run

```bash
# All protocols + dashboard
python -m honeypot.main

# Or with Docker
docker-compose up
```

### Configuration

See [`configs/config.example.yaml`](configs/config.example.yaml) for all options:

```yaml
llm:
  provider: openai
  model: gpt-4o-mini       # cheap and fast; swap to gpt-4o for higher fidelity
  temperature: 0.7

protocols:
  ssh:
    enabled: true
    port: 2222
    banner: "Ubuntu 22.04.3 LTS"
  http:
    enabled: true
    port: 8080
  tcp:
    enabled: true
    port: 9999

logging:
  level: INFO
  json_output: true
  file: logs/honeypot.jsonl
```

### Dashboard

The built-in Flask dashboard shows:
- 🌍 Live attacker sessions (IP · protocol · session duration)
- 📊 Command frequency heatmap
- 🗺️ Geo-IP map of attacker origins
- 📋 Full interaction transcripts

Navigate to `http://localhost:5000` after starting the honeypot.

---

## 🤝 Contributing

Pull requests are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

**To add a resource:** Follow the format in the tables above and open a PR.  
**To improve the honeypot:** Fork, branch, test, and PR against `main`.

---

## 📄 License

MIT © 2026 — See [LICENSE](LICENSE) for details.
