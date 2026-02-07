# AWE: Adaptive Agents for Dynamic Web Penetration Testing

This repository contains the source code for our paper:

> **AWE: Adaptive Agents for Dynamic Web Penetration Testing**
> Akshat Singh Jaswal and Ashish Baghel
> *NDSS LAST-X 2026*

## Abstract

Modern web applications are increasingly produced through AI-assisted development and rapid no-code deployment pipelines, widening the gap between accelerating software velocity and the limited adaptability of existing security tooling. We introduce AWE, a memory-augmented multi-agent framework for autonomous web penetration testing that embeds structured, vulnerability-specific analysis pipelines within a lightweight LLM orchestration layer. Evaluated on the 104-challenge XBOW benchmark, AWE achieves 87% XSS success (+30.5% over MAPTA) and 66.7% blind SQLi success (+33.3%) while consuming 98% fewer tokens than prior work.

## Setup

```bash
git clone https://github.com/stuxlabs/awe.git
cd awe
cp .env.example .env 
docker compose up --build
```

## Usage

```bash
./run-docker.sh <target> --auto    # intelligent orchestration
./run-docker.sh <target> --xss     
./run-docker.sh <target> --sqli    
```

## Structure

```
src/
├── orchestrators/          # LLM-driven agent coordination
├── xss_agent/              # Context-aware XSS pipeline
├── sqli_agent/             # Database fingerprinting + injection
├── ssti_agent/             # Template engine detection
├── xxe_agent/              # XML external entity
├── command_injection_agent/
├── lfi_agent/
├── ssrf_agent/
├── idor_agent/
└── utils/                  # Memory system, browser verification
```

## Citation

```bibtex
-Proceedings to appear - NDSS LAST-X 2026
```
