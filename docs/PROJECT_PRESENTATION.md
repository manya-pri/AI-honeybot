# Project presentation outline

## Problem and limitations of basic honeypots

Basic decoys can collect isolated requests but often lack useful behavior context and explainable triage.

## Proposed solution

AI-Honeybot is a safe local decoy that captures sanitized interactions, extracts behavior features, tracks per-source risk, and exposes activity in a dashboard.

## Architecture and components

Flask honeypot, synthetic web resources, feature extraction, transparent risk rules, reversible temporary response, JSONL history, optional offline GeoIP, and Streamlit dashboard.

## Learning, analysis and boundaries

Current behavior accumulation combines transparent rules with SQLite-backed source memory. The Random Forest uses seeded synthetic scenarios and K-Means describes groups in observed event history; neither claims ground truth or validated accuracy. The agent defaults to local evidence-led analysis and optionally supports structured LLM triage without action tools or response-policy authority.

## Demonstration results and future work

Demonstrate login attempts, SSH-style HTTP interaction, sensitive endpoint probes, decoy access, risk escalation, model assessment, adaptive deception, containment, profile history and dashboard updates. Future work: evaluated ML, a true isolated SSH protocol service, external database support and Docker runtime verification.
