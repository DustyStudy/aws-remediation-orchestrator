# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this repository, please report it privately — **do not open a public GitHub issue**.

Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) feature (Security tab → "Report a vulnerability" on this repo). Please do not include real AWS account IDs, ARNs, or credentials in your report.

You can expect an initial response within 5 business days.

## Scope

This repository is an event-driven orchestration engine that routes AWS Security Hub findings through policy matching, blast-radius guardrails, optional human approval, and remediation execution (SSM Automation). Reports in scope include:

- Logic errors that could cause a remediation to run when it shouldn't (bypassing a guardrail, the circuit breaker, or the resource denylist), or that weaken the approval flow (the HMAC-signed approval links, task-token handling)
- IAM policies broader than the module's own documentation claims
- Logic errors that could cause a remediation to *not* run, or run incorrectly, in a way that leaves a real finding unaddressed
- Supply-chain concerns (malicious or unpinned dependencies, GitHub Actions)
- Secrets or credentials accidentally committed to this repo

Out of scope: vulnerabilities in AWS services themselves (report those to AWS), or issues in downstream forks/deployments not present in this repo's source. The approval-link authentication model has a documented known limitation (see `terraform/lambda/approval_callback/handler.py`'s docstring and `docs/ARCHITECTURE.md`) - reports about that specific, already-documented trade-off aren't necessary, but reports about the signature verification itself being bypassable are very much in scope.

## Supported Versions

This repository doesn't ship versioned releases — the `main` branch is the
single source of truth and the only branch that receives fixes.
