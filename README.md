# API Abuse Detection & Rate Limiting Engine

## Overview

This project is a **security-focused API abuse detection and rate limiting engine** designed to protect HTTP APIs from malicious and abusive traffic.
It operates at the **application layer (L7)** and focuses on detecting **behavioral abuse patterns**, not just raw request volume.

The engine can be deployed as:

* Express/Fastify middleware
* A sidecar service in front of APIs
* A lightweight internal API security gateway

The system emphasizes **risk-based decisions**, **defense-in-depth**, and **forensic visibility**.

---

## Threat Model

This project defends against:

* Brute-force attacks
* Credential stuffing
* Token abuse
* Bot-driven traffic
* Low-and-slow denial-of-service attacks
* Excessive scraping and enumeration

Out of scope:

* Network-layer (L3/L4) DDoS attacks
* Large-scale volumetric floods

The engine is intentionally scoped to **application-level abuse detection**, where most API security failures occur.

---

## Core Concepts

### Identity-Aware Request Analysis

Each request is evaluated using multiple identity dimensions:

* Source IP address
* API key or token (if present)
* Authenticated user ID (if present)
* Request path and HTTP method

This prevents attackers from bypassing protections by rotating a single identifier.

---

### Sliding Window Rate Limiting

The engine implements **sliding window rate limits** instead of fixed windows to prevent burst attacks at window boundaries.

Rate limits can be applied independently to:

* IP addresses
* API keys
* Authenticated users
* Anonymous clients

Limits are configurable and tier-aware.

---

### Abuse Scoring Engine

Rather than blocking requests based on a single threshold, the engine assigns a **risk score** based on multiple behavioral signals, such as:

* Rate limit violations
* High error rates
* Authentication failures
* Endpoint scanning behavior
* Bot-like request timing

Decisions are made using score thresholds:

* Allow
* Throttle
* Temporary ban
* Extended ban

This mirrors how real-world security systems operate.

---

### Automated Banning and Throttling

The engine supports:

* Temporary bans with expiration
* Progressive penalties for repeat offenders
* Automatic recovery after ban expiry

Permanent bans are intentionally avoided to reduce collateral damage.

---

### Security Logging and Auditability

All security decisions are logged with structured data, including:

* Request identity
* Risk score
* Enforcement action
* Reason for decision
* Timestamp

These logs support:

* Incident response
* Abuse analysis
* Forensic investigations

---

## How the System Works

1. A request enters the engine
2. Identity attributes are extracted
3. Existing bans are checked
4. Rate limits are evaluated
5. Behavioral signals are updated
6. An abuse score is calculated
7. An enforcement decision is made
8. The request is allowed, throttled, or blocked
9. The decision is logged

This entire process occurs synchronously before the request reaches the protected API.

---

## Technology Stack

* TypeScript
* Node.js
* Express (middleware-based design)
* In-memory data store (v1)

The initial implementation uses in-memory storage for simplicity and clarity.
The design can be extended to Redis or distributed stores for production use.

---

## Usage

### Installation

```bash
git clone <repository-url>
cd abuse-engine
npm install
```

### Running the Engine

```bash
npm run dev
```

The engine starts an HTTP server that protects configured routes.

---

### Example Integration

```ts
app.use(abuseGuard)
app.use("/api", protectedRoutes)
```

Requests that violate security policies will receive appropriate HTTP responses, such as:

* 429 Too Many Requests
* 403 Forbidden

---

## Configuration

Configuration options include:

* Rate limits per identity type
* Abuse scoring weights
* Ban durations
* Logging verbosity

All values are centralized and designed to be easily adjustable.

---

## Limitations

* In-memory storage is not suitable for multi-instance deployments
* No TLS termination (assumed to be handled upstream)
* No machine learning or anomaly detection (rule-based only)

These limitations are intentional to keep the project focused and auditable.

---

## Security Philosophy

This project follows these principles:

* Detection is as important as prevention
* Behavior matters more than raw volume
* False positives are a security risk
* Security systems must be observable and explainable

---

## Future Improvements

* Redis-backed distributed rate limiting
* Persistent audit logs
* Adaptive thresholds based on traffic baselines
* Integration with SIEM systems
* Support for multiple enforcement strategies

---

## Disclaimer

This project is intended for educational and defensive security purposes only.
It does not replace enterprise-grade WAF or DDoS protection solutions.

---
