# DEATH 13A

### Evidence-Driven Web Reconnaissance & Security Change Analysis Framework

<p align="center">

A Python-based reconnaissance framework that collects publicly observable web information, preserves evidence, detects changes between scans, and produces evidence-backed security analysis.

</p>

---

## Overview

**DEATH 13A** is a Python-based web reconnaissance and security change analysis framework.

The framework goes beyond simply collecting information from a target. Each reconnaissance result can be preserved as evidence, stored as a snapshot, compared against previous observations, and analyzed when a change is detected.

The core workflow is:

```text
Reconnaissance
      ↓
Evidence Collection
      ↓
Fingerprint Generation
      ↓
Snapshot Storage
      ↓
Change Detection
      ↓
Change Normalization
      ↓
Evidence Correlation
      ↓
Impact Analysis
      ↓
Evidence-Backed Report
