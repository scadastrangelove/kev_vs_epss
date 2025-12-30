# EPSS vs Real-World Exploitation (KEV 2025)

**Author:** Sergey Gordeychik
**Affiliation:** CyberOK
**Year:** 2025

This repository contains data, scripts, and analytical artifacts used to evaluate the **predictive power and operational applicability of EPSS (Exploit Prediction Scoring System)** when compared against **confirmed real-world exploitation**, as represented by **CISA’s Known Exploited Vulnerabilities (KEV) catalog**.

The work focuses on **2025 vulnerabilities** and answers two practical questions:

1. *How well does EPSS predict real exploitation?*
2. *What is the operational cost of using EPSS thresholds in patch management?*

---

## 1. Key Findings & Research Takeaways

This section summarizes the conclusions derived from the analysis, formulated in a way suitable for citation in research papers, internal methodologies, or policy documents.

### 1.1 EPSS is a ranking signal, not an exploitation oracle

> *“EPSS should be treated as a probabilistic ranking signal, not as a binary indicator of exploitation.”*

EPSS estimates the **probability of exploitation within a future time window** (30 days).
It does **not** assert whether exploitation is already occurring.

By contrast, **KEV represents confirmed exploitation**. Mixing these two without distinction leads to incorrect operational conclusions.

---

### 1.2 Coverage gaps are an inherent limitation

In the 2025 KEV dataset:

* Total KEV entries: **245**
* EPSS available at the time of KEV inclusion: **203 (≈83%)**
* Missing EPSS at decision time: **≈17%**

> *“If a predictive signal is unavailable at the moment of decision, it cannot be operationally relied upon.”*

Missing EPSS values are not neutral; operationally, they behave as **false negatives**.

---

### 1.3 Recall of EPSS thresholds against KEV is structurally limited

Recall measured against KEV (only where EPSS existed):

| EPSS Threshold | Conditional Recall |
| -------------- | ------------------ |
| ≥ 0.1% (0.001) | 65%                |
| ≥ 1% (0.01)    | 38%                |
| ≥ 10% (0.1)    | 27%                |

When calculated against **all KEV entries** (including missing EPSS):

| EPSS Threshold | Effective Recall |
| -------------- | ---------------- |
| ≥ 0.1%         | 53.9%            |
| ≥ 1%           | 31.8%            |
| ≥ 10%          | 22.4%            |

> *“Using EPSS as a hard gate inevitably excludes a substantial fraction of actively exploited vulnerabilities.”*

---

### 1.4 Low EPSS does not imply low real-world risk

Multiple KEV vulnerabilities exhibited **extremely low EPSS values** at the time of KEV inclusion, including:

* **CVE-2025-14847 (MongoBleed)** — EPSS ≈ 0.00041
* Targeted, perimeter-facing, niche exploitation patterns

> *“EPSS systematically underestimates exploitation that is targeted, low-noise, or ecosystem-specific.”*

This limitation is intrinsic to telemetry-driven prediction models.

---

### 1.5 EPSS may lag behind reality

A distinct class of vulnerabilities shows **delayed EPSS escalation**:

* Initially near-zero EPSS
* Later rising to top percentiles after widespread exploitation signals appear

Examples include CI/CD supply-chain incidents and network appliance vulnerabilities.

> *“EPSS often converges to reality after exploitation becomes visible, not before.”*

---

### 1.6 Percentiles improve communication, not coverage

Percentiles normalize EPSS values across time and model versions, but:

* They do **not** increase recall
* They do **not** reduce false negatives
* They primarily affect **ordering**, not **selection**

> *“Percentiles change priority order, not workload volume.”*

---

### 1.7 Operational conclusion

> *“KEV defines what must be patched. EPSS helps decide what to patch next.”*

A defensible patch prioritization model must treat:

* **KEV** as a mandatory override
* **EPSS** as a secondary sorting and focus signal
* **Non-CVE vulnerabilities** (e.g., local databases, vendor advisories) as first-class risk inputs

---

## 2. Practical Usage

This repository contains both **raw data** and **reproducible scripts** used in the analysis.

---

## 2.1 Files Overview

### Core Data Files

* **`kev_2025_epss.csv`**
  KEV entries for 2025 enriched with EPSS values at:

  * date of KEV inclusion
  * snapshot date (2025-12-29)

* **`epss_scores-2025-12-29.csv`**
  Full EPSS dataset snapshot for all CVEs on 2025-12-29

* **`epss_scores-2025-12-29_cve2025.csv`**
  Filtered EPSS snapshot for **CVE-2025-*** only

---

### Analytical Outputs

* **`epss_threshold_catch_2025.csv`**
  Recall of KEV vulnerabilities at different EPSS thresholds

* **`epss_threshold_patch_load_2025-12-29.csv`**
  Estimated patch workload (counts) per EPSS threshold

* **`epss_deceptive_low_2025.csv`**
  KEV vulnerabilities with **low EPSS at inclusion time**, including:

  * later EPSS growth
  * cases that remained low despite confirmed exploitation

---

### Script

* **`kev_2025_epss.py`**
  Script to:

  * Fetch KEV data
  * Query EPSS (historical and current)
  * Enrich KEV entries
  * Produce reproducible CSV outputs

---

## 2.2 Running the Script

### Requirements

* Python 3.9+
* Dependencies:

  ```bash
  pip install requests pandas
  ```

### Basic Usage

```bash
python kev_2025_epss.py \
  --year 2025 \
  --out kev_2025_epss.csv \
  -v
```

### Resume Mode (recommended for large runs)

```bash
python kev_2025_epss.py \
  --year 2025 \
  --out kev_2025_epss.csv \
  --resume \
  -v
```

### Notes

* EPSS API rate limits are respected via single-CVE requests
* Missing EPSS values are preserved (not imputed)
* Output is flushed incrementally to avoid data loss

---

## 3. Intended Use

This repository is intended for:

* Security research and methodology validation
* Patch prioritization strategy design
* Risk communication with management
* Teaching limitations of predictive security scoring

It is **not** intended to replace threat intelligence, asset context, or expert analysis.

---

## 4. Citation

If you reference this work:

> Gordeychik, S. (2025). *Evaluating EPSS as a Predictive Signal Against Confirmed Exploitation (KEV 2025)*. 

---

## 5. Final Remark

> *“Prediction is useful. Assumptions are dangerous.”*

Use EPSS wisely. Always verify against reality.
