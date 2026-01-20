# UPS: From Signals to Patch Queues (KEV-2025 + vKEV check)

This repository contains the artifacts for the paper **“UPS Meets Patch Queues
Evidence-timeline prioritization under limited capacity, cadence, and compliance gravity”**.

The paper studies how different *evidence thresholds* (Watch+/Track+/Prepare+) affect (1) **shift-left** (patching before KEV inclusion) and (2) **operational workload** under capacity-bounded patch queues.

---

## Contents

### Paper
- `UPS_Meets_Patch_Queues-publish.pdf`  

### Data artifacts
- `timelines.csv`  
  A time-series dataset of vulnerability signal events and derived stages used in the analysis and queue simulation.
  Typical fields include identifiers (e.g., CVE), timestamps, signal types, and derived stage/state.

- `ups-signal-taxonomy.v1.3.0.json`  
  UPS Signal Taxonomy (v1.3.0): a machine-readable definition of supported signal types and their intended semantics.

---

