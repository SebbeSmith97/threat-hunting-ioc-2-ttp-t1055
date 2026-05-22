# Threat Hunting Study for T1055.001 DLL Injection
## Thesis project for program IT-säkerhetsspecialist @ IT-Högskolan, May 2026 

---

## What this is

This repository contains a behavior-based threat hunting study for MITRE ATT&CK
sub-technique **T1055.001 Dynamic-link Library Injection**, implemented for
**Microsoft Defender XDR Advanced Hunting**.

The study is one deliverable of the IT-säkerhetsspecialist thesis project *"From IoC to TTP"*
written by me. Its purpose is to simplify hypothesis-driven,
behavior-based hunting procedures that translate across customer tenants to help SOC analysts
working in a MSSP.

---

## Repository structure

```
/
├── README.md                                    ← This file
├── TEMPLATE.md                                  ← Blank entry template (copy to add new entries)
└── entries/
    └── T1055.001-H01_dll-injection.md ← Example entry: DLL injection
```

---

## How to read an entry

Each entry file has seven sections:

| Section | What it contains |
|---------|-----------------|
| **Metadata** | Hunt ID, technique, tactic, Pyramid of Pain level, hypothesis source, author, version, status |
| **1. Hypothesis statement** | The testable "if … then …" statement the hunt is built around |
| **2. Background** | What the variant is, known adversary use, current relevance, defensive baseline |
| **3. Data requirements** | Which telemetry the query relies on |
| **4. KQL query** | The hunt query, annotated with comments explaining each filter's intent |
| **5. Expected results and tuning** | Legitimate causes, triage refinements, what a true positive looks like, recommended pivots |
| **6. Pyramid of Pain positioning** | Why this entry sits at its declared level and what an adversary would have to change to evade it |
| **7. References (if available)** | MITRE, CTI, schema documentation, community sources |

---

## How to run a hunt

1. Open [Microsoft Defender XDR Advanced Hunting](https://security.microsoft.com/v2/advanced-hunting).
2. Open the entry file you want to run.
3. Read the **Hypothesis statement** first - understand what you are looking for before
   running anything.
4. Read **Expected results and tuning** (Section 5) - know the common false-positive sources
   for this tenant before you see results.
5. Paste the **KQL query** (Section 4) into the Advanced Hunting editor.
6. Adjust the `ago(7d)` time window if needed. Shorter windows run faster; longer windows
   catch slower-moving campaigns.
7. Adjust the `Devices <= 5` prevalence threshold in Step 4 based on your tenant's size and
   baseline noise. In large tenants, a threshold of 3 or lower may produce cleaner results.
8. Run the query and triage the results using the guidance in Section 5.
9. If a result looks suspicious, run the **Recommended pivots** from Section 5.4.

> **Important - baselining** Before running the hunt in a new tenant, spend
> 15–30 minutes understanding which processes routinely perform cross-process operations
> in that environment. Run `DeviceEvents | where ActionType == "WriteProcessMemoryApiCall" | summarize count() by InitiatingProcessFileName | order by count_ desc` against a 30-day window
> to see the baseline. Common writers in your environment should go on the per-tenant
> allow-list described in Section 5.2.

---

## How to add a new entry

1. Copy `TEMPLATE.md` to `entries/` with a filename following the pattern:
   `T{technique}.{subtechnique}-H{nn}_{short-name}.md`
   Example: `T1055.001-H02_reflective-dll-injection.md`
2. Fill in every `{placeholder}`.
3. Run the query against at least one tenant before setting Status to `Tested`.
4. Submit a merge request for review.

---

## Methodology reference

The methodology this study applies is described in full in the accompanying thesis report
(*From IoC to TTP*). The key parts are:

- **Pyramid of Pain** (Bianco 2013) - every entry must operate at the Tools or TTPs level.
  Entries that rely on hashes, filenames or IP addresses are rejected.
- **Hunting Maturity Model** (Bianco 2015) - the study targets HMM2: an analyst who did not
  author an entry can execute it and triage the results using only what is written in the entry.
- **Hypothesis generation** (Lee & Bianco 2016) - every entry starts with an explicit
  "if … then …" hypothesis classified by source (intelligence, situational awareness,
  domain expertise).
- **Analytical patterns** - each entry uses one or more of: baselining, prevalence analysis,
  aggregation and correlation.
