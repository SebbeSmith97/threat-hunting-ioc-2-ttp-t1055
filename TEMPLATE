# Hunt {T1003.001-Hnn} — {Short descriptive title of the variant}

<!--
Instructions:
  1. Copy this file. Rename it after the Hunt ID, e.g. T1055.001-H01_classical-dll-injection.md
  2. Replace every {placeholder} with content.
  3. If a section does not apply, write "Not applicable — {reason}" rather than deleting the section.
  5. Delete this comment block before publishing.
-->

---

## Metadata

| Field             | Value                                                              |
|-------------------|--------------------------------------------------------------------|
| Hunt ID           | T1055.001-H{nn}                                                    |
| MITRE technique   | T1055.001 — Process Injection: Dynamic-link Library Injection      |
| MITRE tactic      | TA0005 — Defense Evasion / TA0004 — Privilege Escalation           |
| Pyramid of Pain   | {Tools \| TTPs}                                                    |
| Hypothesis source | {Intelligence-driven \| Situational awareness \| Domain expertise \| Mixed: X + Y} |
| Author            | {Name}                                                             |
| Version           | {1.0}                                                              |
| Last tested       | {YYYY-MM-DD} against Defender XDR Advanced Hunting                 |
| Status            | {Draft \| Tested \| Production-ready}                              |

---

## 1. Hypothesis statement

### Strategic hypothesis

> {One plain sentence anyone can understand — no API names, table names or technical deep dives.
> Describe the threat logic: what the attacker is trying to do and why that act leaves a trace.}

*Think of this as the answer to "why are we hunting for this?" A non-technical stakeholder
should be able to read it and understand the threat.*

---

### Operational hypothesis

> **If** {adversary behaviour at the API or behavioral level}, **then** {observable signal(s)}
> should appear in {data source(s)}, within {time or sequence constraint}.
>
> This behaviour is durable because {one sentence on why an adversary cannot evade this hunt
> cheaply — what they would have to change to avoid detection}.

*This is the technical layer that drives the query. Name the specific actions, tables, and
timing that make the hunt testable.*

---

### Telemetry

| Table | ActionType/Field | Stage in the chain |
|---|---|---|
| `{TableName}` | `{ActionTypeValue/Field}` | {What this step represents in the attack sequence} |
| `{TableName}` | `{ActionTypeValue/Field}` | {…} |

**Minimum retention required:** {e.g. 7 days for the hunt window. 30 days if baselining first.}

---

### MITRE ATT&CK mapping

| Field | Value |
|---|---|
| Tactic | {TA00XX — Tactic name} |
| Technique | {T1XXX — Technique name} |
| Sub-technique (if available) | {T1XXX.00X — Sub-technique name} |

---

## 2. Data requirements

The telemetry sources and ActionTypes/Fields are listed in the **Telemetry** table in Section 1.
This section adds schema references and any additional retention or collection notes.

**Schema reference:** [Microsoft Learn — Advanced Hunting schema tables](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)

---

## 3. KQL query

```kql
// Hunt T1055.001-H{nn} — {one-line description}
// Hypothesis: {one-line restatement}
// Author: {Name}  |  Version: {1.0}  |  Last tested: {YYYY-MM-DD}

{TableName}
| where Timestamp > ago(7d)                    // hunt window — adjust as needed
| where {primary behavioural filter}           // {comment: what this filter does}
| where {secondary filter}                     // {comment: why}
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    ReportId
| order by Timestamp desc
```

**Query conventions:**
- Time-bounded with `ago()` — safe to run in production without overloading the tenant.
- Every non-obvious filter has a `//` comment explaining intent.
- `| project` returns a triage-friendly column set, not raw `*`.
- Ordered newest-first so fresh activity surfaces immediately.

---

## 4. Expected results and tuning

### 4.1 Expected legitimate causes

{List the benign processes or scenarios most likely to match this query in a real environment.}

- {e.g. Endpoint security products that perform cross-process inspection as part of normal operation}
- {e.g. Debuggers such as Visual Studio or WinDbg}
- {e.g. System monitoring or IT management tooling approved in the environment}

### 4.2 Suggested triage refinements

{Provide guidance for the analyst — not automatic suppression filters. The base query still stays broad and
the analyst refines after seeing results.}

- **If** `InitiatingProcessFileName` belongs to {known category}, verify against the
  environment's allow-list before escalating.
- **If** the activity occurs during {time window / context}, treat as lower priority.
- **If** the initiating process has no corresponding parent in the expected process tree,
  treat as higher priority.

### 4.3 What a true positive looks like

{2–3 sentences describing the shape of malicious activity: unusual parent process, non-admin
user context, off-hours timing, follow-on network activity or unsigned loaded DLL etc.}

### 4.4 Recommended pivots

A **pivot** is a follow-up query that takes a suspicious result from this hunt and looks for
related activity. Run pivots to confirm a suspicion or recover the wider attacker footprint.

- **Pivot 1 —** {e.g. Inspect `DeviceImageLoadEvents` for the target process, look for
  unsigned or unusual-path DLLs loaded within 60 seconds of the thread creation event.}
- **Pivot 2 —** {e.g. Query `DeviceNetworkEvents` for the target process in the 30 minutes
  following the injection, looking for outbound connections to low-prevalence destinations.}
- **Pivot 3 —** {e.g. Check `DeviceProcessEvents` for child processes spawned by the target
  process after the injection, particularly shells or interpreter processes.}

---

## 5. Pyramid of Pain positioning

**Declared level:** {Tools | TTPs}

{One short paragraph defending the declared level. Concretely: what would the adversary have
to change to evade this hunt? If the answer is "rotate a hash or a domain", the entry sits
too low and should be rewritten. If the answer is "stop using the technique entirely", the
entry is at the TTP level.}

---

## 6. References

- **MITRE ATT&CK:** [T1055.001 — DLL Injection](https://attack.mitre.org/techniques/T1055/001/)
- **MITRE procedure examples used:** {List the specific G/S procedure IDs referenced.}
- **Threat intelligence:** {CTI report, CISA advisory, or vendor blog post.}
- **Microsoft schema docs:** {Links to the specific schema pages for each table cited in §3.}
- **Community queries adapted (if any):** {Credit any public query used as a starting point.}
