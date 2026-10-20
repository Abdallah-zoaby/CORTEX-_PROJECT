# CORTEX host evidence model

See [PROJECT_REVIEW.md](PROJECT_REVIEW.md) for the current graduation-project scope, privacy boundary, cancellation/history workflow and reproducible synthetic evaluation. Legacy credential-reading and persistence training actions are now synthetic only; automatic web AI submission and guessed CVE assignment are disabled.

CORTEX is a local evidence/review interface, not an independently validated antivirus engine. The expert's review and an isolated, independently labelled evaluation corpus are still needed before making detection-effectiveness claims.

## Assessment categories

| Category | Confidence basis | What it establishes |
| --- | --- | --- |
| `engine_detection` | `engine_reported` | Defender reported a detection. CORTEX preserves the source, threat/detection IDs, threat name, resource, timestamps and action state. This is not an independent confirmation of malware. |
| `corroborated_suspicion` | `corroborated_indicators` | At least two independent moderate behavioral/integrity indicator groups. Requires investigation; never labelled confirmed malware. |
| `observation` / `configuration_observation` | weak/context-only | An unsigned file, writable path, dual-use name, command option, script, listening service or configuration entry alone. No active-threat score. |
| `unknown` | `insufficient_data` | Missing permissions/provider/file, timeout, unsupported response, inspection limit or changed file. Never converted into a clean result. |

Severity and confidence are separate. No confidence percentage is invented. A valid signature is publisher/integrity evidence, not an exemption for suspicious behavior. No filename/publisher allowlist silently clears other evidence.

The old fake malware hashes (including a password hash labelled as WannaCry), IP-prefix C2 labels and entropy-based ransomware verdicts are removed from the host scan. High entropy alone cannot distinguish compression from encryption. Normal software in AppData is not malware on that basis.

## Defender integration

Normal host assessment reads `Get-MpComputerStatus`, `Get-MpThreat` and `Get-MpThreatDetection`. It does **not** start an antivirus scan or change Defender settings.

- Successful cleaned/quarantined/removed/blocked records without required follow-up are shown as remediated, not active.
- Threat-family `IsActive` alone does not make every old resource active. Per-detection action state is retained.
- Historical, allowed, unresolved, failed-remediation and last-known/stale records remain distinguishable.
- Provider failure is explicit, and a failed refresh does not silently convert last-known detections into a current clean state.
- An empty history means no detections reported by that query, not proof that all files were scanned or are safe.
- PUA names are retained as potentially unwanted detections rather than relabelled as confirmed malware.

The **Defender Scan File** button asks the user to select one existing file and acknowledge that Windows policy may remediate/quarantine it and that configured Defender cloud protection may apply. Completion is reported as command completion with fresh evidence; missing detections are not advertised as clean. A timeout is unknown, and Windows may continue scanning after the PowerShell client times out.

Actual per-detection quarantine and supported restore operations are delegated to **Windows Security**. CORTEX no longer deletes files, terminates processes, edits registry values or disables services based on names or heuristic findings. The old auto-remediation entry point now performs evidence review only. No custom quarantine store or unsafe file-restoration mechanism is introduced.

## Local file and process evidence

Evidence includes the full local path, SHA-256 where collected, size/write time, exact Authenticode status, publisher/thumbprint, PID and observed parent PID/name/path, sampled command line, collection time, signals and recommended next action. Metadata is not a malware scan.

Paths are passed as JSON in a subprocess environment, never interpolated into PowerShell source. The fixed Windows PowerShell executable and its own system module directory are used; an inherited Core/user module path cannot shadow the security cmdlet. No execution-policy bypass or shell interpolation is used.

Files are read in chunks; file identity, size and write time are compared before opening and afterward. Windows Python's `stat`/`fstat` legacy creation-time discrepancy is handled without dropping identity/write-time checks. Changes invalidate the hash/signature result. Cache entries are per assessment and keyed by path and file identity/stat metadata; they are not persistent allowlists.

Default limits are explicit: process executable observations plus at most 15 candidate files in each listed Desktop/Documents/Roaming/Temp location; a 90-second content-inspection budget and 256 MiB per-file hashing limit. Signature calls have their own timeout. Oversized files can retain signature metadata while SHA-256 remains unknown. This is **not a full-volume antivirus scan**, and skipped/unavailable data is reported in coverage.

## Interface and reports

The Forensics tab provides filters for engine detections, corroborated suspicion, observations, unknowns and history; selecting a row shows its full local evidence. Shared JSON/PDF outputs preserve coverage and classifications while omitting command lines, raw response evidence and known secret patterns. Personal data outside those patterns may remain; review exports before sharing.

The PDF contains both host and web findings, confidence/classification and coverage; literal file/command content is escaped as text. Context-only and historical records do not inflate active-threat Analytics. Unknown provider state does not produce a host clearance index. Synthetic visuals and training demos are labelled as simulations. AI explanations are optional, do not run automatically after host assessment and cannot rewrite the evidence classifications.

CORTEX does not upload local file bytes. Explicit AI explanation uses the application's configured provider; Defender follows the user's own Windows/cloud settings. Signed files and Defender detections can still have false negatives/positives.

## Validation and independent review

The automated suite covers benign fixtures, writable locations, unsigned files, duplicate observations, known incorrect legacy hashes, compressed-looking bytes, generic IP prefixes, correlated indicators, changed files, cache invalidation, permission/provider/parse/timeout failures, signature command loading, active/history/remediation/follow-up Defender cases, consent gating, safe legacy action behavior, actual GUI filtering/details/export, PDF content and the existing HTTP/browser/scanner tests. Live Windows verification is read-only; tests never execute live malware or trigger real remediation.

These are regression/policy checks, **not measured real-world detection rates**. The security reviewer should independently label a benign software corpus and a lawfully sourced malware corpus in an isolated disposable lab, record false-positive/negative rates and unknown/coverage rates, inspect policy/source correctness and test native Defender quarantine/restore on authorized disposable targets. Do not add live malware to this repository or normal CI.

References:

- [Get-MpThreatDetection](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpthreatdetection)
- [Defender detection status fields](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpthreatdetection)
- [Get-MpComputerStatus](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus)
- [Start-MpScan](https://learn.microsoft.com/en-us/powershell/module/defender/start-mpscan)
- [Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature)
