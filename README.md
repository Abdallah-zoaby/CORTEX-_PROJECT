# CORTEX

A local security evidence and review platform, authorized web assessment tool and separate synthetic training environment. CORTEX does not certify compliance, replace antivirus software or guarantee a clean device.

## Run locally on Windows

Use Python 3.11 or 3.12 in a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m playwright install chromium
python gui_main.py
```

Host evidence uses Windows security providers; missing permissions or unavailable Defender data remain unknown. The host assessment reads metadata and bounded file samples; it is not a full-volume antivirus scan. AI is optional and the desktop previews aggregate data before sending it. No key is needed for local evidence review.

Optional AI explanations require both `TITANIUM_AI_KEY` and `TITANIUM_AI_MODEL` in the launch environment, then an app restart. Choose a model available to your provider account; CORTEX does not verify remote model availability until a consented request. Encryption keys are never used as provider credentials. The existing Google SDK is deprecated; provider compatibility and live API access are not covered by offline tests.

## Additional pages and honest coverage

- **Mobile & API:** manifest review reads the supplied XML text/file, or an APK containing a text XML manifest, up to 2 MiB. Compiled binary Android manifests require external decoding first; unsupported inputs show an explicit error. Permissions are configuration observations, not malware findings. The API action sends only two authorized, unauthenticated GET probes without following redirects. It does not establish IDOR, authenticate accounts, guess passwords, or inject a synthetic JWT result.
- **Enterprise Hub:** records process/startup/port/hosts/task inventory. Unavailable providers are shown separately. Packet capture is optional, requires Scapy and a supported capture driver, and never substitutes synthetic traffic when unavailable. Capture summaries do not prove attacks. SIEM JSON exports collected records across the reviewed pages with separate observation, unknown and active-engine counts.
- **War Room:** clearly labelled scripted training; the graph is illustrative and static. Each run resets the timeline and training score. Neither the exercise nor replay performs real isolation, firewall changes or attacks. The separate synthetic twin binds only loopback and reports port conflicts.
- **Intelligence:** fictional global events are labelled simulation; published advisories are separate and do not describe threats detected on this device. No configured reputation provider means `UNKNOWN`, never a verdict based on IP prefixes.
- **Scores:** incomplete/unassessed sources suppress the overall index. A displayed index still summarizes bounded findings, not the probability that a device is safe.

Old SQLite scanner databases are upgraded additively for missing release columns. A timestamped `*.pre-upgrade-*.db` backup is saved beside an existing database before the schema is changed. Existing records are retained; a failed backup prevents the upgrade.

## Review and validate

- [Project scope, architecture, privacy, history and evaluation](PROJECT_REVIEW.md)
- [Detection classifications and limitations](DETECTION_MODEL.md)
- Run `python -m unittest discover -s tests -p "test_*.py" -v` after installing the CI test dependencies `flake8 pytest pypdf`.
- Run `python -m evaluation.run --output output/evaluation/policy.json` for a reproducible synthetic policy replay. This is not a real-world malware benchmark.
- Desktop **SCAN HISTORY** reviews sanitized local snapshots and compares matching scopes. **CANCEL ASSESSMENT** requests cooperative cancellation.

Web scans are restricted to the configured origin and implemented checks. Only test targets you own or are explicitly authorized to assess. The local HTTP API supports `POST /scan`, `GET /status/<id>`, `GET /report/<id>` and `POST /cancel/<id>`. Keep it on loopback; it is not an authenticated public service. Native Windows Security handles real remediation; training buttons do not collect credentials or change startup settings.
