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

## Review and validate

- [Project scope, architecture, privacy, history and evaluation](PROJECT_REVIEW.md)
- [Detection classifications and limitations](DETECTION_MODEL.md)
- Run `python -m unittest discover -s tests -p "test_*.py" -v` after installing the CI test dependencies `flake8 pytest pypdf`.
- Run `python -m evaluation.run --output output/evaluation/policy.json` for a reproducible synthetic policy replay. This is not a real-world malware benchmark.
- Desktop **SCAN HISTORY** reviews sanitized local snapshots and compares matching scopes. **CANCEL ASSESSMENT** requests cooperative cancellation.

Web scans are restricted to the configured origin and implemented checks. Only test targets you own or are explicitly authorized to assess. The local HTTP API supports `POST /scan`, `GET /status/<id>`, `GET /report/<id>` and `POST /cancel/<id>`. Keep it on loopback; it is not an authenticated public service. Native Windows Security handles real remediation; training buttons do not collect credentials or change startup settings.
