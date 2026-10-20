"""Windows security queries. Untrusted paths are data, never PowerShell source."""
import base64
import json
import os
import subprocess


class SecurityQueryError(RuntimeError):
    pass


def powershell_json(script, payload=None, timeout=30):
    if os.name != 'nt':
        raise SecurityQueryError('Windows security provider is unavailable on this platform')
    prefix = ("$ErrorActionPreference='Stop'; $WarningPreference='SilentlyContinue'; "
              "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); ")
    encoded = base64.b64encode((prefix + script).encode('utf-16le')).decode('ascii')
    env = dict(os.environ)
    # A PowerShell 7 parent can export a module path incompatible with Windows PS 5.1.
    # Let the Windows executable construct its own built-in module search path.
    for key in list(env):
        if key.upper() == 'PSMODULEPATH':
            env.pop(key)
    windows_ps = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                              'System32', 'WindowsPowerShell', 'v1.0')
    # Security cmdlets must come from the Windows installation, not a shadowing
    # PowerShell Core/user module left in the parent process environment.
    env['PSModulePath'] = os.path.join(windows_ps, 'Modules')
    env['CORTEX_SECURITY_INPUT'] = json.dumps(payload, ensure_ascii=True)
    try:
        result = subprocess.run(
            [os.path.join(windows_ps, 'powershell.exe'), '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
            capture_output=True, encoding='utf-8', errors='replace', timeout=timeout,
            env=env, creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired as exc:
        raise SecurityQueryError('Security query timed out; result is unknown') from exc
    except OSError as exc:
        raise SecurityQueryError('Security provider could not be started') from exc
    if result.returncode:
        raise SecurityQueryError('Security provider denied or failed the query; result is unknown')
    try:
        return json.loads(result.stdout.lstrip('\ufeff').strip())
    except (ValueError, TypeError) as exc:
        raise SecurityQueryError('Security provider returned an invalid response') from exc


SIGNATURE_SCRIPT = r'''
$paths = ConvertFrom-Json $env:CORTEX_SECURITY_INPUT
$records = @(foreach ($path in $paths) {
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        [pscustomobject]@{path=$path; status=[string]$s.Status;
            publisher=$s.SignerCertificate.Subject; thumbprint=$s.SignerCertificate.Thumbprint}
    } catch {
        [pscustomobject]@{path=$path; status='Unavailable'; publisher=$null; thumbprint=$null}
    }
})
ConvertTo-Json -InputObject $records -Depth 5 -Compress
'''


def signatures(paths, runner=powershell_json):
    paths = list(dict.fromkeys(str(p) for p in paths))
    if not paths:
        return {}
    try:
        records = runner(SIGNATURE_SCRIPT, paths, timeout=60)
        if not isinstance(records, list):
            raise SecurityQueryError('Invalid signature list')
        allowed = {'Valid', 'NotSigned', 'HashMismatch', 'NotTrusted', 'UnknownError',
                   'NotSupportedFileFormat', 'Incompatible', 'Unavailable'}
        by_path = {os.path.normcase(r['path']): r for r in records
                   if isinstance(r, dict) and isinstance(r.get('path'), str)}
        output = {}
        for path in paths:
            record = by_path.get(os.path.normcase(path), {})
            status = record.get('status', 'Unavailable')
            output[os.path.normcase(path)] = {
                'status': status if isinstance(status, str) and status in allowed else 'Unavailable',
                'publisher': record.get('publisher') if isinstance(record.get('publisher'), str) else None,
                'thumbprint': record.get('thumbprint') if isinstance(record.get('thumbprint'), str) else None,
            }
        return output
    except SecurityQueryError:
        return {os.path.normcase(path): {'status': 'Unavailable', 'publisher': None,
                                        'thumbprint': None} for path in paths}
