"""Bounded static Android manifest review. Never execute an APK."""
from pathlib import Path
import re
import zipfile
import xml.etree.ElementTree as ET


class MobileAPKAuditor:
    MAX_BYTES = 2 * 1024 * 1024
    ANDROID = '{http://schemas.android.com/apk/res/android}'

    def audit_manifest(self, manifest_content):
        if len(manifest_content.encode('utf-8')) > self.MAX_BYTES:
            raise ValueError('Manifest exceeds the 2 MiB review limit')
        if '<!DOCTYPE' in manifest_content.upper() or '<!ENTITY' in manifest_content.upper():
            raise ValueError('DTD/entity declarations are not accepted')
        root = ET.fromstring(manifest_content)
        if root.tag != 'manifest':
            raise ValueError('Expected an Android manifest XML document')
        findings = []
        for node in root:
            if node.tag in ('uses-permission', 'uses-permission-sdk-23'):
                permission = node.get(self.ANDROID + 'name')
                if permission:
                    findings.append(dict(type='DECLARED_PERMISSION', item=permission, severity='INFO',
                        classification='configuration_observation', description='Declared permission; legitimacy depends on app functionality, not proof of malware'))
            if node.tag == 'application':
                for name in ('debuggable', 'usesCleartextTraffic'):
                    if node.get(self.ANDROID + name) == 'true':
                        findings.append(dict(type='MANIFEST_CONFIGURATION', item=name, severity='INFO',
                            classification='configuration_observation', description=f'{name}=true is declared; review release requirements and network policy'))
        return findings

    def audit_input(self, value):
        value = value.strip()
        if not value:
            raise ValueError('Enter manifest XML or a local manifest/APK path')
        if value.startswith('<'):
            content = value
        else:
            path = Path(value.strip('"'))
            if not path.is_file():
                raise ValueError('Local file does not exist')
            if path.suffix.lower() == '.apk':
                with zipfile.ZipFile(path) as archive:
                    info = archive.getinfo('AndroidManifest.xml')
                    if info.file_size > self.MAX_BYTES:
                        raise ValueError('APK manifest exceeds the 2 MiB review limit')
                    with archive.open(info) as handle:
                        raw = handle.read(self.MAX_BYTES + 1)
            else:
                with path.open('rb') as handle:
                    raw = handle.read(self.MAX_BYTES + 1)
            if len(raw) > self.MAX_BYTES:
                raise ValueError('Manifest exceeds the 2 MiB review limit')
            try:
                content = raw.decode('utf-8-sig')
            except UnicodeError as exc:
                raise ValueError('Binary Android manifests are unsupported; export decoded XML first') from exc
            if not content.lstrip().startswith('<'):
                raise ValueError('Binary Android manifests are unsupported; export decoded XML first')
        return self.audit_manifest(content)

    def find_secrets(self, code_content):
        patterns = (r'AIza[0-9A-Za-z_-]{35}', r'sk_live_[0-9a-zA-Z]{24}',
                    r"""(?i)password\s*[:=]\s*['"]([^'"]+)['"]""")
        return [dict(type='POTENTIAL_SECRET_LITERAL', item='[redacted]', severity='INFO',
                     classification='observation', description='Potential literal; validity and use are unverified')
                for pattern in patterns for _ in re.finditer(pattern, code_content[:self.MAX_BYTES])]
