"""Bounded endpoint observations; no inferred authentication bypass."""
import base64
import json
from urllib.parse import urlsplit
import requests


class APIAuditor:
    def __init__(self, base_url):
        parts = urlsplit(base_url.strip())
        if (parts.scheme not in ('http', 'https') or not parts.hostname
                or parts.username or parts.password or parts.query or parts.fragment):
            raise ValueError('Use an HTTP(S) URL without credentials, query or fragment')
        _ = parts.port
        self.base_url = base_url.strip().rstrip('/')

    def _observe(self, endpoint):
        if not endpoint.startswith('/') or endpoint.startswith('//'):
            raise ValueError('Endpoint must be a relative path')
        url = self.base_url + endpoint
        record = dict(type='API_ENDPOINT_OBSERVATION', source='HTTP endpoint probe',
                      url=url, item=endpoint, severity='INFO', classification='observation',
                      limitations='No authenticated comparison or resource ownership baseline; cannot establish IDOR or broken authentication')
        try:
            with requests.get(url, timeout=(3, 5), allow_redirects=False, stream=True) as response:
                record['status_code'] = response.status_code
                record['description'] = f'Unauthenticated GET returned HTTP {response.status_code}; authorization policy was not assessed'
        except requests.RequestException as exc:
            record.update(classification='unknown', description=f'Endpoint unavailable ({type(exc).__name__}); not a clean result')
        return record

    def test_broken_auth(self, endpoint):
        return self._observe(endpoint)

    def test_idor(self, endpoint, param_name, current_val, target_val):
        endpoint = '/'.join(str(target_val) if s == str(current_val) else s for s in endpoint.split('/'))
        return self._observe(endpoint)

    def test_login_brute(self, endpoint, username):
        return dict(type='AUTH_TEST_NOT_PERFORMED', classification='unknown', severity='INFO',
                    item=endpoint, description='Password guessing is not part of endpoint review')

    def test_jwt_weak_signature(self, token):
        """Inspect supplied header only; never infer server verification."""
        try:
            if len(token) > 16384 or len(token.split('.')) != 3:
                raise ValueError('Invalid JWT structure')
            encoded = token.split('.')[0]
            header = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
            algorithm = header.get('alg')
            if not isinstance(algorithm, str):
                raise ValueError('Missing algorithm')
            return dict(type='JWT_HEADER_OBSERVATION', severity='INFO', classification='observation',
                        item='JWT header', description=f'Declared algorithm: {algorithm}. Server acceptance and verification were not tested')
        except (ValueError, TypeError, AttributeError, UnicodeError):
            return dict(type='JWT_PARSE_UNKNOWN', severity='INFO', classification='unknown',
                        item='JWT header', description='Header could not be parsed; no validation result')

    def audit_full(self):
        return [self._observe('/api/config'), self._observe('/api/user/0')]
