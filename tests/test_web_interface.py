"""HTTP regression tests without scanner imports or network requests."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from enum import Enum

spec = importlib.util.spec_from_file_location(
    'cortex_web_api_test', Path(__file__).resolve().parents[1] / 'engine/scanner/web_interface.py')
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)


class Mode(Enum):
    SAFE = 'safe'


class FakeScanner:
    def __init__(self, config):
        self.config = config
        self.scan_id = 'initial-internal-id'
        self.report_generator = SimpleNamespace(generate=lambda result, format: '<h1>تقرير</h1>')

    async def scan(self, control=None):
        self.scan_id = 'changed-internal-id'
        return SimpleNamespace(scan_id=self.scan_id)


class WebInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.api = web.ScannerWebInterface(SimpleNamespace(scan_id='old-id'),
                                           FakeScanner, SimpleNamespace, Mode)
        self.client = self.api.create_app().test_client()

    def start_job(self):
        with patch.object(web.threading, 'Thread') as thread:
            response = self.client.post('/scan', json={'target': 'http://127.0.0.1'})
            self.assertEqual(response.status_code, 200)
            target = thread.call_args.kwargs['target']
            args = thread.call_args.kwargs['args']
        return response.json['scan_id'], target, args

    def test_job_tracks_completion_and_real_report_despite_internal_id_change(self):
        job_id, worker, args = self.start_job()
        self.assertNotEqual(job_id, 'old-id')
        self.assertEqual(self.client.get('/status/' + job_id).json,
                         {'status': 'queued', 'progress': 0.0})
        self.assertEqual(self.client.get('/report/' + job_id).status_code, 409)
        with patch.object(web.Path, 'write_text') as write:
            worker(*args)
            self.assertEqual(write.call_args.kwargs['encoding'], 'utf-8')
        self.assertEqual(self.client.get('/status/' + job_id).json,
                         {'status': 'completed', 'progress': 1.0})
        response = self.client.get('/report/' + job_id)
        self.assertEqual(response.mimetype, 'text/html')
        self.assertIn('تقرير', response.get_data(as_text=True))
        self.assertIsNone(web.asyncio._get_running_loop())

    def test_unknown_job(self):
        for path in ('/status/unknown', '/report/unknown'):
            self.assertEqual(self.client.get(path).status_code, 404)

    def test_invalid_requests_do_not_start_worker(self):
        invalid = [None, [], {}, {'target': 'file:///tmp/test'},
                   {'target': 'http://localhost:wrong'},
                   {'target': 'http://localhost', 'mode': 'unknown'},
                   {'target': 'http://localhost', 'max_depth': -1},
                   {'target': 'http://localhost', 'max_concurrency': 0},
                   {'target': 'http://localhost', 'max_concurrency': True},
                   {'target': 'http://localhost', 'max_depth': 1.5}]
        with patch.object(web.threading, 'Thread') as thread:
            for value in invalid:
                with self.subTest(value=value):
                    self.assertEqual(self.client.post('/scan', json=value).status_code, 400)
            thread.assert_not_called()

    def test_failure_is_visible_and_no_report_is_claimed(self):
        job_id, worker, args = self.start_job()
        with patch.object(self.api, '_scanner_factory', side_effect=RuntimeError('test')):
            with self.assertLogs('TitaniumScanner', level='ERROR'):
                worker(*args)
        self.assertEqual(self.client.get('/status/' + job_id).json['status'], 'failed')
        self.assertEqual(self.client.get('/report/' + job_id).status_code, 409)

    def test_jobs_are_independent(self):
        first, worker, args = self.start_job()
        second, _, _ = self.start_job()
        self.assertNotEqual(first, second)
        with patch.object(web.Path, 'write_text'):
            worker(*args)
        self.assertEqual(self.client.get('/status/' + first).json['status'], 'completed')
        self.assertEqual(self.client.get('/status/' + second).json['status'], 'queued')

    def test_app_creation_is_idempotent(self):
        self.assertIs(self.api.create_app(), self.api.app)
        self.assertEqual(self.client.get('/').status_code, 200)

    def test_queued_cancel_does_not_run_scanner_or_create_report(self):
        job, worker, args = self.start_job()
        self.assertEqual(self.client.post('/cancel/' + job).status_code, 202)
        with patch.object(self.api, '_scanner_factory') as factory, patch.object(web.Path, 'write_text') as write:
            worker(*args)
        factory.assert_not_called()
        write.assert_not_called()
        self.assertEqual(self.client.get('/status/' + job).json['status'], 'cancelled')
        self.assertEqual(self.client.get('/report/' + job).status_code, 409)

    def test_api_bounds_concurrency_and_rejects_excess_jobs(self):
        self.start_job()
        self.start_job()
        with patch.object(web.threading, 'Thread') as thread:
            self.assertEqual(self.client.post('/scan', json={'target': 'http://127.0.0.1'}).status_code, 429)
            for extra in ({'max_depth': 11}, {'max_concurrency': 51}):
                self.assertEqual(self.client.post('/scan', json=dict(target='http://127.0.0.1', **extra)).status_code, 400)
        thread.assert_not_called()


if __name__ == '__main__':
    unittest.main()
