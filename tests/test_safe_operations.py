"""Exercise privileged paths with synthetic files and mocked OS interfaces."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


class SafeOperationsTests(unittest.TestCase):
    def test_remediation_preserves_even_suspiciously_named_files(self):
        from core.remediation import CortexFixer
        with tempfile.TemporaryDirectory(prefix='cortex-remediation-') as folder:
            root = Path(folder)
            docs = root / 'Documents'
            docs.mkdir()
            canary = docs / 'Cortex_Canary_test.txt'
            locked = docs / 'sample.cortex_locked'
            keep = docs / 'keep.txt'
            for path in (canary, locked, keep):
                path.write_text('synthetic test data', encoding='utf-8')
            with patch('core.remediation.os.path.expanduser', return_value=str(root)), \
                    patch.dict(os.environ, {'APPDATA': str(root)}):
                CortexFixer().remove_malicious_files()
            self.assertTrue(canary.exists())
            self.assertTrue(locked.exists())
            self.assertEqual(keep.read_text(encoding='utf-8'), 'synthetic test data')

    def test_process_remediation_preserves_unmatched_process(self):
        from core.remediation import CortexFixer
        bad, good = Mock(), Mock()
        bad.info, good.info = {'name': 'xmrig.exe'}, {'name': 'safe.exe'}
        with patch('psutil.process_iter', return_value=[bad, good]):
            CortexFixer().kill_bad_processes()
        bad.kill.assert_not_called()
        good.kill.assert_not_called()

    def test_service_commands_do_not_execute_on_host(self):
        from core.remediation import CortexFixer
        with patch('subprocess.run') as run:
            CortexFixer().harden_windows_services()
        run.assert_not_called()

    def test_training_modules_never_access_registry_files_or_credentials(self):
        from simulation.persist import PersistenceSim
        from simulation.leak import DataLeakSim
        from simulation.ransom import RansomSim
        with patch('winreg.OpenKey') as registry, patch('subprocess.check_output') as command, \
                patch('builtins.open') as opened:
            results = (PersistenceSim().attempt_persistence(), DataLeakSim().run_simulation(), RansomSim().execute_encryption())
        registry.assert_not_called()
        command.assert_not_called()
        opened.assert_not_called()
        self.assertTrue(all('[SIMULATION' in result for result in results))

    def test_model_helper_requires_local_key_without_network(self):
        import check_models
        with patch.dict(os.environ):
            os.environ.pop('TITANIUM_AI_KEY', None)
            self.assertEqual(check_models.main(), 1)


if __name__ == '__main__':
    unittest.main()
