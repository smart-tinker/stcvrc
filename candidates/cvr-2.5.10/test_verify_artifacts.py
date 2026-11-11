import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature


SCRIPT = Path(__file__).with_name('verify-artifacts.py')


def sha(data):
    return hashlib.sha256(data).hexdigest()


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public = b'Ed' + b'test-key' + public
        encoded_key = base64.b64encode(b'untrusted comment: fixture\n' + base64.b64encode(self.public) + b'\n').decode()
        self.manifest = {'schemaVersion': 1, 'repository': 'clash-verge-rev/clash-verge-rev',
                         'publicKeyBase64': encoded_key, 'releases': []}
        for number, version in enumerate(('2.5.8', '2.5.10'), 10):
            installer = b'MZ fixture installer ' + version.encode()
            signature = self.sign(installer)
            url = f'https://api.github.com/repos/clash-verge-rev/clash-verge-rev/releases/assets/{number * 10}'
            updater = {'version': 'v' + version, 'platforms': {
                p: {'signature': signature, 'url': url} for p in ('windows-x86_64', 'windows-x86_64-nsis')}}
            config = {'version': version, 'plugins': {'updater': {'pubkey': encoded_key}}}
            config_file = f'tauri-v{version}.conf.json'
            config_data = json.dumps(config).encode()
            (self.root / config_file).write_bytes(config_data)
            release = {'version': version, 'tag': 'v' + version, 'releaseId': number,
                       'sourceCommit': 'a' * 40, 'metadataFile': f'cvr-v{version}-release.json',
                       'config': {'file': config_file, 'sha256': sha(config_data), 'sourceURL': 'https://example.test/config'},
                       'assets': {}}
            payloads = {'installer': (f'Clash.Verge_{version}_x64-setup.exe', installer),
                        'signature': (f'Clash.Verge_{version}_x64-setup.exe.sig', (signature + '\n').encode()),
                        'latest': ('latest.json', json.dumps(updater).encode())}
            metadata = {'id': number, 'tag_name': 'v' + version, 'assets': []}
            for offset, (role, (name, data)) in enumerate(payloads.items()):
                filename = f'latest-v{version}.json' if role == 'latest' else name
                (self.root / filename).write_bytes(data)
                asset = {'file': filename, 'id': number * 10 + offset, 'name': name,
                         'size': len(data), 'sha256': sha(data),
                         'url': f'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v{version}/{name}'}
                release['assets'][role] = asset
                metadata['assets'].append({k: asset[k] for k in ('id', 'name', 'size')} |
                                          {'digest': 'sha256:' + asset['sha256'], 'browser_download_url': asset['url']})
            self.write_json(release['metadataFile'], metadata)
            self.manifest['releases'].append(release)
        self.core = self.root / 'core.exe'
        self.core.write_bytes(b'MZ custom core fixture')
        self.manifest['core'] = {'sourceCommit': 'b' * 40, 'upstreamCommit': 'c' * 40,
                                 'version': 'fixture', 'size': self.core.stat().st_size, 'sha256': sha(self.core.read_bytes())}
        self.manifest_path = self.root / 'inputs.json'
        self.manifest_path.write_text(json.dumps(self.manifest))

    def sign(self, data, key_id=b'test-key', comment='fixture trusted comment'):
        signature = self.key.sign(hashlib.blake2b(data, digest_size=64).digest())
        packet = b'ED' + key_id + signature
        global_signature = self.key.sign(signature + comment.encode())
        return base64.b64encode(b'untrusted comment: fixture\n' + base64.b64encode(packet) +
                                b'\ntrusted comment: ' + comment.encode() + b'\n' +
                                base64.b64encode(global_signature) + b'\n').decode()

    def write_json(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def module(self):
        self.assertTrue(SCRIPT.is_file(), 'Offline verifier has not been implemented')
        spec = importlib.util.spec_from_file_location('cvr_verify', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_complete_pair_and_core_through_cli(self):
        module = self.module()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = module.main(['--artifacts', str(self.root), '--core', str(self.core)], manifest_path=self.manifest_path)
        self.assertEqual(code, 0)
        receipt = json.loads(output.getvalue())
        self.assertEqual([r['version'] for r in receipt['releases']], ['2.5.8', '2.5.10'])
        self.assertEqual(receipt['core']['sha256'], sha(self.core.read_bytes()))
        self.assertEqual(receipt['inputsSha256'], sha(self.manifest_path.read_bytes()))
        self.assertEqual(receipt['extractedPayloads'], 'NOT_VERIFIED')
        self.assertEqual(receipt['nativeAcceptance'], 'NOT_RUN')
        for release in receipt['releases']:
            self.assertTrue(release['trustedCommentVerified'])
            self.assertEqual(len(release['negativeControlsPassed']), 3)
        self.assertNotIn(str(self.root), output.getvalue())

    def repin(self, role, data):
        release = self.manifest['releases'][0]
        asset = release['assets'][role]
        (self.root / asset['file']).write_bytes(data)
        asset.update(size=len(data), sha256=sha(data))
        metadata = json.loads((self.root / release['metadataFile']).read_bytes())
        item = next(a for a in metadata['assets'] if a['id'] == asset['id'])
        item.update(size=len(data), digest='sha256:' + sha(data))
        self.write_json(release['metadataFile'], metadata)

    def assert_rejected(self):
        with self.assertRaises((ValueError, InvalidSignature, KeyError, TypeError)):
            self.module().verify(self.root, self.core, self.manifest)

    def test_byte_substitution_and_signed_digest_change_are_rejected(self):
        asset = self.manifest['releases'][0]['assets']['installer']
        changed = (self.root / asset['file']).read_bytes() + b'!'
        (self.root / asset['file']).write_bytes(changed)
        self.assert_rejected()
        self.repin('installer', changed)
        self.assert_rejected()  # Even a matching metadata digest cannot repair a broken signature.

    def test_bad_signature_packets_and_trusted_comment_are_rejected(self):
        asset = self.manifest['releases'][0]['assets']['signature']
        original = (self.root / asset['file']).read_text().strip()
        lines = base64.b64decode(original).decode().splitlines()
        packet = base64.b64decode(lines[1])
        cases = [b'Ed' + packet[2:], packet[:2] + b'bad-key!' + packet[10:], packet[:-1]]
        variants = []
        for bad in cases:
            changed = lines.copy()
            changed[1] = base64.b64encode(bad).decode()
            variants.append(base64.b64encode(('\n'.join(changed) + '\n').encode()))
        changed = lines.copy()
        changed[2] += '!'
        variants.extend([base64.b64encode(('\n'.join(changed) + '\n').encode()), b'not-base64!', b''])
        for data in variants:
            with self.subTest(data=data[:20]):
                self.repin('signature', data)
                updater = json.loads((self.root / self.manifest['releases'][0]['assets']['latest']['file']).read_bytes())
                for platform in ('windows-x86_64', 'windows-x86_64-nsis'):
                    updater['platforms'][platform]['signature'] = data.decode()
                self.repin('latest', json.dumps(updater).encode())
                self.assert_rejected()

    def test_wrong_signing_key_is_rejected_even_when_config_agrees(self):
        new = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
        raw = new.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        encoded = base64.b64encode(b'untrusted comment: other\n' + base64.b64encode(self.public[:10] + raw) + b'\n').decode()
        self.manifest['publicKeyBase64'] = encoded
        for release in self.manifest['releases']:
            p = self.root / release['config']['file']
            config = json.loads(p.read_bytes())
            config['plugins']['updater']['pubkey'] = encoded
            p.write_text(json.dumps(config))
            release['config']['sha256'] = sha(p.read_bytes())
        self.assert_rejected()

    def test_release_and_asset_metadata_substitutions_are_rejected(self):
        filename = self.manifest['releases'][0]['metadataFile']
        original = json.loads((self.root / filename).read_bytes())
        for field, wrong in [('id', -1), ('tag_name', 'v2.5.9')]:
            changed = copy.deepcopy(original)
            changed[field] = wrong
            self.write_json(filename, changed)
            with self.subTest(field=field):
                self.assert_rejected()
        for field, wrong in [('id', -1), ('name', 'other.exe'), ('size', 0),
                             ('digest', 'sha256:' + '0' * 64), ('browser_download_url', 'https://example.test/other')]:
            changed = copy.deepcopy(original)
            changed['assets'][0][field] = wrong
            self.write_json(filename, changed)
            with self.subTest(asset_field=field):
                self.assert_rejected()
        for assets in [original['assets'][1:], original['assets'] + [original['assets'][0]]]:
            self.write_json(filename, original | {'assets': assets})
            self.assert_rejected()

    def test_config_hash_version_and_key_are_independent_checks(self):
        config_pin = self.manifest['releases'][0]['config']
        path = self.root / config_pin['file']
        original = path.read_bytes()
        path.write_bytes(original + b' ')
        self.assert_rejected()
        for field in ('version', 'key'):
            changed = json.loads(original)
            if field == 'version':
                changed['version'] = '2.5.9'
            else:
                changed['plugins']['updater']['pubkey'] = 'other'
            path.write_text(json.dumps(changed))
            config_pin['sha256'] = sha(path.read_bytes())
            self.assert_rejected()

    def test_each_windows_updater_entry_rejects_signature_and_url_changes(self):
        asset = self.manifest['releases'][0]['assets']['latest']
        original = json.loads((self.root / asset['file']).read_bytes())
        for platform in ('windows-x86_64', 'windows-x86_64-nsis'):
            for field in ('signature', 'url'):
                changed = copy.deepcopy(original)
                changed['platforms'][platform][field] = 'other'
                self.repin('latest', json.dumps(changed).encode())
                with self.subTest(platform=platform, field=field):
                    self.assert_rejected()
        self.repin('latest', json.dumps(original | {'version': 'v0.0.0'}).encode())
        self.assert_rejected()

    def test_changed_core_and_cross_version_inputs_are_rejected(self):
        original = self.core.read_bytes()
        self.core.write_bytes(original + b'!')
        self.assert_rejected()
        self.core.write_bytes(original)
        self.manifest['releases'].reverse()
        self.assert_rejected()

    def test_missing_and_malformed_inputs_exit_without_success_receipt(self):
        module = self.module()
        filename = self.manifest['releases'][0]['metadataFile']
        for data in (None, b'{', b'[]', b'null'):
            path = self.root / filename
            if data is None:
                path.unlink()
            else:
                path.write_bytes(data)
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = module.main(['--artifacts', str(self.root), '--core', str(self.core)], manifest_path=self.manifest_path)
            self.assertEqual(code, 1)
            self.assertEqual(stdout.getvalue(), '')
            self.assertIn('Verification failed:', stderr.getvalue())

    def test_manifest_cannot_open_paths_outside_public_directory(self):
        self.manifest['releases'][0]['metadataFile'] = '../private.json'
        self.assert_rejected()

    def test_fresh_core_hash_without_precomputed_size_is_bound(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['core'].pop('size')
        module = self.module()
        receipt = module.verify(self.root, self.core, manifest)
        self.assertEqual(receipt['core']['size'], self.core.stat().st_size)
        original = self.core.read_bytes()
        self.core.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'custom core SHA256 mismatch'):
            module.verify(self.root, self.core, manifest)


class CandidateSourceContractTests(unittest.TestCase):
    def test_core_is_pinned_to_fresh_mit_lzo_candidate(self):
        manifest = json.loads((SCRIPT.with_name('inputs.json')).read_text(encoding='utf-8'))
        core = manifest['core']
        self.assertEqual(core['sourceCommit'], '086a62c3ce9a77f650786ae2eae92b68909d49e1')
        self.assertEqual(core['upstreamCommit'], '3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8')
        self.assertEqual(core['version'], '1.19.33-STCVRC-candidate-mit-lzo-20261111')
        self.assertEqual(core['buildTime'], '2026-11-11T00:00:00Z')
        self.assertEqual(core['goVersion'], '1.26.11')
        self.assertEqual(core['goArchiveSha256'], '9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec')
        self.assertEqual(core['target'], 'windows/amd64')
        self.assertEqual(core['tags'], ['with_gvisor'])
        self.assertEqual(core['sha256'], 'd72784d98a44b90e561c701589c50f53074958d7cef656607ee5be1143b36c87')
        self.assertNotIn('size', core)


    def test_release_pair_pins_2_5_8_recovery_and_2_5_10_update(self):
        manifest = json.loads(SCRIPT.with_name('inputs.json').read_text(encoding='utf-8'))
        self.assertEqual([release['version'] for release in manifest['releases']], ['2.5.8', '2.5.10'])


class WindowsPayloadWorkflowContractTests(unittest.TestCase):
    def test_windows_payload_job_is_pinned_and_never_executes_the_installer(self):
        workflow = (SCRIPT.parents[2] / '.github' / 'workflows' / 'test.yml').read_text(encoding='utf-8')
        self.assertIn('  cvr-windows-payload:\n', workflow)
        block = workflow.split('  cvr-windows-payload:\n', 1)[1].split('  assemble-draft-rc:\n', 1)[0]
        self.assertIn('runs-on: windows-2022', block)
        self.assertIn('needs: cvr-2-5-10-package', block)
        self.assertIn('7z.exe', block)
        self.assertIn('Get-FileHash', block)
        self.assertIn('2.5.8', block)
        self.assertIn('2.5.10', block)
        self.assertNotRegex(block, r'(?im)^\s*Start-Process\b')
        self.assertNotRegex(block, r'(?im)^\s*&\s*\$installer\b')
        self.assertNotIn('actions/upload-artifact', block)
        self.assertNotIn('actions/cache', block)


    def test_windows_job_executes_and_identifies_only_the_fresh_custom_core(self):
        workflow = (SCRIPT.parents[2] / '.github' / 'workflows' / 'test.yml').read_text(encoding='utf-8')
        block = workflow.split('  cvr-windows-payload:\n', 1)[1].split('  assemble-draft-rc:\n', 1)[0]
        self.assertIn('$coreVersionOutput = & $stockCore -v 2>&1', block)
        self.assertIn('if ($coreExit -ne 0)', block)
        self.assertIn('$buildTimeText = ([DateTime]$manifest.core.buildTime).ToUniversalTime()', block)
        self.assertIn('ToString("yyyy-MM-ddTHH:mm:ss', block)
        self.assertIn('$expectedCoreVersion = "Mihomo Meta $($manifest.core.version) windows amd64 with go$($manifest.core.goVersion) $buildTimeText"', block)
        self.assertIn('StartsWith($expectedCoreVersion', block)
        self.assertIn('Native core process smoke passed', block)
        self.assertLess(block.index('if ($stagedHash -ne $manifest.core.sha256)'), block.index('$coreVersionOutput = & $stockCore -v 2>&1'))


    def test_draft_rc_assembly_waits_for_windows_payload(self):
        workflow = (SCRIPT.parents[2] / '.github' / 'workflows' / 'test.yml').read_text(encoding='utf-8')
        assembly = workflow.split('  assemble-draft-rc:\n', 1)[1]
        needs = assembly.split('    needs:\n', 1)[1].split('    runs-on:', 1)[0]
        self.assertIn('      - cvr-windows-payload\n', needs)


class DraftRCAssemblyGateTests(unittest.TestCase):
    def test_draft_rc_assembly_is_manual_on_main(self):
        workflow = (SCRIPT.parents[2] / '.github' / 'workflows' / 'test.yml').read_text(encoding='utf-8')
        assembly = workflow.split('  assemble-draft-rc:\n', 1)[1]
        condition = assembly.split('    needs:\n', 1)[0]
        self.assertIn("github.event_name == 'workflow_dispatch'", condition)
        self.assertIn("github.ref == 'refs/heads/main'", condition)


if __name__ == '__main__':
    unittest.main()
