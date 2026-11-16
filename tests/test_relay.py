#!/usr/bin/env python3
"""Offline contract tests; creates disposable test keys, never contacts GitHub."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import relay
import notify


class RelayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.key = cls.root / 'recipient.key'
        cls.cert = cls.root / 'recipient.pem'
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=offline-relay-test', '-keyout', str(cls.key), '-out', str(cls.cert),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.payload = {
            'request_id': 'a' * 32, 'source_sha': 'b' * 40, 'abi': 'arm64-v8a',
            'certificate': cls.cert.read_text(),
            'certificate_sha256': hashlib.sha256(cls.cert.read_bytes()).hexdigest(),
            'parent_run_id': '123', 'parent_run_attempt': '2', 'version': '1.2.0', 'build_number': '16',
        }

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_exact_schema_and_certificate(self):
        self.assertEqual(relay.validate_payload(self.payload), self.payload)
        for change in (
            {'unexpected': 'x'}, {'certificate_sha256': '0' * 64}, {'abi': 'invalid'},
            {'parent_run_attempt': 2}, {'request_id': 'x\ninjected=true'},
            {'certificate': self.payload['certificate'] + self.payload['certificate']},
        ):
            with self.subTest(change=list(change)):
                with self.assertRaises(ValueError):
                    relay.validate_payload(dict(self.payload, **change))

    def test_cms_authenticated_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            request = temp / 'request.json'
            request.write_text(json.dumps(self.payload))
            apk = temp / 'input.apk'
            apk.write_bytes(b'APK signing input\x00\xff' * 100)
            output = temp / 'output'
            with patch.dict(os.environ, RELAY_REQUEST=str(request), RELAY_OUTPUT=str(output), RUNNER_TEMP=str(temp)):
                relay.encrypt(apk)
            self.assertEqual({p.name for p in output.iterdir()}, {'payload.cms', 'callback.json'})
            cms = output / 'payload.cms'
            printed = relay.command(['openssl', 'cms', '-cmsout', '-print', '-inform', 'DER', '-in', str(cms)])
            self.assertIn(b'id-smime-ct-authEnvelopedData', printed)
            self.assertIn(b'aes-256-gcm', printed)
            self.assertIn(b'rsaesOaep', printed)
            clear = relay.command([
                'openssl', 'cms', '-decrypt', '-binary', '-inform', 'DER', '-in', str(cms),
                '-recip', str(self.cert), '-inkey', str(self.key),
            ])
            with zipfile.ZipFile(io.BytesIO(clear)) as archive:
                self.assertEqual(archive.namelist(), ['app-release.apk', 'metadata.json'])
                self.assertEqual(archive.read('app-release.apk'), apk.read_bytes())
                metadata = json.loads(archive.read('metadata.json'))
            expected = {k: v for k, v in self.payload.items() if k != 'certificate'}
            expected.update(apk_sha256=hashlib.sha256(apk.read_bytes()).hexdigest(), bytes=apk.stat().st_size)
            self.assertEqual(metadata, expected)
            damaged = bytearray(cms.read_bytes())
            damaged[-1] ^= 1
            bad = temp / 'bad.cms'
            bad.write_bytes(damaged)
            result = subprocess.run([
                'openssl', 'cms', '-decrypt', '-binary', '-inform', 'DER', '-in', str(bad),
                '-recip', str(self.cert), '-inkey', str(self.key),
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertNotEqual(result.returncode, 0, 'GCM corruption must fail authentication')
            self.assertEqual(set(json.loads((output / 'callback.json').read_bytes())), notify.CALLBACK_KEYS)

    def test_callback_untrusted_zip_and_title(self):
        callback = {k: self.payload[k] for k in notify.CALLBACK_KEYS}
        def bundle(names):
            data = io.BytesIO()
            with zipfile.ZipFile(data, 'w') as archive:
                for name in names:
                    archive.writestr(name, json.dumps(callback) if name.endswith('callback.json') else b'CMS')
            return data.getvalue()
        self.assertEqual(notify.callback_from_archive(bundle(['payload.cms', 'callback.json'])), callback)
        for names in (['payload.cms', '../callback.json'], ['payload.cms', 'callback.json', 'extra.py']):
            with self.assertRaises(ValueError):
                notify.callback_from_archive(bundle(names))
        with self.assertRaises(ValueError):
            notify.validate_callback(dict(callback, token='forbidden'))
        with self.assertRaises(ValueError):
            notify.decode_json('{"request_id":"a","request_id":"b"}')
        run = {
            'id': 456, 'status': 'completed', 'conclusion': 'success', 'event': 'repository_dispatch',
            'head_branch': 'main', 'head_repository': {'full_name': notify.REPOSITORY},
            'repository': {'full_name': notify.REPOSITORY}, 'name': 'Encrypted personal APK build',
            'path': '.github/workflows/build.yml', 'display_title': 'Relay ' + self.payload['request_id'],
        }
        self.assertEqual(notify.validate_run(run, '456'), self.payload['request_id'])
        for change in ({'display_title': 'Relay wrong'}, {'head_branch': 'other'}, {'event': 'push'}):
            with self.assertRaises(ValueError):
                notify.validate_run(dict(run, **change), '456')

    def test_cross_host_redirect_drops_token(self):
        request = notify.urllib.request.Request('https://api.github.com/artifact', headers={'Authorization': 'Bearer offline-placeholder'})
        redirected = notify.SafeRedirect().redirect_request(
            request, None, 302, 'Found', {}, 'https://artifact.example.invalid/signed.zip')
        self.assertFalse(redirected.has_header('Authorization'))
        with self.assertRaises(ValueError):
            notify.SafeRedirect().redirect_request(request, None, 302, 'Found', {}, 'http://artifact.example.invalid/a')

    def test_request_and_actual_source_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            event = temp / 'event.json'
            event.write_text(json.dumps({'action': 'build-oronbox-personal', 'client_payload': self.payload}))
            request = temp / 'request.json'
            env_file, outputs = temp / 'env', temp / 'outputs'
            source = temp / 'source'
            source.mkdir()
            (source / '.fvmrc').write_text('{"flutter":"3.47.9"}')
            pubspec = source / 'pubspec.yaml'
            pubspec.write_text('name: test\nversion: 1.2.0+16\n')
            (source / 'android/xms-wearable-lib-cleanroom').mkdir(parents=True)
            def git(args, **kwargs):
                if args[-2:] == ['rev-parse', 'HEAD']:
                    return self.payload['source_sha'].encode()
                if 'merge-base' in args:
                    return b''
                if 'config' in args:
                    return b'https://github.com/OrPudding/XMS_Wearable_SDK_CleanRoom.git\n'
                if 'submodule' in args:
                    return b' ' + b'c' * 40 + b' android/xms-wearable-lib-cleanroom (heads/main)\n'
                self.fail('Unexpected source command')
            with patch.dict(os.environ, RELAY_REQUEST=str(request), GITHUB_EVENT_PATH=str(event),
                            GITHUB_EVENT_NAME='repository_dispatch', GITHUB_ENV=str(env_file),
                            GITHUB_OUTPUT=str(outputs), FLUTTER_VERSION='3.47.9', REQUIRE_SOURCE_ON_MAIN='true'):
                relay.validate()
                self.assertEqual(json.loads(request.read_text()), self.payload)
                self.assertIn('PERSONAL_ABI=arm64-v8a\n', env_file.read_text())
                with patch.object(relay, 'command', side_effect=git), patch.object(relay, 'read_request', return_value=self.payload):
                    relay.verify_source(source)
                    pubspec.write_text('version: 1.2.0+17\n')
                    with self.assertRaises(ValueError):
                        relay.verify_source(source)

    def test_pat_dispatch_exact_four_inputs(self):
        inputs = {k: self.payload[k] for k in notify.CALLBACK_KEYS}
        inputs['relay_run_id'] = '456'
        path = self.root / 'notify-inputs.json'
        path.write_text(json.dumps(inputs))
        with patch.dict(os.environ, NOTIFY_INPUTS=str(path), PRIVATE_SIGN_DISPATCH_TOKEN='offline-placeholder'):
            with patch.object(notify, 'api') as api:
                api.return_value.__enter__.return_value.status = 204
                notify.dispatch()
                args = api.call_args.args
                self.assertEqual(args[0], '/repos/dian-sen/OronBox/actions/workflows/personal-relay-sign.yml/dispatches')
                self.assertEqual(args[2], {'ref': 'main', 'inputs': inputs})


if __name__ == '__main__':
    unittest.main()
