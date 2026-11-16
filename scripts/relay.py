#!/usr/bin/env python3
"""Public relay: validate request, verify source, emit interoperable CMS DER."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

FIELDS = {
    'request_id', 'source_sha', 'abi', 'certificate', 'certificate_sha256',
    'parent_run_id', 'parent_run_attempt', 'version', 'build_number',
}
PLATFORMS = {
    'arm64-v8a': 'android-arm64', 'armeabi-v7a': 'android-arm',
    'x86_64': 'android-x64', 'all': 'android-arm,android-arm64,android-x64',
}
VERSION = r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def load_json(path):
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique_object)


def command(args, **kwargs):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    require(result.returncode == 0, f'{Path(args[0]).name} failed')
    return result.stdout


def validate_payload(payload):
    require(isinstance(payload, dict) and set(payload) == FIELDS, 'Expected exactly nine request fields')
    require(all(isinstance(v, str) for v in payload.values()), 'Request fields must be strings')
    for key, pattern in {
        'request_id': r'[0-9a-f]{32}', 'source_sha': r'[0-9a-f]{40}',
        'certificate_sha256': r'[0-9a-f]{64}', 'parent_run_id': r'[1-9][0-9]{0,19}',
        'parent_run_attempt': r'[1-9][0-9]{0,9}', 'version': VERSION,
        'build_number': r'[1-9][0-9]{0,9}',
    }.items():
        require(re.fullmatch(pattern, payload[key]) is not None, f'Invalid {key}')
    require(len(payload['version']) <= 128, 'Version is too long')
    require(int(payload['build_number']) <= 2100000000, 'Invalid Android build number')
    require(payload['abi'] in PLATFORMS, 'Unsupported ABI')
    pem = payload['certificate'].encode('utf-8')
    require(len(pem) <= 16384 and re.fullmatch(
        rb'-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?', pem
    ) is not None, 'Expected one PEM certificate')
    require(hashlib.sha256(pem).hexdigest() == payload['certificate_sha256'], 'Certificate fingerprint mismatch')
    command(['openssl', 'x509', '-noout', '-checkend', '0'], input=pem)
    public_key = command(['openssl', 'x509', '-pubkey', '-noout'], input=pem)
    rsa = command(['openssl', 'rsa', '-pubin', '-text', '-noout'], input=public_key)
    bits = re.search(rb'Public-Key: \(([0-9]+) bit\)', rsa)
    require(bits is not None and int(bits[1]) >= 2048, 'RSA certificate must be at least 2048 bits')
    return payload


def request_path():
    return Path(os.environ['RELAY_REQUEST'])


def read_request():
    return validate_payload(load_json(request_path()))


def append_env(path, values):
    with open(path, 'a', encoding='utf-8') as stream:
        for key, value in values.items():
            stream.write(f'{key}={value}\n')


def validate():
    event = load_json(os.environ['GITHUB_EVENT_PATH'])
    require(os.environ['GITHUB_EVENT_NAME'] == 'repository_dispatch', 'Wrong event')
    require(event.get('action') == 'build-oronbox-personal', 'Wrong dispatch type')
    payload = validate_payload(event.get('client_payload'))
    path = request_path()
    path.write_text(json.dumps(payload, separators=(',', ':')), encoding='utf-8')
    path.chmod(0o600)
    append_env(os.environ['GITHUB_OUTPUT'], {k: payload[k] for k in ('request_id', 'source_sha')})
    append_env(os.environ['GITHUB_ENV'], {
        'PERSONAL_ABI': payload['abi'], 'PERSONAL_TARGET_PLATFORM': PLATFORMS[payload['abi']],
    })
    print('Validated request schema and one-time RSA certificate.')


def verify_source(source):
    payload = read_request()
    source = Path(source).resolve()

    def git(*args):
        return command(['git', '-C', str(source), *args]).decode().strip()

    require(git('rev-parse', 'HEAD') == payload['source_sha'], 'Source SHA mismatch')
    ancestry = os.environ.get('REQUIRE_SOURCE_ON_MAIN', 'true')
    require(ancestry in ('true', 'false'), 'Invalid REQUIRE_SOURCE_ON_MAIN')
    if ancestry == 'true':
        git('merge-base', '--is-ancestor', payload['source_sha'], 'refs/remotes/origin/main')
    require(json.loads((source / '.fvmrc').read_text())['flutter'] == os.environ['FLUTTER_VERSION'],
            'Flutter pin mismatch')
    matches = re.findall(r'^version:\s*(' + VERSION + r')\+([1-9][0-9]*)\s*$',
                         (source / 'pubspec.yaml').read_text(), re.M)
    require(matches == [(payload['version'], payload['build_number'])], 'pubspec version mismatch')
    module = 'android/xms-wearable-lib-cleanroom'
    require(git('config', '-f', '.gitmodules', '--get', f'submodule.{module}.url') ==
            'https://github.com/OrPudding/XMS_Wearable_SDK_CleanRoom.git', 'Unexpected public SDK URL')
    # Keep the leading status marker: '-'/'+'/'U' is not an initialized exact gitlink.
    status = command(['git', '-C', str(source), 'submodule', 'status', '--recursive']).decode()
    require(status and all(line.startswith(' ') for line in status.splitlines()), 'Submodule gitlink mismatch')
    require((source / module).is_dir(), 'Public SDK submodule is missing')
    print('Verified exact SHA, source versions and recursive public SDK checkout.')


def encrypt(apk):
    payload = read_request()
    apk = Path(apk)
    require(apk.is_file() and not apk.is_symlink() and apk.stat().st_size > 0, 'Missing APK')
    digest = hashlib.sha256()
    with apk.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    metadata = {key: value for key, value in payload.items() if key != 'certificate'}
    metadata.update(apk_sha256=digest.hexdigest(), bytes=apk.stat().st_size)
    output = Path(os.environ['RELAY_OUTPUT'])
    require(not output.exists(), 'Relay output directory already exists')
    output.mkdir(mode=0o700, parents=True)
    try:
        with tempfile.TemporaryDirectory(prefix='oronbox-cms-', dir=os.environ.get('RUNNER_TEMP')) as temp:
            temp = Path(temp)
            certificate = temp / 'recipient.pem'
            certificate.write_bytes(payload['certificate'].encode('utf-8'))
            certificate.chmod(0o600)
            archive = temp / 'payload.zip'
            with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as bundle:
                bundle.write(apk, 'app-release.apk')
                bundle.writestr('metadata.json', json.dumps(metadata, sort_keys=True, separators=(',', ':')))
            # OpenSSL CMS creates AuthEnvelopedData for GCM; never use openssl enc.
            # Ubuntu 24.04's OpenSSL supports OAEP SHA-256; fail closed if unavailable.
            command([
                'openssl', 'cms', '-encrypt', '-binary', '-aes-256-gcm', '-outform', 'DER',
                '-in', str(archive), '-out', str(output / 'payload.cms'),
                '-recip', str(certificate), '-keyopt', 'rsa_padding_mode:oaep',
                '-keyopt', 'rsa_oaep_md:sha256', '-keyopt', 'rsa_mgf1_md:sha256',
            ])
        callback = {key: payload[key] for key in ('request_id', 'parent_run_id', 'parent_run_attempt')}
        (output / 'callback.json').write_text(json.dumps(callback, separators=(',', ':')) + '\n')
        require({p.name for p in output.iterdir()} == {'payload.cms', 'callback.json'}, 'Unexpected output')
    except Exception:
        for name in ('payload.cms', 'callback.json'):
            (output / name).unlink(missing_ok=True)
        raise
    print('Created CMS AES-256-GCM / RSA-OAEP SHA-256 signing input and minimal callback.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    sub.add_parser('validate')
    sub.add_parser('verify-source').add_argument('--source', required=True)
    sub.add_parser('encrypt').add_argument('--apk', required=True)
    args = parser.parse_args()
    try:
        if args.operation == 'validate':
            validate()
        elif args.operation == 'verify-source':
            verify_source(args.source)
        else:
            encrypt(args.apk)
    except (ValueError, OSError, KeyError, json.JSONDecodeError):
        # Do not echo untrusted payloads, private paths or subprocess output to public logs.
        raise SystemExit('Relay validation or encryption failed; no plaintext artifact was published.')


if __name__ == '__main__':
    main()
