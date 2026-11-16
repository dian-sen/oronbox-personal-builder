#!/usr/bin/env python3
"""Isolated public callback consumer. Never check out or execute private source."""
import argparse
import io
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPOSITORY = 'dian-sen/oronbox-personal-builder'
PRIVATE_DISPATCH = 'https://api.github.com/repos/dian-sen/OronBox/actions/workflows/personal-relay-sign.yml/dispatches'
CALLBACK_KEYS = {'request_id', 'parent_run_id', 'parent_run_attempt'}
INPUT_KEYS = CALLBACK_KEYS | {'relay_run_id'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, 'Duplicate JSON key')
        obj[key] = value
    return obj


def decode_json(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def validate_callback(value):
    require(isinstance(value, dict) and set(value) == CALLBACK_KEYS, 'Unexpected callback fields')
    require(all(isinstance(v, str) for v in value.values()), 'Callback fields must be strings')
    for key, pattern in {
        'request_id': r'[0-9a-f]{32}', 'parent_run_id': r'[1-9][0-9]{0,19}',
        'parent_run_attempt': r'[1-9][0-9]{0,9}',
    }.items():
        require(re.fullmatch(pattern, value[key]) is not None, f'Invalid {key}')
    return value


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    """A signed artifact CDN URL must never receive the GitHub token."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlparse(newurl)
        require(target.scheme == 'https' and target.hostname and not target.username, 'Unsafe redirect')
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and target.hostname != 'api.github.com':
            redirected.remove_header('Authorization')
        return redirected


OPENER = urllib.request.build_opener(SafeRedirect())


def api(path, token, body=None):
    url = 'https://api.github.com' + path
    data = None if body is None else json.dumps(body, separators=(',', ':')).encode()
    request = urllib.request.Request(url, data=data, headers={
        'Accept': 'application/vnd.github+json', 'Authorization': f'Bearer {token}',
        'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'oronbox-personal-relay',
        'Content-Type': 'application/json',
    })
    return OPENER.open(request, timeout=60)


def api_json(path, token):
    with api(path, token) as response:
        data = response.read(4 * 1024 * 1024 + 1)
    require(len(data) <= 4 * 1024 * 1024, 'API response too large')
    return decode_json(data)


def validate_run(run, run_id, request_id=None):
    require(isinstance(run, dict) and str(run.get('id')) == str(run_id), 'Wrong workflow run')
    require(run.get('conclusion') == 'success' and run.get('status') == 'completed', 'Run was not successful')
    require(run.get('event') == 'repository_dispatch' and run.get('head_branch') == 'main', 'Wrong run origin')
    require(run.get('head_repository', {}).get('full_name') == REPOSITORY, 'Wrong source repository')
    require(run.get('repository', {}).get('full_name') == REPOSITORY, 'Wrong run repository')
    # GitHub can return the dynamic run-name in `name`; workflow identity is
    # the fixed path plus its authoritative numeric workflow ID, checked below.
    require(run.get('path') == '.github/workflows/build.yml', 'Wrong workflow path')
    title = re.fullmatch(r'Relay ([0-9a-f]{32})', run.get('display_title', ''))
    require(title is not None, 'Invalid run title')
    require(request_id is None or request_id == title[1], 'Run title mismatch')
    return title[1]


def callback_from_archive(raw):
    # Open only callback.json; never extract files, inspect CMS contents or execute artifact code.
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(len(entries) == 2 and {e.filename for e in entries} == {'payload.cms', 'callback.json'},
                'Artifact must contain exactly payload.cms and callback.json')
        info = archive.getinfo('callback.json')
        require(not info.is_dir() and 0 < info.file_size <= 4096 and not info.flag_bits & 1,
                'Invalid callback entry')
        require(archive.getinfo('payload.cms').file_size > 0, 'Missing CMS')
        with archive.open(info) as stream:
            callback = stream.read(4097)
        require(len(callback) <= 4096, 'Callback too large')
        return validate_callback(decode_json(callback))


def prepare():
    event = decode_json(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes())
    event_name = os.environ.get('GITHUB_EVENT_NAME')
    require(os.environ.get('GITHUB_REPOSITORY') == REPOSITORY, 'Wrong repository')
    token = os.environ['GH_TOKEN']
    if event_name == 'workflow_run':
        require(event.get('action') == 'completed', 'Wrong workflow action')
        run = event['workflow_run']
        run_id = str(run['id'])
        require(re.fullmatch(r'[1-9][0-9]{0,19}', run_id) is not None, 'Invalid run ID')
        request_id = validate_run(run, run_id)
    else:
        require(event_name == 'workflow_dispatch' and os.environ.get('GITHUB_REF') == 'refs/heads/main',
                'Recovery requires manual dispatch on main')
        run_id = event.get('inputs', {}).get('relay_run_id', '')
        require(isinstance(run_id, str) and re.fullmatch(r'[1-9][0-9]{0,19}', run_id) is not None,
                'Invalid recovery run ID')
        request_id, run = None, None
    # Re-fetch authoritative run metadata, using only this notify run's GITHUB_TOKEN.
    authoritative = api_json(f'/repos/{REPOSITORY}/actions/runs/{run_id}', token)
    request_id = validate_run(authoritative, run_id, request_id)
    workflow = api_json(f'/repos/{REPOSITORY}/actions/workflows/build.yml', token)
    require(workflow.get('path') == '.github/workflows/build.yml'
            and isinstance(workflow.get('id'), int)
            and authoritative.get('workflow_id') == workflow['id'], 'Wrong build workflow identity')
    if run is not None:
        require(authoritative.get('run_attempt') == run.get('run_attempt'), 'Run attempt changed')
    result = api_json(f'/repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100', token)
    artifacts = result.get('artifacts', [])
    require(result.get('total_count') == 1 and len(artifacts) == 1, 'Expected one run artifact')
    artifact = artifacts[0]
    require(artifact.get('name') == f'relay-{request_id}' and artifact.get('expired') is False,
            'Artifact name or lifetime mismatch')
    require(isinstance(artifact.get('id'), int) and artifact['id'] > 0, 'Invalid artifact ID')
    require(artifact.get('workflow_run', {}).get('id') == int(run_id), 'Artifact run mismatch')
    maximum = 2 * 1024 * 1024 * 1024
    require(isinstance(artifact.get('size_in_bytes'), int) and 0 < artifact['size_in_bytes'] <= maximum,
            'Artifact size is invalid')
    with api(f'/repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip', token) as response:
        raw = response.read(maximum + 1)
    require(len(raw) <= maximum, 'Artifact download too large')
    callback = callback_from_archive(raw)
    require(callback['request_id'] == request_id, 'Callback / run title mismatch')
    callback['relay_run_id'] = run_id
    destination = Path(os.environ['NOTIFY_INPUTS'])
    destination.write_text(json.dumps(callback, separators=(',', ':')))
    destination.chmod(0o600)
    print('Validated exact public run artifact and callback correlation.')


def dispatch():
    inputs = decode_json(Path(os.environ['NOTIFY_INPUTS']).read_bytes())
    require(isinstance(inputs, dict) and set(inputs) == INPUT_KEYS, 'Invalid dispatch input fields')
    validate_callback({k: inputs[k] for k in CALLBACK_KEYS})
    require(isinstance(inputs['relay_run_id'], str) and
            re.fullmatch(r'[1-9][0-9]{0,19}', inputs['relay_run_id']) is not None, 'Invalid relay run ID')
    # The scoped PAT exists in this step only; no source read permissions are needed.
    token = os.environ['PRIVATE_SIGN_DISPATCH_TOKEN']
    path = PRIVATE_DISPATCH.removeprefix('https://api.github.com')
    with api(path, token, {'ref': 'main', 'inputs': inputs}) as response:
        require(response.status == 204, 'Unexpected dispatch response')
    print('Dispatched private signing workflow with four validated string inputs.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'dispatch'))
    args = parser.parse_args()
    try:
        prepare() if args.operation == 'prepare' else dispatch()
    except ValueError as error:
        # Validation messages are fixed strings, never raw payloads or tokens.
        raise SystemExit(f'Isolated callback rejected: {error}') from None
    except urllib.error.HTTPError as error:
        raise SystemExit(f'Isolated callback API request failed: HTTP {error.code}') from None
    except (KeyError, OSError, zipfile.BadZipFile, urllib.error.URLError):
        raise SystemExit('Isolated callback failed parsing or network access.') from None


if __name__ == '__main__':
    main()
