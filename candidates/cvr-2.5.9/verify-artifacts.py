#!/usr/bin/env python3
"""Verify the fixed CVR 2.5.8/2.5.9 installer pair and existing STCVRC core offline."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parent


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def hashes(path):
    sha, prehash = hashlib.sha256(), hashlib.blake2b(digest_size=64)
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            sha.update(block)
            prehash.update(block)
    return sha.hexdigest(), prehash.digest()


def signature_parts(encoded, public):
    lines = base64.b64decode(encoded, validate=True).decode('utf-8').splitlines()
    require(len(lines) == 4, 'unexpected minisign line count')
    require(lines[0].startswith('untrusted comment: '), 'missing untrusted comment')
    require(lines[2].startswith('trusted comment: '), 'missing trusted comment')
    packet = base64.b64decode(lines[1], validate=True)
    global_signature = base64.b64decode(lines[3], validate=True)
    require(len(packet) == 74 and packet[:2] == b'ED', 'expected ED prehashed signature')
    require(packet[2:10] == public[2:10], 'minisign key ID mismatch')
    require(len(global_signature) == 64, 'invalid global signature size')
    return packet[10:], global_signature, lines[2][17:]


def must_reject(callback):
    try:
        callback()
    except (InvalidSignature, ValueError):
        return
    raise ValueError('negative verification control unexpectedly passed')


def public_file(root, name):
    require(isinstance(name, str) and name not in ('', '.', '..') and
            '/' not in name and '\\' not in name and ':' not in name,
            'expected fixed public basename')
    return root / name


def verify(artifacts, core, manifest):
    require(manifest['schemaVersion'] == 1, 'unsupported inputs schema')
    require(manifest['repository'] == 'clash-verge-rev/clash-verge-rev', 'wrong upstream repository')
    require([r['version'] for r in manifest['releases']] == ['2.5.8', '2.5.9'], 'unsupported version pair')
    public_lines = base64.b64decode(manifest['publicKeyBase64'], validate=True).decode().splitlines()
    require(len(public_lines) == 2 and public_lines[0].startswith('untrusted comment: '), 'invalid public key text')
    public = base64.b64decode(public_lines[1], validate=True)
    require(len(public) == 42 and public[:2] == b'Ed', 'invalid public key packet')
    key = Ed25519PublicKey.from_public_bytes(public[10:])
    verified = []
    for release in manifest['releases']:
        version = release['version']
        require(release['tag'] == 'v' + version, 'tag/version mismatch')
        metadata = json.loads(public_file(artifacts, release['metadataFile']).read_bytes())
        require(metadata['id'] == release['releaseId'] and metadata['tag_name'] == release['tag'], 'release identity mismatch')
        config_bytes = public_file(artifacts, release['config']['file']).read_bytes()
        require(hashlib.sha256(config_bytes).hexdigest() == release['config']['sha256'], 'tagged config SHA256 mismatch')
        config = json.loads(config_bytes)
        require(config['version'] == version, 'tagged config version mismatch')
        require(config['plugins']['updater']['pubkey'] == manifest['publicKeyBase64'], 'tagged updater key mismatch')
        require(set(release['assets']) == {'installer', 'signature', 'latest'}, 'expected three asset roles')
        checked_assets = {}
        for role, expected in release['assets'].items():
            matches = [a for a in metadata['assets'] if a['id'] == expected['id'] or a['name'] == expected['name']]
            require(len(matches) == 1, 'missing or duplicate selected asset')
            actual = matches[0]
            for field in ('id', 'name', 'size'):
                require(actual[field] == expected[field], 'asset metadata identity mismatch')
            require(actual['digest'] == 'sha256:' + expected['sha256'], 'asset metadata SHA256 mismatch')
            require(actual['browser_download_url'] == expected['url'], 'asset source URL mismatch')
            path = public_file(artifacts, expected['file'])
            sha, digest = hashes(path)
            require(path.stat().st_size == expected['size'], 'asset size mismatch')
            require(sha == expected['sha256'], 'asset SHA256 mismatch')
            checked_assets[role] = {'name': expected['name'], 'id': expected['id'], 'size': expected['size'], 'sha256': sha}
            if role == 'installer':
                installer_digest = digest
        encoded = public_file(artifacts, release['assets']['signature']['file']).read_text().strip()
        signature, global_signature, comment = signature_parts(encoded, public)
        key.verify(signature, installer_digest)
        key.verify(global_signature, signature + comment.encode())
        changed_digest = bytes([installer_digest[0] ^ 1]) + installer_digest[1:]
        must_reject(lambda: key.verify(signature, changed_digest))
        must_reject(lambda: key.verify(global_signature, signature + (comment + '!').encode()))
        wrong_public = public[:2] + bytes([public[2] ^ 1]) + public[3:]
        must_reject(lambda: signature_parts(encoded, wrong_public))
        updater = json.loads(public_file(artifacts, release['assets']['latest']['file']).read_bytes())
        require(updater['version'].removeprefix('v') == version, 'updater version mismatch')
        installer_id = release['assets']['installer']['id']
        for platform in ('windows-x86_64', 'windows-x86_64-nsis'):
            item = updater['platforms'][platform]
            require(item['signature'] == encoded, 'updater signature mismatch')
            require(item['url'] == f'https://api.github.com/repos/{manifest["repository"]}/releases/assets/{installer_id}', 'updater URL mismatch')
        verified.append({'version': version, 'tag': release['tag'], 'releaseId': release['releaseId'],
                         'sourceCommit': release['sourceCommit'], 'assets': checked_assets,
                         'taggedConfigVerified': True, 'signatureVerified': True,
                         'trustedCommentVerified': True, 'windowsUpdaterEntriesMatch': True,
                         'negativeControlsPassed': ['changed_message', 'changed_trusted_comment', 'wrong_key_id']})
    core_sha, _ = hashes(core)
    require(core.stat().st_size == manifest['core']['size'] and core_sha == manifest['core']['sha256'], 'custom core mismatch')
    return {'schemaVersion': 1, 'releases': verified, 'core': manifest['core'],
            'extractedPayloads': 'NOT_VERIFIED', 'nativeAcceptance': 'NOT_RUN',
            'authenticode': 'NOT_VERIFIED', 'artifactsExecuted': False, 'releasePublished': False}


def main(argv=None, *, manifest_path=ROOT / 'inputs.json'):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('--core', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        inputs = manifest_path.read_bytes()
        receipt = verify(args.artifacts, args.core, json.loads(inputs))
        receipt['inputsSha256'] = hashlib.sha256(inputs).hexdigest()
        receipt['verifierSha256'] = hashes(Path(__file__))[0]
    except (OSError, ValueError, KeyError, TypeError, InvalidSignature) as error:
        print(f'Verification failed: {type(error).__name__}: {error}', file=sys.stderr)
        return 1
    print(json.dumps(receipt, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
