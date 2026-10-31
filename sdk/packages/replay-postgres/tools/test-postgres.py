#!/usr/bin/env python3
"""Create/stop a disposable, Unix-only PostgreSQL16 cluster; never use configured databases."""
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import tempfile
import time

PACKAGE = Path(__file__).resolve().parents[1]
PG_BIN = Path('/usr/lib/postgresql/16/bin')


def main():
    root = Path(tempfile.mkdtemp(prefix='atum-replay-pg-', dir='/tmp'))
    data, socket = root / 'data', root / 'socket'
    socket.mkdir(mode=0o700)
    privileged = os.geteuid() == 0
    if privileged:
        account = pwd.getpwnam('postgres')
        os.chown(root, account.pw_uid, account.pw_gid)
        os.chown(socket, account.pw_uid, account.pw_gid)
    prefix = ['runuser', '-u', 'postgres', '--'] if privileged else []
    # Remove possible inherited database targets. Values are never printed.
    env = {k: v for k, v in os.environ.items() if not k.startswith('PG') and 'DATABASE_URL' not in k}
    env.update(ATUM_REPLAY_TEST_SOCKET=str(socket), ATUM_REPLAY_TEST_PORT='5432')
    records = []
    stopped = False

    def pg(*args, check=True, timeout=20):
        return subprocess.run(prefix + [str(PG_BIN / args[0]), *map(str, args[1:])],
                              env=env, text=True, capture_output=True, check=check, timeout=timeout)

    def wait(running):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            status = pg('pg_ctl', '-D', data, 'status', check=False, timeout=3)
            if (status.returncode == 0) == running:
                return
            time.sleep(0.1)
        raise RuntimeError(f'disposable PostgreSQL did not become running={running}')

    def start():
        pg('pg_ctl', '-D', data, '-l', root / 'postgres.log', '-o',
           f"-k {socket} -p 5432 -c listen_addresses='' -c max_connections=32", '-W', 'start')
        wait(True)

    def stop():
        pg('pg_ctl', '-D', data, '-m', 'fast', '-W', 'stop', check=False)
        wait(False)

    def node(file, *args, is_test=False):
        run = subprocess.run(['node', str(file), *map(str, args)], cwd=PACKAGE, env=env,
                             capture_output=True, text=True, timeout=45)
        if run.returncode:
            raise RuntimeError(f'{Path(file).name} failed ({run.returncode})\n{run.stdout}\n{run.stderr}')
        if is_test:
            counts = dict(re.findall(r'^# (tests|pass|fail|skipped|cancelled) (\d+)$', run.stdout, re.M))
            if not counts or any(counts.get(k) != '0' for k in ('fail', 'skipped', 'cancelled')):
                raise RuntimeError(f'incomplete test run\n{run.stdout}\n{run.stderr}')
            records.append({'file': str(Path(file).relative_to(PACKAGE)), **{k: int(v) for k, v in counts.items()}})
            print(json.dumps(records[-1]), flush=True)
        else:
            print(run.stdout.strip(), flush=True)

    try:
        pg('initdb', '-D', data, '-U', 'postgres', '--auth-local=trust', '--auth-host=reject',
           '--no-locale', '--encoding=UTF8', timeout=30)
        start()
        pg('createdb', '-h', socket, '-p', '5432', '-U', 'postgres', 'atum_replay_test')
        node(PACKAGE / 'tools/run-migration.mjs')
        test_files = sorted((PACKAGE / 'test/postgres').glob('*.test.mjs'))
        if not test_files:
            raise RuntimeError('missing integration tests')
        for file in test_files:
            node(file, is_test=True)
        node(PACKAGE / 'tools/restart-probe.mjs', 'write', root / 'restart-state.json')
        stop()
        start()
        node(PACKAGE / 'tools/restart-probe.mjs', 'read', root / 'restart-state.json')
    finally:
        try:
            stop()
            stopped = True
        finally:
            # Keep any unconfirmed-running cluster intact for safe diagnosis, never unlink it.
            if stopped:
                shutil.rmtree(root)
        print(json.dumps({'cluster_stopped': stopped, 'cluster_removed': not root.exists()}), flush=True)
    print(json.dumps({'postgres_tests': sum(r['tests'] for r in records),
                      'restart': 'passed', 'suites': records}), flush=True)


if __name__ == '__main__':
    main()
