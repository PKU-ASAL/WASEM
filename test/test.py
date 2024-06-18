import json
import glob
import os
import pytest
import resource
import subprocess
import sys

# Set a memory limit of 4GB
resource.setrlimit(resource.RLIMIT_AS, (4 * 1024 * 1024 * 1024, -1))

@pytest.mark.parametrize('wasm_name', [
    'sgx-dnet',
    'sgxwallet',
    'SGXCryptoFile',
    'verifiable-election',
    # 'sgx-log', # out-of-bound memory access
    'sgx-kmeans',
    # 'sgx-reencrypt', # fail to extract wat
    # 'CryptoEnclave', # fail to extract wat
    # 'sgx-pwenclave', # out-of-bound memory access
    # 'sgx-deep-learning', # z3.z3types.Z3Exception: b'Sorts (_ BitVec 32) and (_ BitVec 64) are incompatible'
    'sgx-biniax2',
    # 'sgx-rsa', # out-of-bound memory access
    # 'sgx_protect_file', # out-of-bound memory access
    # 'SGXSSE' # func_DIE error
])

def test_sgx_wasm_can_be_analyzed(wasm_name):
    cmd = ['/usr/bin/env', 'bash', 'run.sh', wasm_name, '--max-time', '5', '--max-memory', '4096']
    subprocess.run(cmd, timeout=60, check=True)

def test_sgx_wasm_can_be_fully_analyzed():
    cmd = ['/usr/bin/env', 'bash', 'run.sh', 'SGXCryptoFile']
    subprocess.run(cmd, timeout=30, check=True)
    result_dir = glob.glob('./output/result/sgxcrypto_*')
    # sort and use last one
    result_dir.sort()
    result_dir = result_dir[-1]
    state_path = glob.glob(f'{result_dir}/bug_state*.json')
    assert len(state_path) == 2, 'should have two bug states'

def test_ecall_list_must_be_specified():
    cmd = [sys.executable, 'main.py', '-f', 'benchmarks/sgxcrypto.wasm', '--symgx']
    proc = subprocess.run(cmd, timeout=5, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # return code should be 1
    assert proc.returncode == 1, 'return code should be 1'
    # "--symgx requires --ecall-list" msg should be in stderr
    assert '--symgx requires --ecall-list' in proc.stderr.decode('utf-8'), 'should have --symgx requires --ecall-list in stderr'


@pytest.mark.parametrize('wasm_path, entry', [
    ('hello_world.wasm', ''),
    ('hello_world_go.wasm', '_start'),
    ('hello_world_rust.wasm', ''),
    ('test.wasm', ''),
])

def test_wasm_can_be_analyzed(wasm_path, entry):
    wasm_path = os.path.join("./test/", wasm_path)
    cmd = [sys.executable, 'main.py', '-f', wasm_path, '-s', '-v', 'info']
    if entry != "":
        cmd.extend(['--entry', entry])
    subprocess.run(cmd, timeout=30, check=True)

@pytest.mark.parametrize('wasm_path, entry', [
    ('hello_world.wasm', ''),
    ('hello_world_go.wasm', '_start'),
    ('hello_world_rust.wasm', ''),
    ('test.wasm', ''),
])

def test_wasm_can_be_analyzed_in_bfs(wasm_path, entry):
    wasm_path = os.path.join("./test/", wasm_path)
    cmd = [sys.executable, 'main.py', '-f', wasm_path, '-s', '-v', 'info', '--search', 'bfs']
    if entry != "":
        cmd.extend(['--entry', entry])
    subprocess.run(cmd, timeout=30, check=True)

@pytest.mark.parametrize('wasm_path, entry', [
    ('hello_world.wasm', ''),
    ('hello_world_go.wasm', '_start'),
    ('hello_world_rust.wasm', ''),
    ('test.wasm', ''),
])

def test_wasm_can_be_analyzed_in_random(wasm_path, entry):
    wasm_path = os.path.join("./test/", wasm_path)
    cmd = [sys.executable, 'main.py', '-f', wasm_path, '-s', '-v', 'info', '--search', 'random']
    if entry != "":
        cmd.extend(['--entry', entry])
    subprocess.run(cmd, timeout=30, check=True)


@pytest.mark.parametrize('wasm_path, entry', [
    ('hello_world.wasm', ''),
    ('hello_world_go.wasm', '_start'),
    ('hello_world_rust.wasm', ''),
    ('test.wasm', ''),
])

def test_wasm_can_be_analyzed_in_interval(wasm_path, entry):
    wasm_path = os.path.join("./test/", wasm_path)
    cmd = [sys.executable, 'main.py', '-f', wasm_path, '-s', '-v', 'info', '--search', 'interval']
    if entry != "":
        cmd.extend(['--entry', entry])
    subprocess.run(cmd, timeout=30, check=True)

def test_return_simulation():
    wasm_path = './test/test_return.wasm'
    cmd = [sys.executable, 'main.py', '-f', wasm_path, '-s', '-v', 'info', '--source_type', 'rust']
    subprocess.run(cmd, timeout=30, check=True)

    result_dir = glob.glob('./output/result/test_return_*')
    assert len(result_dir) == 1, 'more than one matching results, do you have multiple `test_return*` cases?'
    result_dir = result_dir[0]
    state_path = glob.glob(f'{result_dir}/state*.json')
    assert len(state_path) == 1, 'should have only one state output `Exit 0`'

    with open(state_path[0], 'r') as f:
        state = json.load(f)
    assert state['Solution']['proc_exit'] == "\u0000", f'exit code should be 0, got {state["Solution"]["proc_exit"]}'

def test_unreachable_simulation():
    wasm_path = './test/test_unreachable.wasm'
    cmd = [sys.executable, 'main.py', '-f', wasm_path, '-s', '-v', 'info', '--source_type', 'rust']
    subprocess.run(cmd, timeout=30, check=True)

    result_dir = glob.glob('./output/result/test_unreachable_*')
    assert len(result_dir) == 1, 'more than one matching results, do you have multiple `test_unreachable*` cases?'
    result_dir = result_dir[0]
    state_path = glob.glob(f'{result_dir}/state*.json')
    assert len(state_path) == 1, 'should have only one state output `null`'
    with open(state_path[0], 'r') as f:
        state = json.load(f)
    assert state['Solution'] == {}, f'should have no solution, got {state["Solution"]}'

def test_visualize_graph():
    wasm_path = './test/hello_world.wasm'
    cmd = [sys.executable, 'main.py', '-f', wasm_path, '-s', '-v', 'info', '--visualize']
    subprocess.run(cmd, timeout=30, check=True)
    result_dir = glob.glob('./output/visualized_graph/hello_world*.pdf')
    assert len(result_dir) == 1, 'more than one matching results, do you have multiple `hello_world*` cases?'
