import glob
import os
import pytest
import subprocess
import sys

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
    cmd = ['/usr/bin/env', 'bash', 'run.sh', wasm_name, '--max-time']
    cmd.append("5")
    subprocess.run(cmd, timeout=60, check=True)

def test_sgx_wasm_can_be_fully_analyzed():
    cmd = ['/usr/bin/env', 'bash', 'run.sh', 'SGXCryptoFile']
    subprocess.run(cmd, timeout=30, check=True)


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

def test_return_simulation():
    wasm_path = './test/test_return.wasm'
    cmd = [sys.executable, 'main.py', '-f', wasm_path, '-s', '-v', 'info', '--source_type', 'rust']
    subprocess.run(cmd, timeout=30, check=True)

    result_dir = glob.glob('./log/result/test_return_*')
    assert len(result_dir) == 1, 'more than one matching results, do you have multiple `test_return*` cases?'
    result_dir = result_dir[0]
    state_path = glob.glob(f'{result_dir}/state*.json')
    assert len(state_path) == 1, 'should have only one state output `Exit 0`'

    proc = subprocess.run(['jq', '.Solution.proc_exit', state_path[0]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    out = proc.stdout.decode('utf-8').strip()
    expect = '"\\u0000"'
    assert out == expect, f'expect {expect}, got {out}'

def test_unreachable_simulation():
    wasm_path = './test/test_unreachable.wasm'
    cmd = [sys.executable, 'main.py', '-f', wasm_path, '-s', '-v', 'info', '--source_type', 'rust']
    subprocess.run(cmd, timeout=30, check=True)

    result_dir = glob.glob('./log/result/test_unreachable_*')
    assert len(result_dir) == 1, 'more than one matching results, do you have multiple `test_unreachable*` cases?'
    result_dir = result_dir[0]
    state_path = glob.glob(f'{result_dir}/state*.json')
    assert len(state_path) == 1, 'should have only one state output `null`'

    proc = subprocess.run(['jq', '.Solution.proc_exit', state_path[0]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    out = proc.stdout.decode('utf-8').strip()
    expect = 'null'
    assert out == expect, f'expect {expect}, got {out}'