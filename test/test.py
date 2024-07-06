import json
import glob
import os
import pytest
import resource
import subprocess
import sys

# Set a memory limit of 8GB
resource.setrlimit(resource.RLIMIT_AS, (8 * 1024 * 1024 * 1024, -1))

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
    cmd = ['/usr/bin/env', 'bash', 'run.sh', wasm_name, '--max-time', '5', '--max-memory', '8192']
    subprocess.run(cmd, timeout=60, check=True)

def test_sgx_wasm_can_be_fully_analyzed():
    cmd = ['/usr/bin/env', 'bash', 'run.sh', 'SGXCryptoFile']
    subprocess.run(cmd, timeout=45, check=True)
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

def test_c_library():
    cmd = [sys.executable, 'main.py', '-f', 'test/test_c_library.wasm', '-s', '-v', 'info']
    proc = subprocess.run(cmd, timeout=30, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.returncode == 0, f'return code should be 0\nstdout: {proc.stdout.decode("utf-8")}\nstderr: {proc.stderr.decode("utf-8")}'

    result_dir = glob.glob('./output/result/test_c_library*')
    result_dir.sort()
    result_dir = result_dir[-1]
    state_path = glob.glob(f'{result_dir}/state*.json')
    assert len(state_path) == 1, 'currently in concrete mode, should have only one state output'

    with open(state_path[0], 'r') as f:
        state = json.load(f)
    assert state['Return'] == "0", f'return value should be 0, got {state["Return"]}'
    assert state['Output'][0]['name'] == "stdout"
    assert state['Output'][0]['output'] == "str2 is less than str1The substring is: Point\nThe substring is: \x00\nString after |.| is - |.tutorialspoint.com|\nfloor testing below:Value1 = -2.0 \nValue2 = 2.0 \nceil testing below:Value1 = -1.0 \nValue2 = 3.0 \nsqrt testing below:Value1 = fp.to_ieee_bv(NaN) \nValue2 = 1.6733200388199156 \nexp testing below:The exponential value of 1.0 is 2.718281828459045\nThe exponential value of 2.0 is 7.3890560989306495\nabs testing below:value of a = 5\nvalue of b = 10\nEnter character: Character entered: `@`TechOnTheNet.com\nHello, world!\nFinal destination string : This is destinationThis is sotutorialspointtutorialspoint.comThis is string.h library function\n$$$$$$$ string.h library function\nHeloooo!!\nhttp://www.tutorialspoint.com\nstr2 is less than str11234567890\n1234456890\nString value = 98993.489, Float value = 98993.4765625, test padding: a\nFloat value = 98993.4765625, String value = 98993.489, test padding: a\nString value = tutorialspoint.com, Float value = 0.0\n"

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
    result_dir.sort()
    result_dir = result_dir[-1]
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
    result_dir.sort()
    result_dir = result_dir[-1]
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