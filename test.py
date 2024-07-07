from datetime import datetime
import json
import glob
import os
import pytest
import subprocess
import sys

@pytest.mark.parametrize('wasm_name', [
    'sgxwallet',
    'SGXCryptoFile',
    'sgx-kmeans',
])

def test_sgx_wasm_can_be_analyzed(wasm_name):
    cmd = ['/usr/bin/env', 'bash', 'run.sh', wasm_name, '--max-time', '5', '--max-memory', '8192']
    subprocess.run(cmd, timeout=60, check=True)

def test_ecall_list_must_be_specified():
    cmd = [sys.executable, 'main.py', '-f', 'benchmarks/sgxcrypto.wasm', '--symgx']
    proc = subprocess.run(cmd, timeout=5, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # return code should be 1
    assert proc.returncode == 1, 'return code should be 1'
    # "--symgx requires --ecall-list" msg should be in stderr
    assert '--symgx requires --ecall-list' in proc.stderr.decode('utf-8'), 'should have --symgx requires --ecall-list in stderr'

def test_c_library():
    cmd = [sys.executable, 'main.py', '-f', 'test/test_c_library.wasm', '-s', '-v', 'info']
    proc = subprocess.run(cmd, timeout=60, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.returncode == 0, f'return code should be 0\nstdout: {proc.stdout.decode("utf-8")}\nstderr: {proc.stderr.decode("utf-8")}'

    result_dir = glob.glob('./output/result/test_c_library*')
    assert len(result_dir) == 1, 'should have only one result directory, do you have multiple runs?'
    result_dir = result_dir[0]
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
    ('password.wasm', '')
])

def test_wasm_can_be_analyzed(wasm_path, entry):
    wasm_path = os.path.join("./test/", wasm_path)
    cmd = [sys.executable, 'main.py', '-f', wasm_path, '-s', '-v', 'info']
    if entry != "":
        cmd.extend(['--entry', entry])
    subprocess.run(cmd, timeout=60, check=True)

def test_return_simulation():
    wasm_path = './test/test_return.wasm'
    cmd = [sys.executable, 'main.py', '-f', wasm_path, '-s', '-v', 'info']
    subprocess.run(cmd, timeout=60, check=True)

    result_dir = glob.glob('./output/result/test_return_*')
    assert len(result_dir) == 1, 'should have only one result directory, do you have multiple runs?'
    result_dir = result_dir[0]
    state_path = glob.glob(f'{result_dir}/state*.json')
    assert len(state_path) == 1, 'should have only one state returning `1`'

    with open(state_path[0], 'r') as f:
        state = json.load(f)
    assert state['Return'] == "1", f'should return 1, got {state["Return"]}'

def test_unreachable_simulation():
    wasm_path = './test/test_unreachable.wasm'
    cmd = [sys.executable, 'main.py', '-f', wasm_path, '-s', '-v', 'info']
    subprocess.run(cmd, timeout=60, check=True)

    result_dir = glob.glob('./output/result/test_unreachable_*')
    assert len(result_dir) == 1, 'should have only one result directory, do you have multiple runs?'
    result_dir = result_dir[0]
    state_path = glob.glob(f'{result_dir}/state*.json')
    assert len(state_path) == 1, 'should have only one state output `null`'
    with open(state_path[0], 'r') as f:
        state = json.load(f)
    assert state['Solution'] == {}, f'should have no solution, got {state["Solution"]}'

def test_c_sym_args():
    wasm_path = './test/sym_c.wasm'
    cmd = [sys.executable, 'main.py', '-f', wasm_path, '-s', '--sym_args', '1', '--source_type', 'c', '--entry', '__main_void', '-v', 'info']
    subprocess.run(cmd, timeout=60, check=True)

    result_dir = glob.glob('./output/result/sym_c*')
    assert len(result_dir) == 1, 'should have only one result directory, do you have multiple runs?'
    result_dir = result_dir[0]
    state_path = glob.glob(f'{result_dir}/state*.json')
    assert len(state_path) == 3, 'should have three states output'
    for state in state_path:
        with open(state, 'r') as f:
            state = json.load(f)
        assert 'Solution' in state and 'sym_arg_1' in state['Solution'], f'no sym_arg_1 solution found in {state}'
        assert 'Return' in state, f'no Return found in {state}'
        assert 'Output' in state and len(state['Output']) == 2, f'no Output found in {state}'
        inp = state['Solution']["sym_arg_1"]
        analyzed_return = state['Return']
        analyzed_stdout = state['Output'][0]['output']
        expected_return_to_stdout = {"0": "a", "1": "b", "2": "c"}
        assert analyzed_return in expected_return_to_stdout, f'analyzed return value {analyzed_return} not found in expected_return_to_stdout'
        assert analyzed_stdout == expected_return_to_stdout[analyzed_return], f'output mismatched, got {analyzed_stdout}, expected {expected_return_to_stdout[analyzed_return]}'

def test_password_sym_args():
    wasm_path = './test/password.wasm'
    assert os.path.exists(wasm_path), 'password.wasm not found'
    # copy password.wasm for this test
    suffix = datetime.now().strftime("%Y%m%d%H%M%S%f")
    wasm_path = f'./test/password_{suffix}.wasm'
    subprocess.run(['cp', './test/password.wasm', wasm_path], timeout=5, check=True)
    # analyze
    cmd = [sys.executable, 'main.py', '-f', wasm_path, '-s', '--sym_args', '10', '--source_type', 'c', '--entry', '_start', '-v', 'info']
    subprocess.run(cmd, timeout=60, check=True)
    # remove copied wasm
    subprocess.run(['rm', wasm_path, wasm_path.replace('.wasm', '.wat')], timeout=5, check=True)

    result_dir = glob.glob(f'./output/result/password_{suffix}*')
    assert len(result_dir) == 1, 'should have only one result directory, do you have multiple runs?'
    result_dir = result_dir[0]
    state_path = glob.glob(f'{result_dir}/state*.json')
    assert len(state_path) == 6, 'should have six states output'
    for state in state_path:
        with open(state, 'r') as f:
            state = json.load(f)
        assert 'Solution' in state and 'sym_arg_1' in state['Solution'], f'no sym_arg_1 solution found in {state}'
        assert 'Output' in state and len(state['Output']) == 2, f'no Output found in {state}'
        inp = state['Solution']["sym_arg_1"]
        analyzed_stdout = state['Output'][0]['output']
        if 'Return' in state:
            assert state['Return'] == "0", f'should return 0, got {state["Return"]}'
            assert inp == "hello", f'solved input mismatched, got {inp}'
            assert analyzed_stdout == "Password found!\n", f'output mismatched, got {analyzed_stdout}'
        else:
            assert 'Status' in state, f'no Status found in {state}'
            assert state['Status'] == "Exit with status code 1", f'should exit with status code 1, got {state["Status"]}'