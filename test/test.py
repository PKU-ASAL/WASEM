import pytest
import subprocess

@pytest.mark.parametrize('wasm_name', [
    'sgx-dnet',
    'sgxwallet',
    'SGXCryptoFile',
    'verifiable-election',
    'sgx-log',
    'sgx-kmeans',
    # 'sgx-reencrypt', # fail to extract wat
    # 'CryptoEnclave', # fail to extract wat
    'sgx-pwenclave',
    'sgx-deep-learning',
    'sgx-biniax2',
    'sgx-rsa',
    'sgx_protect_file',
    # 'SGXSSE' # func_DIE error
])

def test_wasm_can_be_analyzed(wasm_name):
    cmd = ['/usr/bin/env', 'bash', 'run.sh', wasm_name, '--max-time', '5']
    subprocess.run(cmd, timeout=60, check=True)
