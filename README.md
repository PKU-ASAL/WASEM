# WASEM

![logo](pic/104848503.jfif)

WASEM is a general symbolic execution framework for WebAssembly (WASM) binaries. It serves as the core engine for multiple WASM binary analysis tools and can be used to analyse both normal WASM programs but also WASM files compiled from SGX programs(see our ISSTA and CCS paper in the reference section). Our framework processes the WASM file compiled from the source code of C/C++/Rust/Go, performs symbolic execution, and generates detailed vulnerability reports. These reports include the vulnerability type, location, and the corresponding constraints.

##  Prerequisites 

To run WASEM, install the necessary Python libraries as follows:

```shell
python3 -m pip install -r requirements.txt
```

If you encounter issues building the wheel for leb128, update pip and wheel, then reinstall leb128:

```shell
pip install --upgrade pip wheel
pip install --force-reinstall leb128==1.0.4
```

To analyze files written in other programming languages, you must generate the corresponding WASM file in your local environment. This section provides brief instructions on how to compile C/C++ SGX programs into WASM.

### Compilation

We compile the C/C++ SGX programs into WASM files using [wllvm](https://github.com/travitch/whole-program-llvm) and [wabt](https://github.com/WebAssembly/wabt). Initially, we replace the compiler used in the makefile of SGX programs with the compilers of wllvm and compile them with the -g compile flag.

```shell
# Install prerequisites
sudo apt update
sudo apt-get install cmake libstdc++6-7-dbg libssl-dev
# Download wabt
git clone --recursive https://github.com/WebAssembly/wabt
cd wabt
git submodule update --init
# Build wabt
mkdir build
cd build
cmake ..
cmake --build .
export PATH=$(pwd):$PATH

# OR: for Ubuntu 22.04, you can directly use wabt pre-built releases
curl -JLO "https://github.com/WebAssembly/wabt/releases/download/1.0.32/wabt-1.0.32-ubuntu.tar.gz"
tar xzf wabt-1.0.32-ubuntu.tar.gz
export PATH=$(pwd)/wabt-1.0.32/bin:$PATH

# Compile
CC=wllvm CXX=wllvm++ make SGX_MODE=SIM 
extract-bc xxx.so
llvm-dis xxx.bc
llc -march=wasm32 -filetype=obj xxx.ll
wasm-ld  --no-entry --export-all xxx.o --allow-undefined
wasm2wat xxx.wasm -o xxx.wat
```

We have successfully compiled several benchmarks, which can be found in the `benchmarks/` directory.

## Analysis

### Input Arguments

Our tool can be used by executing the `main.py` with the appropriate parameters. Four arguments are required. The first argument is the name of the wasm file to analyze. The second argument is the ECall list of the program, separated by commas (`,`). The third argument, which is optional, is the function list of the wasm file. If a corresponding wat file exists in the same path as the wasm file, the third argument can be omitted. The fourth argument is the mode to run WASEM. If `--symgx` is set, it will be run in SGX mode, or it will be run in normal mode. For instance, to analyze the `sgx-dent` program in SGX mode for 12 hours, execute the following command:

```shell
python3 main.py -f benchmarks/dnet.wasm --ecall-list sgx_empty_ecall,sgx_ecall_trainer,sgx_ecall_tester,sgx_ecall_classify --symgx --max-time 43200
```

It is worth noting that although we set the `--ecall-list` and `--func-list` manually, they can be automatically obtained using automated tools. However, as this is not the primary focus of this project, we leave it for future work.

### Normal Mode

More Description To Do

### SGX Mode

To facilitate a more convenient analysis of the samples in the `benchmarks/` directory, we have provided a script. You can analyze benchmarks by executing the script with the name of the program you wish to analyze. For instance, to analyze the `sgx-dent` program, use the following command:

```shell
./run.sh sgx-dnet --max-time 43200
```

Other available programs include `sgxwallet`, `SGXCryptoFile`, `verifiable-election`, `sgx-log`, `sgx-kmeans`, `sgx-reencrypt`, `CryptoEnclave`, `sgx-pwenclave`, `sgx-deep-learning`, `sgx-biniax2`, `sgx-rsa`, `sgx_protect_file` and `SGXSSE`.

The vulnerability reports will be generated in the directory `log/`. The format of a vulnerability report is as follows:

```shell
{
    "Status": xxx,
    "Solution": {xxx},
    "Basic_Blocks": [xxx],
    "vulnerability": xxx,
    "iteration round": xxx,
}
```

The `Solution` field represents a set of values that can lead to the vulnerability instruction. `Basic_Blocks` records all the basic blocks encountered during the execution process, which can be used to restore the execution path and the ECall sequence. `Vulnerability` indicates the type of the vulnerability. `iteration round` is the round number of the vulnerability state.

## Citations

If you use any of our tools or datasets in your research for publication, please kindly cite the following paper:

```
@inproceedings{he2023eunomia,
  author = {He, Ningyu and Zhao, Zhehao and Wang, Jikai and Hu, Yubin and Guo, Shengjian and Wang, Haoyu and Liang, Guangtai and Li, Ding and Chen, Xiangqun and Guo, Yao},
  title = {Eunomia: Enabling User-Specified Fine-Grained Search in Symbolically Executing WebAssembly Binaries},
  year = {2023},
  isbn = {9798400702211},
  publisher = {Association for Computing Machinery},
  address = {New York, NY, USA},
  url = {https://doi.org/10.1145/3597926.3598064},
  doi = {10.1145/3597926.3598064},
  booktitle = {Proceedings of the 32nd ACM SIGSOFT International Symposium on Software Testing and Analysis},
  pages = {385–397},
  numpages = {13},
  keywords = {WebAssembly, Symbolic Execution, Domain Specific Language, Path Explosion},
  location = {Seattle, WA, USA},
  series = {ISSTA 2023}
}

```

```
@inproceedings{wang2023symgx,
  title={SymGX: Detecting Cross-boundary Pointer Vulnerabilities of SGX Applications via Static Symbolic Execution},
  author={Wang, Yuanpeng and Zhang, Ziqi and He, Ningyu and Zhong, Zhineng and Guo, Shengjian and Bao, Qinkun and Li, Ding and Guo, Yao and Chen, Xiangqun},
  booktitle={Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security},
  pages={2710--2724},
  year={2023}
}
```

## Feedback

If you have any questions or need further clarification, please post on [the issue page]([Issues · PKU-ASAL/WASEM (github.com)](https://github.com/PKU-ASAL/WASEM/issues)), or you can directly email Yuanpeng Wang at [yuanpeng_wang@pku.edu.cn](yuanpeng_wang@pku.edu.cn).

## Acknowledgements

We would like to thank the anonymous reviewers for their valuable feedback and suggestions.
