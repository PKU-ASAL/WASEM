# WASEM [![test](https://github.com/PKU-ASAL/WASEM/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/PKU-ASAL/WASEM/actions/workflows/test.yml)

![logo](pic/104848503.jfif)


**WASEM is a general symbolic execution framework for WebAssembly (WASM) binaries.** It serves as the **core engine** for multiple **WASM binary analysis** tools and can be used to analyse both normal WASM programs and WASM files compiled from SGX programs *(see our ISSTA and CCS paper in the Citations section)*. Our framework processes the WASM file compiled from the source code of C/C++/Rust/Go, performs symbolic execution, and generates detailed vulnerability reports. These reports include the vulnerability type, location, and the corresponding constraints.

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


## Normal Mode

In this section, we would show how to use WASEM to analyze normal Wasm file.

### Options
All valid options are shown in below:
```shell
WASEM, a symbolic execution engine for Wasm module

optional arguments:
  -h, --help            show this help message and exit

Input arguments:
  -f WASMMODULE, --file WASMMODULE
                        binary file (.wasm)
  --stdin STDIN         stream of stdin
  --sym_stdin SYM_STDIN
                        stream of stdin in N bytes symbols
  --args ARGS           command line
  --sym_args SYM_ARGS [SYM_ARGS ...]
                        command line in symbols, each of them is N bytes at most
  --sym_files SYM_FILES SYM_FILES
                        Create N symbolic files, each of them has M symbolic bytes
  --source_type [{c,go,rust}]
                        type of source file

Features:
  --entry ENTRY         set entry point as the specilized function
  --visualize           visualize the ICFG on basic blocks level
  --incremental         enable incremental solving
  -v [{warning,info,debug}], --verbose [{warning,info,debug}]
                        set the logging level

Analyze:
  -s, --symbolic        perform the symbolic execution
```

We will detail these options according to their functionalities.

### Input Arguments
According to values given to input arguments, WASEM can deassemble the target binary and construct valid inputs.

Specifically, `-f` is not an optional option, following which the path of to be analyzed Wasm binary should be given.
`--stdin STRING` and `--sym_stdin N` can pass concrete or symbolic bytes through the stdin stream.
The difference between them is that a concrete string has to be passed through `--stdin`, and a string consisting of `N` symbolic characters need to be passed through `--sym_stdin`.
For example, `--sym_stdin 5` will input 5 symbolic bytes if some functions need to read input from stdin.

Similarly, `--args STRING1, STRING2, ...` and `--sym_args N1, N2, ...` pass concrete and symbolic arguments to the Wasm binary.
For instance, if `main` requires three arguments where each of them should be two bytes, `--sym_args 2 2 2` is enough.

Some programs will interact with files and conduct reading and writing.
WASEM can also simulate this by a *symbolic file system*.
Users have to apply `--sym_files N M` to create `N` symbolic files, where each of them has (or can hold) `M` bytes at most.

Finally, as several high-level programming languages can be compiled to Wasm binaries. We have achieved some specific optimizations, but users have to indicate the source language by `--source_types`.

### Features
`--entry` can tell WASEM which function is the entry, from which the symbolic execution performs.
Note that the `__original_main` is the default entry for all Wasm binaries following WASI standard.
The toolchain we mentioned in the [previous section](README.md#prerequisites) can generate Wasm binaries following WASI standard.

As we mentioned in our paper, the given Wasm will be parsed into ICFG.
Sometimes visualizing the ICFG is necessary for debugging.
Thus `--visualize` can achieve this goal.

During symbolic execution, constraints solving is a bottleneck for the performance.
We have implemented a set of optimizations on the solving process.
The `--incremental` refers to *incremental solving*, which may not always introduce positive optimizations during the analysis. Therefore, we set a flag to allow users to decidie if enable the incremental solving.

The `-v` is an optional option.
Accoding to different values, different levels of logging can be generated, which may help the debugging.

### Analyze
The `-s` is a mandatory option.
It will enable the symbolic execution analysis on the given Wasm binary.

## Example
If we want to execute a program which does not requrie any extra arguments and input, the command should be:

```shell
python main.py -f PATH_TO_WASM_BINARY -s
```

The corresponding logging and results of feasible paths will be generated in `./log` folder.

If compilicated arguments are required. For example, a `base64` program whose `main` is like:

```c
// main of base64
int main(int argc, char **argv)
{
  // environment setting
  ...

  while ((opt = getopt_long(argc, argv, "diw:", long_options, NULL)) != -1)
    switch (opt) {
      // call functions according to passed arguments
      ...
    }

  // encode or decode
}
```
We can see that the `base64` not only requires a two bytes arguments, but also needs a string of input to encode or decode. Also, the encoded or decoded results will go to a file.
Thus, the command to analyze the `base64` is like:

```shell
python main.py -f PATH_TO_BASE64 -s --sym_args 2 --sym_stdin 5 --sym_files 1 10 -v info
```


## SGX Mode

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


### Input Arguments

Our tool can be used by executing the `main.py` with the appropriate parameters. Four arguments are required. The first argument is the name of the wasm file to analyze. The second argument is the ECall list of the program, separated by commas (`,`). The third argument, which is optional, is the function list of the wasm file. If a corresponding wat file exists in the same path as the wasm file, the third argument can be omitted. The fourth argument is the mode to run WASEM. If `--symgx` is set, it will be run in SGX mode, or it will be run in normal mode. For instance, to analyze the `sgx-dent` program in SGX mode for 12 hours, execute the following command:

```shell
python3 main.py -f benchmarks/dnet.wasm --ecall-list sgx_empty_ecall,sgx_ecall_trainer,sgx_ecall_tester,sgx_ecall_classify --symgx --max-time 43200
```

It is worth noting that although we set the `--ecall-list` and `--func-list` manually, they can be automatically obtained using automated tools. However, as this is not the primary focus of this project, we leave it for future work.

To facilitate a more convenient analysis of the samples in the `benchmarks/` directory, we have provided a script. You can analyze benchmarks by executing the script with the name of the program you wish to analyze. For instance, to analyze the `sgx-dent` program, use the following command:

```shell
./run.sh sgx-dnet --max-time 43200
```

Other available programs include `sgxwallet`, `SGXCryptoFile`, `verifiable-election`, `sgx-log`, `sgx-kmeans`, `sgx-reencrypt`, `CryptoEnclave`, `sgx-pwenclave`, `sgx-deep-learning`, `sgx-biniax2`, `sgx-rsa`, `sgx_protect_file` and `SGXSSE`.

### Output Report

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
