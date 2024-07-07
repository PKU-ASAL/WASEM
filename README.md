# WASEM [![test](https://github.com/PKU-ASAL/WASEM/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/PKU-ASAL/WASEM)

![logo](pic/104848503.jfif)


**WASEM is a general symbolic execution framework for WebAssembly (WASM) binaries.** It serves as the **core engine** for multiple **WASM binary analysis** tools and can be used to analyse both normal WASM programs and WASM files compiled from SGX programs *(see our ISSTA and CCS paper in the Citations section)*. Our framework processes the WASM file compiled from the source code of C/C++/Rust/Go, performs symbolic execution, and generates detailed vulnerability reports. These reports include the vulnerability type, location, and the corresponding constraints.

##  Prerequisites 

To run WASEM, ensure you have Python 3.7 or a later version installed. Then, install the required Python libraries by executing the following command:

```shell
python3 -m pip install -r requirements.txt
```

If you encounter issues building the wheel for leb128, update pip and wheel, then reinstall leb128:

```shell
pip install --upgrade pip wheel
pip install --force-reinstall leb128
```

To verify everything is set up correctly, run the following command:

```shell
python3 -m pytest test.py -vv
```

This command traverses the `./test` folder and performs symbolic execution on all Wasm binaries.
If successful, a success message will be displayed, typically **after several seconds**.

Sample Wasm binaries, including "Hello World" in C, Go, and Rust, are provided in the folder. 
These can be compiled from their respective source languages; the compilation processes are detailed in [WASI tutorial](https://github.com/bytecodealliance/wasmtime/blob/main/docs/WASI-tutorial.md#compiling-to-wasi) (C and Rust), and [WASI "Hello World" example](https://wasmbyexample.dev/examples/wasi-hello-world/wasi-hello-world.go.en-us.html) (Go).

For Rust and C++ project, you can use `wasm-tools` to demangle symbol names in the `name` section. Install with `cargo install wasm-tools`. Confirm by `wasm-tools --version`. Details can be found at [Wasm Tools](https://github.com/bytecodealliance/wasm-tools).

## Normal Mode

This section demonstrates how to use WASEM to analyze normal Wasm file.

### Options
All valid options are shown in below:

```shell
WASEM, a general symbolic execution framework for WebAssembly (WASM) binaries

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
  --search [{dfs,bfs,random,interval}]
                        set the search algorithm
```

We will detail these options according to their functionalities.

### Input Arguments
WASEM can deassemble the target binary and construct valid inputs based on the values of the input arguments.

Specifically, `-f` option is mandatory, and it must be followed by the path of the Wasm binary to be analyzed. The `--stdin STRING` and `--sym_stdin N` options allow users to pass concrete and symbolic bytes through the stdin stream, respectively. A concrete string must be passed using `--stdin`, while a string consisting of `N` symbolic characters must be passed using `--sym_stdin`. For example, `--sym_stdin 5` inputs 5 symbolic bytes for functions that read from stdin.

Similarly, `--args STRING1, STRING2, ...` and `--sym_args N1, N2, ...` options pass concrete and symbolic arguments to the Wasm binary. For instance, if `main` requires three arguments, each two bytes long, `--sym_args 2 2 2` is enough.

Some programs interact with files. WASEM simulates this using a *symbolic file system*. Users can create `N` symbolic files, each with up to `M` bytes, using the `--sym_files N M` option.

As multiple high-level programming languages can be compiled to Wasm binaries, we have implemented specific optimizations. To take advantage of these optimizations, users must indicate the source language using the `--source_type` option.

### Features
`--entry` specifies the entry function from which symbolic execution begins. By default, the entry function is `__original_main`. Users must specify a proper entry function to ensure the symbolic execution is performed correctly.

The input Wasm is parsed into an Interprocedural Control Flow Graph (ICFG), which can be visualized for debugging purposes using the `--visualize` option (requires `graphviz`, installable via `sudo apt install graphviz` on Ubuntu).

The constraint solving process is a bottleneck for symbolic execution performance; however, we have implemented some optimizations to mitigate this issue. The `--incremental` flag enables *incremental solving*. Note that it may not always yield positive results during analysis, and is therefore optional.

The `-v` option controls the logging level, allowing users to adjust the verbosity of logging output to aid in debugging.

### Analyze
The `-s` is a mandatory option. It enables symbolic execution analysis on the given Wasm binary.

The `--search` option specifies the search algorithm used during symbolic execution. The default algorithm is Depth-First Search (DFS), but users can choose from the following options: `bfs`, `random`, and `interval`.

### Output
The output of WASEM, including logs and results, is stored in the `output` folder, with each file named according to the pattern `NAME_TIMESTAMP`.

The log file follows a specific format, which illustrates the call trace of the anaylzed program:

```log
2024-07-01 07:50:36,191 | WARNING | Totally remove 27 unrelated functions, around 50.000% of all functions
2024-07-01 07:50:36,205 | INFO | Call: __original_main -> __main_void
2024-07-01 07:50:36,218 | INFO | Call: __main_void -> __wasi_args_sizes_get
2024-07-01 07:50:36,219 | INFO | Call: args_sizes_get (import)
2024-07-01 07:50:36,219 | INFO | 	args_sizes_get, argc_addr: 70792, arg_buf_size_addr: 70796
2024-07-01 07:50:36,219 | INFO | Return: args_sizes_get (import)
2024-07-01 07:50:36,219 | INFO | Return: __wasi_args_sizes_get
...
```

The result is a JSON file containing feasible paths with their solutions, formatted as follows:

```json
{
    "Status": "xxx",
    "Solution": {"xxx"},
    "Output": [
        {
            "name": "stdout",
            "output": "xxx"
        },
        {
            "name": "stderr",
            "output": "xxx"
        }
    ]
}
```

You can use `./clean.sh -f` to remove all files in the `output` folder.

### Example
To execute a program that takes no extra arguments or input, use the following command:

```shell
python3 launcher.py -f PATH_TO_WASM_BINARY -s
```

If compilicated arguments are required, for example, a `base64` program with a `main` function like:

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

The `base64` program expects two-byte arguments and a string input to encode or decode, producing output that is written to a file.
Thus, the command to analyze `base64` is like:

```shell
python3 launcher.py -f PATH_TO_BASE64 -s --sym_args 2 --sym_stdin 5 --sym_files 1 10
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

The vulnerability reports will be generated in the directory `output/result/PROGRAM_NAME`. The format of a vulnerability report is as follows:

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

If you have any questions or need further clarification, please post on the [Issues](https://github.com/PKU-ASAL/WASEM/issues) page, or you can directly email Yuanpeng Wang at [yuanpeng_wang@pku.edu.cn](yuanpeng_wang@pku.edu.cn).

## Acknowledgements

We would like to thank the anonymous reviewers for their valuable feedback and suggestions.
