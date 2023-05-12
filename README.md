# SYMGX

There are many memory vulnerablities hidden in exisitng SGX programs that can be exploited by the adversaries to launch memory attacks. We our goal is to develop a useful tool to detect these vulnerabilities in programs.

In this project, we have implemented a **symbolic execution framework** for SGX programs. Our framework takes the Wasm file compiled from source codes of SGX programs in C/C++, symbolically executes it and generate vulnerability reports of the programs(containing the vulnerability type, report position and the corresponding constraints).



##  Prerequisites 
To run the samples (some simple Wasm files compiled from C), you have to install some python libraries as follows:

```shell
python3 -m pip install -r requirements.txt
```

## Toolchain

To analyze the files written in other programming languages, you have to generate the corresponding Wasm file in your local environment. In this section, we would briefly give the instruction about how to compile C/C++ SGX programs into Wasm.

### Compile
We compile the C/C++ SGX programs into Wasm files with the help of Wllvm. We first modify the compiler used in the makefile of SGX programs and compile them with the compile flag -g.

```shell
CC=wllvm CXX=wllvm++ make SGX_MODE=SIM 
extract-bc xxx.so
llvm-dis xxx.bc
llc -march=wasm32 -filetype=obj xxx.ll
wasm-ld  --no-entry --export-all xxx.o --allow-undefined
wasm2wat xxx.wasm -o xxx.wat
```

We have successfully compile some benchmarks and you can find them in Benchmarks/


## Analyze
You can run the sample codes in Benchmarks by running the run.sh and specify the benchmark you want to run. We take sgx-dent as an example and you can run it with the command:

```shell
./run.sh sgx-dnet
```