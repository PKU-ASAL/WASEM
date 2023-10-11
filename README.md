# SYMGX

There are many memory vulnerablities hidden in exisitng SGX programs that can be exploited by the adversaries to launch memory attacks. We our goal is to develop a useful tool to detect these vulnerabilities in programs.

In this project, we have implemented a **symbolic execution framework** for SGX programs. Our framework takes the Wasm file compiled from source codes of SGX programs in C/C++, symbolically executes it and generate vulnerability reports of the programs(containing the vulnerability type, report position and the corresponding constraints).



##  Prerequisites 
To run SYMGX, you have to install some python libraries as follows:

```shell
python3 -m pip install -r requirements.txt
```

## Toolchain

To analyze the files written in other programming languages, you have to generate the corresponding Wasm file in your local environment. In this section, we would briefly give the instruction about how to compile C/C++ SGX programs into Wasm.

### Compile
We compile the C/C++ SGX programs into Wasm files with the help of [Wllvm](https://github.com/travitch/whole-program-llvm) and wabt. We first replace the compiler used in the makefile of SGX programs with compilers of wllvm and compile them with the compile flag `-g`.

```shell
CC=wllvm CXX=wllvm++ make SGX_MODE=SIM 
extract-bc xxx.so
llvm-dis xxx.bc
llc -march=wasm32 -filetype=obj xxx.ll
wasm-ld  --no-entry --export-all xxx.o --allow-undefined
wasm2wat xxx.wasm -o xxx.wat
```

We have successfully compile some benchmarks and you can find them in `Benchmarks/`.


## Analyze

### Input Arguments
Our tool can be used by running the main.py with correct parameters. There are three arguments needed. The first argument is the name of the wasm file to analyze. The second argument is the ECall list of the program and separated by `,`. The third argument is alternative and is the function list of thr wasm file. If there is a corresponding wat file in the same path of the wasm file, the third argument can be ommitted. For example, to analyze the sgx-dent program, we can execute the following command:
```shell
python3 main.py Benchmarks/dnet.wasm sgx_empty_ecall,sgx_ecall_trainer,sgx_ecall_tester,sgx_ecall_classify
```

It is worth noting that although we set the second and third parameters manually, they can be obtained automatically by automated tools. However, since it is not the main contribution of this work, we leave it for future work.

### Script
To provide the users a more convenient way to analyze the samples in Benchmarks/, we write a script and you can analyze benchmarks by running the script with the name of the programs you want to analyze. We take sgx-dent as an example and you can run it with the command:

```shell
./run.sh sgx-dnet
```

Other programs are sgx-dnet, sgxwallet, SGXCryptoFile, verifiable-election, sgx-log, sgx-kmeans, sgx-reencrypt, CryptoEnclave, sgx-pwenclave, sgx-deep-learning, sgx-biniax2, sgx-rsa, sgx_protect_file, SGXSSE.

### Output

The vulnerability rreports will be generated in the folder log/program-name_time. The format of a vulenrability is as follow.
```shell
{
    "Status": xxx,
    "Solution": {xxx},
    "Basic_Blocks": [xxx],
    "vulnerability": xxx,
    "iteration round": xxx,
}
```

`Solution` represents a set of values that can lead to the vulnerability instruction. `Basic_Blocks` records all the basic blocks met in the execution process, which can be used to restore the execution path and the ECall sequence. `Vulnerability` is the type of the vulnerability. `iteration round` is the round number of the vulnerability state.

## Contributors

The main contributors of WASEM are:

Teachers: Ding Li

Students: Ningyu He, Yuanpeng Wang

## Citations

If you use any of our tools or datasets in your research for publication, please kindly cite the following paper:

```
@article{he2023eunomia,
  title={Eunomia: Enabling User-specified Fine-Grained Search in Symbolically Executing WebAssembly Binaries},
  author={He, Ningyu and Zhao, Zhehao and Wang, Jikai and Hu, Yubin and Guo, Shengjian and Wang, Haoyu and Liang, Guangtai and Li, Ding and Chen, Xiangqun and Guo, Yao},
  journal={arXiv preprint arXiv:2304.07204},
  year={2023}
}
```

SymGX: Detecting Cross-boundary Pointer Vulnerabilities of SGX Applications via Static Symbolic Execution 

## Feedback

Should you have any question, please post to [the issue page]([Issues · PKU-ASAL/WASEM (github.com)](https://github.com/PKU-ASAL/WASEM/issues)), or email Yuanpeng Wang via [yuanpeng_wang@pku.edu.cn](yuanpeng_wang@pku.edu.cn).

## Acknowledgements

We would like to thank the anonymous reviewers for their valuable feedback and suggestions.