#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import sys
from datetime import datetime
from os import makedirs, path

import sh

from seewasm.arch.wasm.configuration import Configuration

def do_symgx(args):
    from SymGX import SymGX
    # ecall_list must be specified
    if not args.ecall_list:
        print("Error: --symgx requires --ecall-list")
        exit(1)
    SymGX(args)

def do_normal(args):
    module_bytecode = args.file.read()
    # create the corresponding wat file
    wat_file_path = args.file.name.replace('.wasm', '.wat')
    if not path.exists(wat_file_path):
        sh.Command('wasm2wat')([args.file.name, "-o", wat_file_path])
        print(
            f"The corresponding wat file is written in: {wat_file_path}",
            flush=True)
    # conduct symbolic execution
    if args.symbolic:
        Configuration.set_verbose_flag(args.verbose)
        Configuration.set_entry(args.entry)
        Configuration.set_visualize(args.visualize)
        Configuration.set_source_type(args.source_type)
        Configuration.set_stdin(args.stdin, args.sym_stdin)
        Configuration.set_sym_files(args.sym_files)
        Configuration.set_incremental_solving(args.incremental)
        Configuration.set_elem_index_to_func(wat_file_path)

        command_file_name = f"./log/result/{Configuration.get_file_name()}_{Configuration.get_start_time()}/command.json"
        makedirs(path.dirname(command_file_name), exist_ok=True)
        with open(command_file_name, 'w') as fp:
            json.dump({"Command": " ".join(sys.argv)}, fp, indent=4)

        # --args and --sym_args can exist simultaneously
        # their order are fixed, i.e., --args is in front of --sym_args
        # the file_name is always the argv[0]
        Configuration.set_args(
            Configuration.get_file_name(),
            args.args, args.sym_args)

        # import necessary part
        from seewasm.arch.wasm.emulator import WasmSSAEmulatorEngine
        from seewasm.arch.wasm.graph import Graph
        from seewasm.arch.wasm.visualizator import visualize

        wasmVM = WasmSSAEmulatorEngine(module_bytecode)
        # run the emulator for SSA
        Graph.wasmVM = wasmVM
        Graph.initialize()
        # draw the ICFG on basic block level, and exit
        if Configuration.get_visualize():
            # draw here
            visualize(Graph)

            print(f"The visualization of ICFG is done.")
            return

        graph = Graph()
        graph.traverse()
    else:
        pass

def parse():
    parser = argparse.ArgumentParser(
        description='WASEM, a general symbolic execution framework for WebAssembly (WASM) binaries ')

    inputs = parser.add_argument_group('Input arguments')
    inputs.add_argument('-f', '--file',
                        type=argparse.FileType('rb'),
                        help='binary file (.wasm)',
                        metavar='WASMMODULE', required=True)
    inputs.add_argument('--stdin',
                        action='store',
                        type=str,
                        help='stream of stdin')
    inputs.add_argument('--sym_stdin',
                        action='store',
                        type=int,
                        nargs=1,
                        help='stream of stdin in N bytes symbols')
    inputs.add_argument('--args',
                        action='store',
                        type=str,
                        help='command line')
    inputs.add_argument(
        '--sym_args', type=int, nargs='+',
        help="command line in symbols, each of them is N bytes at most")
    inputs.add_argument(
        '--sym_files', type=int, nargs=2,
        help="Create N symbolic files, each of them has M symbolic bytes")
    inputs.add_argument(
        '--source_type', default='c', const='c', nargs='?',
        choices=['c', 'go', 'rust'],
        help='type of source file')

    features = parser.add_argument_group('Features')
    features.add_argument(
        '--entry', type=str, nargs=1, default=["__original_main"],
        help='set entry point as the specilized function')
    features.add_argument(
        '--visualize', action='store_true',
        help='visualize the ICFG on basic blocks level')
    features.add_argument(
        '--incremental', action='store_true',
        help='enable incremental solving')
    features.add_argument(
        '-v', '--verbose', default='warning', const='warning', nargs='?',
        choices=['warning', 'info', 'debug'],
        help='set the logging level')

    analyze = parser.add_argument_group('Analyze')
    analyze.add_argument(
        '-s', '--symbolic', action='store_true',
        help='perform the symbolic execution')
    analyze.add_argument(
        '--max-time', action='store', type=int,
        help='maximum time in seconds')

    symgx = parser.add_argument_group('Symgx')
    symgx.add_argument('--symgx', action='store_true', help='enable the branch of symgx', default=False)
    symgx.add_argument('--ecall-list', help='ecall list string, separated by commas (`,`)')
    symgx.add_argument('--func-list', help='function list string, separated by commas (`,`)')

    args = parser.parse_args()
    return args

def main():
    args = parse()
    job_start_time = datetime.now()
    current_time_start = job_start_time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"Start to analyze: {current_time_start}", flush=True)
    Configuration.set_file(args.file.name)
    Configuration.set_start_time(job_start_time.strftime("%Y%m%d%H%M%S"))
    print(f"Running...", flush=True)

    if args.symgx:
        do_symgx(args)
    else:
        do_normal(args)

    print(f"Finished.", flush=True)
    job_end_time = datetime.now()
    current_time_end = job_end_time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"End of analyze: {current_time_end}", flush=True)
    elapsed_time = job_end_time - job_start_time
    print(f"Time elapsed: {elapsed_time}", flush=True)

if __name__ == '__main__':
    main()