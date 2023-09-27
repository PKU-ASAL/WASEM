#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import sys
from datetime import datetime
from os import makedirs, path

import sh
from launch import launch
from SymGX import SymGX



def main():
    parser = argparse.ArgumentParser(
        description='SeeWasm, a symbolic execution engine for Wasm module')

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

    symgx = parser.add_argument('--symgx', help='enable the branch of symgx')

    args = parser.parse_args()

    if args.symgx:
        print('0')
        SymGX(args)
    else:
        print('1')
        launch(args)

if __name__ == '__main__':
    job_start_time = datetime.now()
    current_time_start = job_start_time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"Start to analyze: {current_time_start}", flush=True)
    #Configuration.set_start_time(current_time_start)

    print(f"Running...", flush=True)
    main()
    print(f"Finished.", flush=True)

    job_end_time = datetime.now()
    current_time_end = job_end_time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"End of analyze: {current_time_end}", flush=True)
    elapsed_time = job_end_time - job_start_time
    print(f"Time elapsed: {elapsed_time}", flush=True)
