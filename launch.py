#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import sys
from datetime import datetime
from os import makedirs, path

import sh

from seewasm.arch.wasm.configuration import Configuration
from seewasm.arch.wasm.graph import Graph
from seewasm.arch.wasm.visualizator import visualize


def launch(args):

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
        Configuration.set_file(args.file.name)
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
        parser.print_help()


