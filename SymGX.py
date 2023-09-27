#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import sys
from datetime import datetime
from os import makedirs, path

from eunomia.arch.wasm.configuration import Configuration
from eunomia.arch.wasm.pathgraph import Graph
from eunomia.arch.wasm.visualizator import visualize
from eunomia.arch.wasm.mythread import multi_thread_process

def SymGX(args):

    octo_bytecode = args.file.read()
    Ecall_list = args.symgx.split(",")

    if len(sys.argv) == 3:
        namelist = []
        watfile = filename[:-5] + ".wat"
        with open(watfile,'r') as wf:
            while True:
                line = wf.readline()
                if line == "":
                    break
                if line[0:9] == "  (func $":
                    start = 9
                    end = 10
                    while line[end] != ' ':
                        end += 1
                    name = line[start:end]
                    namelist.append(name)
        wf.close()
    else:
        namelist = sys.argv[3].split(",")
    
    # import necessary part
    from eunomia.arch.wasm.emulator import WasmSSAEmulatorEngine

    multi_thread_process(octo_bytecode, namelist, Ecall_list)




