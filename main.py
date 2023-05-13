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

def main():

    filename = sys.argv[1]
    Ecall_list = sys.argv[2].split(",")

    with open(filename,'rb') as f:
        octo_bytecode = f.read()
    f.close()

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



if __name__ == '__main__':
    job_start_time = datetime.now()
    current_time_start = job_start_time.strftime("%Y-%m-%d %H:%M:%S")
    # print(f"Start to analyze: {current_time_start}", flush=True)
    Configuration.set_start_time(current_time_start)

    main()

    job_end_time = datetime.now()
    current_time_end = job_end_time.strftime("%Y-%m-%d %H:%M:%S")
    # print(f"End of analyze: {current_time_end}", flush=True)
    elapsed_time = job_end_time - job_start_time
    print(f"Time elapsed: {elapsed_time}", flush=True)
