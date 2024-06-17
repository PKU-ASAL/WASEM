#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from eunomia.arch.wasm.mythread import multi_thread_process

def SymGX(args):

    octo_bytecode = args.file.read()
    Ecall_list = args.ecall_list.split(",")

    if not args.func_list:
        namelist = []
        filename = os.path.basename(args.file.name)
        watfile = filename[:-5] + ".wat"
        watpath = os.path.join(os.path.dirname(args.file.name), watfile)
        with open(watpath, 'r') as wf:
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
        namelist = args.func_list.split(",")

    if not args.max_time:
        max_time = 12*60*60
    else:
        max_time = args.max_time
    print("set time limit: %d seconds" % max_time)

    multi_thread_process(octo_bytecode, namelist, Ecall_list, max_time)
