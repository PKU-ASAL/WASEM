from threading import Lock, Thread, currentThread
from time import sleep
from eunomia.arch.wasm.emulator import WasmSSAEmulatorEngine
#from eunomia.arch.wasm.pathgraph import Graph
from eunomia.arch.wasm.configuration import Configuration
from collections import defaultdict
from queue import PriorityQueue
import time

CoreNum = 1
alive = False
block_visit = set()
tuple_seen = list()
state_pool = PriorityQueue()
state_pool_lock = Lock()
edge_num = defaultdict(int)
edge_num_lock = Lock()

wasmVMdict = dict()


GlobalEcallList = list()

statenum = 0

basicblock_num = 0

basicblock_file = "bb.txt"

def Init_state(wasmVM, func):
    func_index_name, param_str, _, _ = wasmVM.get_signature(func)

    return wasmVM.init_state(func, param_str)

class myThread(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        from eunomia.arch.wasm.pathgraph import Graph
        t = currentThread()
        with open(basicblock_file, 'a') as f:
            f.write("basic block num: %d\n"%(basicblock_num))  
        T1 = time.time()
        global alive
        while alive:
            state_pool_lock.acquire()
            if not state_pool.empty():
                score, (state, func) = state_pool.get()
                state_pool_lock.release()
                print('Thread id : %d get a state %d and start to process' % (t.ident, state.statenum))
                wasmVM = wasmVMdict[func]
                # run the emulator for SSA
                graph = Graph(func)
                graph.wasmVM = wasmVM
                graph.GlobalEcallList = GlobalEcallList
                graph.round = round
                graph.manual_guide = False
                graph.initialize()
                graph.traverse(state)
                print('Thread id : %d finish a state' % t.ident)
                T2 = time.time()
                with open(basicblock_file, 'a') as f:
                    f.write("%f %d\n"%(T2-T1, len(block_visit)))  
            else:
                state_pool_lock.release()
                print('Thread id : %d get nothing fall asleep' % t.ident)
                sleep(30)

def multi_thread_process(octocode, namelist, Ecall_list):
    global GlobalEcallList
    global statenum
    global basicblock_num
    GlobalEcallList = Ecall_list

    wasmVM = WasmSSAEmulatorEngine(isglobal = True, bytecode = octocode, namelist = namelist)

    basicblock_num = len(wasmVM.cfg.basicblocks)
    for func in Ecall_list:
        state = Init_state(wasmVM, func)
        state.statenum = statenum
        statenum += 1
        state_pool.put((-999, (state, func)))
        wasmVMdict[func] = WasmSSAEmulatorEngine(isglobal = False, Engine = wasmVM, entryFunc = func)

    global alive
    alive = True
    threadlist = []
    for i in range(CoreNum):
        threadlist.append(myThread())

    for thread in threadlist:
        thread.start()

    sleep(43200)
    alive = False

    for thread in threadlist:
        thread.join()
    
