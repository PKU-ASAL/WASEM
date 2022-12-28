from copy import deepcopy
from collections import defaultdict, deque
from queue import Queue

from eunomia.arch.wasm.configuration import Configuration
from eunomia.arch.wasm.exceptions import (ProcFailTermination,
                                          ProcSuccessTermination)
from eunomia.arch.wasm.instruction import WasmInstruction
from eunomia.arch.wasm.instructions.ControlInstructions import C_LIBRARY_FUNCS
from eunomia.arch.wasm.utils import (query_cache, readable_internal_func_name,
                                     write_result)
from eunomia.arch.wasm.mythread import state_pool_lock, block_visit, state_pool, edge_num, edge_num_lock, statenum
from eunomia.core.basicblock import BasicBlock
from eunomia.core.edge import EDGE_FALLTHROUGH
from z3 import unsat

import logging

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



# config the logger
logging_config = {
    'filename': f'./log/log/{Configuration.get_file_name()}_{Configuration.get_start_time()}.log',
    'filemode': 'w+',
    'format': '%(asctime)s | %(levelname)s | %(message)s',
}
if 'debug' == Configuration.get_verbose_flag():
    logging_config['level'] = logging.DEBUG
elif 'info' == Configuration.get_verbose_flag():
    logging_config['level'] = logging.INFO
else:
    logging_config['level'] = logging.WARNING
logging.basicConfig(**logging_config)




class Graph:
    """
    A Graph class, include several vital properties.
    Also, it is used to traverse the CFG according to the algorithm.

    Properties:
        _func_to_bbs: a mapping, from function's name to its included basic blocks (wrapped in a list);
        _bb_to_instructions: a mappming, from basic block's name to its included instruction objects (wrapped in a list);
        _aes_func: a mapping, not clear;
        _bbs_graph: a mapping, from basic block's name to a mapping, from edge type to its corresponding pointed to basic block's name;
        _rev_bbs_graph: same as above, but its reversed;
        _workers: reserved, for multi-processing;
    """
    


    

    def __init__(self, entry_func):
        self.func_to_bbs = defaultdict(list)
        self.bb_to_instructions = defaultdict(list)
        self.aes_func = defaultdict(set)
        self.bbs_graph = defaultdict(lambda: defaultdict(str))  # nested dict
        self.rev_bbs_graph = defaultdict(lambda: defaultdict(str))
        self.wasmVM = None
        self.entry = entry_func
        self.final_states = {self.entry: None}


    def initialize(self):
        """
        initialize these class properties
        """
        def init_func_to_bbs(cfg):
            """
            initialize the func_to_bbs structure
            """
            for func in cfg.functions:
                func_name, func_bbs = func.name, func.basicblocks
                self.func_to_bbs[func_name] = [bb.name for bb in func_bbs]

        def init_bbs_graph(cfg):
            """
            initialize the bbs_graph
            """
            edges = cfg.edges
            # sort the edges, according to the edge.from and edge.to,
            # or the order of br_table branches will be random, the true_0 will not corrspond to the nearest block
            # TODO quite a huge overhead, try another way
            edges = sorted(edges, key=lambda x: (
                x.node_from, int(x.node_to.split('_')[2], 16)))

            type_ids = defaultdict(lambda: defaultdict(int))
            for edge in edges:
                node_from, node_to, edge_type = edge.node_from, edge.node_to, edge.type
                # we append a number after the edge type, because the br_table may have multiple conditional_true branches. See eunomia/arch/wasm/cfg.py
                if not edge_type[-1].isdigit():
                    # non-br_table case
                    numbered_edge_type = edge_type + '_' + \
                        str(type_ids[node_from][edge_type])
                else:
                    # br_table case
                    numbered_edge_type = edge_type
                self.bbs_graph[node_from][numbered_edge_type] = node_to
                type_ids[node_from][edge_type] += 1

            # append single nodes into the bbs_graph
            for bb in cfg.basicblocks:
                bb_name = bb.name
                if bb_name not in self.bbs_graph:
                    self.bbs_graph[bb_name] = defaultdict(str)

        def init_bb_to_instr(cfg):
            """
            initialize the bb_to_instructions
            """
            bbs = cfg.basicblocks
            for bb in bbs:
                # Update the `cur_bb` fielf for each instruction
                for ins in bb.instructions:
                    ins.cur_bb = bb.name
                self.bb_to_instructions[bb.name] = bb.instructions

        def init_aes_func(cfg):
            """
            initialize the aes_func
            """
            for bb_name, instructions in self.bb_to_instructions.items():
                for instr in instructions:
                    if instr.name == 'call':  # aes rules will be regarded as instrumented function calls
                        instr_operand = instr.operand_interpretation.split(' ')[
                            1]
                        try:
                            func_offset = int(instr_operand)
                        except ValueError:
                            func_offset = int(instr_operand, 16)
                        target_func = self.wasmVM.ana.func_prototypes[func_offset]
                        func_name, _, _, _ = target_func
                        readable_name = readable_internal_func_name(
                            Configuration.get_func_index_to_func_name(), func_name)
                        # aes function's name is generated in "name$index" format.
                        if len(readable_name.split('$')) == 2:
                            self.aes_func[bb_name].add(readable_name)

        def init_dummy_blocks():
            """
            Insert dummy entry and end before and aftr each function's cfg.
            Refer to: https://github.com/HNYuuu/Wasm-SE/issues/70

            Also update basicblocks in cfg, and class variables, e.g., bbs_graph and bb_to_instructions
            """
            # extract node with zero indegree and outdegree
            for func_name, bbs in self.func_to_bbs.items():
                out_degree = {b: 0 for b in bbs}
                zero_outdegree = set()
                for b in bbs:
                    out_degree[b] += len(self.bbs_graph[b])
                for b in bbs:
                    if out_degree[b] == 0:
                        zero_outdegree.add(b)

                assert zero_outdegree, "a function should have at least one exit point"

                dummy_end_block_offset = -1
                dummy_end_block_nature_offset = -1
                for zero_outdegree_bb in zero_outdegree:
                    # the bb's end_offset is its last instruction's offset_end
                    bb_end_offset = self.bb_to_instructions[zero_outdegree_bb][
                        -1].offset_end
                    bb_end_instr_nature_offset = self.bb_to_instructions[
                        zero_outdegree_bb][-1].nature_offset
                    dummy_end_block_offset = max(
                        dummy_end_block_offset, bb_end_offset + 1)
                    dummy_end_block_nature_offset = max(
                        dummy_end_block_nature_offset,
                        bb_end_instr_nature_offset + 1)
                dummy_end_block_offset_hex = str(
                    hex(dummy_end_block_offset)[2:])

                func_index = b.split('_')[1]
                # construct dummy end
                dummy_end = BasicBlock()
                dummy_end.name = f"block_{func_index}_{dummy_end_block_offset_hex}"

                end_ins = WasmInstruction(
                    1, 'nop', None, 0, b'\x0b', 0, 0, 'dummy end',
                    offset=dummy_end_block_offset,
                    nature_offset=dummy_end_block_nature_offset)
                end_ins.cur_bb = dummy_end.name

                dummy_end.start_offset = dummy_end_block_offset
                dummy_end.start_instr = end_ins
                dummy_end.instructions = [end_ins]
                dummy_end.end_instr = end_ins
                dummy_end.end_offset = end_ins.offset_end

                # insert dummy blocks
                self.func_to_bbs[func_name].append(dummy_end.name)
                self.bb_to_instructions[dummy_end.name] = dummy_end.instructions

                # construct edges from original exit points to the dummy end block
                # and update class variables
                for exit in zero_outdegree:
                    self.bbs_graph[exit][f"{EDGE_FALLTHROUGH}_0"] = dummy_end.name
                self.bbs_graph[dummy_end.name] = defaultdict(str)

        def _remove_original_edge(bb_names):
            """
            Extract the successive block of bb_name, and return it.
            Also, remove the edge in bbs_graph
            """
            bb_to_succ_bb_mapping = dict()

            # update bbs_graph
            for bb, edge_callee_mapping in self.bbs_graph.items():
                if bb in bb_names:
                    assert len(edge_callee_mapping) == 1
                    # the succ bb is the first element of values
                    # keep the bb and succ_bb relation
                    bb_to_succ_bb_mapping[bb] = next(
                        iter(edge_callee_mapping.values()))

                    edge_callee_mapping["fallthrough_0"] = ""

            return bb_to_succ_bb_mapping

        def _find_max_fallthrough_edge_count(nested_dict, bb_name):
            edge_count = -1
            for e, callee in nested_dict[bb_name].items():
                if e.startswith('fall') and callee != "":
                    edge_count = max(edge_count, int(e.split('_')[1]))
            return edge_count + 1

        def _update_edges(bb_name, succ_bb_name, entry_name, dummy_end_name):
            """
            Insert two edges: bb_name to entry_name, dummy_end_name to callee_bb_name
            Update corresponding variables in bbs_graph
            """

            # update bbs_graph
            self.bbs_graph[bb_name][
                f"fallthrough_{_find_max_fallthrough_edge_count(self.bbs_graph, bb_name)}"] = entry_name
            self.bbs_graph[dummy_end_name][
                f"fallthrough_{_find_max_fallthrough_edge_count(self.bbs_graph, dummy_end_name)}"] = succ_bb_name

        def _update_xref(dummy_end_name, succ_bb_name, callee_op):
            """
            Append a tuple in the xref of the `nop` instruction who locates in dummy end.
            The tuple consists of: the next block's name, and its belonging function's name
            """
            dummy_end_bb_instrs = self.bb_to_instructions[dummy_end_name]
            assert len(
                dummy_end_bb_instrs) == 1, f"{dummy_end_name} consists of more than 1 instructions: {dummy_end_bb_instrs}"
            dummy_end_bb_instrs[0].xref.append((succ_bb_name, callee_op))

        def link_dummy_blocks():
            """
            Remove edges after call, directly link it to the callee's dummy entry.
            Also link the dummy end to the next instruction of the call.
            Update edges in cfg and bbs_graph in class
            """
            # this list stores which block should be updated and the callee is its value
            # each ele consists of the current bb and its callee's op
            need_update_bb_info = list()

            for bb_name, instructions in self.bb_to_instructions.items():
                last_ins = instructions[-1]
                if last_ins.name == 'call':
                    # find the dummy blocks' name
                    # if the callee is imported in, do nothing and continue
                    callee_op = last_ins.operand_interpretation.split(' ')[1]
                    try:
                        callee_op = int(callee_op)
                    except ValueError:
                        callee_op = int(callee_op, 16)
                    # if the callee is the import function
                    funcname = readable_internal_func_name(Configuration.get_func_index_to_func_name(),f"$func{callee_op}")
                    if funcname not in self.func_to_bbs.keys():
                        continue
                    # if the callee is emulated as C library funcs
                    #if funcname in C_LIBRARY_FUNCS:
                    #    continue

                    need_update_bb_info.append([bb_name, callee_op])
                elif last_ins.name == 'call_indirect':
                    # find all possible callees
                    # refer to call_indirect in `ControlInstructions.py`
                    # store all dummy blocks in pair
                    possible_callees = self.wasmVM.ana.elements[0]['elems']
                    for possible_callee in possible_callees:
                        # if the callee is the import function
                        if f"$func{possible_callee}" not in self.func_to_bbs.keys():
                            continue
                        # if the callee is emulated as C library funcs
                        if readable_internal_func_name(
                                Configuration.get_func_index_to_func_name(),
                                f"$func{possible_callee}") in C_LIBRARY_FUNCS:
                            continue

                        need_update_bb_info.append([bb_name, possible_callee])

            bb_names, _ = list(zip(*need_update_bb_info))
            # remove all bb's direct succ in bbs_graph
            # and return a dict, whose key is the bb, and the value is the succ bb
            bb_succ_bb_mapping = _remove_original_edge(set(bb_names))
            # update edges and xref
            for bb, callee_op in need_update_bb_info:
                # extract callee
                funcname = readable_internal_func_name(Configuration.get_func_index_to_func_name(),f"$func{callee_op}")
                callee_bbs = self.func_to_bbs[funcname]
                callee_entry, callee_dummy_end = callee_bbs[0], callee_bbs[-1]

                succ_bb = bb_succ_bb_mapping[bb]
                _update_edges(bb, succ_bb, callee_entry, callee_dummy_end)
                _update_xref(callee_dummy_end, succ_bb, callee_op)

        def init_rev_bbs_graph():
            for bb, edge_callee in self.bbs_graph.items():
                for edge, callee in edge_callee.items():
                    if edge not in self.rev_bbs_graph[callee]:
                        self.rev_bbs_graph[callee][edge] = bb
                    else:
                        self.rev_bbs_graph[callee][
                            f"fallthrough_{_find_max_fallthrough_edge_count(self.rev_bbs_graph, callee)}"] = bb

            # for those zero indegree
            for bb in self.bbs_graph.keys():
                if bb not in self.rev_bbs_graph:
                    self.rev_bbs_graph[bb] = defaultdict(str)

        cfg = self.wasmVM.cfg
        init_func_to_bbs(cfg)
        init_bbs_graph(cfg)
        init_bb_to_instr(cfg)
        init_aes_func(cfg)
        init_dummy_blocks()
        link_dummy_blocks()
        init_rev_bbs_graph()



    def traverse(self, state = None):
        """
        This object can be initialized by a list of functions, each of them
        will be regarded as an entry function to perform symbolic execution
        """
        entry_func = self.entry
        self.final_states[entry_func] = self.traverse_one(entry_func, state)

    def traverse_one(self, func, state=None):
        """
        Symbolically executing the given function

        Args:
            func (str): The to be analyzed function's name
            state (VMstate, optional): From which the execution will begin. Defaults to None.

        Returns:
            list(VMstate): A list of states
        """
        # func_index_name is like $func16
        func_index_name, param_str, _, _ = self.wasmVM.get_signature(func)
        if func not in self.func_to_bbs:
            func = func_index_name

        if state is None:
            state = self.wasmVM.init_state(func, param_str)
        else:
            

            self.wasmVM.init_locals(state, func, param_str) 

        # retrieve all the relevant basic blocks
        entry_func_bbs = self.func_to_bbs[func]
        # filter out the entry basic block and corresponding instructions
        entry_bb = list(filter(lambda bb: bb[-2:] == '_0', entry_func_bbs))[0]
        blks = []
        for _, bbs in self.func_to_bbs.items():
            blks += bbs

        if Configuration.get_algo() == 'interval':
            global block_visit
            if entry_bb not in block_visit:
                block_visit.add(entry_bb)
            final_states = self.algo_interval(entry_bb, state, blks)
        else:
            raise Exception("There is no traversing algorithm you required.")

        return final_states

    def has_cycle(self, u, g, nodes, vis):
        vis.add(u)
        for t in g[u]:
            if g[u][t] in nodes and (
                g[u][t] in vis or self.has_cycle(g[u][t],
                                                g, nodes, vis)):
                return True
        vis.remove(u)
        return False

    def algo_interval(self, entry, state, blks):
        """
        Traverse the CFG according to intervals.
        See our paper for more details
        """
        # rg, g, ninterval = self.rev_bbs_graph, self.bbs_graph, 0
        # while True:
        #     intervals = self.intervals_gen(entry, blks, rg, g)
        #     if len(intervals) == ninterval:
        #         break
        #     ninterval = len(intervals)
        #     no_cycle_nodes = {}
        #     c = 0
        #     for h in intervals:
        #         if not self.has_cycle(h, g, intervals[h], set()):
        #             for v in intervals[h]:
        #                 no_cycle_nodes[v] = {v}
        #         else:
        #             no_cycle_nodes[h] = intervals[h]
        #     heads = {v: head
        #              for head in no_cycle_nodes for v in no_cycle_nodes
        #              [head]}
        #     nrg, ng = defaultdict(
        #         lambda: defaultdict(str)), defaultdict(
        #         lambda: defaultdict(str))
        #     for v in g:
        #         if v in heads:
        #             for t in g[v]:
        #                 if g[v][t] in heads:
        #                     ng[heads[v]][t] = heads[g[v][t]]
        #     for v in rg:
        #         if v in heads:
        #             for t in rg[v]:
        #                 if rg[v][t] in heads:
        #                     nrg[heads[v]][t] = heads[rg[v][t]]
        #     rg, g = nrg, ng
        # print(ninterval)
        # a mapping from a node to its corresponding interval's head
        intervals = self.intervals_gen(
            entry, blks, self.rev_bbs_graph, self.bbs_graph)
        heads = {v: head for head in intervals for v in intervals[head]}
        heads['return'] = 'return'

        final_states = self.visit_interval([state], entry, heads, "return")


        return final_states["return"]
    
    def push_in_queue(self, state):
        global statenum
        for ecall in self.GlobalEcallList:
            state_pool_lock.acquire()
            _state = deepcopy(state)
            _state.statenum = statenum
            statenum += 1
            state_pool.put((state.round - state.new_branches,(_state, ecall)))
            state_pool_lock.release()
            print(f"state {state.statenum} generate state {_state.statenum}")



    def intervals_gen(self, blk, blk_lis, revg, g):
        """
        Generate intervals according to paper: Frances E Allen. 1970. Control flow analysis

        Return:
            intervals, a mapping, from each interval's head to the interval's composed nodes
        """
        intervals = {}
        nodes = set(blk_lis)
        que = deque([blk])
        while que:
            current_block = que.popleft()
            new_interval = {current_block}
            while True:
                succs = set([g[v][t] for v in new_interval for t in g[v]])
                succs = succs - new_interval
                ext = set()
                for v in succs:
                    prevs = set([revg[v][t] for t in revg[v]])
                    if prevs <= new_interval:
                        ext.add(v)
                new_interval |= ext
                if not ext:
                    break
            nodes = nodes - new_interval
            new_header = set()

            # modified version:
            for node in new_interval:
                for possible_header in g[node].values():
                    if possible_header in nodes:
                        new_header.add(possible_header)

            # original version:
            # for v in nodes:
            #     prevs = revg[v].values()
            #     if not new_interval.isdisjoint(prevs):
            #         new_header.add(v)

            que.extend(list(new_header))
            intervals[current_block] = new_interval
        return intervals

    def visit_interval(self, states, blk, heads, prev=None):
        """
        Performing interval traversal, see our paper for more details

        Note: `blk` is the head of an interval
        """

        que = Queue()  # takes minimum value at first
        que._put((states, blk, blk))
        final_states = defaultdict(list)

        def producer():
            while not que.empty():
                yield que._get()

        # @wrap_non_picklable_objects
        def consumer(item):
            (state, current_block, cur_head) = item
            succs_list = self.bbs_graph[current_block].items()
            halt_flag = False
            # adopt DFS to traverse two intervals
            try:
                # print(current_block)
                for _state in state:
                    _state.block_list.append(current_block)
                #print(bcolors.OKGREEN,"start a block",bcolors.ENDC)
                emul_states = self.wasmVM.emulate_basic_block(
                    state, self.bb_to_instructions[current_block])
                #print(bcolors.OKBLUE,"end a block",bcolors.ENDC)
            except ProcSuccessTermination:
                # end of path
                return False, state
            except ProcFailTermination:
                # trigger exit()
                write_result(state[0])
                return False, state
            if len(succs_list) == 0:
                halt_flag = False
                return halt_flag, emul_states

            avail_br = {}
            for edge_type, next_block in succs_list:
                valid_state = list(
                    filter(
                        lambda s: not self.can_cut(
                            edge_type, next_block, s),
                        emul_states))
                if len(valid_state) > 0:
                    avail_br[(edge_type, next_block)] = valid_state
            # rest:
            # current_bb_name, it is only set in store_context and restore_context
            # edge_type, it is only set in br_if, if and br_table
            for valid_state in avail_br.values():
                for s in valid_state:
                    s.current_bb_name = ''
                    s.edge_type = ''

            for br in avail_br:
                (edge_type, next_block), valid_state = br, avail_br[br]
                new_head = heads[next_block]

                
                for valid_state_item in valid_state:
                    edge_num_lock.acquire()
                    if edge_num[(current_block, next_block)] == 0:
                        valid_state_item.new_branches += 1
                    edge_num[(current_block, next_block)] += 1
                    edge_num_lock.release()
                    que.put(([valid_state_item], next_block, new_head))
                    
                    if next_block not in block_visit:
                        block_visit.add(next_block)
            return halt_flag, []

        for item in producer():
            halt_flag, emul_states = consumer(item)

            for item in emul_states:
                # only the block that locates at the end of the entry function
                # can be regarded as end of path
                if item.new_branches:
                    item.new_branches = 0
                    item.round += 1
                    self.push_in_queue(item)
                if readable_internal_func_name(
                        Configuration.get_func_index_to_func_name(),
                        item.current_func_name) == Configuration.get_entry():
                    write_result(item)
            
            final_states['return'].extend(emul_states)
            #if halt_flag:
            #    break
        return final_states

    def sat_cut(self, solver):
        # TODO need cached here
        return unsat == query_cache(solver)

    def can_cut(self, edge_type, next_block, state):
        """
        The place in which users can determine if cut the branch or not (Default: according to SMT-solver).
        """
        if state.edge_type:
            not_same_edge = state.edge_type != edge_type
            return not_same_edge or self.sat_cut(state.solver)

        if state.current_bb_name == '':
            # normal situation, check the current_func_name
            cur_func = state.current_func_name
            found = -1
            for func, blks in self.func_to_bbs.items():
                if next_block in blks:
                    found = 1
                    break
            assert found
            not_same_func = readable_internal_func_name(
                Configuration.get_func_index_to_func_name(),
                cur_func) != readable_internal_func_name(
                Configuration.get_func_index_to_func_name(),
                func)

            return not_same_func or self.sat_cut(state.solver)
        else:
            # after restore_context, check the current_bb_name
            cur_bb = state.current_bb_name
            for _, blks in self.func_to_bbs.items():
                try:
                    cur_bb_index = blks.index(cur_bb)
                except ValueError:
                    continue

                succ_block = blks[cur_bb_index + 1]
                break

            not_same_bb = succ_block != next_block
            return not_same_bb or self.sat_cut(state.solver)

