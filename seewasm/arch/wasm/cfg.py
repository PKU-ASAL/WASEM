# Its purpose is to generate the CFG and visualize it

from collections import defaultdict
from logging import getLogger

from seewasm.analysis.cfg import CFG
from seewasm.arch.wasm.analyzer import WasmModuleAnalyzer
from seewasm.arch.wasm.configuration import Configuration
from seewasm.arch.wasm.disassembler import WasmDisassembler
from seewasm.arch.wasm.format import format_bb_name, format_func_name
from seewasm.arch.wasm.utils import readable_internal_func_name
from seewasm.core.basicblock import BasicBlock
from seewasm.core.edge import (EDGE_CALL, EDGE_CONDITIONAL_FALSE,
                               EDGE_CONDITIONAL_TRUE, EDGE_FALLTHROUGH,
                               EDGE_UNCONDITIONAL, Edge)
from seewasm.core.function import Function
from seewasm.core.utils import bytecode_to_bytes

logging = getLogger(__name__)

DESIGN_IMPORT = {'fillcolor': 'turquoise',
                 'shape': 'box',
                 'style': 'filled'}

DESIGN_EXPORT = {'fillcolor': 'grey',
                 'shape': 'box',
                 'style': 'filled'}


def enum_func(module_bytecode):
    """
    return a list of Function
    see:: seewasm.core.function
    """

    functions = list()
    analyzer = WasmModuleAnalyzer(module_bytecode)

    protos = analyzer.func_prototypes
    import_len = len(analyzer.imports_func)

    for idx, code in enumerate(analyzer.codes):
        # get corresponding function prototype
        name, param_str, return_str, _ = protos[import_len + idx]

        prefered_name = format_func_name(name, param_str, return_str)
        instructions = WasmDisassembler().disassemble(code)
        cur_function = Function(0, instructions[0], name=name,
                                prefered_name=prefered_name)
        cur_function.instructions = instructions

        cur_function.end_offset = instructions[-1].offset_end
        cur_function.end_instr = instructions[-1]
        cur_function.size = sum([i.size for i in instructions])

        functions.append(cur_function)
    return functions


def enum_func_name_call_indirect(functions):
    ''' return a list of function name if they used call_indirect
    '''
    func_name = list()

    # iterate over functions
    for func in functions:
        for inst in func.instructions:
            if inst.name == "call_indirect":
                func_name.append(func.name)
    func_name = list(set(func_name))
    return func_name


def enum_func_call_edges(functions, len_imports):
    ''' return a list of tuple with
        (index_func_node_from, index_func_node_to)
    '''
    call_edges = list()

    # iterate over functions
    for index, func in enumerate(functions):
        node_from = len_imports + index
        # iterates over instruction
        for inst in func.instructions:
            # detect if inst is a call instructions
            if inst.name == "call":  # is_call:
                # logging.debug('%s', inst.operand_interpretation)
                # if inst.name == "call":
                # only get the import_id
                import_id = inst.operand_interpretation.split(' ')[1]
                if import_id.startswith('0x'):
                    import_id = int(import_id, 16)
                else:
                    import_id = int(import_id)
                node_to = int(import_id)
                # The `call_indirect` operator takes a list of function arguments and as the last operand the index into the table.
                # elif inst.name == "call_indirect":
                # the last operand is the index on the table
                # print(inst.operand_interpretation)
                # print(type(inst.insn_byte[1]))
                # node_to = inst.insn_byte[1]
                # node_to = int(inst.operand_interpretation.split(',')[-1].split(' ')[-1])
                call_edges.append((node_from, node_to))

    return call_edges


def enum_blocks_edges(function_id, instructions):
    """
    Return a list of basicblock after
    statically parsing given instructions
    """

    basicblocks = list()
    edges = list()

    branches = []
    xrefs = set()

    intent = 0
    blocks_tmp = []
    blocks_list = []

    # it can be used to quickly find a given inst in instructions
    instructions_id_to_index = {}
    for i, inst in enumerate(instructions):
        instructions_id_to_index[id(inst)] = i

    # we need to do that because jump label are relative to the current block index
    for index, inst in enumerate(instructions[:-1]):

        if inst.is_block_terminator:
            start, name = blocks_tmp.pop()
            if inst.name == 'else':
                end = inst.offset - 1
            else:
                end = inst.offset_end
            blocks_list.append((intent, start, end, name))
            intent -= 1
        if inst.is_block_starter:  # in ['block', 'loop']:
            blocks_tmp.append((inst.offset, inst.name))
            intent += 1
        if inst.is_branch:
            branches.append((intent, inst))

    # add function body end
    blocks_list.append((0, 0, instructions[-1].offset_end, 'func'))
    blocks_list = sorted(blocks_list, key=lambda tup: (tup[1], tup[0]))

    # print(blocks_list)

    for depth, inst in branches:
        labl = list()
        if inst.name == 'br_table':
            labl = [i for i in inst.insn_byte[2:]]
        else:
            labl.append(int(inst.operand_interpretation.split(' ')[-1]))

        for d2 in labl:  # intent, start, end, name
            rep = next(((i, s, e, n) for i, s, e, n in blocks_list if (
                i == (depth - d2) and s < inst.offset and e > inst.offset_end)), None)

            if rep:
                i, start, end, name = rep
                # if we branch to a 'loop' label
                # we go at the entry of the 'loop' block
                if name == 'loop':
                    value = start
                # if we branch to a 'block' label
                # we go at the end of the "block" block
                elif name == 'block' or name == 'func':
                    value = end
                # we don't know
                else:
                    value = None
                inst.xref.append(value)
                xrefs.add(value)

    # assign xref for "if" branch
    # needed because 'if' don't used label
    for index, inst in enumerate(instructions[:-1]):
        if inst.name == 'if':
            g_block = next(
                iter([b for b in blocks_list if b[1] == inst.offset]), None)
            jump_target = g_block[2] + 1
            inst.xref.append(jump_target)
            xrefs.add(jump_target)
        elif inst.name == 'else':
            g_block = next(
                iter([b for b in blocks_list if b[1] == inst.offset]), None)
            jump_target = g_block[2] + 1
            inst.xref.append(jump_target)
            xrefs.add(jump_target)

    # enumerate blocks
    new_block = True

    for index, inst in enumerate(instructions):

        # creation of a block
        if new_block:
            block = BasicBlock(inst.offset,
                               inst,
                               name=format_bb_name(function_id, inst.offset))
            new_block = False
        # add current instruction to the basicblock
        block.instructions.append(inst)

        # next instruction is a jump target
        if index < (len(instructions) - 1) and \
                instructions[index + 1].offset in xrefs:
            new_block = True
        # absolute jump - br
        elif inst.is_branch_unconditional:
            new_block = True
        # conditionnal jump - br_if
        elif inst.is_branch_conditional:
            new_block = True
        # is_block_terminator
        # GRAPHICAL OPTIMIZATION: merge end together
        elif index < (len(instructions) - 1) and \
                instructions[index + 1].name in ['else', 'loop']:  # is_block_terminator
            new_block = True
        # last instruction of the bytecode
        elif inst.offset == instructions[-1].offset:
            new_block = True

        if new_block:
            block.end_offset = inst.offset_end
            block.end_instr = inst
            basicblocks.append(block)
            new_block = True

    # enumerate edges
    for index, block in enumerate(basicblocks):
        # get the last instruction
        inst = block.end_instr
        # unconditional jump - br
        if inst.is_branch_unconditional:
            for ref in inst.xref:
                edges.append(Edge(block.name, format_bb_name(
                    function_id, ref), EDGE_UNCONDITIONAL))
        # conditionnal jump - br_if, if, br_table
        elif inst.is_branch_conditional:
            if inst.name == 'if':
                edges.append(Edge(block.name,
                                  format_bb_name(
                                      function_id, inst.offset_end + 1),
                                  EDGE_CONDITIONAL_TRUE))
                if_b = next(
                    iter([b for b in blocks_list if b[1] == inst.offset]),
                    None)
                # else_block = blocks_list[blocks_list.index(if_block) + 1]
                jump_target = if_b[2] + 1
                edges.append(Edge(block.name,
                                  format_bb_name(function_id, jump_target),
                                  EDGE_CONDITIONAL_FALSE))
            # we add it to correct the br_table behavior
            # we define the default branch is conditional_false
            # the others as consitional_true @wasm-se
            elif inst.name == 'br_table':
                # conditional_true's
                labels = [i for i in inst.insn_byte[2:]]
                for _index, ref in enumerate(inst.xref):
                    for _block in basicblocks:
                        if ref and _block.instructions[0].offset == ref:
                            if _index != len(inst.xref) - 1:
                                edges.append(
                                    Edge(
                                        block.name, _block.name,
                                        f'{EDGE_CONDITIONAL_TRUE}_{str(labels[_index])}'))
                            else:
                                edges.append(
                                    Edge(
                                        block.name, _block.name,
                                        EDGE_CONDITIONAL_FALSE + '_0'))
                            break
            else:
                for ref in inst.xref:
                    # if ref != inst.offset_end + 1:
                    # I comment the above statement because there is a situation that
                    # both true and false branch jump to the same destination. We have
                    # to keep the true branch, though it is useless
                    # create conditionnal true edges
                    edges.append(Edge(block.name,
                                      format_bb_name(function_id, ref),
                                      EDGE_CONDITIONAL_TRUE))
                # create conditionnal false edge
                edges.append(Edge(block.name,
                                  format_bb_name(
                                      function_id, inst.offset_end + 1),
                                  EDGE_CONDITIONAL_FALSE))
        # instruction that end the flow
        elif [i.name for i in block.instructions if i.is_halt]:
            pass
        elif inst.is_halt:
            pass

        # handle the case when you have if and else following
        elif inst.offset != instructions[-1].offset and \
                block.start_instr.name != 'else' and \
                instructions[instructions_id_to_index[id(inst)] + 1].name == 'else':

            else_ins = instructions[instructions.index(inst) + 1]
            else_b = next(
                iter([b for b in blocks_list if b[1] == else_ins.offset]),
                None)

            edges.append(Edge(block.name, format_bb_name(
                function_id, else_b[2] + 1), EDGE_FALLTHROUGH))
        # add the last intruction "end" in the last block
        elif inst.offset != instructions[-1].offset:
            # EDGE_FALLTHROUGH
            edges.append(Edge(block.name, format_bb_name(
                function_id, inst.offset_end + 1), EDGE_FALLTHROUGH))

    # prevent duplicate edges
    edges = list(set(edges))
    return basicblocks, edges


class WasmCFG(CFG):
    """
    Return a CFG of a given Wasm module's bytecode
    """

    def __init__(self, module_bytecode):
        self.module_bytecode = bytecode_to_bytes(module_bytecode)

        self.functions = list()
        self.basicblocks = list()
        self.edges = list()
        self.call_graph = dict()

        self.run_static_analysis()

    def run_static_analysis(self):
        """
        Initialize three propoerties for this class, i.e., function, basic block and edge
        """
        self.functions = enum_func(self.module_bytecode)

        for idx, func in enumerate(self.functions):
            # print(func)
            func.basicblocks, edges = enum_blocks_edges(idx, func.instructions)
            # all bb name are unique so we can create global bb & edge list
            self.basicblocks += func.basicblocks
            self.edges += edges

    def get_functions_call_edges(self, analyzer, format_fname=False):

        nodes = list()
        edges = list()

        if not self.functions:
            self.functions = enum_func(self.module_bytecode)

        # create nodes
        for name, param_str, return_str, _ in analyzer.func_prototypes:
            if format_fname:
                nodes.append(format_func_name(name, param_str, return_str))
            else:
                nodes.append(name)

        # logging.debug('nodes: %s', nodes)

        # create edges
        tmp_edges = enum_func_call_edges(self.functions,
                                         len(analyzer.imports_func))

        # tmp_edges = [(node_from, node_to), (...), ...]
        for node_from, node_to in tmp_edges:
            # node_from
            name, param, ret, _ = analyzer.func_prototypes[node_from]
            if format_fname:
                from_final = format_func_name(name, param, ret)
            else:
                from_final = name
            # node_to
            name, param, ret, _ = analyzer.func_prototypes[node_to]
            to_final = format_func_name(name, param, ret)
            if format_fname:
                to_final = format_func_name(name, param, ret)
            else:
                to_final = name
            edges.append(Edge(from_final, to_final, EDGE_CALL))
        # logging.debug('edges: %s', edges)

        return (nodes, edges)

    def __str__(self):
        line = ("length functions = %d\n" % len(self.functions))
        line += ("length basicblocks = %d\n" % len(self.basicblocks))
        line += ("length edges = %d\n" % len(self.edges))
        return line

    def build_call_graph(self, analyzer):
        _, edges = self.get_functions_call_edges(analyzer)

        self.call_graph = defaultdict(set)
        for edge in edges:
            e_from = readable_internal_func_name(
                Configuration.get_func_index_to_func_name(),
                edge.node_from)
            e_to = readable_internal_func_name(
                Configuration.get_func_index_to_func_name(),
                edge.node_to)
            self.call_graph[e_from].add(e_to)

        self.call_graph = {k: list(v) for k, v in self.call_graph.items()}
