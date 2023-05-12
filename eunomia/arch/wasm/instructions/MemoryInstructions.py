# emulate the memory related instructions
from copy import deepcopy
import re
from datetime import datetime
from eunomia.arch.wasm.configuration import bcolors
from eunomia.arch.wasm.dwarfParser import (get_func_index_from_state,
                                           get_source_location_string)
from eunomia.arch.wasm.memanalyzer import DATA_BASE
from eunomia.arch.wasm.exceptions import UnsupportInstructionError
from eunomia.arch.wasm.memory import (insert_symbolic_memory,
                                      lookup_symbolic_memory_data_section)
from eunomia.arch.wasm.utils import getConcreteBitVec, write_vulnerabilities
from eunomia.arch.wasm.shadow import shadow
from z3 import (BitVecVal, BitVec, Extract, Float32, Float64, SignExt, ZeroExt,
                fpBVToFP, fpToIEEEBV, is_bv_value, is_bv, simplify, And, sat, Or)
from eunomia.arch.wasm.utils import one_time_query_cache

memory_count = 2
memory_step = 2


class MemoryInstructions:
    def __init__(self, instr_name, instr_operand, instr_string):
        self.instr_name = instr_name
        self.instr_operand = instr_operand
        self.instr_str = instr_string

    def emulate(self, state, data_section, analyzer):
        global memory_count, memory_step
        states = []
        if self.instr_name == 'current_memory':
            state.symbolic_stack.append(BitVecVal(memory_count, 32))
            states = [state]
        elif self.instr_name == 'grow_memory':
            prev_size = memory_count
            memory_count += memory_step
            state.symbolic_stack.append(BitVecVal(prev_size, 32))
            states = [state]
        elif 'load' in self.instr_name:
            states = load_instr(self.instr_str, state, data_section, analyzer)
        elif 'store' in self.instr_name:
            states = store_instr(self.instr_str, state, analyzer)
        else:
            raise UnsupportInstructionError

        return states


def load_instr(instr, state, data_section, analyzer):
    base = state.symbolic_stack.pop()
    shadow_base = state.shadow_stack.pop()
    # offset maybe int or hex
    try:
        offset = int(instr.split(' ')[2])
    except ValueError:
        offset = int(instr.split(' ')[2], 16)
    addr = simplify(base + offset)

    

    # determine how many bytes should be loaded
    # the dict is like {'8': 1}
    bytes_length_mapping = {str(k): k // 8 for k in range(8, 65, 8)}
    instr_name = instr.split(' ')[0]
    if len(instr_name) == 8:
        load_length = bytes_length_mapping[instr_name[1:3]]
    else:
        load_length = bytes_length_mapping[re.search(
            r"load([0-9]+)\_", instr_name).group(1)]


    if shadow_base.stack_pointer:
        func_variables = analyzer.func_variables[state.current_func_name] 
        find = 0
        for _name, _tag, _offset, _size in func_variables:
            if _offset == offset:
                find = 1
                _shadow = shadow(shadow_base.taint, True, addr, False, _size, False)
                break
        if not find:
            offsets = [x[2] for x in analyzer.func_variables[state.current_func_name]]
            offsets.append(analyzer.func_stack_length[state.current_func_name]) 
            offsets.sort()
            for x in offsets:
                if x > offset:
                    size = x - offset
                    break
            _shadow = shadow(shadow_base.taint, True, addr, False, size, False)
        shadow_base = _shadow

    assert shadow_base.pointer or is_bv_value(base)
    if shadow_base.pointer:
        if shadow_base.taint:
            if shadow_base.pointer > 0:
                if shadow_base.base_taint:
                    op = And(addr > analyzer.enclave_bounds[0], addr + load_length < analyzer.enclave_bounds[1], addr + load_length > addr)
                    if sat == one_time_query_cache(state.solver, op):
                        func_ind = get_func_index_from_state(analyzer, state)
                        func_offset = state.instr.offset
                        write_vulnerabilities(state, state, f"load taint pointer within enclave{get_source_location_string(analyzer, func_ind, func_offset)}")

                        op = And(addr >= analyzer.enclave_bounds[1], addr + load_length > addr)
                        if sat == one_time_query_cache(state.solver, op):
                            state.solver.add()
                            state.symbolic_stack.append(BitVec("{"+state.current_func_name + "_load_from(" + str(addr)+")out_of_enclave"+str(datetime.timestamp(datetime.now()))[-5:]+"}", load_length * 8))
                            state.shadow_stack.append(shadow(True, -1))
                            return [state]
                        else:
                            return []
                    else:
                        state.symbolic_stack.append(BitVec("{"+state.current_func_name + "_load_from(" + str(addr)+")out_of_enclave"+str(datetime.timestamp(datetime.now()))[-5:]+"}", load_length * 8))
                        state.shadow_stack.append(shadow(True, -1))
                        return [state]
                else:
                    op = And(Or(addr < shadow_base.base, addr + load_length > shadow_base.base + shadow_base.size), addr + load_length > addr)
                    if sat == one_time_query_cache(state.solver, op):
                        func_ind = get_func_index_from_state(analyzer, state)
                        func_offset = state.instr.offset
                        write_vulnerabilities(state, f"load taint length out of bound{get_source_location_string(analyzer, func_ind, func_offset)}")
                        return []
            else:
                op = And(addr > analyzer.enclave_bounds[0], addr + load_length < analyzer.enclave_bounds[1], addr + load_length > addr)
                if sat == one_time_query_cache(state.solver, op):
                    func_ind = get_func_index_from_state(analyzer, state)
                    func_offset = state.instr.offset
                    write_vulnerabilities(state, f"load unknown type of taint variable{get_source_location_string(analyzer, func_ind, func_offset)}")

                    op = And(addr >= analyzer.enclave_bounds[1], addr + load_length > addr)
                    if sat == one_time_query_cache(state.solver, op):
                        state.solver.add()
                        state.symbolic_stack.append(BitVec("{"+state.current_func_name + "_load_from(" + str(addr)+")out_of_enclave"+str(datetime.timestamp(datetime.now()))[-5:]+"}", load_length * 8))
                        state.shadow_stack.append(shadow(True, -1))
                        return [state]
                    else:
                        return []
                   
                else:
                    state.symbolic_stack.append(BitVec("{load_from("+str(addr)+")_out_of_enclave"+str(datetime.timestamp(datetime.now()))[-5:]+"}", load_length * 8))
                    state.shadow_stack.append(shadow(True, -1))
                    return [state]
        else:
            if shadow_base.pointer > 0:
                assert not shadow_base.base_taint
    else:
        assert addr.as_long() >= DATA_BASE and addr.as_long() + load_length <= state.memory_manager.data_bound






    if is_bv_value(addr):
        addr = addr.as_long()
        states = lookup_symbolic_memory_data_section(state, data_section, addr, load_length, instr)
    else:
        assert(is_bv_value(shadow_base.base))
        assert(shadow_base.size >= load_length)
        states = []
        addr_list = [shadow_base.base]
        if (shadow_base.base + shadow_base.size - load_length) not in addr_list:
            addr_list.append(shadow_base.base + shadow_base.size - load_length)
        if (shadow_base.base + (shadow_base.size - load_length) // 2) not in addr_list:
            addr_list.append(shadow_base.base + (shadow_base.size - load_length) // 2)
        for i, _addr in enumerate(addr_list):
            if i == len(addr_list) - 1:
                _state = state
            else:
                _state = deepcopy(state)
            _state.solver.add(_addr == addr)
            states += insert_symbolic_memory(_state, data_section, _addr, load_length, instr)
    return states



    if val.size() != 8 * load_length:
        # we assume the memory are filled by 0 initially
        val = ZeroExt(8 * load_length - val.size(), val)

    if val is None:
        exit(f"the loaded value should not be None")
        # val = BitVec(f'load{load_length}*({addr})', 8*load_length)

    # cast to other type of bit vector
    float_mapping = {
        'f32': Float32,
        'f64': Float64,
    }
    if len(instr_name) == 8 and instr_name[0] == "f":
        val = simplify(fpBVToFP(val, float_mapping[instr_name[:3]]()))
    elif instr_name[-2] == "_":
        if instr_name[-1] == "s":  # sign extend
            val = simplify(
                SignExt(int(instr_name[1: 3]) - load_length * 8, val))
        else:
            val = simplify(
                ZeroExt(int(instr_name[1: 3]) - load_length * 8, val))

    # if can not load from the memory area
    if val is not None:
        state.symbolic_stack.append(val)
    else:
        state.symbolic_stack.append(getConcreteBitVec(
            instr_name[:3], f'load_{instr_name[:3]}*({str(addr)})'))


# deal with store instruction
def store_instr(instr, state, analyzer):
    # offset may be int or hex
    try:
        offset = int(instr.split(' ')[2])
    except ValueError:
        offset = int(instr.split(' ')[2], 16)

    val, base = state.symbolic_stack.pop(), state.symbolic_stack.pop()
    shadow_val, shadow_base = state.shadow_stack.pop(), state.shadow_stack.pop()
    addr = simplify(base + BitVecVal(offset,32))


    # change addr's type to int if possible
    # or it will be the BitVecRef
    
    # determine how many bytes should be stored
    # the dict is like {'8': 1}
    bytes_length_mapping = {str(k): k // 8 for k in range(8, 65, 8)}
    instr_name = instr.split(' ')[0]
    if len(instr_name) == 9:
        if instr_name[0] == 'f':
            val = fpToIEEEBV(val)
        stored_length = bytes_length_mapping[instr_name[1:3]]
    else:
        stored_length = bytes_length_mapping[re.search(
            r"store([0-9]+)", instr_name).group(1)]
        val = simplify(Extract(stored_length * 8 - 1, 0, val))


    if shadow_base.stack_pointer:
        func_variables = analyzer.func_variables[state.current_func_name] 
        find = 0
        for _name, _tag, _offset, _size in func_variables:
            if offset >= _offset and offset < _offset + _size:
                find = 1
                _shadow = shadow(shadow_base.taint, True, addr, False, _offset + _size - offset, False)
                break
        if not find:
            offsets = [x[2] for x in analyzer.func_variables[state.current_func_name]]
            offsets.append(analyzer.func_stack_length[state.current_func_name]) 
            offsets.sort()
            for x in offsets:
                if x > offset:
                    size = x - offset
                    break
            _shadow = shadow(shadow_base.taint, True, addr, False, size, False)
        shadow_base = _shadow

    assert shadow_base.pointer or is_bv_value(base)
    if shadow_base.pointer:
        if shadow_base.taint:
            if shadow_base.pointer > 0:
                if shadow_base.base_taint:
                    op = And(addr > analyzer.enclave_bounds[0], addr + BitVecVal(stored_length, 32) < analyzer.enclave_bounds[1], addr + stored_length > addr)
                    if sat == one_time_query_cache(state.solver, op):
                        func_ind = get_func_index_from_state(analyzer, state)
                        func_offset = state.instr.offset
                        write_vulnerabilities(state, f"store taint pointer within enclave{get_source_location_string(analyzer, func_ind, func_offset)}")

                        op = And(addr >= analyzer.enclave_bounds[1], addr + stored_length > addr)
                        if sat == one_time_query_cache(state.solver, op):
                            state.solver.add(op)
                            return [state]
                        else:
                            return []

                    else:
                        return [state]
                else:
                    op = And(Or(addr < shadow_base.base, addr + BitVecVal(stored_length, 32) > (shadow_base.base + shadow_base.size)), addr + BitVecVal(stored_length, 32) > addr)
                    if sat == one_time_query_cache(state.solver, op):
                        func_ind = get_func_index_from_state(analyzer, state)
                        func_offset = state.instr.offset
                        write_vulnerabilities(state, f"store taint length out of bound{get_source_location_string(analyzer, func_ind, func_offset)}")
                        return []
            else:
                op = And(addr > analyzer.enclave_bounds[0], addr + stored_length < analyzer.enclave_bounds[1], addr + stored_length > addr)
                if sat == one_time_query_cache(state.solver, op):
                    func_ind = get_func_index_from_state(analyzer, state)
                    func_offset = state.instr.offset
                    write_vulnerabilities(state, f"store unknown type of taint variable{get_source_location_string(analyzer, func_ind, func_offset)}")

                    op = And(addr >= analyzer.enclave_bounds[1], addr + stored_length > addr)
                    if sat == one_time_query_cache(state.solver, op):
                        state.solver.add(op)
                        return [state]
                    else:
                        return []
                else:
                    return [state]
        else:
            if shadow_base.pointer > 0:
                assert not shadow_base.base_taint
    else:
        assert addr.as_long() >= DATA_BASE and addr.as_long() + stored_length <= state.memory_manager.data_bound


    if is_bv_value(addr):
        addr = addr.as_long()
        states = insert_symbolic_memory(state, addr, stored_length, val, shadow_val)
    elif is_bv(addr):
        assert(is_bv_value(shadow_base.base) and ((not is_bv(shadow_base.size)) or is_bv_value(shadow_base.size)))
        assert(shadow_base.size >= stored_length)
        states = []
        addr_list = [shadow_base.base]
        if simplify(shadow_base.base + shadow_base.size - stored_length) not in addr_list:
            addr_list.append(simplify(shadow_base.base + shadow_base.size - stored_length))
        if (shadow_base.base + (shadow_base.size - stored_length) // 2) not in addr_list:
            addr_list.append(simplify(shadow_base.base + (shadow_base.size - stored_length) // 2))
        for i, _addr in enumerate(addr_list):
            if i == len(addr_list) - 1:
                _state = state
            else:
                _state = deepcopy(state)
            _state.solver.add(_addr == addr)
            states += insert_symbolic_memory(_state, _addr, stored_length, val, shadow_val)
            
    else:
        assert 0
    return states

