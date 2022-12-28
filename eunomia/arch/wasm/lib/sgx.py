import logging
from eunomia.arch.wasm.configuration import bcolors
from eunomia.arch.wasm.lib.utils import sgx_extract_params
from z3 import And, unsat, Not, Or, BitVecVal, is_bv_value
from eunomia.arch.wasm.utils import one_time_query_cache, write_vulnerabilities
from eunomia.arch.wasm.shadow import shadow
from eunomia.arch.wasm.memanalyzer import STACK_TOP, HEAP_BASE, DATA_BASE, MAX_HEAP_SIZE
import copy
from eunomia.arch.wasm.dwarfParser import get_func_index_from_state, get_source_location_string
from z3 import (And, BitVec, BitVecVal, Concat, Extract, If, is_bv,
                is_bv_value, sat, simplify, Float32, Float64, fpBVToFP, fpToIEEEBV, SignExt, ZeroExt)

MAX_DEFAULT_MALLLOC_SIZE = 4096


class SGXStandardFunction:
    def __init__(self, name, cur_func_name):
        self.name = name
        self.cur_func = cur_func_name

    def emul(self, state, param_str, return_str, analyzer):
        if self.name == 'sgx_is_within_enclave':
            params, shadow_params = sgx_extract_params(param_str, state)
            length, addr = params
            shadow_length, shadow_addr = shadow_params
            assert shadow_addr.pointer

            if length.size() != addr.size():
                if length.size() == 32:
                    length = simplify(SignExt(32, length))
                elif addr.size() == 32:
                    addr = simplify(SignExt(32, addr))
            op = And(addr >= analyzer.enclave_bounds[0], addr + length <= analyzer.enclave_bounds[1])

            no_need_true, no_need_false = False, False
            if unsat == one_time_query_cache(state.solver, op):
                no_need_true = True
            if unsat == one_time_query_cache(state.solver, Not(op)):
                no_need_false = True


            states = []
            if no_need_true and no_need_false:
                pass
            elif not no_need_false and not no_need_true:
                new_state = copy.deepcopy(state)
                # conditional_true
                state.solver.add(op)
                state.symbolic_stack.append(BitVecVal(1, 32))
                state.shadow_stack.append(shadow(False, False))
                # conditional_false
                new_state.solver.add(Not(op))
                new_state.symbolic_stack.append(BitVecVal(0, 32))
                new_state.shadow_stack.append(shadow(False, False))
                # append
                states.append(state)
                states.append(new_state)
            else:
                if no_need_false:
                    state.solver.add(op)
                    state.symbolic_stack.append(BitVecVal(1, 32))
                    state.shadow_stack.append(shadow(False, False))
                else:
                    state.solver.add(Not(op))
                    state.symbolic_stack.append(BitVecVal(0, 32))
                    state.shadow_stack.append(shadow(False, False))
                states.append(state)

            return states

        elif self.name == 'sgx_is_outside_enclave':
            params, shadow_params = sgx_extract_params(param_str, state)
            length, addr = params
            shadow_length, shadow_addr = shadow_params
            assert shadow_addr.pointer

            if length.size() != addr.size():
                if length.size() == 32:
                    length = simplify(SignExt(32, length))
                elif addr.size() == 32:
                    addr = simplify(SignExt(32, addr))
            op1 = (addr + length) <= analyzer.enclave_bounds[0]
            op2 = addr >= analyzer.enclave_bounds[1]
            op = Or(op1, op2)

            no_need_true, no_need_false = False, False
            if unsat == one_time_query_cache(state.solver, op):
                no_need_true = True
            if unsat == one_time_query_cache(state.solver, Not(op)):
                no_need_false = True


            states = []
            if no_need_true and no_need_false:
                pass
            elif not no_need_false and not no_need_true:
                new_state = copy.deepcopy(state)
                # conditional_true
                state.solver.add(op)
                state.symbolic_stack.append(BitVecVal(1, 32))
                state.shadow_stack.append(shadow(False, False))
                # conditional_false
                new_state.solver.add(Not(op))
                new_state.symbolic_stack.append(BitVecVal(0, 32))
                new_state.shadow_stack.append(shadow(False, False))
                # append
                states.append(state)
                states.append(new_state)
            else:
                if no_need_false:
                    state.solver.add(op)
                    state.symbolic_stack.append(BitVecVal(1, 32))
                    state.shadow_stack.append(shadow(False, False))
                else:
                    state.solver.add(Not(op))
                    state.symbolic_stack.append(BitVecVal(0, 32))
                    state.shadow_stack.append(shadow(False, False))
                states.append(state)

            return states
        elif self.name == 'malloc':
            params, shadow_params = sgx_extract_params(param_str, state)
            length, = params
            shadow_length, = shadow_params
            if is_bv_value(length):
                length_val = length.as_long()
                for i, bounds in enumerate(state.memory_manager.free_list):
                    low_bound, size = bounds
                    if size >= length_val:
                        base = BitVecVal(low_bound,32)
                        if size > length_val:
                            state.memory_manager.free_list[i] = [low_bound + length_val, size - length_val]
                        else:
                            state.memory_manager.free_list.pop(i)
                        state.memory_manager.heap[low_bound] = length_val
                        state.symbolic_stack.append(base)
                        state.shadow_stack.append(shadow(False, True, base, False, length_val, False))
                        state.symbolic_memory[(low_bound, low_bound + length_val)] = ([1])
                        state.shadow_memory[(low_bound,low_bound + length_val)] = None
                        return [state]
                assert 0
            else:
                if length.size() == 64:
                    divisor = BitVecVal(2 ** 32, 64)
                    # mod
                    length = simplify(Extract(31, 0, length % divisor))
                length_list = [8,16,32,64,128,256,512,1024,2048,4096,8192,10240]
                valid_num = 0
                states = []
                for malloc_length in length_list:
                    if valid_num == 3:
                        break
                    op = BitVecVal(malloc_length,32) == length 
                    if sat == one_time_query_cache(state.solver, op):
                        new_state = copy.deepcopy(state)
                        new_state.solver.add(BitVecVal(malloc_length, 32) == copy.deepcopy(length))
                        found = 0
                        for i, bounds in enumerate(state.memory_manager.free_list):
                            low_bound, size = bounds
                            if size >= malloc_length:
                                found = 1
                                base = BitVecVal(low_bound, 32)
                                if size > malloc_length:
                                    state.memory_manager.free_list[i] = [low_bound + malloc_length, size - malloc_length]
                                else:
                                    state.memory_manager.free_list.pop(i)
                                state.memory_manager.heap[low_bound] = malloc_length
                                state.symbolic_stack.append(base)
                                state.shadow_stack.append(shadow(False, True, base, False, malloc_length, False))
                                state.symbolic_memory[(low_bound, low_bound + malloc_length)] = ([1])
                                state.shadow_memory[(low_bound,low_bound + malloc_length)] = None
                                states.append(state)
                                break
                        assert found
                        valid_num += 1
                    else:
                        continue
                return states


        elif self.name == 'calloc':
            params, shadow_params = sgx_extract_params(param_str, state)
            nitem, sizet = params
            shadow_nitem, shadow_sizet = shadow_params
            if is_bv_value(nitem) and is_bv_value(sizet):
                length_val = nitem.as_long() * sizet.as_long()
                for i, bounds in enumerate(state.memory_manager.free_list):
                    low_bound, size = bounds
                    if size >= length_val:
                        base = BitVecVal(low_bound,32)
                        if size > length_val:
                            state.memory_manager.free_list[i] = [low_bound + length_val, size - length_val]
                        else:
                            state.memory_manager.free_list.pop(i)
                        state.memory_manager.heap[low_bound] = length_val
                        state.symbolic_stack.append(base)
                        state.shadow_stack.append(shadow(False, True, base, False, length_val, False))
                        state.symbolic_memory[(low_bound, low_bound + length_val)] = ([2,0])
                        state.shadow_memory[(low_bound,low_bound + length_val)] = None
                        return [state]
                assert 0
            else:
                length = simplify(nitem * sizet)

                length_list = [8,16,32,64,128,256,512,1024,2048,4096,8192,10240]
                valid_num = 0
                states = []
                for malloc_length in length_list:
                    if valid_num == 3:
                        break
                    op = BitVecVal(malloc_length,32) == length 
                    if sat == one_time_query_cache(state.solver, op):
                        new_state = copy.deepcopy(state)
                        new_state.solver.add(BitVecVal(malloc_length, 32) == copy.deepcopy(length))
                        found = 0
                        for i, bounds in enumerate(state.memory_manager.free_list):
                            low_bound, size = bounds
                            if size >= malloc_length:
                                found = 1
                                base = BitVecVal(low_bound, 32)
                                if size > malloc_length:
                                    state.memory_manager.free_list[i] = [low_bound + malloc_length, size - malloc_length]
                                else:
                                    state.memory_manager.free_list.pop(i)
                                state.memory_manager.heap[low_bound] = malloc_length
                                state.symbolic_stack.append(base)
                                state.shadow_stack.append(shadow(False, True, base, False, malloc_length, False))
                                state.symbolic_memory[(low_bound, low_bound + malloc_length)] = ([1])
                                state.shadow_memory[(low_bound,low_bound + malloc_length)] = None
                                states.append(state)
                                break
                        assert found
                        valid_num += 1
                    else:
                        continue
                return states

        elif self.name == 'free':
            params, shadow_params = sgx_extract_params(param_str, state)
            pointer, = params
            shadow_pointer, = shadow_params

            assert shadow_pointer.pointer == 1
            assert is_bv_value(pointer)
            pointer_val = pointer.as_long()
            
            assert pointer_val in state.memory_manager.heap
            size = state.memory_manager.heap[pointer_val]
            state.memory_manager.heap.pop(pointer_val)
            pointer_up_bound = pointer_val + size


            for i, bounds in enumerate(state.memory_manager.free_list):
                low_bound, _size = bounds
                if pointer_up_bound < low_bound:
                    state.memory_manager.free_list.insert(i,[pointer_val, size])
                    break
                elif pointer_up_bound == low_bound:
                    state.memory_manager.free_list[i] = [pointer_val, size + _size]
                    break
                elif pointer_val == low_bound + _size:
                    if i == len(state.memory_manager.free_list) - 1:
                        state.memory_manager.free_list[i] = [low_bound, size + _size]
                        break
                    else:
                        n_bound, n_size = state.memory_manager.free_list[i+1]
                        if n_bound == pointer_val + size:
                            state.memory_manager.free_list[i:i+2] = [[low_bound, size + _size + n_size]]
                        else:
                            state.memory_manager.free_list[i] = [low_bound, size + _size]
                        break
                elif i == len(state.memory_manager.free_list) - 1:
                    state.memory_manager.free_list.appned([pointer_val, size]) 

            for low_bound, up_bound in state.symbolic_memory:
                if low_bound < pointer_up_bound and up_bound > pointer_val:
                    assert low_bound >= pointer_val and up_bound <= pointer_up_bound
                    state.symbolic_memory.pop((low_bound, up_bound))
                    state.shadow_memory.pop((low_bound, up_bound))
            return [state]
            
            
        elif self.name =='sgx_ocalloc':
            params, shadow_params = sgx_extract_params(param_str, state)
            length, = params
            shadow_length, = shadow_params
            if is_bv_value(length):
                state.symbolic_stack.append(BitVecVal(STACK_TOP + 1024, 32))
                state.shadow_stack.append(shadow(False, True, None, False, None, 0))
                assert STACK_TOP + 1024 + length.as_long() > STACK_TOP + 1024
                return [state]
            else:
                state.symbolic_stack.append(BitVecVal(STACK_TOP + 1024, 32))
                state.shadow_stack.append(shadow(False, True, None, False, None, 0))
                state.solver.add(BitVecVal(STACK_TOP+1024,length.size())+length > BitVecVal(STACK_TOP+1024,length.size()))
                return [state]
        elif self.name == 'sgx_ocfree':
            return [state]
        elif self.name == 'sgx_ocall':
            params, shadow_params = sgx_extract_params(param_str, state)
            _ , _ = params
            _ , _ = shadow_params
            state.symbolic_stack.append(BitVecVal(0,32))
            state.shadow_stack.append(shadow(False, False))
            return [state]
        elif self.name == 'memset':
            params, shadow_params = sgx_extract_params(param_str, state)
            length, val, pointer = params
            shadow_length,  shadow_val, shadow_pointer = shadow_params

            addr = pointer
            store_length = length

            assert is_bv_value(val)
            assert not shadow_val.taint and not shadow_val.pointer == True
            assert is_bv_value(pointer)
            assert shadow_pointer.pointer 
            if shadow_pointer.taint:
                if shadow_pointer.pointer > 0:
                    if shadow_pointer.base_taint:
                        op = And(addr > analyzer.enclave_bounds[0], addr + store_length < analyzer.enclave_bounds[1], addr + store_length > addr)
                        if sat == one_time_query_cache(state.solver, op):
                            #print(state.solver)
                            #print(op)
                            assert 0
                            func_ind = get_func_index_from_state(analyzer, state)
                            func_offset = state.instr.offset
                            write_vulnerabilities(state, f"load taint pointer within enclave{get_source_location_string(analyzer, func_ind, func_offset)}")
                            return []
                        else:
                            state.symbolic_stack.append(BitVecVal(1, 32))
                            state.shadow_stack.append(shadow(False, False))
                            return [state]
                    else:
                        op = And(Or(addr < shadow_pointer.base, addr + store_length > shadow_pointer.base + shadow_pointer.size), addr + store_length > addr)
                        if sat == one_time_query_cache(state.solver, op):
                            func_ind = get_func_index_from_state(analyzer, state)
                            func_offset = state.instr.offset
                            write_vulnerabilities(state, f"memset load taint length out of bound{get_source_location_string(analyzer, func_ind, func_offset)}")
                            return []
                else:
                    op = And(addr > analyzer.enclave_bounds[0], addr + store_length < analyzer.enclave_bounds[1], addr + store_length > addr)
                    if sat == one_time_query_cache(state.solver, op):
                        assert 0
                        func_ind = get_func_index_from_state(analyzer, state)
                        func_offset = state.instr.offset
                        write_vulnerabilities(state, f"memset load unknown type of taint variable{get_source_location_string(analyzer, func_ind, func_offset)}")
                        return []

            else:
                if shadow_pointer.pointer > 0:
                    assert not shadow_pointer.base_taint

            if is_bv_value(length):
                addr = pointer.as_long()
                len_val = length.as_long()
                if addr >= DATA_BASE and addr < state.memory_manager.data_bound:
                    found = 0
                    for low, up in state.memory_manager.data_section:
                        if low < addr + len_val and up > addr:
                            assert low == addr and up == addr + len_val
                            found = 1
                            state.memory_manager.data_section[(low,up)] = [2,val.as_long()]
                            state.memory_manager.shadow_data_section [(low, up)] = shadow(False, -1)
                    assert found
                elif addr >= analyzer.enclave_bounds[0] and addr < analyzer.enclave_bounds[1]: 
                    assert (addr >= HEAP_BASE and addr < HEAP_BASE + MAX_HEAP_SIZE) or (addr >= state.globals[0].as_long() and addr < STACK_TOP)
                    for low,up in [x for x in state.symbolic_memory]:
                        if low < addr + len_val and up > addr:
                            assert low >= addr and up <= addr + len_val
                            state.symbolic_memory.pop((low, up))
                            state.shadow_memory.pop((low, up))
                    state.symbolic_memory[(addr, addr + len_val)] = [2, val.as_long()]
                    state.shadow_memory[(addr, addr + len_val)] = shadow(False, False)
                else:
                    assert addr >= STACK_TOP + 1024 and addr + len_val > addr
            else:
                addr = pointer.as_long()
                assert addr >= HEAP_BASE and addr < HEAP_BASE + MAX_HEAP_SIZE
                assert unsat == one_time_query_cache(state.solver, (length!=shadow_pointer.size))
                memory_maps = [x for x in state.symbolic_memory]
                for low,up in memory_maps:
                    if low < addr + MAX_DEFAULT_MALLLOC_SIZE and up > addr:
                        assert low >= addr and up <= addr + MAX_DEFAULT_MALLLOC_SIZE
                        state.symbolic_memory.pop((low, up))
                        state.shadow_memory.pop((low, up))
                state.symbolic_memory[(addr, addr + MAX_DEFAULT_MALLLOC_SIZE)] = [2, val.as_long()]
                state.shadow_memory[(addr, addr + MAX_DEFAULT_MALLLOC_SIZE)] = shadow(False, False)

                
            state.symbolic_stack.append(pointer)
            state.shadow_stack.append(shadow_pointer)
            return [state]
        elif self.name == 'memcpy_s':
            params, shadow_params = sgx_extract_params(param_str, state)
            length, src, dst_length, dst = params
            shadow_length, shadow_src, shadow_dst_length, shadow_dst = shadow_params


            if not is_bv_value(src) and is_bv_value(dst):
                op = And(src >= BitVecVal(analyzer.enclave_bounds[0],32), src <= BitVecVal(analyzer.enclave_bounds[0],32))
                assert unsat == one_time_query_cache(state.solver, op)
                dst = dst.as_long()
                assert (dst >= HEAP_BASE and dst <= HEAP_BASE + MAX_HEAP_SIZE)
                assert dst in state.memory_manager.heap
                state.symbolic_memory[dst, dst + state.memory_manager.heap[dst]] = [3]
                state.shadow_memory[dst, dst + state.memory_manager.heap[dst]] = shadow(True, -1)
                state.symbolic_stack.append(BitVecVal(0,32))
                state.shadow_stack.append(shadow(False,False))
                return [state]


            assert is_bv_value(dst)
            assert is_bv_value(src)

            if shadow_dst.taint or shadow_length.taint:
                if dst.as_long() == 0:
                    func_ind = get_func_index_from_state(analyzer, state)
                    func_offset = state.instr.offset
                    write_vulnerabilities(state, f"memcpy_s store null pointer {get_source_location_string(analyzer, func_ind, func_offset)}")
                    return []
                if shadow_dst.pointer > 0:
                    if shadow_dst.base_taint:
                        op = And(dst > BitVecVal(analyzer.enclave_bounds[0],32) , dst + length < BitVecVal(analyzer.enclave_bounds[1],32) , dst + length > dst)
                        if sat == one_time_query_cache(state.solver, op):
                            #print(state.solver)
                            #print(op)
                            func_ind = get_func_index_from_state(analyzer, state)
                            func_offset = state.instr.offset
                            write_vulnerabilities(state, f"memcpy_s store taint pointer within enclave{get_source_location_string(analyzer, func_ind, func_offset)}")
                            return []
                        else:
                            dst_outside = 1
                    else:
                        op = And(Or(dst < shadow_dst.base, dst + length > shadow_dst.base + shadow_dst.size), dst + length > dst)
                        if sat == one_time_query_cache(state.solver, op):
                            func_ind = get_func_index_from_state(analyzer, state)
                            func_offset = state.instr.offset
                            write_vulnerabilities(state, f"memcpy_s store taint length out of bound{get_source_location_string(analyzer, func_ind, func_offset)}")
                            return []
                else:
                    op = And(dst > BitVecVal(analyzer.enclave_bounds[0], 32), dst + length < BitVecVal(analyzer.enclave_bounds[1], 32), dst + length > dst)
                    if sat == one_time_query_cache(state.solver, op):
                        assert 0
                        func_ind = get_func_index_from_state(analyzer, state)
                        func_offset = state.instr.offset
                        write_vulnerabilities(state, f"load unknown type of taint variable{get_source_location_string(analyzer, func_ind, func_offset)}")
                        return []

            else:
                if shadow_dst.pointer > 0:
                    assert not shadow_dst.base_taint

            if shadow_src.taint or shadow_length.taint:
                if dst.as_long() == 0:
                    func_ind = get_func_index_from_state(analyzer, state)
                    func_offset = state.instr.offset
                    write_vulnerabilities(state, f"memcpy_s load null pointer{get_source_location_string(analyzer, func_ind, func_offset)}")
                    return []
                if shadow_src.pointer > 0:
                    if shadow_src.base_taint:
                        op = And(src > BitVecVal(analyzer.enclave_bounds[0], 32), src + length < BitVecVal(analyzer.enclave_bounds[1], 32), src + length > src)
                        if sat == one_time_query_cache(state.solver, op):
                            #print(state.solver)
                            #print(op)
                            func_ind = get_func_index_from_state(analyzer, state)
                            func_offset = state.instr.offset
                            write_vulnerabilities(state, f"memcpy_s load taint pointer within enclave{get_source_location_string(analyzer, func_ind, func_offset)}")
                            return []
                        else:
                            src_outside = 1
                    else:
                        op = And(Or(src < shadow_src.base, src + length > shadow_src.base + shadow_src.size), src + length > src)
                        if sat == one_time_query_cache(state.solver, op):
                            func_ind = get_func_index_from_state(analyzer, state)
                            func_offset = state.instr.offset
                            write_vulnerabilities(state, f"memcpy_s load taint length out of bound{get_source_location_string(analyzer, func_ind, func_offset)}")
                            return []
                else:
                    op = And(src > BitVecVal(analyzer.enclave_bounds[0], 32), src + length < BitVecVal(analyzer.enclave_bounds[1], 32), src + length > src)
                    if sat == one_time_query_cache(state.solver, op):
                        assert 0
                        func_ind = get_func_index_from_state(analyzer, state)
                        func_offset = state.instr.offset
                        write_vulnerabilities(state, f"load unknown type of taint variable{get_source_location_string(analyzer, func_ind, func_offset)}")
                        return []

            else:
                if shadow_src.pointer > 0:
                    assert not shadow_src.base_taint

            addr_dst = dst.as_long()
            addr_src = src.as_long()
            if addr_dst > STACK_TOP + 1024:
                state.symbolic_stack.append(BitVecVal(0,32))
                state.shadow_stack.append(shadow(False,False))
                return [state]
            elif addr_src > STACK_TOP + 1024:
                assert is_bv_value(length)
                for low, up in [x for x in state.symbolic_memory]:
                    if low < addr_dst + length.as_long() and up > addr_dst:
                        state.symbolic_memory.pop((low,up))
                state.symbolic_memory[(addr_dst, addr_dst+length.as_long())] = [3]
                state.shadow_memory[(addr_dst, addr_dst+length.as_long())] = shadow(True, -1)
                state.symbolic_stack.append(BitVecVal(0,32))
                state.shadow_stack.append(shadow(False,False))
                return [state]

            assert 0
        elif self.name == 'memcpy':
            params, shadow_params = sgx_extract_params(param_str, state)
            length, src, dst = params
            shadow_length, shadow_src, shadow_dst = shadow_params
            assert is_bv_value(dst)
            assert is_bv_value(src)
            dst_outside = -1
            src_outside = -1


            addr_dst = dst.as_long()
            addr_src = src.as_long()
            if shadow_dst.taint or shadow_length.taint:
                if addr_dst == 0:
                    func_ind = get_func_index_from_state(analyzer, state)
                    func_offset = state.instr.offset
                    write_vulnerabilities(state, f"memcpy store null pointer_{get_source_location_string(analyzer, func_ind, func_offset)}")
                    return []
                if shadow_dst.pointer > 0:
                    if shadow_dst.base_taint:
                        op = And(dst > BitVecVal(analyzer.enclave_bounds[0],32) , dst + length < BitVecVal(analyzer.enclave_bounds[1],32) , dst + length > dst)
                        if sat == one_time_query_cache(state.solver, op):
                            #print(state.solver)
                            #print(op)
                            func_ind = get_func_index_from_state(analyzer, state)
                            func_offset = state.instr.offset
                            write_vulnerabilities(state, f"memcpy store taint pointer within enclave{get_source_location_string(analyzer, func_ind, func_offset)}")
                            return []
                        else:
                            dst_outside = 1
                    else:
                        op = And(Or(dst < shadow_dst.base, dst + length > shadow_dst.base + shadow_dst.size), dst + length > dst)
                        if sat == one_time_query_cache(state.solver, op):
                            func_ind = get_func_index_from_state(analyzer, state)
                            func_offset = state.instr.offset
                            write_vulnerabilities(state, f"memcpy store taint length out of bound{get_source_location_string(analyzer, func_ind, func_offset)}")
                            return []
                else:
                    op = And(dst > BitVecVal(analyzer.enclave_bounds[0], 32), dst + length < BitVecVal(analyzer.enclave_bounds[1], 32), dst + length > dst)
                    if sat == one_time_query_cache(state.solver, op):
                        assert 0
                        func_ind = get_func_index_from_state(analyzer, state)
                        func_offset = state.instr.offset
                        write_vulnerabilities(state, f"load unknown type of taint variable{get_source_location_string(analyzer, func_ind, func_offset)}")
                        return []

            else:
                if shadow_dst.pointer > 0:
                    assert not shadow_dst.base_taint

            if shadow_src.taint or shadow_length.taint:
                if addr_src == 0:
                    func_ind = get_func_index_from_state(analyzer, state)
                    func_offset = state.instr.offset
                    write_vulnerabilities(state, f"memcpy load null pointer_{get_source_location_string(analyzer, func_ind, func_offset)}")
                    return []
                if shadow_src.pointer > 0:
                    if shadow_src.base_taint:
                        op = And(src > BitVecVal(analyzer.enclave_bounds[0], 32), src + length < BitVecVal(analyzer.enclave_bounds[1], 32), src + length > src)
                        if sat == one_time_query_cache(state.solver, op):
                            #print(state.solver)
                            #print(op)
                            func_ind = get_func_index_from_state(analyzer, state)
                            func_offset = state.instr.offset
                            write_vulnerabilities(state, f"memcpy load taint pointer within enclave{get_source_location_string(analyzer, func_ind, func_offset)}")
                            return []
                        else:
                            src_outside = 1
                    else:
                        op = And(Or(src < shadow_src.base, src + length > shadow_src.base + shadow_src.size), src + length > src)
                        if sat == one_time_query_cache(state.solver, op):
                            func_ind = get_func_index_from_state(analyzer, state)
                            func_offset = state.instr.offset
                            write_vulnerabilities(state, f"memcpy load taint length out of bound{get_source_location_string(analyzer, func_ind, func_offset)}")
                            return []
                else:
                    op = And(src > BitVecVal(analyzer.enclave_bounds[0], 32), src + length < BitVecVal(analyzer.enclave_bounds[1], 32), src + length > src)
                    if sat == one_time_query_cache(state.solver, op):
                        assert 0
                        func_ind = get_func_index_from_state(analyzer, state)
                        func_offset = state.instr.offset
                        write_vulnerabilities(state, f"load unknown type of taint variable{get_source_location_string(analyzer, func_ind, func_offset)}")
                        return []

            else:
                if shadow_src.pointer > 0:
                    assert not shadow_src.base_taint

            assert is_bv_value(length)
            length = length.as_long()

            if src_outside == 1:
                val = [3]
                shadow_val = shadow(True, -1)

            else:
                if src >= DATA_BASE and src + length <= state.memory_manager.data_bound:
                    found = 0
                    for low, up in analyzer.data_section:
                        if low <= src and src + length <= up:
                            found = 1
                            data_section_bytes = analyzer.data_section[(low, up)][src -low : src + length - low]
                            data_section_bitvec = BitVecVal(
                                int.from_bytes(data_section_bytes, 'little'),
                                len(data_section_bytes) * 8)
                            val = simplify(Extract(length * 8 - 1, 0, data_section_bitvec))
                            shadow_val = shadow(False, False)
                    if not found:
                        for low, up in state.memory_manager.data_section:
                            if low <= src and src + length <= up:
                                found = 1
                                data = state.memory_manager.data_section[(low, up)]
                                if is_bv(data):
                                    assert low == src and up == src + length
                                    val = data
                                    shadow_val = state.memory_manager.shadow_data_section[(low,up)]
                                else:
                                    data_section_bytes = state.memory_manager.data_section[(low, up)][src-low : src+length-low]
                                    data_section_bitvec = BitVecVal(
                                        int.from_bytes(data_section_bytes, 'little'),
                                        len(data_section_bytes) * 8)
                                    val = simplify(Extract(length * 8 - 1, 0, data_section_bitvec))
                                    assert state.memory_manager.shadow_data_section[(low,up)] == None
                                    shadow_val = shadow(False, -1)
                    assert found
                else:
                    assert (src >= HEAP_BASE and src + length <= HEAP_BASE + MAX_HEAP_SIZE) or (src >= state.globals[0].as_long() and src + length <= STACK_TOP)
                    found = 0
                    for low, up in state.symbolic_memory:
                        if low <= src and up >= src + length:
                            assert low == src and up == src + length
                            found = 1
                            break
                    assert found
                    val = state.symbolic_memory[(src, src + length)]
                    shadow_val = state.shadow_memory[(src, src + length)]


            if dst_outside != 1:
                if dst >= DATA_BASE and dst + length <= state.memory_manager.data_bound:
                    found = 0
                    for low, up in state.memory_manager.data_section:
                        if low <= dst and dst + length <= up:
                            found = 1
                            assert low == dst and dst + length == up
                            state.memory_manager.data_section[(low, up)] = val
                            state.memory_manager.shadow_data_section[(low, up)] = shadow_val
                    assert found
                else:
                    assert (dst >= HEAP_BASE and dst + length <= HEAP_BASE + MAX_HEAP_SIZE) or (dst >= state.globals[0].as_long() and dst + length <= STACK_TOP)
                    found = 0
                    for low, up in state.symbolic_memory:
                        if low <= dst and up >= dst+length:
                            assert low == dst and up == dst + length
                            found = 1
                            break
                    assert found
                    state.symbolic_memory[(dst, dst + length)] = val
                    state.shadow_memory[(dst, dst + length)] = shadow_val

            state.symbolic_stack.append(dst)
            state.shadow_stack.append(shadow_dst)
            return [state]

            
        else:
            assert 0