# emulate the arithmetic related instructions

import logging
import re
from eunomia.arch.wasm.configuration import (Configuration, Enable_Lasers,
                                             bcolors)
from eunomia.arch.wasm.dwarfParser import (get_func_index_from_state,
                                           get_source_location_string)
from eunomia.arch.wasm.exceptions import UnsupportInstructionError
from eunomia.arch.wasm.modules.DivZeroLaser import DivZeroLaser
from eunomia.arch.wasm.modules.OverflowLaser import OverflowLaser
from eunomia.arch.wasm.shadow import shadow
from z3 import (RNE, RTN, RTP, RTZ, BitVec, BitVecVal, Float32, Float64, SRem,
                UDiv, URem, fpAbs, fpAdd, fpDiv, fpMax, fpMin, fpMul, fpNeg,
                fpRoundToIntegral, fpSqrt, fpSub, is_bool, simplify, is_bv_value)

helper_map = {
    'i32': 32,
    'i64': 64,
    'f32': [8, 24],
    'f64': [11, 53]
}

float_helper_map = {
    'f32': Float32,
    'f64': Float64
}


class ArithmeticInstructions:
    def __init__(self, instr_name, instr_operand, _):
        self.instr_name = instr_name
        self.instr_operand = instr_operand

    def emulate(self, state, analyzer):
        overflow_check_flag = False
        overflow_laser = None
        if Configuration.get_lasers() & Enable_Lasers.OVERFLOW.value:
            overflow_check_flag = True
            overflow_laser = OverflowLaser()

        div_zero_flag = False
        div_zero_laser = None
        if Configuration.get_lasers() & Enable_Lasers.DIVZERO.value:
            div_zero_flag = True
            div_zero_laser = DivZeroLaser()

        flags = [overflow_check_flag, div_zero_flag]
        laser_objs = [overflow_laser, div_zero_laser]

        def do_emulate_arithmetic_int_instruction(
                state, flags, laser_objs, analyzer):
            instr_type = self.instr_name[:3]

            if '.clz' in self.instr_name or '.ctz' in self.instr_name:
                # wasm documentation says:
                # This instruction is fully defined when all bits are zero;
                # it returns the number of bits in the operand type.
                state.symbolic_stack.pop()
                state.shadow_stack.pop()
                state.symbolic_stack.append(
                    BitVecVal(helper_map[instr_type], helper_map[instr_type]))
                state.shadow_stack.append(shadow(False,False))
            elif '.popcnt' in self.instr_name:
                # wasm documentation says:
                # This instruction is fully defined when all bits are zero;
                # it returns 0.
                state.symbolic_stack.pop()
                state.shadow_stack.pop()
                state.symbolic_stack.append(
                    BitVecVal(0, helper_map[instr_type]))
                state.shadow_stack.append(shadow(False,False))
            else:
                arg1, arg2 = state.symbolic_stack.pop(), state.symbolic_stack.pop()
                shadow1, shadow2 = state.shadow_stack.pop(), state.shadow_stack.pop()
                # arg1 and arg2 could be BitVecRef, BitVecValRef and BoolRef
                if is_bool(arg1):
                    arg1 = BitVec(str(arg1), helper_map[instr_type])
                    logging.warning(
                        f"[!] In `ArithmeticInstructions.py`, arg1 is BoolRef, translated to BitVec which may lead to some information loss")
                if is_bool(arg2):
                    arg2 = BitVec(str(arg2), helper_map[instr_type])
                    logging.warning(
                        f"[!] In `ArithmeticInstructions.py`, arg2 is BoolRef, translated to BitVec which may lead to some information loss")

                assert arg1.size(
                ) == helper_map[instr_type], f"in arithmetic instruction, arg1 size is {arg1.size()} instead of {helper_map[instr_type]}"
                assert arg2.size(
                ) == helper_map[instr_type], f"in arithmetic instruction, arg2 size is {arg2.size()} instead of {helper_map[instr_type]}"

                if '.sub' in self.instr_name:
                    result = arg2 - arg1
                elif '.add' in self.instr_name:
                    result = arg2 + arg1
                elif '.mul' in self.instr_name:
                    result = arg2 * arg1
                elif '.div_s' in self.instr_name:
                    result = arg2 / arg1
                elif '.div_u' in self.instr_name:
                    result = UDiv(arg2, arg1)
                elif '.rem_s' in self.instr_name:
                    result = SRem(arg2, arg1)
                elif '.rem_u' in self.instr_name:
                    result = URem(arg2, arg1)
                else:
                    raise UnsupportInstructionError

                overflow_check_flag, div_zero_flag = flags[0], flags[1]
                overflow_laser, div_zero_laser = laser_objs[0], laser_objs[1]
                if overflow_check_flag:
                    overflowed = overflow_laser.fire(
                        result, state.solver, state.sign_mapping)
                    if overflowed:
                        func_ind = get_func_index_from_state(analyzer, state)
                        func_offset = state.instr.offset
                        logging.warning(
                            f"{bcolors.WARNING}Overflowed! {get_source_location_string(analyzer, func_ind, func_offset)}{bcolors.ENDC}")
                if div_zero_flag:
                    divzeroed = div_zero_laser.fire(result, state.solver)
                    if divzeroed:
                        func_ind = get_func_index_from_state(analyzer, state)
                        func_offset = state.instr.offset
                        logging.warning(
                            f"{bcolors.WARNING}Div-zero! {get_source_location_string(analyzer, func_ind, func_offset)}{bcolors.ENDC}")
                result = simplify(result)

                taint = shadow1.taint or shadow2.taint
                if (shadow1.pointer > 0) or (shadow2.pointer > 0):
                    if shadow1.pointer > 0 and shadow2.pointer > 0:
                        assert '.sub' in self.instr_name
                        _shadow = shadow(taint, False)
                    else:
                        assert '.sub' in self.instr_name or '.add' in self.instr_name
                        if shadow1.pointer > 0:
                            p = shadow1
                            offset = shadow2
                            p_val = arg1
                            offset_value = arg2
                        else:
                            p = shadow2
                            offset = shadow1
                            p_val = arg2
                            offset_value = arg1
                        if p.stack_pointer:
                            assert is_bv_value(offset_value) and is_bv_value(result)
                            assert not taint
                            offset_value = offset_value.as_long()
                            p_value = p_val.as_long()

                            if '.sub' in self.instr_name:
                                if analyzer.func_stack_length[state.current_func_name]:
                                    assert analyzer.func_stack_length[state.current_func_name] == offset_value
                                else:
                                    
                                    func_index = None
                                    func_name = state.current_func_name
                                    if func_name[0] == '$':
                                        func_index = int(re.match('\$func(.*)', func_name).group(1))
                                    else:
                                        for index, wat_func_name in Configuration.get_func_index_to_func_name().items():
                                            if wat_func_name == func_name:
                                                func_index = index
                                                break

                                    assert func_index is not None, f"[!] Cannot find your entry function: {func_name}"
                                    func_info = analyzer.func_prototypes[func_index]
                                    func_index_name, param_str, return_str, func_type = *func_info,

                                    if return_str:
                                        analyzer.func_stack_length[state.current_func_name] = offset_value
                                        analyzer.func_variables[state.current_func_name].insert(0,['',3,offset_value - 4, 4])
                                        analyzer.func_variables[state.current_func_name][1][-1] = offset_value - 4 - analyzer.func_variables[state.current_func_name][1][-2]
                                        if analyzer.func_variables[state.current_func_name][-1][-2] != 0:
                                            analyzer.func_variables[state.current_func_name].append(['', 4, 0, analyzer.func_variables[state.current_func_name][-1][-2]])
                                        assert analyzer.func_variables[state.current_func_name][0][-1] >= 0
                                    else:
                                        analyzer.func_stack_length[state.current_func_name] = offset_value
                                        analyzer.func_variables[state.current_func_name][0][-1] = offset_value - analyzer.func_variables[state.current_func_name][0][-2]
                                        if analyzer.func_variables[state.current_func_name][-1][-2] != 0:
                                            analyzer.func_variables[state.current_func_name].append(['', 4, 0, analyzer.func_variables[state.current_func_name][-1][-2]])
                                        assert analyzer.func_variables[state.current_func_name][0][-1] >= 0
                                _shadow = shadow(taint, True, None, None, None, True)
                            else:
                                if analyzer.func_stack_length[state.current_func_name] == offset_value:
                                    _shadow = shadow(taint, True, None, None, None, True)
                                    mem = [x for x in state.symbolic_memory]
                                    for low, up in mem:
                                        if p_value < up and low < p_value + offset_value:
                                            assert low >= p_value and up <= p_value + offset_value
                                            state.symbolic_memory.pop((low,up))
                                            state.shadow_memory.pop((low,up))
                                else:
                                    func_variables = analyzer.func_variables[state.current_func_name] 
                                    find = 0
                                    for _name, _tag, _offset, _size in func_variables:
                                        if offset_value >= _offset and offset_value < _offset + _size:
                                            find = 1
                                            _shadow = shadow(taint, True, result, False, _offset + _size - offset_value, False)
                                            break
                                    assert find
                        else:
                            _shadow = shadow(taint, True, p.base, p.base_taint, p.size, False)
                else:
                    assert shadow1.pointer == False or shadow1.pointer == -1
                    assert shadow2.pointer == False or shadow2.pointer == -1
                    if shadow1.pointer or shadow2.pointer:
                        _shadow = shadow(taint, -1)
                    else:
                        _shadow = shadow(taint, False)

                state.symbolic_stack.append(result)
                state.shadow_stack.append(_shadow)

            return [state]

        def do_emulate_arithmetic_float_instruction(state, flags, laser_objs):
            # TODO need to be clarified
            # wasm default rounding rules
            rm = RNE()

            instr_type = self.instr_name[:3]

            two_arguments_instrs = ['add', 'sub',
                                    'mul', 'div', 'min', 'max', 'copysign']
            one_argument_instrs = ['sqrt', 'floor',
                                   'ceil', 'trunc', 'nearest', 'abs', 'neg']

            # add instr_type before each instr
            two_arguments_instrs = [str(instr_type + '.' + i)
                                    for i in two_arguments_instrs]
            one_argument_instrs = [str(instr_type + '.' + i)
                                   for i in one_argument_instrs]

            # pop two elements
            if self.instr_name in two_arguments_instrs:
                arg1, arg2 = state.symbolic_stack.pop(), state.symbolic_stack.pop()
                shadow1, shadow2 = state.shadow_stack.pop(), state.shadow_stack.pop()
                assert not (shadow1.pointer or shadow2.pointer)

                assert arg1.ebits() == helper_map[instr_type][0] and arg1.sbits(
                ) == helper_map[instr_type][1], 'In do_emulate_arithmetic_float_instruction, arg1 type mismatch'
                assert arg2.ebits() == helper_map[instr_type][0] and arg2.sbits(
                ) == helper_map[instr_type][1], 'In do_emulate_arithmetic_float_instruction, arg2 type mismatch'

                if '.add' in self.instr_name:
                    result = fpAdd(rm, arg2, arg1)
                elif '.sub' in self.instr_name:
                    result = fpSub(rm, arg2, arg1)
                elif '.mul' in self.instr_name:
                    result = fpMul(rm, arg2, arg1)
                elif '.div' in self.instr_name:
                    result = fpDiv(rm, arg2, arg1)
                elif '.min' in self.instr_name:
                    result = fpMin(arg2, arg1)
                elif '.max' in self.instr_name:
                    result = fpMax(arg2, arg1)
                elif '.copysign' in self.instr_name == 'f32.copysign':
                    # extract arg2's sign to overwrite arg1's sign
                    if arg2.isPositive() ^ arg1.isPositive():
                        result = fpNeg(arg1)
                _shadow = shadow(shadow1.taint or shadow2.taint, False)
            # pop one element
            elif self.instr_name in one_argument_instrs:
                arg1 = state.symbolic_stack.pop()
                shadow1 = state.shadow_stack.pop()
                assert not shadow1.taint

                assert arg1.ebits() == helper_map[instr_type][0] and arg1.sbits(
                ) == helper_map[instr_type][1], 'In do_emulate_arithmetic_float_instruction, arg1 type mismatch'

                if '.sqrt' in self.instr_name:
                    result = fpSqrt(rm, arg1)
                elif '.floor' in self.instr_name:
                    # round toward negative
                    result = fpRoundToIntegral(RTN(), arg1)
                elif '.ceil' in self.instr_name:
                    # round toward positive
                    result = fpRoundToIntegral(RTP(), arg1)
                elif '.trunc' in self.instr_name:
                    # round toward zero
                    result = fpRoundToIntegral(RTZ(), arg1)
                elif '.nearest' in self.instr_name:
                    # round to integeral ties to even
                    result = fpRoundToIntegral(RNE(), arg1)
                elif '.abs' in self.instr_name:
                    result = fpAbs(arg1)
                elif '.neg' in self.instr_name:
                    result = fpNeg(arg1)
                
                _shadow = shadow(shadow1.taint, False)
            else:
                raise UnsupportInstructionError

            overflow_check_flag, div_zero_flag = flags[0], flags[1]
            overflow_laser, div_zero_laser = laser_objs[0], laser_objs[1]
            if overflow_check_flag:
                overflow_laser.fire(result, state.solver)
            if div_zero_flag:
                div_zero_laser.fire(result, state.solver)

            result = simplify(result)
            state.symbolic_stack.append(result)
            state.shadow_stack.append(_shadow)

            return [state]

        op_type = self.instr_name[:1]
        if op_type == 'i':
            return do_emulate_arithmetic_int_instruction(
                state, flags, laser_objs, analyzer)
        else:
            return do_emulate_arithmetic_float_instruction(
                state, flags, laser_objs)
