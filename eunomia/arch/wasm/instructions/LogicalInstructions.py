# emulate the logical related instructions

from eunomia.arch.wasm.configuration import Configuration, Enable_Lasers
from eunomia.arch.wasm.exceptions import UnsupportInstructionError
from eunomia.arch.wasm.shadow import shadow
from z3 import (
    UGE, UGT, ULE, ULT, BitVecVal, If, fpEQ, fpGEQ, fpGT, fpLEQ, fpLT, fpNEQ,
    is_bool, is_bv, is_bv_value, simplify, is_true, is_false)

helper_map = {
    'i32': 32,
    'i64': 64,
    'f32': [8, 24],
    'f64': [11, 53]
}


class LogicalInstructions:
    def __init__(self, instr_name, instr_operand, _):
        self.instr_name = instr_name
        self.instr_operand = instr_operand

    # TODO overflow check in this function?
    def emulate(self, state):
        overflow_check_flag = False
        if Configuration.get_lasers() & Enable_Lasers.OVERFLOW.value:
            overflow_check_flag = True

        def do_emulate_logical_int_instruction(state, overflow_check_flag):
            instr_type = self.instr_name[:3]
            if 'eqz' in self.instr_name:
                arg0 = state.symbolic_stack.pop()
                shadow0 = state.shadow_stack.pop()

                assert arg0.size(
                ) == helper_map[instr_type], f"in `eqz` the argument popped size is {arg0.size()} instead of {helper_map[instr_type]}"

                result = arg0 == 0
                _shadow = shadow(shadow0.taint, False)


            else:
                arg1, arg2 = state.symbolic_stack.pop(), state.symbolic_stack.pop()
                shadow1, shadow2 = state.shadow_stack.pop(), state.shadow_stack.pop()
                assert not (shadow1.pointer and shadow2.pointer)

                assert is_bv(arg1) and is_bv(
                    arg2), f"in `logical` instruction, arg1 or arg2 type is wrong instead of BitVec"

                if 'eq' in self.instr_name:
                    result = arg1 == arg2
                elif 'ne' in self.instr_name:
                    result = arg1 != arg2
                elif 'lt_s' in self.instr_name:
                    result = arg2 < arg1
                elif 'lt_u' in self.instr_name:
                    result = ULT(arg2, arg1)
                elif 'gt_s' in self.instr_name:
                    result = arg2 > arg1
                elif 'gt_u' in self.instr_name:
                    result = UGT(arg2, arg1)
                elif 'le_s' in self.instr_name:
                    result = arg2 <= arg1
                elif 'le_u' in self.instr_name:
                    result = ULE(arg2, arg1)
                elif 'ge_s' in self.instr_name:
                    result = arg2 >= arg1
                elif 'ge_u' in self.instr_name:
                    result = UGE(arg2, arg1)
                else:
                    raise UnsupportInstructionError

                # record if the op is signed or unsigned when the overflow check flag is enabled
                def speculate_sign(op, instr_name, sign_mapping):
                    # if the op is a bitvecval, we do not change anything
                    if not (is_bv(op) and not is_bv_value(op)):
                        return

                    # unsigned is False and signed is True
                    # the signed will overlap the unsigned
                    if '_u' in instr_name:
                        sign_mapping[op.hash()] = sign_mapping.get(
                            op.hash(), 0) | 0
                    else:
                        sign_mapping[op.hash()] = sign_mapping.get(
                            op.hash(), 0) | 1

                if overflow_check_flag and (
                        '_u' in self.instr_name or '_s' in self.instr_name):
                    speculate_sign(arg1, self.instr_name, state.sign_mapping)
                    speculate_sign(arg2, self.instr_name, state.sign_mapping)
                
                taint = shadow1.taint or shadow2.taint
                _shadow = shadow(taint, False)

            # try to simplify result and insert 1 or 0 directly, instead of an ite statement
            result = simplify(result)
            if is_true(result):
                state.symbolic_stack.append(BitVecVal(1, 32))
            elif is_false(result):
                state.symbolic_stack.append(BitVecVal(0, 32))
            else:
                state.symbolic_stack.append(
                    If(result, BitVecVal(1, 32), BitVecVal(0, 32)))

            
            state.shadow_stack.append(_shadow)

            return [state]

        def do_emulate_logical_float_instruction(state):
            arg1, arg2 = state.symbolic_stack.pop(), state.symbolic_stack.pop()
            shadow1, shadow2 = state.shadow_stack.pop(), state.shadow_stack.pop()
            assert not (shadow1.pointer or shadow2.pointer)
            instr_type = self.instr_name[:3]

            assert arg1.ebits() == helper_map[instr_type][0] and arg1.sbits(
            ) == helper_map[instr_type][1], 'emul_logical_f_instr arg1 type mismatch'
            assert arg2.ebits() == helper_map[instr_type][0] and arg2.sbits(
            ) == helper_map[instr_type][1], 'emul_logical_f_instr arg2 type mismatch'

            if 'eq' in self.instr_name:
                result = fpEQ(arg1, arg2)
            elif 'ne' in self.instr_name:
                result = fpNEQ(arg1, arg2)
            elif 'lt' in self.instr_name:
                result = fpLT(arg2, arg1)
            elif 'le' in self.instr_name:
                result = fpLEQ(arg2, arg1)
            elif 'gt' in self.instr_name:
                result = fpGT(arg2, arg1)
            elif 'ge' in self.instr_name:
                result = fpGEQ(arg2, arg1)
            else:
                raise UnsupportInstructionError

            # try to simplify result and insert 1 or 0 directly, instead of an ite statement
            result = simplify(result)
            if is_true(result):
                state.symbolic_stack.append(BitVecVal(1, 32))
            elif is_false(result):
                state.symbolic_stack.append(BitVecVal(0, 32))
            else:
                state.symbolic_stack.append(
                    If(result, BitVecVal(1, 32), BitVecVal(0, 32)))

            taint = shadow1.taint or shadow2.taint
            state.shadow_stack.append(shadow(taint, False))

            return [state]

        op_type = self.instr_name[:1]
        if op_type == 'i':
            return do_emulate_logical_int_instruction(
                state, overflow_check_flag)
        else:
            return do_emulate_logical_float_instruction(state)
