# emulate the variable related instructions

from eunomia.arch.wasm.exceptions import UnsupportInstructionError, UnsupportGlobalTypeError
from z3 import BitVecVal, is_bv, is_bv_value
from eunomia.arch.wasm.utils import getConcreteBitVec, write_vulnerabilities
from eunomia.arch.wasm.dwarfParser import (get_func_index_from_state,
                                           get_source_location_string)


class VariableInstructions:
    def __init__(self, instr_name, instr_operand, _):
        self.instr_name = instr_name
        self.instr_operand = instr_operand

    def emulate(self, state, analyzer):
        # TODO
        # for go_samples.nosync/tinygo_main.wasm, the global.get operand would be prefixed by four \x80
        if self.instr_operand.startswith(b'\x80\x80\x80\x80'):
            self.instr_operand = self.instr_operand[4:]
        op = int.from_bytes(self.instr_operand, byteorder='little')

        if self.instr_name == 'get_local':
            if op in state.local_var:
                state.symbolic_stack.append(state.local_var[op])
                state.shadow_stack.append(state.shadow_local[op])
            else:
                assert 0,"local not exists"
            '''
            if state.local_var.get(op, None) is not None:
                state.symbolic_stack.append(state.local_var[op])
            else:
                state.symbolic_stack.append(state.local_var[op])
            '''
                # raise UninitializedLocalVariableError
        elif self.instr_name == 'set_local':
            var = state.symbolic_stack.pop()
            shadow = state.shadow_stack.pop()
            state.local_var[op] = var
            state.shadow_local[op] = shadow
        elif self.instr_name == 'get_global':
            global_index = op
            global_operand = state.globals[global_index]
            global_shadow = state.shadow_globals[global_index]
            assert op == 0

            if isinstance(
                    global_operand, str) or isinstance(
                    global_operand, int):
                state.symbolic_stack.append(BitVecVal(global_operand, 32))
                state.shadow_stack.append(global_shadow)
            elif is_bv(global_operand) or is_bv_value(global_operand):
                # the operand is a BitVecRef or BitVecNumRef
                state.symbolic_stack.append(global_operand)
                state.shadow_stack.append(global_shadow)
            else:
                raise UnsupportGlobalTypeError
        elif self.instr_name == 'set_global':
            global_operand = state.symbolic_stack.pop()
            global_index = op
            global_shadow = state.shadow_stack.pop()
            assert op == 0
            if not is_bv_value(global_operand):
                assert global_shadow.taint
                func_ind = get_func_index_from_state(analyzer, state)
                func_offset = state.instr.offset
                write_vulnerabilities(state, f"store taint length out of bound{get_source_location_string(analyzer, func_ind, func_offset)}")
                return []
            state.globals[global_index] = global_operand
            state.shadow_globals[global_index] = global_shadow
        elif self.instr_name == 'tee_local':
            var = state.symbolic_stack[-1]
            shadow = state.shadow_stack[-1]
            state.local_var[op] = var
            state.shadow_local[op]=shadow
        else:
            raise UnsupportInstructionError
        return [state]
