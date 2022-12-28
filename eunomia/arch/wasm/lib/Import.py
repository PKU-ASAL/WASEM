from eunomia.arch.wasm.lib.utils import sgx_extract_params
from eunomia.arch.wasm.shadow import shadow
from z3 import BitVec, FP, Float32, Float64
from datetime import datetime
class ImportFunction:
    def __init__(self, name, cur_func_name):
        self.name = name
        self.cur_func = cur_func_name

    def emul(self, state, param_str, return_str):
        params, shadow_params = sgx_extract_params(param_str, state)

        if return_str:
            if return_str == 'i32' :
                state.symbolic_stack.append(BitVec("__"+self.name+"_from_"+self.cur_func+str(datetime.timestamp(datetime.now()))[-5:]+"__",32))
            elif return_str == 'i64':
                state.symbolic_stack.append(BitVec("__"+self.name+"_from_"+self.cur_func+str(datetime.timestamp(datetime.now()))[-5:]+"__",64))

            elif return_str == 'f32':
                ret = BitVec("__"+self.name+"_from_"+self.cur_func+str(datetime.timestamp(datetime.now()))[-5:]+"__", 32)
                state.symbolic_stack.append(FP("__"+self.name+"_from_"+self.cur_func+str(datetime.timestamp(datetime.now()))[-5:]+"__", Float32()))
            elif return_str == 'f64':
                state.symbolic_stack.append(FP("__"+self.name+"_from_"+self.cur_func+str(datetime.timestamp(datetime.now()))[-5:]+"__", Float64()))
            else:
                assert 0
        state.shadow_stack.append(shadow(False, False))
        
        return [state]