# this is the helper function which are only used in lib folder

from eunomia.arch.wasm.memory import (insert_symbolic_memory,
                                      lookup_symbolic_memory_data_section)
from z3 import BitVecVal, is_bv, is_bv_value

def _extract_params(param_str, state):
    assert 0
    param_cnt = len(param_str.split(" "))
    params = []
    for _ in range(param_cnt):
        params.append(state.symbolic_stack.pop())

    # concretize
    params_result = []
    for i in params:
        if is_bv_value(i):
            params_result.append(i.as_long())
        else:
            params_result.append(i)

    return params_result

def sgx_extract_params(param_str, state):
    """
    Return a list of elements, which are the arguments of the given import function.
    Note that, the order will be reversed.
    For example, if the signature of function foo is: foo (a, b), the returned arguments will be [b, a]
    """
    param_cnt = len([x for x in param_str.split(" ") if x]) 
    params = []
    shadow_params = []
    for _ in range(param_cnt):
        params.append(state.symbolic_stack.pop())
        shadow_params.append(state.shadow_stack.pop())




    return params,shadow_params


def _storeN(state, dest, val, len_in_bytes):
    if not is_bv(val):
        state.symbolic_memory = insert_symbolic_memory(
            state.symbolic_memory, dest, len_in_bytes,
            BitVecVal(val, len_in_bytes * 8))
    else:
        state.symbolic_memory = insert_symbolic_memory(
            state.symbolic_memory, dest, len_in_bytes, val)


def _loadN(state, data_section, dest, len_in_bytes):
    val = lookup_symbolic_memory_data_section(
        state.symbolic_memory, data_section, dest, len_in_bytes)
    if is_bv_value(val):
        val = val.as_long()
    return val
