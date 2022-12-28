from z3 import is_bv, BitVec, BitVecVal, simplify, Extract
class shadow:
    def __init__(self, taint:'bool', pointer = False, base = None, base_taint = None, size = None, stack_pointer = 0):
        self.taint = taint
        #0--non-pointer 1--pointer -1--unknown
        self.pointer = pointer
        if self.pointer == True or self.pointer == 1:
            self.base = base
            self.base_taint = base_taint
            if is_bv(size) and size.size() == 64:
                divisor = BitVecVal(2 ** 32, 64)
                size = simplify(Extract(31, 0, size % divisor))
            self.size = size
            #0--normal pointer -1--global variable 1--stack pointer 
            self.stack_pointer = stack_pointer
        else:
            self.base = None
            self.base_taint = None
            self.size = None
            self.stack_pointer = None
    


    def __str__(self):
        s = '<taint:'
        s += str(self.taint)
        s+=',pointer:'+str(self.pointer)
        if self.pointer:
            s+=',base:'+str(self.base)
            s+=',base_taint:'+str(self.base_taint)
            s+=',size:'+str(self.size)
            s+=',stack_pointer:'+str(self.stack_pointer)
        s+='>' 
        return str(s)

    def __repr__(self):
        s = '<taint:'
        s += str(self.taint)
        s+=',pointer:'+str(self.pointer)
        if self.pointer:
            s+=',base:'+str(self.base)
            s+=',base_taint:'+str(self.base_taint)
            s+=',size:'+str(self.size)
            s+=',stack_pointer:'+str(self.stack_pointer)
        s+='>'
        return str(s)

    def copy_shadow(self):
        if self.pointer:
            return shadow(self.taint, self.pointer, self.base, self.base_taint, self.size, self.stack_pointer)
        return shadow(self.taint, self.pointer)
