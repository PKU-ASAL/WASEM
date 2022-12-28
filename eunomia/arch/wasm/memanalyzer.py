
MAX_HEAP_SIZE = 0x100000
MAX_STACK_SIZE = 0x40000
HEAP_BASE = 0x40000
STACK_TOP = 0x200000
DATA_BASE = 1024

##################################

class memory_manager:

    def __init__(self, state, analyzer):
        ##################################
        #globals
        datas = analyzer.datas
        self.data_section = dict()
        self.shadow_data_section = dict()
        if len(datas) == 0:
            data_bound = DATA_BASE
        elif len(datas) == 1:
            data_bound = datas[0]['offset'] + datas[0]['size']
        else:
            assert len(datas) == 2
            data_bound = max(datas[0]['offset'] + datas[0]['size'], datas[1]['offset'] + datas[1]['size'])
            data_section_value = datas[1]
            data = data_section_value['data']
            offset = data_section_value['offset']
            size = data_section_value['size']
            self.data_section[(offset,offset+size)]=data
            self.shadow_data_section[(offset,offset+size)] = [None]

        globals = analyzer.globals[1:]
        exports = analyzer.exports
        global_exports = [x for x in exports if x['kind'] == 3]
        assert len(globals) == len(global_exports)
        period = 1
        additional_globals = list()
        __data_end = None
        for i in range(len(globals)):
            assert global_exports[i]['index'] == i + 1
            if period == 1:
                if global_exports[i]['field_str'] == '__dso_handle':
                    period = 2
                    continue
                if int(globals[i][1]) >= data_bound:
                    additional_globals.append(int(globals[i][1]))
            else:
                assert global_exports[i]['field_str'][0:2] == '__'
                if global_exports[i]['field_str'] == '__data_end':
                    __data_end = int(globals[i][1])
        assert __data_end

        additional_globals.sort()

        for i, global_var in enumerate(additional_globals):
            if i != len(additional_globals) - 1:
                assert additional_globals[i+1] > additional_globals[i]
                self.data_section[additional_globals[i],additional_globals[i+1]] = [2,0]
                self.shadow_data_section[additional_globals[i],additional_globals[i+1]] = None
            else:
                assert __data_end > additional_globals[i]
                self.data_section[additional_globals[i], __data_end] = [2,0]
                self.shadow_data_section[additional_globals[i], __data_end] = None

        
        self.data_bound = __data_end
        assert self.data_bound <= HEAP_BASE

        ##################################
        #heap
        self.heap_base = HEAP_BASE
        self.max_heap_size = MAX_HEAP_SIZE
        self.free_list = [[self.heap_base, MAX_HEAP_SIZE]]
        self.heap = dict()


        ##################################
        #stack
        self.stack_upperbound = STACK_TOP
        self.max_stack_size = MAX_STACK_SIZE
        state.globals[0] = STACK_TOP