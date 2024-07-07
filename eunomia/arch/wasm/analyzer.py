# This file is written by Octopus
# Its purpose is to analyze and parse the decoded Wasm bytecode

# from wasm.decode import decode_module
import io
import json
import os
from logging import getLogger

import leb128
from elftools.dwarf.dwarfinfo import (DebugSectionDescriptor, DwarfConfig,
                                      DWARFInfo)
from eunomia.arch.wasm.constant import KIND_TYPE, LANG_TYPE
from eunomia.arch.wasm.decode import decode_module
from eunomia.arch.wasm.dwarfParser import dwarf_section_names, parse_expr
from eunomia.arch.wasm.memanalyzer import memory_manager
from eunomia.arch.wasm.format import (format_kind_function, format_kind_global,
                                      format_kind_memory, format_kind_table)
from eunomia.arch.wasm.memanalyzer import DATA_BASE, STACK_TOP
from eunomia.core.utils import bytecode_to_bytes

from wasm import (SEC_CODE, SEC_UNK, decode_module, format_instruction,
                  format_lang_type, format_mutability)
from wasm.modtypes import (CodeSection, DataSection, ElementSection,
                           ExportSection, FunctionSection, GlobalSection,
                           ImportSection, MemorySection, StartSection,
                           TableSection, TypeSection)

logging = getLogger(__name__)

class typeinfo:
    def __init__(self, name = None, pointer = None, size = None, struct=False, tmp = False):
        self.tmp = tmp
        self.name = name
        self.struct = struct
        if not struct:
            self.pointer = pointer
            self.size = size
        else:
            self.size = size
            self.members = []

    def set(self, typeinfo):
        assert self.tmp
        self.name = typeinfo.name
        self.struct = typeinfo.struct
        if not typeinfo.struct:
            self.pointer = typeinfo.pointer
            self.size = typeinfo.size
        else:
            self.size = typeinfo.size
            self.members = typeinfo.members
        self.tmp = False

    def __str__(self):
        res = ""
        if self.name:
            res += "name: " + self.name + "\n"
        if self.struct:
            res += "structure\n"
            res += "size: " + str(self.size) + "\n"
        else :
            res += "not structure\n"
            res += "size: " + str(self.size) + "\n"
            res += "pointer: " + str(self.pointer) + "\n"
        return res
        
class WasmModuleAnalyzer(object):
    '''Analyze and extract informations from wasm module'''

    def __init__(self, module_bytecode, namelist, analysis=True):
        self.module_bytecode = bytecode_to_bytes(module_bytecode)

        self.magic = None
        self.version = None
        self.types = list()
        self.imports_all = list()
        self.imports_func = list()
        self.func_types = list()
        self.tables = list()
        self.memories = list()
        self.globals = list()
        self.exports = list()
        self.start = None
        self.elements = list()
        self.codes = list()
        self.datas = list()
        self.names = list()
        self.customs = list()
        self.func_prototypes = list()
        self.func_offsets = list()
        self.dwarf_info = None
        # self.strings = list() - TODO

        if analysis:
            self.analyze(namelist)

    def attributes_reset(self):
        self.magic = None
        self.version = None
        self.types = list()
        self.imports_all = list()
        self.imports_func = list()
        self.func_types = list()
        self.tables = list()
        self.memories = list()
        self.globals = list()
        self.exports = list()
        self.start = None
        self.elements = list()
        self.codes = list()
        self.datas = list()
        self.names = list()
        self.customs = list()
        self.func_prototypes = list()
        self.func_offsets = list()
        self.dwarf_info = None

    def __str__(self):
        return str(self.show())

    def show(self):
        """Return dict with WasmModuleAnalyzer attributes"""
        return {'magic': self.magic,
                'version': self.version,
                'types': self.types,
                'imports_all': self.imports_all,
                'imports_func': self.imports_func,
                'func_types': self.func_types,
                'tables': self.tables,
                'memories': self.memories,
                'globals': self.globals,
                'exports': self.exports,
                'start': self.start,
                'elements': self.elements,
                'length codes': len(self.codes),
                'datas': self.datas,
                'func_prototypes': self.func_prototypes}

    def __get_section(self, section_type):
        mod_iter = iter(decode_module(self.module_bytecode))
        _, _ = next(mod_iter)
        sections = list(mod_iter)

        # iterate over all section
        for cur_sec, cur_sec_data in sections:
            sec = cur_sec_data.get_decoder_meta()['types']['payload']

            if isinstance(sec, section_type):
                return cur_sec_data
        return None

    def __decode_header(self, header, h_data):
        """Decode wasm header
        Return tuple (magic, version) of wasm module header
        .. seealso:: https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md#high-level-structure
        """
        magic = \
            h_data.magic.to_bytes(header.magic.byte_size, 'little')
        version = \
            h_data.version.to_bytes(header.version.byte_size, 'little')
        return (magic, version)

    def __decode_type_section(self, type_section):
        """Decode wasm type section
        Return a list of tuple (param_str, return_str)
        .. seealso:: https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md#type-section
        """
        type_list = []

        for idx, entry in enumerate(type_section.payload.entries):
            param_str = ''
            return_str = ''

            param_str += ' '.join([LANG_TYPE.get(_x)
                                  for _x in entry.param_types])
            if entry.return_type:
                return_str = '%s' % LANG_TYPE.get(entry.return_type)

            type_list.append((param_str, return_str))
        return type_list

    def __decode_import_section(self, import_section):
        """Decode import section to tuple of list
        .. seealso:: https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md#import-section
        """
        entries = import_section.payload.entries
        import_list = []
        import_func_list = []

        for idx, entry in enumerate(entries):
            #            for encoding in ('utf-8', 'utf-16-be'):
            #                value = str(v)
            #                try:
            #                    value = v.decode(encoding)
            #                    break
            #                except UnicodeDecodeError:
            #                    value = str(v)
            try:
                module_str = entry.module_str.tobytes().decode('utf-8')
            except UnicodeDecodeError:
                module_str = entry.module_str.tobytes()
            try:
                field_str = entry.field_str.tobytes().decode('utf-8')
            except UnicodeDecodeError:
                field_str = entry.field_str.tobytes()

            # logging.debug('%s %s', module_str, field_str)
            kind_type = KIND_TYPE.get(entry.kind)

            if kind_type == 'function':
                f_type = format_kind_function(entry.type.type)
                import_list.append((entry.kind, module_str, field_str, f_type))
                # add also the info into the specific import function list
                import_func_list.append((module_str, field_str, f_type))
            elif kind_type == 'table':
                tabl = format_kind_table(entry.type.element_type,
                                         entry.type.limits.flags,
                                         entry.type.limits.initial,
                                         entry.type.limits.maximum)
                import_list.append((entry.kind, module_str, field_str, tabl))

            elif kind_type == 'memory':
                mem = format_kind_memory(entry.type.limits.flags,
                                         entry.type.limits.initial,
                                         entry.type.limits.maximum)
                import_list.append((entry.kind, module_str, field_str, mem))

            elif kind_type == 'global':
                gbl = format_kind_global(entry.type.content_type,
                                         entry.type.mutability)
                import_list.append((entry.kind, module_str, field_str, gbl))
            else:
                logging.error(f"unknown {entry.kind} {module_str} {field_str}")
        return (import_list, import_func_list)

    def __decode_function_section(self, function_section):
        """Decode function section
        The function section declares the signatures of all functions in the module
        Return list of indices (int)
        .. seealso:: https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md#function-section
        """
        return function_section.payload.types

    def __decode_table_section(self, table_section):
        """
        .. seealso:: https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md#table-section
        """
        # on the MVP, table size == 1
        entries = table_section.payload.entries
        table_list = []

        for idx, entry in enumerate(entries):
            element_type = entry.element_type
            flags = entry.limits.flags
            initial = entry.limits.initial
            maximum = entry.limits.maximum

            fmt = format_kind_table(element_type,
                                    flags,
                                    initial,
                                    maximum)
            table_list.append(fmt)
        return table_list

    def __decode_memory_section(self, memory_section):
        """
        .. seealso:: https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md#memory-section
        """
        # on the MVP, memory size == 1
        memory_l = list()
        entries = memory_section.payload.entries

        for idx, entry in enumerate(entries):
            flags = entry.limits.flags
            initial = entry.limits.initial
            maximum = entry.limits.maximum

            fmt = format_kind_memory(flags,
                                     initial,
                                     maximum)

            memory_l.append(fmt)
        return memory_l

    def __decode_global_section(self, global_section):
        """
        .. seealso:: https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md#global-section
        """
        globals_l = list()

        for entry in global_section.payload.globals:
            mutability = format_mutability(entry.type.mutability)
            content_type = format_lang_type(entry.type.content_type)

            for cur_insn in entry.init:
                # only keep the number
                current_instruction = format_instruction(
                    cur_insn).split(' ')[1]
                # 'end' follows a 'const', so break
                break

            fmt = format_kind_global(
                mutability, content_type, current_instruction)
            globals_l.append(fmt)

        return globals_l

    def __decode_export_section(self, export_section):
        """
        .. seealso:: https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md#export-section
        """
        entries = export_section.payload.entries
        export_list = []

        for idx, entry in enumerate(entries):
            # field_str == function_name
            try:
                field_str = entry.field_str.tobytes().decode('utf-8')
            except UnicodeDecodeError:
                field_str = entry.field_str.tobytes()
            kind = entry.kind
            index = entry.index

            fmt = {'field_str': field_str,
                   'kind': kind,
                   'index': index}
            export_list.append(fmt)
        return export_list

    def __decode_start_section(self, start_section):
        return start_section.payload.index

    def __decode_element_section(self, element_section):
        """
        .. seealso:: https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md#element-section
        """
        entries = element_section.payload.entries
        element_list = []

        for idx, entry in enumerate(entries):
            for cur_insn in entry.offset:
                offset = int(format_instruction(cur_insn).split(' ')[1])
                break

            fmt = {'index': entry.index,
                   'offset': offset,
                   'elems': entry.elems}

            element_list.append(fmt)
        return element_list

    def __decode_code_section(self, code_section):
        """
        .. seealso:: https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md#code-section
        """
        bodies = code_section.payload.bodies
        code_list = []

        for idx, entry in enumerate(bodies):
            code_raw = entry.code.tobytes()
            code_list.append(code_raw)
        return code_list

    def __decode_data_section(self, data_section):
        """
        .. seealso:: https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md#data-section
        """
        entries = data_section.payload.entries
        assert len(entries)<=2
        data_list = []

        for idx, entry in enumerate(entries):
            data = entry.data.tobytes()
            for cur_insn in entry.offset:
                offset = int(format_instruction(cur_insn).split(' ')[1])
                break

            fmt = {'offset': offset,
                   'size': entry.size,
                   'data': data}
            data_list.append(fmt)
        return data_list

    def __decode_name_section(self, name_section):
        """
        .. seealso:: https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md#name-section
        """
        payload = name_section.payload.tobytes()
        # print(payload)

        total = 0
        names_list = list()

        f = io.BytesIO(payload)
        f.read(4)  # drop 4 bytes
        total += 4

        # it is used to indicate how many bytes should be read
        # as the index can be more than a byte
        varuint_carry = 0
        # sometimes, there is a \x01 after the magic 4 bytes
        # we have to jump over it
        first_come = True

        while total < len(payload):

            tmp = payload[total : total + 1 + varuint_carry]
            index = leb128.u.decode(tmp)
            total += 1 + varuint_carry
            # jump over the \x01 after the magic 4 bytes
            if (index == 1 or index == 4) and first_come:
                index = leb128.u.decode(payload[total: total + 1 + varuint_carry])
                total += 1 + varuint_carry

            first_come = False

            if index == 127:
                # TODO it can read at most 32 bits
                # we just consider the 2 bytes right now
                varuint_carry = 1

            tmp = payload[total: total+1]
            name_len = leb128.u.decode(tmp)
            total += 1
            if (leb128.u.decode(payload[total+name_len:total+name_len + 1 +varuint_carry]) != index + 1):
                name_len = leb128.u.decode(payload[total-1:total + 1])
                total += 1
            name_str = payload[total: total + name_len]
            if name_str == b"\x00":
                break
            total += name_len


            '''
            #ve:
            twobytelist = [x for x in range(30)]
            #sgxsse:[17,23,57,60,61,62,69]

            if index in twobytelist:
                # TODO it can read at most 32 bits
                # we just consider the 2 bytes right now
                tmp1 = f.read(1)
                name_len1 = leb128.u.decode(tmp1)
                pairlist = [[x,1]for x in range(30)]
                if [index,name_len1] in pairlist:
                    
                    tmp2 = f.read(1)
                    name_len2 = leb128.u.decode(tmp2)
                    #name_len = name_len2*128+name_len1
                    list3 = [68,71,95,92,111,87,121,108,122,28,97,101,22]
                    if name_len2 in list3:
                        if payload[total+2] == 115 or payload[total+2]==97 or payload[total+2]==95:
                            name_len = name_len2
                            total += 2
                        else:
                            tmp3= f.read(1)
                            name_len3 = leb128.u.decode(tmp3)
                            name_len = name_len3*128+name_len2
                            total += 3
                    else:
                        name_len = name_len2
                        total += 2
                else:
                    name_len = name_len1
                    total += 1
            else:

                tmp = f.read(1)
                name_len = leb128.u.decode(tmp)
                total += 1


            name_str = f.read(name_len)

            total += name_len
            '''
            '''
            twobytelist = [x for x in range(40)]
            if index in twobytelist:
                # TODO it can read at most 32 bits
                # we just consider the 2 bytes right now
                tmp1 = f.read(1)
                name_len1 = leb128.u.decode(tmp1)
                pairlist = [[x,1] for x in twobytelist]
                if [index,name_len1] in pairlist:
                    
                    tmp2 = f.read(1)
                    name_len2 = leb128.u.decode(tmp2)
                    #name_len = name_len2*128+name_len1
                    list3 = []
                    if name_len2 in list3:
                        if payload[total+2] == 115 or payload[total+2]==97 or payload[total+2]==95:
                            name_len = name_len2
                            total += 2
                        else:
                            tmp3= f.read(1)
                            name_len3 = leb128.u.decode(tmp3)
                            name_len = name_len3*128+name_len2
                            total += 3
                    else:
                        name_len = name_len2
                        total += 2
                else:
                    name_len = name_len1
                    total += 1
            else:

                tmp = f.read(1)
                name_len = leb128.u.decode(tmp)
                total += 1


            name_str = f.read(name_len)

            total += name_len
            '''

            # if encounter `_start.command_export`, terminate the parsing process
            if b'command_export' in name_str:
                names_list.append((index, 6, b'_start'))
                break
            if b'(' in name_str:
                name_str = bytes((str(name_str, encoding = "utf-8").split('('))[0], encoding = "utf-8")
            names_list.append((index, name_len, name_str))
        f.close()
        return names_list

    def __decode_unknown_section(self, unknown_section):
        """
        .. seealso:: https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md#high-level-structure
        """
        sec_name = unknown_section.name.tobytes()
        payload = unknown_section.payload.tobytes()
        return (sec_name, payload)

    def get_func_prototypes_ordered(self, namelist):
        """create ordered list of functions"""

        func_prototypes = list()

        # get imported functions
        for _, name, type_idx in self.imports_func:
            _param, _return = self.types[type_idx]
            func_prototypes.append((name, _param, _return, 'import'))


        # get all internal functions
        for idx, code in enumerate(self.codes):
            _param, _return = self.types[self.func_types[idx]]
            real_index = len(self.imports_func) + idx
            name = '$func%d' % real_index
            f_type = 'local'

            # if exported function - overwrite name
            # comment below to ease function call jump


            name = namelist[idx]
            f_type = 'export'

            # TODO: need to test
            if real_index == self.start:
                assert 0
                name = '* ' + name
            func_prototypes.append((name, _param, _return, f_type))
        assert len(self.codes) == len(namelist)
        return func_prototypes

    def get_null_func_stack_length(self):
        func_stack_length = dict()
        for name, _param, _return, f_type in self.func_prototypes:
            func_stack_length[name] = None
        return func_stack_length


    def get_func_variables(self):
        func_variables = dict()
        seen = list()
        funcoffset = 0
        for i,x in enumerate(self.func_prototypes):
            if x[3] == 'import' or x[0] == '__wasm_call_ctors':
                continue
            funcoffset = i
            break
        assert funcoffset != 0
        tmp_prototypes = self.func_prototypes[funcoffset:]
        for CU in self.dwarf_info.iter_CUs():
            # DWARFInfo allows to iterate over the compile units contained in
            # the .debug_info section. CU is a CompileUnit object, with some
            # computed attributes (such as its offset in the section) and
            # a header which conforms to the DWARF standard. The access to
            # header elements is, as usual, via item-lookup.

            # Start with the top DIE, the root for this CU's DIE tree
            top_DIE = CU.get_top_DIE()
            for child in top_DIE.iter_children():
                if child.tag == 'DW_TAG_subprogram'  and 'DW_AT_name' in child.attributes and str(child.attributes['DW_AT_name'].value)[2:-1] not in [x[1] for x in self.imports_func]:
                    func_die = child
                    variables = []
                    if 'DW_AT_declaration' in child.attributes:
                        continue
                    for subchild in func_die.iter_children():
                        def iterate_child(subchild, variables):
                            if subchild.tag == 'DW_TAG_formal_parameter':
                                tag = 1
                            elif subchild.tag == 'DW_TAG_variable':
                                tag = 2
                            elif subchild.tag == 'DW_TAG_unspecified_parameters':
                                variables.append([None,3,None,None])
                                return
                            elif subchild.tag == 'DW_TAG_label':
                                return
                            elif subchild.tag == 'DW_TAG_lexical_block':
                                for ssschild in subchild.iter_children():
                                    iterate_child(ssschild, variables)
                                return
                            else:
                                return
                                assert 0
                            name = str(subchild.attributes['DW_AT_name'].value)[2:-1]
                            
                            if 'DW_AT_location' not in subchild.attributes or subchild.attributes['DW_AT_location'].form == 'DW_FORM_sec_offset':
                                return
                            location = subchild.attributes['DW_AT_location'].value
                            if len(location) == 2:
                                offset = location[1]
                            elif len(location) == 3:
                                if location[0] == 145:
                                    offset = location[1] - 128 + location[2] *128
                                else:
                                    assert location[0] == 237
                                    return
                            elif len(location)==4:
                                offset = location[1] - 128 + (location[2] - 128) * 128 + location[3] * 128 * 128
                                assert location[0] == 145
                            elif len(location) == 5:
                                if location[0] == 3:
                                    offset = location[1] + location[2] * 256
                                    assert location[3] == 0 and location[4] == 0
                                    return
                                else:
                                    assert 0
                            else:
                                assert 0
                            variables.append([name,tag,offset])
                        iterate_child(subchild, variables)
                    variables1 = [x for x in variables if x[1] < 3]
                    variables2 = [x for x in variables if x[1] > 2]
                    assert len(variables2) <= 1
                    variables1.sort(key = lambda x : x[2],reverse=True)
                    variables = variables1 + variables2
                    for idx,i in enumerate(variables):
                        if idx == 0 or i[1] > 2:
                            i.append(None)
                            continue
                        i.append(variables[idx-1][2]-i[2])
                    func_name = str(child.attributes['DW_AT_name'].value)[2:-1]
                    '''
                    found = 0
                    for i,func in enumerate(self.func_prototypes):
                        if func_name in func[0] and (i not in seen) and (func_name == func[0] or func[0][0]=='_'):
                            found = 1
                            seen.append(i)
                            func_name = func[0]
                            break
                    if not found:
                        for i in self.func_prototypes:
                            print(i)
                    assert found
                    '''
                    found = 0
                    for i in range(len(tmp_prototypes)):
                        if func_name == tmp_prototypes[i][0]:
                            if tmp_prototypes[i][0]  in func_variables:
                                continue
                            func_variables[tmp_prototypes[i][0]] = variables
                            found = 1
                            seen.append(i)
                            break
                    if not found:
                        for i in range(len(tmp_prototypes)):
                            if i not in seen and func_name in tmp_prototypes[i][0]:
                                assert tmp_prototypes[i][0] not in func_variables
                                func_variables[tmp_prototypes[i][0]] = variables
                                found = 1
                                seen.append(i)
                                break
                    assert found

        assert len(func_variables) + funcoffset <= len(self.func_prototypes)
        return func_variables



    def analyze(self, namelist):
        """analyse the complete module & extract informations """
        # src: https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md
        # custom     0   name, .debug_str, ...
        # Type       1   Function signature declarations
        # Import     2   Import declarations
        # Function   3   Function declarations
        # Table      4   Indirect function table and other tables
        # Memory     5   Memory attributes
        # Global     6   Global declarations
        # Export     7   Exports
        # Start      8   Start function declaration
        # Element    9   Elements section
        # Code       10  Function bodies (code)
        # Data       11  Data segments

        # reset attributes
        self.attributes_reset()

        mod_iter = iter(decode_module(self.module_bytecode))
        # decode header version - usefull in the future (multiple versions)
        header, header_data = next(mod_iter)
        self.magic, self.version = self.__decode_header(header, header_data)

        #
        # Wasm sections
        #
        sections = list(mod_iter)

        for cur_sec, cur_sec_data in sections:
            sec = cur_sec_data.get_decoder_meta()['types']['payload']

            if isinstance(sec, TypeSection):
                self.types = self.__decode_type_section(cur_sec_data)
            elif isinstance(sec, ImportSection):
                self.imports_all, self.imports_func = \
                    self.__decode_import_section(cur_sec_data)
            elif isinstance(sec, FunctionSection):
                self.func_types = self.__decode_function_section(cur_sec_data)
            elif isinstance(sec, TableSection):
                self.tables = self.__decode_table_section(cur_sec_data)
            elif isinstance(sec, MemorySection):
                self.memories = self.__decode_memory_section(cur_sec_data)
            elif isinstance(sec, GlobalSection):
                self.globals = self.__decode_global_section(cur_sec_data)
            elif isinstance(sec, ExportSection):
                self.exports = self.__decode_export_section(cur_sec_data)
            elif isinstance(sec, StartSection):
                # TODO not analyzed
                self.start = self.__decode_start_section(cur_sec_data)
            elif isinstance(sec, ElementSection):
                self.elements = self.__decode_element_section(cur_sec_data)
            elif isinstance(sec, CodeSection):
                self.codes = self.__decode_code_section(cur_sec_data)
            elif isinstance(sec, DataSection):
                self.datas = self.__decode_data_section(cur_sec_data)
            else:
                # name section
                if cur_sec_data.id == SEC_UNK and cur_sec_data.name.tobytes() == b'name':
                    self.names = self.__decode_name_section(cur_sec_data)
                    
                else:
                    # TODO - handle properly .debug_str section
                    
                    self.customs.append(
                        self.__decode_unknown_section(cur_sec_data))

        # create dwarf_info and func_offsets
        self.analyze_debug_info(sections)
        self.typescan()
        
        # create ordered list of functions
        self.func_prototypes = self.get_func_prototypes_ordered(namelist)
        self.func_variables = self.get_func_variables()
        self.func_stack_length = self.get_null_func_stack_length()
        self.enclave_bounds = [DATA_BASE, STACK_TOP] 

        return True



    
    def parse_structure(self, type_records, child):
        if hasattr(child,'DW_AT_NAME'):
            name = str(child.attributes['DW_AT_name'].value)[2:-1]
        else:
            name = None
        if 'DW_AT_declaration' in child.attributes:
            return
        size = child.attributes['DW_AT_byte_size'].value
        tmp = typeinfo(name, size=size, struct=True)
        
        for grandchild in child.iter_children():
            if grandchild.tag == 'DW_TAG_member':
                mname = str(grandchild.attributes['DW_AT_name'].value)[2:-1]
                mtype = grandchild.attributes['DW_AT_type'].value
                offset = grandchild.attributes['DW_AT_data_member_location'].value
                tmp.members.append([mname,mtype,offset])
            elif grandchild.tag == 'DW_TAG_structure_type':
                self.parse_structure(type_records,grandchild)
            else:
                assert False
        if child.offset not in type_records:
            type_records[child.offset] = tmp
        else:
            type_records[child.offset].set(tmp)



    def get_typeinfo(self, type_value):
        if type_value not in self.type_records:
            return None
        _type = self.type_records[type_value]
        if isinstance(_type, typeinfo):
            return _type
        else:
            return self.get_typeinfo(_type)

    def typescan(self):
        dwarfinfo = self.dwarf_info
        type_records = dict()
        for CU in dwarfinfo.iter_CUs():
            # DWARFInfo allows to iterate over the compile units contained in
            # the .debug_info section. CU is a CompileUnit object, with some
            # computed attributes (such as its offset in the section) and
            # a header which conforms to the DWARF standard. The access to
            # header elements is, as usual, via item-lookup.

            # Start with the top DIE, the root for this CU's DIE tree
            top_DIE = CU.get_top_DIE()

            for child in top_DIE.iter_children():
                if child.tag == 'DW_TAG_base_type':
                    type_records[child.offset] = typeinfo(name=str(child.attributes['DW_AT_name'].value)[2:-1],pointer=False, size=child.attributes['DW_AT_byte_size'].value)

        for CU in dwarfinfo.iter_CUs():
            # DWARFInfo allows to iterate over the compile units contained in
            # the .debug_info section. CU is a CompileUnit object, with some
            # computed attributes (such as its offset in the section) and
            # a header which conforms to the DWARF standard. The access to
            # header elements is, as usual, via item-lookup.

            # Start with the top DIE, the root for this CU's DIE tree
            top_DIE = CU.get_top_DIE()

            for child in top_DIE.iter_children():
                if child.tag == 'DW_TAG_pointer_type':
                    type_records[child.offset] = typeinfo(None, pointer = True, size = 4)

        for CU in dwarfinfo.iter_CUs():
            # DWARFInfo allows to iterate over the compile units contained in
            # the .debug_info section. CU is a CompileUnit object, with some
            # computed attributes (such as its offset in the section) and
            # a header which conforms to the DWARF standard. The access to
            # header elements is, as usual, via item-lookup.

            # Start with the top DIE, the root for this CU's DIE tree
            top_DIE = CU.get_top_DIE()

            for child in top_DIE.iter_children():
                if child.tag == 'DW_TAG_enumeration_type':

                    typename = str(child.attributes['DW_AT_name'].value)[2:-1] if 'DW_AT_name' in child.attributes else None
                    type_records[child.offset] = typeinfo(name=typename, pointer = False, size=child.attributes['DW_AT_byte_size'].value)

        for CU in dwarfinfo.iter_CUs():
            # DWARFInfo allows to iterate over the compile units contained in
            # the .debug_info section. CU is a CompileUnit object, with some
            # computed attributes (such as its offset in the section) and
            # a header which conforms to the DWARF standard. The access to
            # header elements is, as usual, via item-lookup.

            # Start with the top DIE, the root for this CU's DIE tree
            top_DIE = CU.get_top_DIE()

            for child in top_DIE.iter_children():
                if child.tag == 'DW_TAG_structure_type':
                    self.parse_structure(type_records, child)
                
                elif child.tag == 'DW_TAG_typedef':
                    type_records[child.offset] = child.attributes['DW_AT_type'].value
                    
                elif child.tag == 'DW_TAG_const_type':
                    if 'DW_AT_type' not in child.attributes:
                        continue
                    type_records[child.offset] = child.attributes['DW_AT_type'].value
        self.type_records = type_records

    def analyze_debug_info(self, sections):
        """
        analyze dwarf info in wasm file, stored in self.dwarf_info and self.func_offsets
        self.func_offsets contains offsets of defined function in the module, without import functions.

        the offset is the offset of the first instruction in function defination to the start of Code Section
        (relative within wasm file's Code Section). So that it's compatible with the DWARF for WebAssembly specification.
        .. seealso:: https://yurydelendik.github.io/webassembly-dwarf/#pc
        """
        data = {i: None for i in dwarf_section_names}
        offset = 8
        for _, cur_sec_data in sections:
            len_dict = cur_sec_data.get_decoder_meta()['lengths']
            # whole section size
            size = len_dict['id'] + len_dict['payload_len'] + \
                cur_sec_data.payload_len
            name = None
            if cur_sec_data.id == SEC_UNK:
                name = cur_sec_data.name.tobytes().decode()
                # if it's debug info related Section
                if name in dwarf_section_names:
                    # data size before real payload (Custom Section)
                    payload_header_size = len_dict['id'] + len_dict['payload_len'] + \
                        len_dict['name'] + len_dict['name_len']
                    stream = io.BytesIO()
                    payload_data = cur_sec_data.payload.tobytes()
                    stream.write(payload_data)
                    data[name] = DebugSectionDescriptor(
                        stream=stream,
                        name=name,
                        global_offset=offset + payload_header_size,
                        size=len(payload_data),
                        address=0)  # not within address space
            elif cur_sec_data.id == SEC_CODE:
                # calculate first instruction offset of functions
                vec_code_len_dict = cur_sec_data.payload.get_decoder_meta()[
                    'lengths']
                func_offset = vec_code_len_dict['count']
                functions = cur_sec_data.payload.bodies
                for function in functions:
                    function_len_dict = function.get_decoder_meta()['lengths']
                    code_offset = func_offset + \
                        function_len_dict['body_size'] + \
                        function_len_dict['local_count'] + \
                        function_len_dict['locals']
                    # function's first instruction relative offset of the Code Section
                    self.func_offsets.append(code_offset)
                    func_offset += function_len_dict['body_size'] + \
                        function.body_size
            offset += size
        (debug_info_sec_name, debug_aranges_sec_name, debug_abbrev_sec_name,
            debug_str_sec_name, debug_line_sec_name, debug_frame_sec_name,
            debug_loc_sec_name, debug_ranges_sec_name, debug_pubtypes_name,
            debug_pubnames_name, debug_addr_name, debug_str_offsets_name,
            debug_line_str, debug_loclists, debug_rnglists, debug_sup, gnu_debugaltlink) = dwarf_section_names

        self.dwarf_info = DWARFInfo(config=DwarfConfig(
            little_endian=True,
            default_address_size=4,
            machine_arch='wasm'),
            debug_info_sec=data[debug_info_sec_name],
            debug_aranges_sec=data[debug_aranges_sec_name],
            debug_abbrev_sec=data[debug_abbrev_sec_name],
            debug_frame_sec=data[debug_frame_sec_name],
            eh_frame_sec=None,
            debug_str_sec=data[debug_str_sec_name],
            debug_loc_sec=data[debug_loc_sec_name],
            debug_ranges_sec=data[debug_ranges_sec_name],
            debug_line_sec=data[debug_line_sec_name],
            debug_pubtypes_sec=data[debug_pubtypes_name],
            debug_pubnames_sec=data[debug_pubnames_name],
            # The following sections require pyelftools>=0.31, use `pip install --upgrade "pyelftools>=0.31"` to upgrade
            debug_addr_sec=data[debug_addr_name],
            debug_str_offsets_sec=data[debug_str_offsets_name],
            debug_line_str_sec=data[debug_line_str],
            debug_loclists_sec=data[debug_loclists],
            debug_rnglists_sec=data[debug_rnglists],
            debug_sup_sec=data[debug_sup],
            gnu_debugaltlink_sec=data[gnu_debugaltlink],
        )

    def is_compiled_with_emscripten(self):
        matching_list = self.get_emscripten_calls()
        return True if matching_list else False

    def get_emscripten_calls(self):
        res = [x for x, _, _,
               _ in self.func_prototypes if is_emscripten_func(x)]
        return res

    # emscripten syscall from:
    # * https://github.com/kripken/emscripten/blob/incoming/system/lib/fetch/asmfs.cpp
    # * http://gauss.ececs.uc.edu/Courses/c4029/code/syscall_32.tbl.html
    def contains_emscripten_syscalls(self):
        EMSCRIPTEN_SYSCALL_JSON = '/signatures/emscripten_syscalls.json'
        path = os.path.dirname(os.path.realpath(
            __file__)) + EMSCRIPTEN_SYSCALL_JSON

        json_data = open(path).read()
        data = json.loads(json_data)

        func_names = [x for x, _, _, _ in self.func_prototypes]
        match = list()
        for name in func_names:
            try:
                # remove '_' to match '__syscallXX' & '___syscallXX'
                syscall = data[name.replace('_', '')]
                match.append((name, syscall))
            except KeyError:
                pass
        return match


def is_emscripten_func(x):
    # from https://github.com/kripken/emscripten/blob/master/emscripten.py
    EMSCRIPTEN_LIST = [
        # create_basic_funcs
        'abort', 'assert', 'enlargeMemory', 'getTotalMemory',
        'abortOnCannotGrowMemory',
        'abortStackOverflow',
        'abortStackOverflowEmterpreter',
        'segfault', 'alignfault', 'ftfault',
        'SAFE_HEAP_LOAD', 'SAFE_HEAP_LOAD_D',
        'SAFE_HEAP_STORE', 'SAFE_HEAP_STORE_D', 'SAFE_FT_MASK',
        # create_receiving
        '_memcpy', '_memset', 'runPostSets',
        '_emscripten_replace_memory', '__start_module',
        # create_asm_runtime_funcs
        'stackAlloc', 'stackSave',
        'stackRestore', 'establishStackSpace', 'setThrew',
        'setTempRet0', 'getTempRet0',
        'setDynamicTop',
        'emterpret',
        'setAsyncState', 'emtStackSave',
        'emtStackRestore', 'getEmtStackMax', 'setEmtStackMax',
        'setAsync',
        'addOnExit',
        # from emscripten/emcc.py
        '_stbi_load', '_stbi_load_from_memory', '_stbi_image_free',
        '___cxa_demangle',
        '_malloc', '_free',
        'allocate', 'getMemory',
        '___errno_location', '_fflush',
        'FS_createFolder',
        'FS_createPath',
        'FS_createDataFile',
        'FS_createPreloadedFile',
        'FS_createLazyFile',
        'FS_createLink',
        'FS_createDevice',
        'FS_unlink',
        'addRunDependency',
        'removeRunDependency',
        # from emscripten/tools/ctor_evaller.py
        '_sbrk', '___cxa_atexit', '_atexit', 'dumpGlobals',
        # from emscripten/system/lib/pthreads.symbols
        '___assert_fail', '___errno_location', '___lock',
        '___pthread_self', '___pthread_tsd_main',
        '___pthread_tsd_run_dtors', '___pthread_tsd_size',
        '___shm_mapname', '___timedwait', '___unlock',
        '___vm_lock', '___vm_lock_impl', '___vm_unlock',
        '___vm_unlock_impl', '___wait', '__pthread_getcanceltype',
        '__pthread_isduecanceled', '__pthread_msecs_until',
        '____atomic_is_lock_free', '__llvm_atomic_load_add_i32_p0i32',
        '__llvm_memory_barrier', '_accept', '_access',
        '_atexit', '_bind', '_calloc', '_chdir', '_chmod',
        '_chown', '_chroot', '_clearenv', '_clearerr',
        '_clock_gettime', '_close', '_closedir', '_confstr',
        '_connect', '_creat', '_crypt', '_ctermid', '_dprintf',
        '_dup', '_dup2', '_emscripten_asm_const',
        '_emscripten_futex_wait', '_emscripten_futex_wake',
        '_emscripten_get_now', '_emscripten_is_main_runtime_thread',
        '_emscripten_main_thread_process_queued_calls',
        '_emscripten_pthread_attr_settransferredcanvases',
        '_emscripten_pthread_attr_gettransferredcanvases',
        '_emscripten_sync_run_in_main_thread',
        '_emscripten_sync_run_in_main_thread_0',
        '_emscripten_sync_run_in_main_thread_1',
        '_emscripten_sync_run_in_main_thread_2',
        '_emscripten_sync_run_in_main_thread_3',
        '_emscripten_sync_run_in_main_thread_4',
        '_emscripten_sync_run_in_main_thread_5',
        '_emscripten_sync_run_in_main_thread_6',
        '_emscripten_sync_run_in_main_thread_xprintf_varargs',
        '_encrypt', '_fchdir', '_fchmod', '_fchown', '_fclose',
        '_fcntl', '_fdopen', '_feof', '_ferror', '_fflush',
        '_fgetc', '_fgetpos', '_fgets', '_fileno', '_fopen',
        '_fpathconf', '_fprintf', '_fputc', '_fputs', '_fread',
        '_free', '_freopen', '_fscanf', '_fseek', '_fsetpos',
        '_fstat', '_fstatvfs', '_fsync', '_ftell', '_ftruncate',
        '_fwrite', '_getchar', '_getcwd', '_getenv',
        '_gethostname', '_getlogin', '_getlogin_r',
        '_getpeername', '_gets', '_getsockname', '_getsockopt',
        '_gettimeofday', '_ioctl', '_isatty', '_lchmod',
        '_lchown', '_link', '_listen', '_lockf', '_lseek',
        '_lstat', '_malloc', '_mkdir', '_mkdtemp', '_mkfifo',
        '_mknod', '_mkstemp', '_mktemp', '_mmap', '_munmap',
        '_nanosleep', '_open', '_opendir', '_pclose',
        '_perror', '_pipe', '_poll', '_popen', '_posix_fallocate',
        '_pread', '_printf', '_pthread_attr_destroy',
        '_pthread_attr_getdetachstate', '_pthread_attr_getguardsize',
        '_pthread_attr_getinheritsched', '_pthread_attr_getschedparam',
        '_pthread_attr_getschedpolicy', '_pthread_attr_getscope',
        '_pthread_attr_getstack', '_pthread_attr_getstacksize',
        '_pthread_attr_init', '_pthread_attr_setdetachstate',
        '_pthread_attr_setguardsize', '_pthread_attr_setinheritsched',
        '_pthread_attr_setschedparam', '_pthread_attr_setschedpolicy',
        '_pthread_attr_setscope', '_pthread_attr_setstack',
        '_pthread_attr_setstacksize', '_pthread_barrier_destroy',
        '_pthread_barrier_init', '_pthread_barrier_wait',
        '_pthread_barrierattr_destroy',
        '_pthread_barrierattr_getpshared',
        '_pthread_barrierattr_init',
        '_pthread_barrierattr_setpshared',
        '_pthread_cleanup_pop',
        '_pthread_cleanup_push',
        '_pthread_cond_broadcast', '_pthread_cond_destroy',
        '_pthread_cond_init', '_pthread_cond_signal',
        '_pthread_cond_timedwait', '_pthread_cond_wait',
        '_pthread_condattr_destroy', '_pthread_condattr_getclock',
        '_pthread_condattr_getpshared', '_pthread_condattr_init',
        '_pthread_condattr_setclock',
        '_pthread_condattr_setpshared', '_pthread_create',
        '_pthread_equal', '_pthread_getattr_np',
        '_pthread_getspecific', '_pthread_key_create',
        '_pthread_key_delete', '_pthread_mutex_consistent',
        '_pthread_mutex_destroy', '_pthread_mutex_getprioceiling',
        '_pthread_mutex_init', '_pthread_mutex_lock',
        '_pthread_mutex_setprioceiling', '_pthread_mutex_timedlock',
        '_pthread_mutex_trylock', '_pthread_mutex_unlock',
        '_pthread_mutexattr_destroy',
        '_pthread_mutexattr_getprotocol',
        '_pthread_mutexattr_getpshared',
        '_pthread_mutexattr_getrobust',
        '_pthread_mutexattr_gettype', '_pthread_mutexattr_init',
        '_pthread_mutexattr_setprotocol',
        '_pthread_mutexattr_setpshared',
        '_pthread_mutexattr_setrobust',
        '_pthread_mutexattr_settype', '_pthread_once',
        '_pthread_rwlock_destroy', '_pthread_rwlock_init',
        '_pthread_rwlock_rdlock', '_pthread_rwlock_timedrdlock',
        '_pthread_rwlock_timedwrlock',
        '_pthread_rwlock_tryrdlock', '_pthread_rwlock_trywrlock',
        '_pthread_rwlock_unlock', '_pthread_rwlock_wrlock',
        '_pthread_rwlockattr_destroy',
        '_pthread_rwlockattr_getpshared',
        '_pthread_rwlockattr_init',
        '_pthread_rwlockattr_setpshared', '_pthread_self',
        '_pthread_setcancelstate', '_pthread_setcanceltype',
        '_pthread_setspecific', '_pthread_spin_destroy',
        '_pthread_spin_init', '_pthread_spin_lock',
        '_pthread_spin_trylock', '_pthread_spin_unlock',
        '_pthread_testcancel', '_putchar', '_putenv',
        '_puts', '_pwrite', '_read', '_readdir', '_readdir_r',
        '_readlink', '_realpath', '_recv', '_recvfrom',
        '_recvmsg', '_remove', '_rename', '_rewind', '_rewinddir',
        '_rmdir', '_sbrk', '_scanf', '_sched_get_priority_max',
        '_sched_get_priority_min', '_seekdir', '_select',
        '_sem_close', '_sem_destroy', '_sem_getvalue',
        '_sem_init', '_sem_open', '_sem_post', '_sem_timedwait',
        '_sem_trywait', '_sem_unlink', '_sem_wait', '_send',
        '_sendmsg', '_sendto', '_setenv', '_shm_unlink',
        '_shutdown', '_snprintf', '_socket', '_stat', '_statvfs',
        '_symlink', '_sysconf', '_tcgetattr', '_tcsetattr',
        '_telldir', '_tempnam', '_tmpfile', '_tmpnam',
        '_truncate', '_ttyname', '_ttyname_r', '_tzset',
        '_umask', '_ungetc', '_unlink', '_unsetenv', '_usleep',
        '_utime', '_utimes', '_vsnprintf', '_write']

    if x.startswith('_emscripten_'):
        return True
    # function_tables(...)
    elif x.startswith('dynCall_'):
        return True
    # create_basic_funcs(...)
    elif x.startswith('nullFunc_'):
        return True
    elif x.startswith('invoke_'):
        return True
    elif x.startswith('jsCall_'):
        return True
    elif x.startswith('ftCall_'):
        return True
    # syscalls
    elif x.replace('_', '').startswith('syscall'):
        return True
    elif x in EMSCRIPTEN_LIST:
        return True
    else:
        return False
