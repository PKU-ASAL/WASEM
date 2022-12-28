#-------------------------------------------------------------------------------
# elftools example: dwarf_die_tree.py
#
# In the .debug_info section, Dwarf Information Entries (DIEs) form a tree.
# pyelftools provides easy access to this tree, as demonstrated here.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import print_function
from pathlib import Path
import sys
import io
from elftools.dwarf.dwarfinfo import (DebugSectionDescriptor, DwarfConfig,
                                      DWARFInfo)
from eunomia.arch.wasm.dwarfParser import dwarf_section_names
from wasm import (SEC_CODE, SEC_UNK, decode_module, format_instruction,
                  format_lang_type, format_mutability)
from eunomia.arch.wasm.cfg import WasmCFG
from eunomia.core.utils import bytecode_to_bytes

# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']

from elftools.elf.elffile import ELFFile



# 可以根据自己的需求，把常用的封装起来，用的时候直接调用就可以了
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



def analyze_debug_info(sections):
        """
        analyze dwarf info in wasm file, stored in self.dwarf_info and self.func_offsets
        self.func_offsets contains offsets of defined function in the module, without import functions.

        the offset is the offset of the first instruction in function defination to the start of Code Section
        (relative within wasm file's Code Section). So that it's compatible with the DWARF for WebAssembly specification.
        .. seealso:: https://yurydelendik.github.io/webassembly-dwarf/#pc
        """
        data = {i: None for i in dwarf_section_names}
        offset = 8
        func_offsets = list()
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
                    func_offsets.append(code_offset)
                    func_offset += function_len_dict['body_size'] + \
                        function.body_size
            offset += size
        (debug_info_sec_name, debug_aranges_sec_name, debug_abbrev_sec_name,
            debug_str_sec_name, debug_line_sec_name, debug_frame_sec_name,
            debug_loc_sec_name, debug_ranges_sec_name, debug_pubtypes_name,
            debug_pubnames_name, debug_addr_name, debug_str_offsets_name) = dwarf_section_names

        dwarf_info = DWARFInfo(config=DwarfConfig(
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
            #debug_addr_sec=data[debug_addr_name],
            #debug_str_offsets_sec=data[debug_str_offsets_name],
        )

        return dwarf_info


def process_file(filename):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:

        bytecode = f.read()
        cfg = WasmCFG(bytecode)
        module_bytecode = cfg.module_bytecode
        module_bytecode = bytecode_to_bytes(module_bytecode)
        mod_iter = iter(decode_module(module_bytecode))
        # decode header version - usefull in the future (multiple versions)
        header, header_data = next(mod_iter)
        sections = list(mod_iter)

        dwarfinfo = analyze_debug_info(sections)

        print(dwarfinfo)

        for CU in dwarfinfo.iter_CUs():
            # DWARFInfo allows to iterate over the compile units contained in
            # the .debug_info section. CU is a CompileUnit object, with some
            # computed attributes (such as its offset in the section) and
            # a header which conforms to the DWARF standard. The access to
            # header elements is, as usual, via item-lookup.
            print('  Found a compile unit at offset %s, length %s' % (
                CU.cu_offset, CU['unit_length']))

            # Start with the top DIE, the root for this CU's DIE tree
            top_DIE = CU.get_top_DIE()
            print('    Top DIE with tag=%s' % top_DIE.tag)

            # We're interested in the filename...
            print('    name=%s' % Path(top_DIE.get_full_path()).as_posix())

            # Display DIEs recursively starting with top_DIE
            die_info_rec(top_DIE)


def die_info_rec(die, level = 0 ,indent_level='    '):
    """ A recursive function for showing information about a DIE and its
        children.
    """
    print(indent_level + 'level: %d DIE tag=%s  ' % (level,die.tag) + '  addr=%s'% die.offset)
    print(bcolors.HEADER + str(die) +bcolors.ENDC)
    if die.tag == 'DW_TAG_variable':
        print("a")
        print(str(die))
    child_indent = indent_level + '  '
    child_level = level + 1
    for child in die.iter_children():
        die_info_rec(child, child_level,child_indent)


if __name__ == '__main__':

    process_file("DoublePointer.wasm")






