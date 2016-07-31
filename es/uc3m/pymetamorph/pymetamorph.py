from __future__ import print_function

import random
import sys

import pefile
from capstone import *
from keystone import *


class Pymetamorph(object):
    def __init__(self, file, debug=False, load_file=True):
        from capstone import x86_const
        self.NON_COMPILABLE_INSTRUCTION_IDS = [x86_const.X86_INS_RCR, x86_const.X86_INS_SAR, x86_const.X86_INS_SHL,
                                               x86_const.X86_INS_SHR]
        self.load_file = load_file
        self.file = file
        self.debug = debug
        self.instructions = []
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True
        self.cs.syntax = CS_OPT_SYNTAX_ATT
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        self.ks.syntax = KS_OPT_SYNTAX_ATT
        self.label_table = None
        self.original_inst = []
        if load_file:
            self.pe_handler = PEHandler(pefile.PE(self.file))
            if self.debug:
                print(self.pe_handler.dump())
                print('loading file')
            self.original_entry_point = self.pe_handler.getEntryPointAddress()
            self.base_of_code = self.pe_handler.getBaseOfCodeAddress()
            self.code_section = self.pe_handler.findSection(self.base_of_code)
            if self.code_section is None:
                raise Exception('unable to find .text section')
            raw_code = self.code_section.get_data(self.base_of_code, self.code_section.Misc_VirtualSize)
            for i in self.cs.disasm(raw_code,
                                    self.base_of_code):
                self.original_inst.append(i)
                self.instructions.append(MetaIns(i))
        else:
            self.instructions = []

    def insert_nop(self, initial_address=None):
        address = 0
        if initial_address is None:
            address = self.base_of_code
        nop = None
        for nop in self.cs.disasm(str(bytearray([0x90])), 0):
            break
        new_inst = []
        append = True
        for i in self.instructions:
            if append and random.random < 0.1:
                for _ in range(5):
                    address = self.append_instruction(new_inst, nop, address)
                append = False
            address = self.append_meta_instruction(new_inst, i, address)
        self.instructions = new_inst

    @staticmethod
    def append_instruction(instruction_list, instruction, address, overwrite_original_address=False):
        ins = MetaIns(instruction)
        if overwrite_original_address:
            ins.original_addr = address
        ins.new_addr = address
        instruction_list.append(ins)
        return address + instruction.size

    def append_meta_instruction(self, instruction_list, instruction, address, overwrite_original_address=False):
        return self.append_instruction(instruction_list, instruction.original_inst, address, overwrite_original_address)

    def shuffle_blocks(self, initial_address=None):
        """
        divides the code in blocks and shuffles them to morph the code of the program.
        It also insert a jump instruction to the next block at the end of each code block
        """
        size_of_blocks = random.randint(len(self.instructions) / 10, len(self.instructions) / 3)
        offset = 0
        blocks = []
        initial_block_inst = dict()
        i = 0
        if initial_address is None:
            initial_address = self.base_of_code
        while offset < len(self.instructions):
            blocks.append((i, self.instructions[offset:min(offset + size_of_blocks, len(self.instructions))]))
            initial_block_inst[i] = blocks[i][1][0]
            i += 1
            offset += size_of_blocks
        if self.debug:
            print('number of blocks: %d' % (len(blocks)))
        random.shuffle(blocks)
        instructions = []
        for block_number, block in blocks:
            jump_inst = None
            if block_number + 1 in initial_block_inst:
                asm, _ = self.ks.asm('jmp 0x%x' % initial_block_inst[block_number + 1].original_addr)
                for jump_inst in self.cs.disasm(str(bytearray(asm)), 0):
                    break
            if jump_inst is not None:
                self.append_instruction(block, jump_inst, 0)
            instructions += block
        self.update_addresses(instructions, initial_address)
        self.instructions = instructions

    def sort_instructions(self):
        sorted(self.instructions, key=lambda instruction: instruction.new_addr)

    def generate_label_table(self):
        from capstone import x86_const
        jmp_table = dict()
        for inst in self.instructions:
            try:
                if (x86_const.X86_INS_JAE <= inst.original_inst.id <= x86_const.X86_INS_JS) \
                        or x86_const.X86_INS_CALL == inst.original_inst.id:
                    addr = int(inst.original_inst.op_str, 16)
                    jmp_table[addr] = None
            except:
                pass
        return jmp_table

    @staticmethod
    def update_addresses(instructions, initial_address):
        address = initial_address
        for instruction in instructions:
            instruction.new_addr = address
            address += instruction.size

    def print_new_dissas(self, output_path):
        offset = self.base_of_code
        code = ''
        for inst in self.instructions:
            code += str(inst.new_bytes)
        out = open(output_path, 'w')
        for inst in self.cs.disasm(code, offset):
            out.write("0x%x:\t%s\t%s\n" % (
                inst.address, inst.mnemonic, inst.op_str))
        out.close()

    def print_disass(self, output_path, ):
        out = open(output_path, 'w')
        for inst in self.instructions:
            out.write("0x%x:\t%s\t%s\n" % (
                inst.original_inst.address, inst.original_inst.mnemonic, inst.original_inst.op_str))
        out.close()

    def write_file(self, filename):
        """ TODO load next sections from original file, rewrite them with the appropriate offset on the new file
         and modify file headers to allocate sections with new ofsets"""
        new_code = self.generate_binary_code()
        self.locate_by_original_address(self.original_entry_point)
        new_entry_point = self.locate_by_original_address(
            self.original_entry_point).new_addr
        self.pe_handler.setEntryPointAddress(new_entry_point)
        self.code_section.Misc_VirtualSize = len(new_code)
        self.code_section.Misc_PhysicalAddress = len(new_code)
        self.code_section.Misc = len(new_code)
        gap = self.pe_handler.getSectionAligment() - (len(new_code) % self.pe_handler.getSectionAligment())
        gap_bytes = str(bytearray([0 for _ in range(gap)]))
        new_code += gap_bytes
        self.code_section.SizeOfRawData = len(new_code)
        if not self.pe_handler.writeBytes(self.base_of_code, new_code):
            raise Exception('code out of text section')
        if self.debug:
            print('new file struct')
            print(self.pe_handler.dump())
        self.pe_handler.writeFile(filename)

    def locate_by_original_address(self, Address):
        for instruction in self.instructions:
            if instruction.original_addr == Address:
                return instruction
        return None

    def update_label_table(self):
        self.label_table = self.generate_label_table()
        self.get_instructions_from_labels()

    def get_instructions_from_labels(self):
        for instruction in self.instructions:
            if instruction.original_addr in self.label_table:
                self.label_table[instruction.original_addr] = instruction

    def apply_label_table(self):
        from capstone import x86_const
        re_apply = False
        first = True
        num_reps = 0
        while first or re_apply:
            first = False
            re_apply = False
            offset = self.base_of_code
            num_reps += 1
            for instruction in self.instructions:
                if instruction.new_addr != offset:
                    if not re_apply:
                        re_apply = True
                    asm, _ = self.generate_binary_instruction(instruction.original_inst, offset)
                    instruction.new_bytes = asm
                    instruction.new_addr = offset
                if (x86_const.X86_INS_JAE <= instruction.original_inst.id <= x86_const.X86_INS_JS) \
                        or x86_const.X86_INS_CALL == instruction.original_inst.id:
                    try:
                        original_address = int(instruction.original_inst.op_str, 16)
                        if original_address in self.label_table and self.label_table[original_address] is not None:
                            asm, _ = self.ks.asm('%s 0x%x' % (instruction.original_inst.mnemonic,
                                                              self.label_table[original_address].new_addr), offset)
                            asm = str(bytearray(asm))
                            if len(asm) != len(instruction.new_bytes):
                                if len(asm) < len(instruction.new_bytes):
                                    asm += str(bytearray([0x90 for i in range(len(instruction.new_bytes) - len(asm))]))
                            instruction.new_bytes = asm
                    except ValueError as e:
                        pass
                offset += len(instruction.new_bytes)
        return num_reps

    def generate_binary_instruction(self, instruction, offset):
        if instruction.id in self.NON_COMPILABLE_INSTRUCTION_IDS:
            return str(instruction.bytes), len(instruction.bytes)
        else:
            try:
                asm, _ = self.ks.asm(instruction.mnemonic + ' ' + instruction.op_str, offset)
                inst = str(bytearray(asm))
            except KsError as e:
                print(
                    "0x%x:\t%s\t%s" % (
                        instruction.address, instruction.mnemonic, instruction.op_str))
                print(instruction.mnemonic + ' ' + instruction.op_str + ' ' + str(offset))
                if instruction.op_str.endswith('%fs:'):
                    asm, _ = self.ks.asm(instruction.mnemonic + ' ' + instruction.op_str + '0', offset)
                    inst = str(bytearray(asm))
            return inst, len(inst)

    def generate_binary_code(self):
        code = ''
        for instruction in self.instructions:
            code += instruction.new_bytes
        return str(code)

    def shift_code_section(self):
        section_pointer = 0
        section_size = 0
        self.pe_handler.getLastSectionPointerAndSize()
        new_code_pointer = section_pointer + section_size
        self.code_section.PointerToRawData = new_code_pointer
        self.code_section.VirtualAddress = new_code_pointer
        self.pe_handler.setBaseOfCode(new_code_pointer)
        self.update_addresses(self.instructions, new_code_pointer)

    def get_code_size(self):
        size = 0
        for inst in self.instructions:
            size += len(inst.new_bytes)
        return size


class MetaIns(object):
    def __init__(self, original_inst, new_bytes=None, new_address=None):
        self.original_inst = original_inst
        self.original_addr = original_inst.address
        if new_address is None:
            self.new_addr = original_inst.address
        else:
            self.new_addr = new_address
        self.original_bytes = original_inst.bytes
        if new_bytes is None:
            self.new_bytes = original_inst.bytes
        else:
            self.new_bytes = new_bytes

    @property
    def size(self):
        return len(self.new_bytes)

# self.size = original_inst.size


class PEHandler(object):
    def __init__(self, pe):
        self.pe = pe

    def dump(self):
        return self.pe.dump_info()

    def getEntryPointAddress(self):
        return self.pe.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint

    def getBaseOfCodeAddress(self):
        return self.pe.OPTIONAL_HEADER.BaseOfCode

    def findSection(self, address):
        for section in self.pe.sections:
            if section.contains_rva(address):
                return section
        return None

    def getLastSectionPointerAndSize(self):
        section_pointer = 0
        section_size = 0
        for section in self.pe.sections:
            if section.PointerToRawData > section_pointer:
                section_pointer = section.PointerToRawData
                section_size = section.SizeOfRawData
        return section_pointer, section_size

    def setBaseOfCode(self, new_code_pointer):
        self.pe.OPTIONAL_HEADER.BaseOfCode = new_code_pointer

    def setEntryPointAddress(self, new_entry_point):
        self.pe.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_point

    def getSectionAligment(self):
        return self.pe.OPTIONAL_HEADER.SectionAlignment

    def getSizeOfImage(self):
        return self.pe.OPTIONAL_HEADER.SizeOfImage

    def setSizeOfImage(self, size):
        self.pe.OPTIONAL_HEADER.SizeOfImage = size

    def writeBytes(self, offset, bytes):
        return self.pe.set_bytes_at_offset(offset, bytes)

    def writeFile(self, filename):
        self.pe.write(filename)


def main(file_path):
    meta = Pymetamorph(file_path, load_file=True, debug=True)
    meta.shuffle_blocks()
    meta.update_label_table()
    meta.apply_label_table()
    meta.write_file('meta.exe')
    meta.print_disass('original.asm')
    meta.print_new_dissas('new.asm')


if __name__ == '__main__':
    if len(sys.argv) > 1:
        main(sys.argv[1])

'''print(
                "0x%x:\t%s\t%s" % (inst.original_inst.address, inst.original_inst.mnemonic, inst.original_inst.op_str))
            print('{},{},{},{}'.format(inst.original_inst.id, inst.original_inst.groups,
                                       inst.original_inst.regs_read, inst.original_inst.regs_write))'''
