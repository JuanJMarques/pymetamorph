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
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        self.label_table = None
        if load_file:
            self.pe = pefile.PE(self.file)
            if self.debug:
                print(self.pe.dump_info())
                print('loading file')
            self.base_of_code = self.pe.OPTIONAL_HEADER.BaseOfCode
            code_section = self.find_section(self.base_of_code)
            if code_section is None:
                raise Exception('unable to find .text section')
            raw_code = code_section.get_data(self.base_of_code, code_section.SizeOfRawData)
            for i in self.cs.disasm(raw_code,
                                    self.base_of_code):
                self.instructions += [MetaIns(i)]
        else:
            self.instructions = []

    def find_section(self, address):
        for section in self.pe.sections:
            if section.contains_rva(address):
                return section
        return None

    def insert_nop(self, initial_address=None):
        address = 0
        if initial_address is None:
            address = self.base_of_code
        nop = None
        for nop in self.cs.disasm(str(bytearray([0x90])), 0):
            break
        new_inst = []
        for i in self.instructions:
            if random.random() < 0.2:
                for j in range(random.randint(0, 10)):
                    address = self.append_instruction(new_inst, nop, address)
            address = self.append_meta_instruction(new_inst, i, address)
        if random.random() < 1:
            for j in range(random.randint(0, 10)):
                address = self.append_instruction(new_inst, nop, address)
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
        while offset <= len(self.instructions):
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
                    jmp_table[addr] = addr
                    # jmp_table['0x%x' % addr] = addr
            except:
                pass
        # if self.debug:
        print(sorted(jmp_table))
        return jmp_table

    @staticmethod
    def update_addresses(instructions, initial_address):
        address = initial_address
        for instruction in instructions:
            instruction.new_addr = address
            address += instruction.size

    def print_disass(self):
        out = open("code.asm", 'w')
        for inst in self.instructions:
            out.write("0x%x:\t%s\t%s\n" % (
                inst.original_inst.address, inst.original_inst.mnemonic, inst.original_inst.op_str))
            print(
                "0x%x:\t%s\t%s" % (inst.original_inst.address, inst.original_inst.mnemonic, inst.original_inst.op_str))
        out.close()

    def write_file(self, path):
        """ TODO load next sections from original file, rewrite them with the appropriate offset on the new file
         and modify file headers to allocate sections with new ofsets"""
        new_entry_point = self.locate_by_original_address(
            self.pe.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint).new_addr
        if self.debug:
            print('original file struct')
            print(self.pe.dump_info())
        self.pe.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_point
        new_code = self.generate_binary_code()
        self.pe.set_bytes_at_offset(self.base_of_code, new_code)
        if self.debug:
            print('new file struct')
            print(self.pe.dump_info())
        self.pe.write(path)

    def locate_by_original_address(self, Address):
        for instruction in self.instructions:
            if instruction.original_addr == Address:
                return instruction
        return None

    def update_label_table(self):
        self.label_table = self.generate_label_table()
        self.get_new_addresses_of_labels()

    def get_new_addresses_of_labels(self):
        for instruction in self.instructions:
            if instruction.original_addr in self.label_table:
                self.label_table[instruction.original_addr] = instruction.new_addr

    def apply_label_table(self):
        from capstone import x86_const
        new_instructions = []
        for instruction in self.instructions:
            if (x86_const.X86_INS_JAE <= instruction.original_inst.id <= x86_const.X86_INS_JS) \
                    or x86_const.X86_INS_CALL == instruction.original_inst.id:
                new_jump = None
                asm = None
                try:
                    original_address = int(instruction.original_inst.op_str, 16)
                    if original_address in self.label_table:
                        for asm in self.ks.asm('%s 0x%x' % (
                                instruction.original_inst.mnemonic,
                                self.label_table[original_address])):
                            asm = str(bytearray(asm))
                            break
                    for ins in self.cs.disasm(asm, 0):
                        new_jump = MetaIns(ins)
                        new_jump.original_addr = instruction.original_addr
                        new_jump.new_addr = instruction.new_addr
                        break
                    new_instructions.append(new_jump)
                except ValueError as e:
                    new_instructions.append(instruction)
            else:
                new_instructions.append(instruction)
        self.instructions = new_instructions

    def generate_binary_code(self):
        code = ''
        for instruction in self.instructions:
            if instruction.original_inst.id in self.NON_COMPILABLE_INSTRUCTION_IDS:
                code += str(instruction.original_inst.bytes)
            else:
                bin_inst, _ = self.ks.asm(instruction.original_inst.mnemonic + ' ' + instruction.original_inst.op_str)
                code += str(bytearray(bin_inst))
        return code


class MetaIns(object):
    def __init__(self, original_inst):
        self.original_inst = original_inst
        self.original_addr = original_inst.address
        self.new_addr = original_inst.address
        self.original_bytes = original_inst.bytes
        self.new_bytes = original_inst.bytes
        self.size = original_inst.size


def main(file_path):
    meta = Pymetamorph(file_path, load_file=True, debug=True)
    meta.shuffle_blocks()
    meta.update_label_table()
    meta.debug = True
    meta.apply_label_table()
    meta.insert_nop()
    meta.write_file('meta.exe')


if __name__ == '__main__':
    if len(sys.argv) > 1:
        main(sys.argv[1])

'''print(
                "0x%x:\t%s\t%s" % (inst.original_inst.address, inst.original_inst.mnemonic, inst.original_inst.op_str))
            print('{},{},{},{}'.format(inst.original_inst.id, inst.original_inst.groups,
                                       inst.original_inst.regs_read, inst.original_inst.regs_write))'''
