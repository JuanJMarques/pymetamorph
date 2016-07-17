from __future__ import print_function

import random
import sys

import pefile
from capstone import *
from capstone import x86_const
from keystone import *


class Pymetamorph(object):
    def __init__(self, file, debug=False, load_file=True):
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

    def insert_nop(self):
        if self.load_file:
            address = self.instructions[0].new_addr
        else:
            address = 0
        nop = None
        for nop in self.cs.disasm(str(bytearray([0x90])), 0x1000):
            break
        new_inst = []
        for i in self.instructions:
            if random.random() < 0.2:
                for j in range(random.randint(0, 10)):
                    address = self.append_instruction(new_inst, nop, address, True)
        if random.random() < 1:
            for j in range(random.randint(0, 10)):
                address = self.append_instruction(new_inst, nop, address, True)
        self.instructions = new_inst

    @staticmethod
    def append_instruction(instruction_list, instruction, address, overwrite_original_address=False):
        ins = MetaIns(instruction)
        if overwrite_original_address:
            ins.original_addr = address
        ins.new_addr = address
        instruction_list.append(ins)
        return address + instruction.size

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
        new_entry_point = self.locate_by_original_address(
            self.pe.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint).new_addr
        self.pe.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_point
        if self.debug:
            print(self.pe.dump_info())

    def locate_by_original_address(self, Address):
        for intstruction in self.instructions:
            if intstruction.original_addr == Address:
                return intstruction
        return None

    def update_label_table(self):
        self.label_table = self.generate_label_table()
        self.get_new_addresses_of_labels()

    def get_new_addresses_of_labels(self):
        for instruction in self.instructions:
            if instruction.original_addr in self.label_table:
                self.label_table[instruction.original_addr] = instruction.new_addr

    def aply_label_table(self):
        new_instructions = []
        for instruction in self.instructions:
            if (x86_const.X86_INS_JAE <= instruction.original_inst.id <= x86_const.X86_INS_JS) \
                    or x86_const.X86_INS_CALL == instruction.original_inst.id:
                new_jump = None
                asm = None
                for asm in self.ks.asm('%s 0x%x' % (
                        instruction.original_inst.mnemonic,
                        self.label_table[int(instruction.original_inst.op_str), 16])):
                    break
                for ins in self.cs.disasm(asm, 0):
                    new_jump = MetaIns(ins)
                    new_jump.original_addr = instruction.original_addr
                    new_jump.new_addr = instruction.new_addr
                    break
                new_instructions.append(new_jump)
            else:
                new_instructions.append(instruction)
        self.instructions = new_instructions



class MetaIns(object):
    def __init__(self, original_inst):
        self.original_inst = original_inst
        self.original_addr = original_inst.address
        self.new_addr = original_inst.address
        self.original_bytes = original_inst.bytes
        self.new_bytes = original_inst.bytes
        self.size = original_inst.size


def main(file_path):
    meta = Pymetamorph(file_path, load_file=True)
    meta.shuffle_blocks()
    meta.update_label_table()
    meta.debug = True
    meta.aply_label_table()
    meta.write_file('meta.exe')
    # meta.print_disass()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        main(sys.argv[1])

'''print(
                "0x%x:\t%s\t%s" % (inst.original_inst.address, inst.original_inst.mnemonic, inst.original_inst.op_str))
            print('{},{},{},{}'.format(inst.original_inst.id, inst.original_inst.groups,
                                       inst.original_inst.regs_read, inst.original_inst.regs_write))'''
