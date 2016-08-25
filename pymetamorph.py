from __future__ import print_function

import random
import sys

import numpy as np
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
            self.code_size = self.code_section.Misc_VirtualSize
            raw_code = self.code_section.get_data(self.base_of_code, self.code_size)
            for i in self.cs.disasm(raw_code,
                                    self.base_of_code):
                self.original_inst.append(i)
                inst = MetaIns(i)
                if not len(self.instructions) == 0:
                    previous = self.instructions[-1]
                    inst.previous_instruction = previous
                    previous.next_instruction = inst
                self.instructions.append(inst)
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

    def shuffle_functions(self):
        initial_address = self.base_of_code
        functions = self.__get_functions()
        random.shuffle(functions)
        instructions = []
        for function in functions:
            instructions += function
        self.update_addresses(instructions, initial_address)
        self.instructions = instructions

    def __get_functions(self):
        from capstone import x86_const
        inf_margin = self.base_of_code
        sup_margin = self.base_of_code + self.code_size
        index = self.original_entry_point
        func_table = []
        function_calls = set()
        function_calls.add(index)
        processed_functions = []
        processed_addrs = []
        while len(function_calls) > 0:
            addr = function_calls.pop()
            processed_functions.append(addr)
            function = []
            func_table.append(function)
            inst = self.locate_by_original_address(addr)
            jmp_table = set()
            # processed_jumps = []
            cont = True
            while cont:
                function.append(inst)
                processed_addrs.append(inst.original_addr)
                if x86_const.X86_GRP_JUMP in inst.original_inst.groups:
                    if inst.original_inst.operands[0].type == x86_const.X86_OP_IMM:
                        jump_address = inst.original_inst.operands[0].imm
                        if inf_margin <= jump_address < sup_margin:
                            if x86_const.X86_INS_JMP == inst.original_inst.id:
                                # if jump_address not in jmp_table \
                                #         and jump_address not in processed_addrs:
                                #         and jump_address not in processed_jumps \
                                if jump_address not in processed_addrs:
                                    inst.new_bytes = str(bytearray([0x90]))
                                    inst = self.locate_by_original_address(jump_address)
                                else:
                                    cont = (len(jmp_table) > 0)
                                    if cont:
                                        jump_address = jmp_table.pop()
                                        # processed_jumps.append(jump_address)
                                        inst = self.locate_by_original_address(jump_address)
                            else:
                                if jump_address not in jmp_table \
                                        and jump_address not in processed_addrs:
                                    # and jump_address not in processed_jumps \
                                    jmp_table.add(jump_address)
                                cont = (inst.next_instruction is not None)
                                inst = inst.next_instruction
                    else:
                        cont = (len(jmp_table) > 0)
                        if cont:
                            jump_address = jmp_table.pop()
                            # processed_jumps.append(jump_address)
                            inst = self.locate_by_original_address(jump_address)
                elif x86_const.X86_GRP_CALL in inst.original_inst.groups \
                        and inst.original_inst.operands[0].type == x86_const.X86_OP_IMM:
                    call_address = inst.original_inst.operands[0].imm
                    if inf_margin <= call_address < sup_margin \
                            and call_address not in processed_addrs:
                        function_calls.add(call_address)
                        # print(
                        #     "0x%x:\t%s\t%s" % (
                        #     inst.original_inst.address, inst.original_inst.mnemonic, inst.original_inst.op_str))
                    cont = (inst.next_instruction is not None)
                    inst = inst.next_instruction
                elif x86_const.X86_GRP_RET in inst.original_inst.groups:
                    cont = (len(jmp_table) > 0)
                    if cont:
                        jump_address = jmp_table.pop()
                        # processed_jumps.append(jump_address)
                        inst = self.locate_by_original_address(jump_address)
                else:
                    cont = (inst.next_instruction is not None)
                    inst = inst.next_instruction
        return func_table

    def sort_instructions(self):
        sorted(self.instructions, key=lambda instruction: instruction.new_addr)

    def generate_label_table(self):
        from capstone import x86_const
        jmp_table = dict()
        for inst in self.instructions:
            try:
                if (x86_const.X86_GRP_JUMP in inst.original_inst.groups
                    or x86_const.X86_GRP_CALL in inst.original_inst.groups) \
                        and inst.original_inst.operands[0].type == x86_const.X86_OP_IMM:
                    addr = int(inst.original_inst.operands[0].imm)
                    jmp_table[addr] = None
            except Exception as e:
                raise e
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
                if x86_const.X86_GRP_JUMP in instruction.original_inst.groups \
                        or x86_const.X86_GRP_CALL in instruction.original_inst.groups:
                    try:
                        if instruction.original_inst.operands[0].type == x86_const.X86_OP_IMM:
                            original_address = instruction.original_inst.operands[0].imm
                            if original_address in self.label_table and self.label_table[original_address] is not None:
                                asm, _ = self.ks.asm('%s 0x%x' % (instruction.original_inst.mnemonic,
                                                                  self.label_table[original_address].new_addr), offset)
                                asm = str(bytearray(asm))
                                instruction.new_bytes = asm
                            else:
                                asm, _ = self.ks.asm(instruction.original_inst.mnemonic + ' '
                                                     + instruction.original_inst.op_str, offset)
                                asm = str(bytearray(asm))
                                instruction.new_bytes = asm
                        else:
                            asm, _ = self.ks.asm(instruction.original_inst.mnemonic + ' '
                                                 + instruction.original_inst.op_str, offset)
                            asm = str(bytearray(asm))
                            instruction.new_bytes = asm

                    except ValueError as e:
                        pass
                if len(instruction.new_bytes) != len(instruction.original_bytes):
                    print('-----------------------------------------------------------------------------------------')
                    print(b'0x{:x}:\t{}\t{}\t{}'.format(
                        instruction.original_inst.address, instruction.original_inst.mnemonic,
                        instruction.original_inst.op_str, instruction.original_bytes))
                    for ins in self.cs.disasm(instruction.new_bytes, offset):
                        print(b'0x{:x}:\t{}\t{}\t{}'.format(
                            ins.address, ins.mnemonic, ins.op_str, instruction.new_bytes))
                    print('-----------------------------------------------------------------------------------------')
                instruction.new_addr = offset
                offset += len(instruction.new_bytes)
        return num_reps

    def generate_binary_instruction(self, instruction, offset):
        if instruction.id in self.NON_COMPILABLE_INSTRUCTION_IDS:
            return str(instruction.bytes), len(instruction.bytes)
        else:
            inst = None
            try:
                asm, _ = self.ks.asm(instruction.mnemonic + ' ' + instruction.op_str, offset)
                inst = str(bytearray(asm))
            except KsError as e:
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

    def permute_registers(self):
        functions = self.__get_functions()
        for function in functions:
            registers = self.get_registers_from_function(function)
            copy = [x for x in registers]
            random.shuffle(copy, random.random)
            permutation_map = dict()
            for i in range(len(registers)):
                permutation_map[registers[i]] = copy[i]
            self.apply_permutation(function, permutation_map)
        pass

    @staticmethod
    def get_registers_from_function(function):
        from capstone import x86_const
        registers = set()
        for instruction in function:
            operands = instruction.original_inst.operands
            for operand in operands:
                if operand.type == x86_const.X86_OP_REG \
                        and (operand.reg == x86_const.X86_REG_EDI
                             or operand.reg == x86_const.X86_REG_ESI
                             or operand.reg == x86_const.X86_REG_EBX
                             or operand.reg == x86_const.X86_REG_ECX
                             or operand.reg == x86_const.X86_REG_EDX):
                    registers.add(operand.reg)
        return list(registers)

    def apply_permutation(self, function, permutation_map):
        from capstone import x86_const
        new_reg_names = list()
        if len(function) > 0:
            aux_inst = function[0].original_inst
            for reg in permutation_map.values():
                new_reg_names.append(aux_inst.reg_name(reg))
        for instruction in function:
            operands = instruction.original_inst.operands
            new_inst_str = instruction.original_inst.mnemonic + ' ' + instruction.original_inst.op_str
            recompile = False
            counter = 0
            for operand in operands:
                if operand.type == x86_const.X86_OP_REG \
                        and operand.reg in permutation_map \
                        and (operand.reg == x86_const.X86_REG_EDI
                             or operand.reg == x86_const.X86_REG_ESI
                             or operand.reg == x86_const.X86_REG_EBX
                             or operand.reg == x86_const.X86_REG_ECX
                             or operand.reg == x86_const.X86_REG_EDX):
                    new_inst_str = new_inst_str.replace(instruction.original_inst.reg_name(operand.reg)
                                                        , '{' + str(counter) + '}')
                    counter += 1
                    recompile = True
            if recompile:
                new_inst_str = new_inst_str.format(*new_reg_names)
                asm, _ = self.ks.asm(new_inst_str, instruction.new_addr)
                instruction.new_bytes = str(bytearray(asm))

    def equivalent_instruction_substitution(self):
        from capstone import x86_const
        for instruction in self.instructions:
            try:
                if instruction.original_inst.id == x86_const.X86_INS_ADD:
                    if len(instruction.original_inst.operands) == 2 \
                            and instruction.original_inst.operands[0].type == x86_const.X86_OP_IMM:
                        new_inst_str = instruction.original_inst.mnemonic.replace('add', 'sub') + ' ' \
                                       + instruction.original_inst.op_str.replace(
                            '{:x}'.format(instruction.original_inst.operands[0].imm),
                            '{:x}'.format(self.convert_to_unsigned(-1 * instruction.original_inst.operands[0].imm,
                                                                   instruction.original_inst.operands[0].size)))
                        # asm,_ = self.ks.asm(new_inst_str)
                        # instruction.new_bytes=str(asm)
                elif instruction.original_inst.id == x86_const.X86_INS_SUB:
                    if len(instruction.original_inst.operands) == 2 \
                            and instruction.original_inst.operands[0].type == x86_const.X86_OP_IMM:
                        new_inst_str = instruction.original_inst.mnemonic.replace('sub', 'add') + ' ' \
                                       + instruction.original_inst.op_str.replace(
                            '{:x}'.format(instruction.original_inst.operands[0].imm),
                            '{:x}'.format(self.convert_to_unsigned(-1 * instruction.original_inst.operands[0].imm,
                                                                   instruction.original_inst.operands[0].size)))
                        asm, _ = self.ks.asm(new_inst_str)
                        instruction.new_bytes = str(asm)
                elif instruction.original_inst.id == x86_const.X86_INS_XOR:
                    if len(instruction.original_inst.operands) == 2 and ((instruction.original_inst.operands[
                                                                              0].type == x86_const.X86_OP_IMM and
                                                                                  instruction.original_inst.operands[
                                                                                      0].imm == 0)
                                                                         or (
                                        instruction.original_inst.operands[1].type == x86_const.X86_OP_IMM and
                                        instruction.original_inst.operands[1].imm == 0)
                                                                         or (
                                            instruction.original_inst.operands[0].type == x86_const.X86_OP_REG and
                                            instruction.original_inst.operands[1].type == x86_const.X86_OP_REG
                                and instruction.original_inst.operands[0].reg == instruction.original_inst.operands[
                                    1].reg)):
                        # print("0x%x:\t%s\t%s" % (instruction.original_inst.address, instruction.original_inst.mnemonic,
                        #                          instruction.original_inst.op_str))
                        pass
                elif instruction.original_inst.id == x86_const.X86_INS_OR:
                    if len(instruction.original_inst.operands) == 2 and \
                                    instruction.original_inst.operands[0].type == x86_const.X86_OP_REG and \
                                    instruction.original_inst.operands[1].type == x86_const.X86_OP_REG and \
                                    instruction.original_inst.operands[0].reg == instruction.original_inst.operands[
                                1].reg:
                        new_inst_str = self.insn_name(x86_const.X86_INS_CMP) + ' $0,' \
                                       + instruction.original_inst.reg_name(instruction.original_inst.operands[0].reg)
                        asm, _ = self.ks.asm(new_inst_str)
                        instruction.new_bytes = str(asm)
                    pass
                elif instruction.original_inst.id == x86_const.X86_INS_AND:
                    # print("0x%x:\t%s\t%s" % (instruction.original_inst.address, instruction.original_inst.mnemonic,
                    #                          instruction.original_inst.op_str))
                    if len(instruction.original_inst.operands) == 2:
                        if instruction.original_inst.operands[0].type == x86_const.X86_OP_IMM and \
                                        instruction.original_inst.operands[0].imm == 0:
                            new_inst_str = instruction.original_inst.mnemonic.replace('and', 'mov') + ' ' \
                                           + instruction.original_inst.op_str
                            asm, _ = self.ks.asm(new_inst_str)
                            instruction.new_bytes = str(asm)
                        elif instruction.original_inst.operands[0].type == x86_const.X86_OP_REG and \
                                        instruction.original_inst.operands[1].type == x86_const.X86_OP_REG and \
                                        instruction.original_inst.operands[0].reg == instruction.original_inst.operands[
                                    1].reg:
                            new_inst_str = instruction.original_inst.insn_name(x86_const.X86_INS_CMP) + ' $0' \
                                           + instruction.original_inst.reg_name(
                                instruction.original_inst.operands[0].reg)
                            asm, _ = self.ks.asm(new_inst_str)
                            instruction.new_bytes = str(asm)
                            pass
                    pass
            except Exception as e:
                print("0x%x:\t%s\t%s" % (instruction.original_inst.address, instruction.original_inst.mnemonic,
                                         instruction.original_inst.op_str))
                raise e
        print('')

    def insn_name(self, ins_id):
        from capstone import _cs as cs
        return cs.cs_insn_name(self.cs.csh, ins_id).decode('ascii')

    @staticmethod
    def convert_to_unsigned(number, size):
        if size == 1:
            return np.uint8(number)
        elif size == 2:
            return np.uint16(number)
        else:
            return np.uint32(number)


class MetaIns(object):
    def __init__(self, original_inst, new_bytes=None, new_address=None, next_instruction=None,
                 previous_instruction=None):
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
        self._next_instruction = next_instruction
        self._previous_instruction = previous_instruction

    @property
    def next_instruction(self):
        return self._next_instruction

    @next_instruction.setter
    def next_instruction(self, value):
        self._next_instruction = value

    @property
    def previous_instruction(self):
        return self._previous_instruction

    @previous_instruction.setter
    def previous_instruction(self, value):
        self._previous_instruction = value

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
    meta.equivalent_instruction_substitution()
    meta.permute_registers()
    meta.shuffle_functions()
    meta.update_label_table()
    meta.apply_label_table()
    meta.print_disass('original.asm')
    meta.write_file('meta.exe')
    meta.print_new_dissas('new.asm')


if __name__ == '__main__':
    if len(sys.argv) > 1:
        main(sys.argv[1])

'''print(
                "0x%x:\t%s\t%s" % (inst.original_inst.address, inst.original_inst.mnemonic, inst.original_inst.op_str))
            print('{},{},{},{}'.format(inst.original_inst.id, inst.original_inst.groups,
                                       inst.original_inst.regs_read, inst.original_inst.regs_write))'''
