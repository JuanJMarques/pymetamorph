from __future__ import print_function

import argparse
import random

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
            self.pe_handler = PEHandler(self.file)
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
                                if jump_address not in processed_addrs:
                                    inst.new_bytes = str(bytearray([0x90]))
                                    inst = self.locate_by_original_address(jump_address)
                                else:
                                    cont = (len(jmp_table) > 0)
                                    if cont:
                                        jump_address = jmp_table.pop()
                                        inst = self.locate_by_original_address(jump_address)
                            else:
                                if jump_address not in jmp_table \
                                        and jump_address not in processed_addrs:
                                    jmp_table.add(jump_address)
                                cont = (inst.next_instruction is not None)
                                inst = inst.next_instruction
                    else:
                        cont = (len(jmp_table) > 0)
                        if cont:
                            jump_address = jmp_table.pop()
                            inst = self.locate_by_original_address(jump_address)
                elif x86_const.X86_GRP_CALL in inst.original_inst.groups \
                        and inst.original_inst.operands[0].type == x86_const.X86_OP_IMM:
                    call_address = inst.original_inst.operands[0].imm
                    if inf_margin <= call_address < sup_margin \
                            and call_address not in processed_addrs:
                        function_calls.add(call_address)
                    cont = (inst.next_instruction is not None)
                    inst = inst.next_instruction
                elif x86_const.X86_GRP_RET in inst.original_inst.groups:
                    cont = (len(jmp_table) > 0)
                    if cont:
                        jump_address = jmp_table.pop()
                        inst = self.locate_by_original_address(jump_address)
                else:
                    cont = (inst.next_instruction is not None)
                    inst = inst.next_instruction
        return func_table

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

    def get_code_size(self):
        size = 0
        for inst in self.instructions:
            size += len(inst.new_bytes)
        return size

    def permute_registers(self, probability=0.4):
        functions = self.__get_functions()
        for function in functions:
            rndm = random.random()
            if rndm < probability:
                registers = self.get_registers_from_function(function)
                copy = [x for x in registers]
                random.shuffle(copy, random.random)
                permutation_map = dict()
                for i in range(len(registers)):
                    if registers[i] != copy[i]:
                        permutation_map[registers[i]] = copy[i]
                if len(permutation_map) > 0:
                    self.apply_register_permutation(function, permutation_map)

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
                             or operand.reg == x86_const.X86_REG_EBX):
                    registers.add(operand.reg)
        return list(registers)

    def apply_register_permutation(self, function, permutation_map):
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
                             or operand.reg == x86_const.X86_REG_EBX):
                    new_inst_str = new_inst_str.replace(instruction.original_inst.reg_name(operand.reg)
                                                        , '{' + str(counter) + '}')
                    counter += 1
                    recompile = True
            if recompile:
                new_inst_str = new_inst_str.format(*new_reg_names)
                asm, _ = self.ks.asm(new_inst_str, instruction.new_addr)
                instruction.new_bytes = str(bytearray(asm))

    def equivalent_instruction_substitution(self, probability=0.3):
        from capstone import x86_const
        for instruction in self.instructions:
            try:
                rndm = random.random()
                if rndm < probability:
                    if instruction.original_inst.id == x86_const.X86_INS_ADD:
                        if len(instruction.original_inst.operands) == 2 \
                                and instruction.original_inst.operands[0].type == x86_const.X86_OP_IMM:
                            new_inst_str = instruction.original_inst.mnemonic.replace('add', 'sub') + ' ' \
                                           + instruction.original_inst.op_str.replace('$', '$-')
                            asm, _ = self.ks.asm(new_inst_str, instruction.original_addr)
                            instruction.new_bytes = str(bytearray(asm))
                            for i in self.cs.disasm(instruction.new_bytes, instruction.original_addr):
                                instruction.original_inst = i
                    elif instruction.original_inst.id == x86_const.X86_INS_SUB:
                        if len(instruction.original_inst.operands) == 2 \
                                and instruction.original_inst.operands[0].type == x86_const.X86_OP_IMM:
                            new_inst_str = instruction.original_inst.mnemonic.replace('sub', 'add') + ' ' \
                                           + instruction.original_inst.op_str.replace('$', '$-')
                            asm, _ = self.ks.asm(new_inst_str, instruction.original_addr)
                            instruction.new_bytes = str(bytearray(asm))
                            for i in self.cs.disasm(instruction.new_bytes, instruction.original_addr):
                                instruction.original_inst = i
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
                            if instruction.original_inst.operands[0].type == x86_const.X86_OP_REG:
                                new_inst_str = instruction.original_inst.mnemonic.replace('xor', 'mov') + ' ' \
                                               + '$0,%' + instruction.original_inst.reg_name(
                                    instruction.original_inst.operands[0].reg)
                            else:
                                new_inst_str = instruction.original_inst.mnemonic.replace('xor', 'mov') + ' ' \
                                               + '$0,%' + instruction.original_inst.reg_name(
                                    instruction.original_inst.operands[1].reg)
                            asm, _ = self.ks.asm(new_inst_str, instruction.original_addr)
                            instruction.new_bytes = str(bytearray(asm))
                            for i in self.cs.disasm(instruction.new_bytes, instruction.original_addr):
                                instruction.original_inst = i
                    elif instruction.original_inst.id == x86_const.X86_INS_OR:
                        if len(instruction.original_inst.operands) == 2 and \
                                        instruction.original_inst.operands[0].type == x86_const.X86_OP_REG and \
                                        instruction.original_inst.operands[1].type == x86_const.X86_OP_REG and \
                                        instruction.original_inst.operands[0].reg == instruction.original_inst.operands[
                                    1].reg:
                            new_inst_str = self.insn_name(x86_const.X86_INS_CMP) + ' $0, %' \
                                           + instruction.original_inst.reg_name(
                                instruction.original_inst.operands[0].reg)
                            asm, _ = self.ks.asm(new_inst_str, instruction.original_addr)
                            instruction.new_bytes = str(bytearray(asm))
                            for i in self.cs.disasm(instruction.new_bytes, instruction.original_addr):
                                instruction.original_inst = i
                    elif instruction.original_inst.id == x86_const.X86_INS_AND:
                        if len(instruction.original_inst.operands) == 2:
                            if instruction.original_inst.operands[0].type == x86_const.X86_OP_IMM and \
                                            instruction.original_inst.operands[0].imm == 0:
                                new_inst_str = instruction.original_inst.mnemonic.replace('and', self.insn_name(
                                    x86_const.X86_INS_MOV)) + ' ' \
                                               + instruction.original_inst.op_str
                                asm, _ = self.ks.asm(new_inst_str, instruction.original_addr)
                                instruction.new_bytes = str(bytearray(asm))
                                for i in self.cs.disasm(instruction.new_bytes, instruction.original_addr):
                                    instruction.original_inst = i
                            elif instruction.original_inst.operands[0].type == x86_const.X86_OP_REG and \
                                            instruction.original_inst.operands[1].type == x86_const.X86_OP_REG and \
                                            instruction.original_inst.operands[0].reg == \
                                            instruction.original_inst.operands[
                                                1].reg:
                                new_inst_str = instruction.original_inst.insn_name(x86_const.X86_INS_CMP) + ' $0' \
                                               + instruction.original_inst.reg_name(
                                    instruction.original_inst.operands[0].reg)
                                asm, _ = self.ks.asm(new_inst_str, instruction.original_addr)
                                instruction.new_bytes = str(bytearray(asm))
                                for i in self.cs.disasm(instruction.new_bytes, instruction.original_addr):
                                    instruction.original_inst = i
            except Exception as e:
                pass

    def insn_name(self, ins_id):
        from capstone import _cs as cs
        return cs.cs_insn_name(self.cs.csh, ins_id).decode('ascii')



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

class PEHandler(object):
    def __init__(self, file_path):
        self.pe = pefile.PE(file_path)

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


def parse_args():
    parser = argparse.ArgumentParser(
        description='Pymetamorph: a metamorphic engine for Windowns 32 bits executables made in python',
        epilog='if no optionals arguments are passed the default behavior is the same as '
               'pymetamorph -i -r -sf -n -ip 0.3 -rp 0.4')
    parser.add_argument('-i', '--instruction_substitution', action='store_true', required=False,  # default=True,
                        help='Perform equivalent instruction substitution, default value is true')
    parser.add_argument('-ip', '--instruction_substitution_probability', type=float, required=False,  # default=0.3,
                        help='Probability to perform an equivalent substitution to an instruction, default value is 0.3')
    parser.add_argument('-r', '--register_swap', action='store_true', required=False,  # default=True,
                        help='Perform register swapping, default value is true')
    parser.add_argument('-rp', '--register_swapping_probability', type=float, required=False,  # default=0.4,
                        help='Probability to swap registers in a subrutine, default value is 0.4')
    parser.add_argument('-ss', '--subrutine_swapping', action='store_true', required=False,  # default=False,
                        help='Perform swapping positions between the programs subrutines, default value is false')
    parser.add_argument('-n', '--nop_insert', action='store_true', required=False,  # default=True,
                        help='Insert NOP instruction randomly in the programs code, default value is true')
    parser.add_argument('-sf', '--shuffle_code_blocks', action='store_true', required=False,  # default=True,
                        help='Divide the code into blocks and shuffle their position')
    parser.add_argument('input_file', type=str, help='The originals path to the executable file')
    parser.add_argument('output_file', type=str, help='The path of the new executable file')

    args = parser.parse_args()
    if not (
                    args.instruction_substitution or args.nop_insert or args.register_swap or args.shuffle_code_blocks or args.subrutine_swapping):
        args.instruction_substitution = True
        args.nop_insert = True
        args.register_swap = True
        args.shuffle_code_blocks = True
        args.subrutine_swapping = False
    if args.instruction_substitution and args.instruction_substitution_probability is None:
        args.instruction_substitution_probability = 0.3
    if args.register_swap and args.register_swapping_probability is None:
        args.register_swapping_probability = 0.4
    return args


def main():
    args = parse_args()
    meta = Pymetamorph(args.input_file, load_file=True)
    if args.instruction_substitution and args.instruction_substitution_probability > 0:
        meta.equivalent_instruction_substitution(args.instruction_substitution_probability)
    if args.register_swap and args.register_swapping_probability > 0:
        meta.permute_registers(args.register_swapping_probability)
    if args.subrutine_swapping:
        meta.shuffle_functions()
    if args.shuffle_code_blocks:
        meta.shuffle_blocks()
    meta.update_label_table()
    meta.apply_label_table()
    meta.write_file(args.output_file)


if __name__ == '__main__':
    main()
