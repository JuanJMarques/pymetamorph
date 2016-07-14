from __future__ import print_function
from capstone import *
from keystone import *
import pefile
import random

FILE_PATH = 'D:\\vba\\VisualBoyAdvance-SDL.exe'


class Pymetamorph(object):
    def __init__(self, file, debug=False, load_file=True):
        self.load_file = load_file
        self.file = file
        self.debug = debug
        self.instructions = []
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        if load_file:
            self.pe = pefile.PE(self.file)
            if self.debug:
                print('loading file')
            code_section = self.find_section(self.pe.OPTIONAL_HEADER.BaseOfCode)
            if code_section is None:
                raise Exception('unable to find .text section')
            raw_code = code_section.get_data(self.pe.OPTIONAL_HEADER.BaseOfCode, code_section.SizeOfRawData)
            for i in self.cs.disasm(raw_code,
                                    self.pe.OPTIONAL_HEADER.BaseOfCode):
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
                    address = self.append_instruction(new_inst, nop, address)
        if random.random() < 1:
            for j in range(random.randint(0, 10)):
                address = self.append_instruction(new_inst, nop, address)
        self.instructions = new_inst

    @staticmethod
    def append_instruction(instruction_list, instruction, address):
        ins = MetaIns(instruction)
        ins.original_addr = address
        ins.new_addr = address
        instruction_list += ins
        return address + instruction.size

    def sort_instructions(self):
        sorted(self.instructions, key=lambda instruction: instruction.new_addr)


class MetaIns(object):
    def __init__(self, original_inst):
        self.original_inst = original_inst
        self.original_addr = original_inst.address
        self.new_addr = original_inst.address
        self.original_bytes = original_inst.bytes
        self.new_bytes = original_inst.bytes


def main(file_path):
    meta = Pymetamorph(file_path, load_file=False)
    meta.insert_nop()


if __name__ == '__main__':
    main(FILE_PATH)

'''
def main(file_path):
    print("Opening {}".format(file_path))
    try:
        CODE = b"INC ecx; DEC edx"
        pe = pefile.PE(file_path)
        eop = pe.OPTIONAL_HEADER.BaseOfCode
        section = find_section(pe,eop)
        if not section:
            raise Exception('no .text section found')
        code = section.get_data(eop,section.SizeOfRawData)
        cs = Cs(CS_ARCH_X86,CS_MODE_32)
        cs2 = Cs(CS_ARCH_X86,CS_MODE_32)
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        asd = []
        for i in cs.disasm(code, eop):
            print ("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
            if i.mnemonic == 'shr' or i.mnemonic == 'rcr' or i.mnemonic == 'sar' or i.mnemonic == 'shl':
                asd += i.bytes
            else:
                encoding, count = ks.asm(i.mnemonic+' '+i.op_str)
                asd += encoding
            # print ("{} (number of statements: {}".format(encoding,count))
        for i in cs2.disasm(str(asd)):
            print ("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

    except Exception as e:
        print e
'''


# from keystone import *

# # separate assembly instructions by ; or \n
# CODE = b"INC ecx; DEC edx"
#
# try:
#     # Initialize engine in X86-32bit mode
#     ks = Ks(KS_ARCH_X86, KS_MODE_32)
#     encoding, count = ks.asm(CODE)
#     print("%s = %s (number of statements: %u)" % (CODE, encoding, count))
# except KsError as e:
#     print("ERROR: %s" % e)
