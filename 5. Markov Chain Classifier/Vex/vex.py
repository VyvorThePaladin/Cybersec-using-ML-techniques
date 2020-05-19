
import os
import pyvex
import archinfo
from Disassemblies import Disassembly
import binascii


import logging

#pyvex.set_iropt_level(2)
# Set logging for this module
logger = logging.getLogger("Vex.vex")
#logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)

fileHandler = logging.FileHandler("{0}.log".format(os.path.splitext(os.path.basename(__file__))[0]), mode='w')
logger.addHandler(fileHandler)


class BlockNode(object):
    """
    Angr BlockNode shim
    """

    __slots__ = ['addr', 'vex']

    def __init__(self, addr, vex_irsb):
        assert isinstance(vex_irsb, pyvex.IRSB), "Expected a type of Vex IRSB"

        # Start address of the block
        self.addr = addr

        # Sets the vex irsb object
        self.vex = vex_irsb



class AngrFunction(object):
    """
    Angr function shim
    https://github.com/angr/angr/blob/master/angr/knowledge/function.py
    """

    __slots__ = ['addr', 'arch', 'name', 'syscall', 'is_plt', 'block_map', 'disassembly_basicblock_list','segment_name',
                 'entry_irsb']

    def __init__(self, disassembly_function, arch):
        """
        Function constructor
        :param addr:            The address of the function.
        :param name:            (Optional) The name of the function.
        :param syscall:         (Optional) Whether this function is a syscall or not.
        """

        # Make sure we have received the proper Disassemby Function object
        assert isinstance(disassembly_function, Disassembly.DisassemblyFunction), \
            "Expected a type of DisassembyFunction"

        assert isinstance(arch, archinfo.Arch), "Expect a type of archinfo.Arch"

        # Address
        self.addr = disassembly_function.start_address

        # Arch information object
        self.arch = arch

        # Name
        self.name = disassembly_function.name

        # Syscall (@todo: Get this information)
        self.syscall = False

        # Segment name
        self.segment_name = disassembly_function.segment_name

        # Is plt (@todo: Get this information)
        self.is_plt = self._is_plt(self.segment_name)

        # Dictionary that maps an address to a corresponding block
        self.block_map = dict()

        self.disassembly_basicblock_list = disassembly_function.disassembly_basicblock_list

        self._generate_blocks()

    def get_block(self, address):

        try:
            return self.block_map[address]

        except KeyError:

            logger.warning("Unable to retrieve irsb with start address 0x{0:x} in function {1}".format(address,self.name))

            return None

    def _generate_blocks(self):

        block_list = []

        logger.debug("Generating blocks for Function: {}".format(self.name))


        for dis_basicblock in self.disassembly_basicblock_list:

            logger.debug("Processing basic block: start address 0x{0:x}; end address 0x{1:x}".
                         format(dis_basicblock.start_address, dis_basicblock.end_address))

            vex_irsb_opcode_bytes = bytes()
            vex_irsb_num_bytes = 0
            vex_irsb_num_instructions = 0
            vex_irsb_start_address = None
            for dis_instruction in dis_basicblock.disassembly_instruct_list:

                logger.debug("[0x{0:x}] Opcode bytes: '{1}' size: '{2}'".format(dis_instruction.address,
                                                                                binascii.hexlify(bytearray(dis_instruction.opcode_bytes)),
                                                                                dis_instruction.size))

                logger.debug("Instruction mnemonic: {}".format(dis_instruction.mnemonic))

                if vex_irsb_start_address is None:

                    vex_irsb_start_address = dis_instruction.address

                    logger.debug("vex irsb start address 0x{0:x}".format(vex_irsb_start_address))

                    pass

                if self._is_repeatable_inst(dis_instruction.mnemonic):

                    # Repeatable instructions need to be its own basic block so that they
                    # can jump back to themselves or jump to the next instruction that follows.

                    # Therefore, we'll wrap up the current irsb. That way the repeatable instructions will start
                    # at the start of a new irsb

                    # ****Wrap up the current irsb if previous instructions have been placed in it****
                    if vex_irsb_num_instructions > 0:
                        irsb = self._generate_irsb(vex_irsb_opcode_bytes,
                                                   vex_irsb_start_address,
                                                   self.arch,
                                                   vex_irsb_num_instructions,
                                                   vex_irsb_num_bytes)

                        # Create the BlockNode that houses the irsb object
                        block = BlockNode(vex_irsb_start_address, irsb)

                        # Add the block to block map
                        self.block_map[vex_irsb_start_address] = block

                    # *****Create an irsb soley for this repeatable instruction****
                    irsb = self._generate_irsb(dis_instruction.opcode_bytes,
                                               dis_instruction.address,
                                               self.arch,
                                               1,
                                               dis_instruction.size)

                    # Create the BlockNode that houses the irsb object
                    block = BlockNode(dis_instruction.address, irsb)

                    # Add the block to block map
                    self.block_map[dis_instruction.address] = block

                    # ****Reset the vex irsb elements since we will now began building a new irsb*****
                    vex_irsb_start_address = None
                    vex_irsb_opcode_bytes = bytes()
                    vex_irsb_num_instructions = 0
                    vex_irsb_num_bytes = 0

                    continue

                vex_irsb_opcode_bytes += dis_instruction.opcode_bytes
                vex_irsb_num_instructions += 1
                vex_irsb_num_bytes += dis_instruction.size

                if self._is_a_unconditional_branch_mnemonic(dis_instruction.mnemonic):

                    # End of the irsb because this instruction is an unconditional branch
                    irsb = self._generate_irsb(vex_irsb_opcode_bytes,
                                               vex_irsb_start_address,
                                               self.arch,
                                               vex_irsb_num_instructions,
                                               vex_irsb_num_bytes)

                    # Create the BlockNode that houses the irsb object
                    block = BlockNode(vex_irsb_start_address, irsb)

                    # Add the block to block map
                    self.block_map[vex_irsb_start_address] = block

                    # Reset the vex irsb elements since we will now began building a new irsb
                    vex_irsb_start_address = None
                    vex_irsb_opcode_bytes = bytes()
                    vex_irsb_num_instructions = 0
                    vex_irsb_num_bytes = 0

                    continue



            # Check if we need to create another irsb
            # Note: This occurs if the dis_basicblock does not terminate with a unconditional
            #       branch or return instruction
            if vex_irsb_num_bytes > 0:

                assert vex_irsb_opcode_bytes is not None
                assert vex_irsb_num_instructions > 0


                irsb = self._generate_irsb(vex_irsb_opcode_bytes,
                                           vex_irsb_start_address,
                                           self.arch,
                                           vex_irsb_num_instructions,
                                           vex_irsb_num_bytes)

                # Create the BlockNode that houses the irsb object
                block = BlockNode(vex_irsb_start_address, irsb)

                # Add the block to block map
                self.block_map[vex_irsb_start_address] = block

    @staticmethod
    def _is_repeatable_inst(mnemonic):

        if mnemonic in ['ins', 'movs', 'outs', 'lods', 'stos', 'cmps', 'scas']:

            return True

        return False

    @staticmethod
    def _is_plt(segment_name):

        if segment_name in ['.idata','.plt']:

            return True

        elif segment_name in ['.text']:

            return False

        else:

            raise Exception("Unsupported segment_name: {}".format(segment_name))

    def _generate_irsb(self,
                       vex_irsb_opcode_bytes,
                       vex_irsb_start_address,
                       arch,
                       vex_irsb_num_instructions,
                       vex_irsb_num_bytes ):

        irsb = None

        try:

            # Create the irsb object
            irsb = pyvex.IRSB(data=vex_irsb_opcode_bytes,
                              mem_addr=vex_irsb_start_address,
                              arch=arch,
                              num_inst=vex_irsb_num_instructions,
                              num_bytes=vex_irsb_num_bytes)

            logger.debug("Irsb size: {}".format(irsb.size))

            logger.debug(irsb._pp_str())

        except pyvex.errors.PyVEXError as ex:

            pass
            # logger.warning("[0x{0:x}] Problem creating irsb with start address: {1}; \nRecovering from Pyvex.Error -->{2}"
            #                .format(vex_irsb_start_address,ex))

            # Since we had a problem generating the IRSB with supplied opcodes, we'll replace with the equivalent
            # byte length of nops
            # Problem likely hardware instructions that can't be emulated/virtualized
            irsb = self._generate_nop_irsb(vex_irsb_start_address, vex_irsb_num_bytes)

            logger.warning("Replacing problem opcode with nops of the same length as original opcode")
            logger.warning(irsb._pp_str())


        return irsb

    def _generate_nop_irsb(self, address, num_bytes):

        nopcode_bytes = ""
        num_inst = 0

        if address is None:

            address = 0x00

        if isinstance(self.arch, archinfo.ArchX86):

            nopcode_bytes = b"\x90" * num_bytes
            num_inst = num_bytes

        elif isinstance(self.arch, archinfo.ArchAMD64):

            nopcode_bytes = b"\x90" * num_bytes
            num_inst = num_bytes

        else:

            raise ValueError("Unsupported architecture: {}".format(repr(self.arch)))

        # Create the nop irsb object
        irsb = pyvex.IRSB(data=nopcode_bytes,
                          mem_addr=address,
                          arch=self.arch,
                          num_inst=num_inst,
                          num_bytes=num_bytes)

        return irsb

    @staticmethod
    def _is_a_unconditional_branch_mnemonic(mnemonic):

        if mnemonic in ['call','jmp']:
            return True

        return False


    @property
    def block_addrs(self):
        """
        An iterator of all local block addresses in the current function.
        :return: block addresses.
        """

        for addr in self.block_map:
            yield addr

    @property
    def blocks(self):
        """
        An iterator of all local blocks in the current function.
        :return: angr.lifter.Block instances.
        """

        for key in self.block_map:
            try:
                yield self.block_map[key]
            except KeyError:
                logger.error("Unable to get block at address: {}".format(key))

    @property
    def entry_block(self):

        return self.block_map[self.addr]


class Vex(object):
    def __init__(self, disassembly_binary):

        # Verify we have an object of type Disassemblies binary
        assert isinstance(disassembly_binary, Disassembly.DisassemblyBinary), "Expected object of type 'Disassemblies'"

        self._disassembly_binary = disassembly_binary

        # Processor type
        self._proc_type = disassembly_binary.proc_type

        # Word size
        self._word_size = disassembly_binary.word_size

        # Endness (Little endian vs Big endian)
        self._endness = disassembly_binary.endness

        # # Disassemblies function map where the address is the key
        self._disass_func_map = {dis_func.start_address: dis_func for dis_func in
                                  self._disassembly_binary.disassembly_func_list}

        # # Function cache
        self._function_cache = {}

        # Function addresses
        self._function_addrs = None

        # Sha256 hash
        self._binary_sha256_hash = disassembly_binary.binary_sha256_hash

        # Initialize binary name
        self._binary_name = disassembly_binary.binary_name

        # Import symbol list
        self._import_symbol_list = disassembly_binary.import_symbol_list

        # Arch information
        self._arch = None
        if self._proc_type == Disassembly.ProcessorType.x86_64:

            # AMD 64
            self._arch = archinfo.ArchAMD64()

        elif self._proc_type == Disassembly.ProcessorType.x86:

            self._arch = archinfo.ArchX86()

        else:
            raise ValueError("Unsupported architecture: '{}'".format(self._proc_type))

    # def get_angr_function_by_name(self, func_name):
    #
    #     for disassembly_function in self._disassembly_binary.disassembly_func_list:
    #
    #         if func_name != disassembly_function.name:
    #             continue
    #
    #         logger.info("Generating angr function: Name {}, Address {}".format(disassembly_function.name,
    #                                                                            disassembly_function.start_address))
    #         angr_func = AngrFunction(disassembly_function, self._arch)
    #
    #         return angr_func

    def get_angr_function(self, addr):

        # Check if we have a cached copy
        if addr in self._function_cache:

            angr_func = self._function_cache[addr]

            logger.debug("Retrieving angr function:{}".format(angr_func.name))

            return angr_func

        # Not in cache, so need to create
        else:

            if addr in self.function_addrs:

                # Get the disassembly function
                disas_func = self._disass_func_map[addr]

                # Convert to an angr function
                angr_func = AngrFunction(disas_func, self._arch)

                logger.debug("Retrieving angr function:{}".format(angr_func.name))

                # Add to cache
                self._function_cache[addr] = angr_func

                return angr_func
            else:
                logger.warning("No function with address : 0x{0:x}".format(addr))
                return None

    @classmethod
    def from_disassembly_binary_file(cls, dis_binary_file_path):

        # Get the disassembly binary object
        disassembly_binary = Disassembly.DisassemblyBinary.deserialize_from_file(dis_binary_file_path)

        vex_obj = cls(disassembly_binary)

        return vex_obj

    @property
    def binary_sha256_hash(self):
        return self._binary_sha256_hash

    @property
    def binary_name(self):
        return self._binary_name

    @property
    def function_addrs(self):

        # Lazy initialize
        if self._function_addrs is None:
            self._function_addrs = sorted({disas_func.start_address for disas_func in
                                           self._disassembly_binary.disassembly_func_list})

        return self._function_addrs

    @property
    def import_symbol_list(self):
        return self._import_symbol_list

    @property
    def num_functions(self):

        return len(self._disassembly_binary.disassembly_func_list)

    @property
    def functions(self):

        """
        An iterator of all angr functions in the disassembly binary
        :return: angr function instances.
        """
        for func_addr in self.function_addrs:
            angr_func = self.get_angr_function(func_addr)
            yield angr_func

    @property
    def segment_index(self):
        return self._disassembly_binary.segment_index

    @property
    def total_segments(self):
        return self._disassembly_binary.total_segments


def test_harness():
    logger.info("****************Test Harness*****************")


    TEST_DISASSEMBLY_PB_FILE_PATH = "../malware_protos/" \
                                    "sample_J__70cb0b4b8e60dfed949a319a9375fac44168ccbb_Disassembly_2bef7e6b17643300cd8d98dd90a4c3cb0a051ee03272166c7d9589aa62652f6c.pb.z"

    # Build the disassembly object from an xml file
    test_disassembly_binary = Disassembly.DisassemblyBinary.deserialize_from_file(TEST_DISASSEMBLY_PB_FILE_PATH)

    vex = Vex(test_disassembly_binary)

    total_funcs = vex.num_functions

    processed_funcs = 0

    # # ====== Debug a function =======
    # angr_func = vex.get_angr_function(0x101f850)
    # logger.info("[{}/{}]function name: {}".format(processed_funcs, total_funcs, angr_func.name))
    #
    # block_index =0
    # for block in angr_func.blocks:
    #
    #     print("Block index: {}".format(block_index))
    #
    #     block.vex.pp()
    #
    #     block_index +=1
    #
    #     pass
    #
    # return
    # # # ====== Debug a function =======

    for angr_func in vex.functions:

        logger.info("[{}/{}]function name: {}".format(processed_funcs,total_funcs,angr_func.name))

        for block in angr_func.blocks:

            logger.info(block.vex._pp_str())

            pass

        processed_funcs +=1
        pass

    #func_name_list = [angr_func.name for angr_func in vex.functions]

    #logger.info("Function name list: \n{}".format(func_name_list))

    # for angr_func in  vex.functions:
    #
    #     logger.info("Evaluating function {}".format(angr_func.name))

    # for block in angr_func.blocks:
    #
    #     logger.debug("Block address :0x{0:x}".format(block.addr))
    #
    # irsb = pyvex.IRSB("\x63\x10", 0x400400, archinfo.ArchAMD64(), num_bytes=2)
    #
    # # pretty-print the basic block
    # irsb.pp()
    #
    # logger.debug("{}".format(irsb._pp_str()))

    pass

    logger.info("***************END Test Harness****************")


if __name__ == "__main__":
    test_harness()
