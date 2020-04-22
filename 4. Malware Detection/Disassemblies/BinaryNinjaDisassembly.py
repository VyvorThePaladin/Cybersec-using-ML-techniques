from __future__ import absolute_import
import os


try:
    from Disassemblies.Disassembly import *
except Exception as ex:
    from Disassemblies import *


import time
import sys
from Common.TargaryenUtils import TargaryenUtils
import binaryninja as binja

from binaryninja.enums import Endianness

import logging

# Set logging for this module
logger = logging.getLogger("Disassemblies.BinaryNinja")
logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)

MAX_NUM_FUNCTIONS_PER_PB_MSG = 1000

# Max binary file size that will be disassembled
MAX_BINARY_FILE_SIZE_LIMIT = 10000000

class BinaryNinjaDisassemblyBinary(DisassemblyBinary):
    def __init__(self,
                 binary_name,
                 binary_sha256_hash,
                 proc_type,
                 file_type,
                 word_size,
                 endness):
        super(BinaryNinjaDisassemblyBinary, self).__init__(binary_name,
                                                           binary_sha256_hash,
                                                           proc_type,
                                                           file_type,
                                                           word_size,
                                                           endness)

    @staticmethod
    def serialize_to_file_from_BinaryNinja(binary_file_path, output_dir=None, compress=True):

        try:

            bv=None

            # Make sure file is below file size limit
            binary_file_size = os.path.getsize(binary_file_path)
            if binary_file_size > MAX_BINARY_FILE_SIZE_LIMIT:
                raise BinaryNinjaDisassemblyException("Binary {} exceeds file size limit {}: {}".format(binary_file_path,
                                                                                                        MAX_BINARY_FILE_SIZE_LIMIT,
                                                                                                        binary_file_size))

            bv = binja.BinaryViewType.get_view_of_file(binary_file_path)

            # Run the linear sleep analysis option and wait until it completes
            # bv.add_analysis_option("linearsweep")
            # bv.update_analysis_and_wait()

            if bv is None:
                raise BinaryNinjaDisassemblyException("Unable to disassemble file: {}".format(binary_file_path))

            binja.log_to_stdout(True)
            # binja.log_info("-------- %s --------" % binary_file_path)
            # binja.log_info("START: 0x%x" % bv.start)
            # binja.log_info("ENTRY: 0x%x" % bv.entry_point)
            # binja.log_info("ARCH: %s" % bv.arch.name)
            # binja.log_info("\n-------- Function List --------")

            binary_file_sha256_hash = DisassemblyBinary.generate_file_sha256_hash(binary_file_path)

            start_time = time.time()
            #
            # # Binary name
            binary_name = os.path.basename(binary_file_path)
            logger.info("Creating an BinaryNinja DisasemblyBinary object for :'{}'".format(binary_name))

            # ***Get the word size***
            word_size = None
            if bv.arch.default_int_size == 4:
                word_size = ArchWordSize.BITS_32
            elif bv.arch.default_int_size == 8:
                word_size = ArchWordSize.BITS_64
            else:
                word_size = ArchWordSize.BITS_16

            logger.debug("Arch word size {}".format(repr(word_size)))

            # ***Get processor type***
            proc_type = None
            if bv.arch.name == "x86":
                proc_type = ProcessorType.x86

            elif bv.arch.name == "x86_64":
                proc_type = ProcessorType.x86_64

            else:
                raise ValueError("Unsupported processor '{}'".format(bv.arch.name))

            logger.debug("proc_type: {}".format(repr(proc_type)))

            # ***Get endness***
            endness = None
            if bv.arch.endianness == Endianness.LittleEndian:
                endness = Endness.LITTLE_ENDIAN

            elif bv.arch.endianness == Endianness.BigEndian:
                endness = Endness.BIG_ENDIAN
            else:
                raise ValueError("(ENDNESS) Unexpected value '{}'".format(bv.arch.endianness ))

            # ***Get file type***
            file_type_name = bv.view_type
            file_type = None
            if "ELF" in file_type_name and word_size == ArchWordSize.BITS_64:
                file_type = FileType.ELF64

            elif "ElF" in file_type_name and word_size == ArchWordSize.BITS_32:
                file_type = FileType.ELF32

            elif "PE" in file_type_name and word_size == ArchWordSize.BITS_64:
                file_type = FileType.PE64

            elif "PE" in file_type_name and word_size == ArchWordSize.BITS_32:
                file_type = FileType.PE32

            else:
                raise ValueError("Unsupported file type {}".format(file_type_name))

            logger.debug("File type info: {}".format(file_type_name))

            # Initialize the import symbol list
            import_symbol_list = BinaryNinjaDisassemblyBinary.get_import_symbol_list(bv)

            disassembly_binary = DisassemblyBinary(binary_name,
                                                   binary_file_sha256_hash,
                                                   proc_type,
                                                   file_type,
                                                   word_size,
                                                   endness,
                                                   import_symbol_list=import_symbol_list)

            file_name = "{}_Disassembly_{}.pb".format(binary_name, binary_file_sha256_hash)

            if output_dir:
                file_path = os.path.join(output_dir, file_name)

            else:
                file_path = file_name

            # Get the list of function start addresses
            binja_func_list = [binja_func for binja_func in bv.functions]

            pass

            # Count the number of total functions
            total_num_functions = len(binja_func_list)
            logger.info("Total number of functions: {}".format(total_num_functions))

            num_functions_processed = 0

            segment_index = 0

            total_num_segments = (total_num_functions / MAX_NUM_FUNCTIONS_PER_PB_MSG) + 1

            # Set the total number of segments for the disasembled binary
            disassembly_binary.total_segments = total_num_segments

            is_multiple_segments = total_num_segments > 1

            while True:

                # Remaining number of functions that need to be processed
                remaining_num_functions_to_process = total_num_functions - num_functions_processed

                if remaining_num_functions_to_process <= 0:
                    logger.info("Finished processing all the functions ({})".format(num_functions_processed))
                    break

                # Number of functions in this segment that will be processed
                num_functions_in_current_segment = min(remaining_num_functions_to_process, MAX_NUM_FUNCTIONS_PER_PB_MSG)
                logger.debug(
                    "Processing {} functions in segment {}".format(num_functions_in_current_segment, segment_index))

                end_index_of_curr_segment = num_functions_processed + num_functions_in_current_segment
                logger.debug("End index of current segment: {}".format(end_index_of_curr_segment))
                binja_func_list_segment = binja_func_list[num_functions_processed: end_index_of_curr_segment]

                # Generate list of IDA Disassemblies functions for this segment
                disasm_func_list = [BinaryNinjaDisassemblyFunction.from_BinaryNinja(bv, binja_func) for binja_func in
                                    binja_func_list_segment]

                # Set the func list of the binary to point to this disassembly list
                disassembly_binary.disassembly_func_list = disasm_func_list

                # Set the segment_index for this index
                if is_multiple_segments:
                    curr_file_path = file_path + ".part{}".format(segment_index + 1)
                else:
                    curr_file_path = file_path

                # Set the segment index
                disassembly_binary.segment_index = segment_index

                # Serialize this segment to file
                disassembly_binary.serialize_to_file(curr_file_path, compress)

                # Update the number functions processed to include the number processed in current segment
                num_functions_processed += num_functions_in_current_segment
                logger.info("Processed {}/{} functions".format(num_functions_processed, total_num_functions))

                # Increment number of segments
                segment_index += 1

            elapsed_time = time.time() - start_time
            logger.info("Elapsed time:{}".format(str(elapsed_time)))

        except Exception as ex:

            logger.exception("Problem encountered disassembling {}: {}".format(binary_file_path,ex))
            raise BinaryNinjaDisassemblyException(ex)


        finally:


            # If we don't close the file, we'll have a file handle leak
            if bv:
                bv.file.close()

        return file_path

    @staticmethod
    def get_import_symbol_list(bv):

        symbols = bv.symbols

        import_symbol_list = [ImportSymbol(symbols[key].name, "", symbols[key].address) for key in symbols]

        return import_symbol_list

class BinaryNinjaDisassemblyFunction(DisassemblyFunction):
    def __init__(self, name, start_address, end_address, segment_name, disassembly_basicblock_list):

        super(BinaryNinjaDisassemblyFunction, self).__init__(name,
                                                             start_address,
                                                             end_address,
                                                             segment_name,
                                                             disassembly_basicblock_list)

    @classmethod
    def from_BinaryNinja(cls, bv, binja_func):

        # Get the function name
        name = binja_func.symbol.full_name
        #binja.log_info("Function: {}".format(name))
        assert isinstance(name, str), "Error: Function name is not an ascii string"

        # The effective address is the start address of the function
        start_address = binja_func.start
        #
        # Retrieve the func end address from the function attribute
        end_address = 0  # @Todo: Figure out how to get end address
        #
        # Retrieve the segment name
        segment_name = ""  # @Todo: Figure out how to get segment name
        # assert isinstance(segment_name, str), "Error: Segment name is not an ascii string"


        disassembly_basicblock_list = [BinaryNinjaBasicBlock.from_BinaryNinja(bv, block) for block in binja_func]


        binja_disassembly_function = cls(name, start_address, end_address, segment_name, disassembly_basicblock_list)

        return binja_disassembly_function

class BinaryNinjaBasicBlock(DisassemblyBasicBlock):

    def __init(self, start_address, end_address, disassembly_instruct_list):

        super(BinaryNinjaBasicBlock, self).__init__(start_address, end_address, disassembly_instruct_list)

    @classmethod
    def from_BinaryNinja(cls, bv, block):

        start = block.start

        end = block.end

        idx = start

        #inst_index = 0

        #num_instructions = len(block.disassembly_text) - 1

        # Pre-allocate space for list
        #block_disassembly_instruct_list = num_instructions * [None]

        arch = block.arch

        #inst_index = 0
        block_disassembly_instruct_list = []

        while idx < end:
            binja_disasm_instruction = BinaryNinjaDisassemblyInstruction.from_BinaryNinja(bv,
                                                                                          arch,
                                                                                          idx)

            #block_disassembly_instruct_list[inst_index] = binja_disasm_instruction
            block_disassembly_instruct_list.append(binja_disasm_instruction)
            # disassembly_instruct_list.append(binja_disasm_instruction)

            # Get address of the next opcode
            idx += binja_disasm_instruction.size

            # inst_index += 1

            pass

        binja_disassembly_basicblock = cls(start, end, block_disassembly_instruct_list)

        return binja_disassembly_basicblock


class BinaryNinjaDisassemblyInstruction(DisassemblyInstruction):
    def __init__(self, address, opcode_bytes, mnemonic):
        super(BinaryNinjaDisassemblyInstruction, self).__init__(address, opcode_bytes, mnemonic)


    @classmethod
    def from_BinaryNinja(cls, bv, arch, instruction_ea):


        # Get bytes starting at instruction's effective address
        data = bv.read(instruction_ea, arch.max_instr_length)

        # Get the instruction information
        info = arch.get_instruction_info(data, instruction_ea)

        # Get the instruction text
        inst_text = arch.get_instruction_text(data, instruction_ea)
        mnemonic = str(inst_text[0][0])

        # Instruction length
        length = info.length


        # Opcode bytes
        opcode_bytes = data[0:length]

        logger.debug("0x{0:x} Mnemonic: '{1}' Opcode Bytes: '{2}'".format(instruction_ea, mnemonic,
                                                          TargaryenUtils.pretty_byte_string(opcode_bytes)))

        # Create the disassembly instruction object
        binja_disassembly_instruction = cls(instruction_ea, opcode_bytes, mnemonic)

        return binja_disassembly_instruction


class BinaryNinjaDisassemblyException(Exception):
    pass

def main():
    # Note: An example of the arguments needed to run script on command line is as follows:
    #       C:\Program Files (x86)\IDA 6.95>idaw64.exe -a -A  -S"C:\Users\malachi\Documents\Projects\Targaryen\
    #       targaryen\Disassemblies\IDADisassembly.py C:\tmp\scratch\test.pb" C:\tmp\scratch\executable.notepad.exe_7004.exe

    logger.info("*******BinaryNinja Disassembler*****************")

    target_binary = None
    output_dir_path = None

    output_dir_path = "./"
    target_binary = "../test/binaries/explorer/explorer.exe"

    if len(sys.argv) > 1:
        target_binary = sys.argv[1]
        output_dir_path = sys.argv[2]



    rc = 0

    try:

        BinaryNinjaDisassemblyBinary.serialize_to_file_from_BinaryNinja(target_binary, output_dir_path)

    except BinaryNinjaDisassemblyException as ex:

        rc = 1
        logger.exception(str(ex))

    except Exception as ex:

        logger.exception(str(ex))

    # finally:
    #
    #     sys.exit(rc)

    # ida_disassembly_binary = IDADisassemblyBinary.from_IDA()

    # ida_disassembly_binary.serialize_to_file(file_path)

    logger.info("*******END Disassembler**************")

    return 0


if __name__ == "__main__":
    main()
