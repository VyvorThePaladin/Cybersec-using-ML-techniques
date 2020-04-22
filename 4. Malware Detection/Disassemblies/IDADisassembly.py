from __future__ import absolute_import
import os
from idaapi import *
try:
    from Disassemblies.Disassembly import *
except Exception as ex:
    from Disassemblies import *

import idc
import time

import logging

# Set logging for this module
logger = logging.getLogger("Disassemblies.IDADisassembly")
logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)

MAX_NUM_FUNCTIONS_PER_PB_MSG = 10000


class IDADisassemblyBinary(DisassemblyBinary):
    def __init__(self,
                 binary_name,
                 binary_sha256_hash,
                 proc_type,
                 file_type,
                 word_size,
                 endness):
        super(IDADisassemblyBinary, self).__init__(binary_name,
                                                   binary_sha256_hash,
                                                   proc_type,
                                                   file_type,
                                                   word_size,
                                                   endness)

    @staticmethod
    def serialize_to_file_from_IDA(output_dir_path=None, compress=True):

        # Wait for auto-analysis to finish before running script
        logger.info("Waiting for auto-analysis to complete before getting disassembly info")
        idaapi.autoWait()

        start_time = time.time()

        # Binary name
        binary_name = idaapi.get_root_filename()  # @todo: Figure out how to get binary name
        assert isinstance(binary_name, str), "Error: Binary name is not an ascii string"

        logger.info("Creating an IDA DisasemblyBinary object for :'{}'".format(binary_name))

        # Get the binary's file path
        binary_file_path = idaapi.get_input_file_path()
        assert isinstance(binary_file_path, str), "Error: Binary hash is not an ascii string"

        binary_file_sha256_hash = DisassemblyBinary.generate_file_sha256_hash(binary_file_path)

        assert isinstance(binary_file_sha256_hash, str), "Error: Binary hash is not an ascii string"

        info = idaapi.get_inf_structure()

        # ***Get the word size***
        word_size = None
        if info.is_64bit():
            word_size = ArchWordSize.BITS_64
        elif info.is_32bit():
            word_size = ArchWordSize.BITS_32
        else:
            word_size = ArchWordSize.BITS_16

        logger.debug("Arch word size {}".format(repr(word_size)))

        # ***Get processor type***
        proc_type = None
        if info.procName == "metapc" and word_size == ArchWordSize.BITS_32:
            proc_type = ProcessorType.x86

        elif info.procName == "metapc" and word_size == ArchWordSize.BITS_64:
            proc_type = ProcessorType.x86_64

        else:
            raise ValueError("Unsupported processor '{}'".format(info.procName))

        print "proc_type: {}".format(repr(proc_type))

        # ***Get endness***
        endness = None
        if proc_type == ProcessorType.x86_64 or proc_type == ProcessorType.x86:
            endness = Endness.LITTLE_ENDIAN
        else:
            raise ValueError("(ENDNESS) Unsupported processor '{}'".format(info.procName))

        # ***Get file type***
        file_type_name = idaapi.get_file_type_name()
        file_type = None
        if "ELF64" in file_type_name:
            file_type = FileType.ELF64

        elif "ElF" in file_type_name:
            file_type = FileType.ELF32

        elif "PE" in file_type_name and word_size == ArchWordSize.BITS_64:
            file_type = FileType.PE64

        elif "PE" in file_type_name and word_size == ArchWordSize.BITS_32:
            file_type = FileType.PE32

        else:
            raise ValueError("Unsupported file type {}".format(file_type_name))

        logger.debug('Processor: {}'.format(info.procName))

        logger.debug("File type info: {}".format(idaapi.get_file_type_name()))

        disassembly_binary = DisassemblyBinary(binary_name,
                                               binary_file_sha256_hash,
                                               proc_type,
                                               file_type,
                                               word_size,
                                               endness)

        # Initialize the import symbol list
        disassembly_binary.import_symbol_list = IDADisassemblyBinary.get_import_symbols()

        file_name = "{}_Disassembly_{}.pb".format(binary_name, binary_file_sha256_hash)

        if output_dir_path:
            file_path = os.path.join(output_dir_path,file_name)

        else:
            file_path = file_name

        # Get the list of function start addresses
        func_ea_list = [ida_func_ea for ida_func_ea in Functions()]

        # Count the number of total functions
        total_num_functions = len(func_ea_list)
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
            logger.debug("Processing {} functions in segment {}".format(num_functions_in_current_segment, segment_index))

            end_index_of_curr_segment = num_functions_processed + num_functions_in_current_segment
            logger.debug("End index of current segment: {}".format(end_index_of_curr_segment))
            func_ea_list_segment = func_ea_list[num_functions_processed: end_index_of_curr_segment]

            # Generate list of IDA Disassemblies functions for this segment
            disassembly_list = [IDADisassemblyFunction.from_IDA(ida_func_ea) for ida_func_ea in func_ea_list_segment]

            # Set the func list of the binary to point to this disassembly list
            disassembly_binary.disassembly_func_list = disassembly_list

            # Set the segment_index for this index
            if is_multiple_segments:
                curr_file_path = file_path +".part{}".format(segment_index+1)
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

    @staticmethod
    def get_import_symbols():

        import_symbol_list =[]

        library_name = None

        def imp_cb(ea, name, ord):

            if name:
                logger.debug("%08x: %s (ord#%d)" % (ea, name, ord))

                import_symbol = ImportSymbol(str(name), str(library_name), ea)
                import_symbol_list.append(import_symbol)
            # True -> Continue enumeration
            # False -> Stop enumeration
            return True

        nimps = idaapi.get_import_module_qty()

        logger.info("Found {} import libraries...".format(nimps))

        for i in xrange(0, nimps):
            library_name = idaapi.get_import_module_name(i)
            if not library_name:
                logger.warning("Failed to get import module name for #%d" % i)
                continue

            logger.debug("Walking-> %s" % library_name)
            idaapi.enum_import_names(i, imp_cb)

        logger.debug("All done...")

        return import_symbol_list




    # @classmethod
    # def from_IDA(cls):
    #
    #     # Wait for auto-analysis to finish before running script
    #     logger.info("Waiting for auto-analysis to complete before getting disassembly info")
    #     idaapi.autoWait()
    #
    #     start_time = time.time()
    #
    #     # Binary name
    #     binary_name = idaapi.get_root_filename()  # @todo: Figure out how to get binary name
    #     assert isinstance(binary_name, str), "Error: Binary name is not an ascii string"
    #
    #     logger.info("Creating an IDA DisasemblyBinary object for :'{}'".format(binary_name))
    #
    #     # Get the binary's file path
    #     binary_file_path = idaapi.get_input_file_path()
    #     assert isinstance(binary_file_path, str), "Error: Binary hash is not an ascii string"
    #
    #     binary_file_kha256_hash = DisassemblyBinary.generate_file_sha256_hash(binary_file_path)
    #
    #     assert isinstance(binary_file_sha256_hash, str), "Error: Binary hash is not an ascii string"
    #
    #     info = idaapi.get_inf_structure()
    #
    #     # ***Get the word size***
    #     word_size = None
    #     if info.is_64bit():
    #         word_size = ArchWordSize.BITS_64
    #     elif info.is_32bit():
    #         word_size = ArchWordSize.BITS_32
    #     else:
    #         word_size = ArchWordSize.BITS_16
    #
    #     logger.debug("Arch word size {}".format(repr(word_size)))
    #
    #     # ***Get processor type***
    #     proc_type = None
    #     if info.procName == "metapc" and word_size == ArchWordSize.BITS_32:
    #         proc_type = ProcessorType.x86
    #
    #     elif info.procName == "metapc" and word_size == ArchWordSize.BITS_64:
    #         proc_type = ProcessorType.x86_64
    #
    #     else:
    #         raise ValueError("Unsupported processor '{}'".format(info.procName))
    #
    #     print "proc_type: {}".format(repr(proc_type))
    #
    #     # ***Get endness***
    #     endness = None
    #     if proc_type == ProcessorType.x86_64 or proc_type == ProcessorType.x86:
    #         endness = Endness.LITTLE_ENDIAN
    #     else:
    #         raise ValueError("(ENDNESS) Unsupported processor '{}'".format(info.procName))
    #
    #     # ***Get file type***
    #     file_type_name = idaapi.get_file_type_name()
    #     file_type = None
    #     if "ELF64" in file_type_name:
    #         file_type = FileType.ELF64
    #
    #     elif "ElF" in file_type_name:
    #         file_type = FileType.ELF32
    #
    #     elif "PE" in file_type_name and word_size == ArchWordSize.BITS_64:
    #         file_type = FileType.PE64
    #
    #     elif "PE" in file_type_name and word_size == ArchWordSize.BITS_32:
    #         file_type = FileType.PE32
    #
    #     else:
    #         raise ValueError("Unsupported file type {}".format(file_type_name))
    #
    #     logger.debug('Processor: {}'.format(info.procName))
    #
    #     logger.debug("File type info: {}".format(idaapi.get_file_type_name()))
    #
    #     disassembly_binary = cls(binary_name,
    #                              binary_file_sha256_hash,
    #                              proc_type,
    #                              file_type,
    #                              word_size,
    #                              endness)
    #
    #     # Get the IDA effective address list from IDA
    #     # ida_func_ea_list = Functions()
    #
    #     # Get total number of functions
    #     total_num_functions = sum(1 for x in Functions())
    #
    #     num_functions_processed = 0
    #
    #     # Create and append the IDADisammbly functions to the function list
    #     for ida_func_ea in Functions():
    #         func_name = Name(ida_func_ea)
    #         assert isinstance(func_name, str), "Error: Function name is not an ascii string"
    #
    #         logger.info("[{}/{}] Processing function: '{}'".format(num_functions_processed,
    #                                                                total_num_functions,
    #                                                                func_name))
    #         #  Generate an ida disassembly function object
    #         ida_disassembly_function = IDADisassemblyFunction.from_IDA(ida_func_ea)
    #
    #         # Append the ida disassembly function to list
    #         disassembly_binary.append_disassembly_func(ida_disassembly_function)
    #
    #         num_functions_processed += 1
    #
    #     elapsed_time = time.time() - start_time
    #
    #     logger.info("Elapsed time:{}".format(str(elapsed_time)))
    #
    #     return disassembly_binary


class IDADisassemblyFunction(DisassemblyFunction):
    def __init__(self, name, start_address, end_address, segment_name,disassembly_basicblock_list):

        super(IDADisassemblyFunction, self).__init__(name,
                                                     start_address,
                                                     end_address,
                                                     segment_name,
                                                     disassembly_basicblock_list)

    @classmethod
    def from_IDA(cls, func_ea):



        # Get the function name
        name = Name(func_ea)
        assert isinstance(name, str), "Error: Function name is not an ascii string"

        # The effective adress is the start address of the function
        start_address = func_ea

        # Retireve the func end address from the function attribute
        end_address = GetFunctionAttr(func_ea, FUNCATTR_END)

        # Retrieve the segment name
        segment_name = idc.SegName(func_ea)
        assert isinstance(segment_name, str), "Error: Segment name is not an ascii string"

        # Get the function item list, which contains the instruction items
        #func_item_list = FuncItems(func_ea)


        # Get an IDA function handle
        f = idaapi.get_func(func_ea)
        if not f:
            raise Exception("No function at 0x%x" % func_ea)

        # Get flow chart object
        fc = idaapi.FlowChart(f)

        # Create the basic block objects
        disassembly_basicblock_list = [IDADisassemblyBasicBlock.from_IDA(block) for block in fc]


        # Create the disassembly function object
        ida_disassembly_function = cls(name, start_address, end_address, segment_name, disassembly_basicblock_list)

        # # Iterate through the blocks in the flow chart
        # for block in fc:
        #
        #     basic_block = IDADisassemblyBasicBlock.from_IDA(block)
        #     #print "[0x%x] Basic block [0x%x - 0x%x)" % (block.startEA,block.startEA, block.endEA)
        #     #for head in Heads(block.startEA, block.endEA):
        #     #    print name, ":", "0x%08x" % (head), ":", GetDisasm(head), GetMnem(head);
        #
        # for item_ea in func_item_list:
        #
        #     # Check that the function item is an instruction
        #     if not isCode(GetFlags(item_ea)):
        #         continue
        #
        #     # Create the disassembly instruction object
        #     ida_disassembly_instruction = IDADisassemblyInstruction.from_IDA(item_ea)
        #
        #     # Append disassembly instruction object to function
        #     ida_disassembly_function.append_disassembly_instruct(ida_disassembly_instruction)

        return ida_disassembly_function


class IDADisassemblyBasicBlock(DisassemblyBasicBlock):

    def __init(self, start_address, end_address, disassembly_instruct_list):

        super(IDADisassemblyBasicBlock, self).__init__(start_address, end_address, disassembly_instruct_list)

    @classmethod
    def from_IDA(cls, block):

        # Get start address of basic block
        start_address = block.startEA

        # Get end address of basic lock
        end_address = block.endEA

        # Build the disassembly instruction list
        disassembly_instruction_list = [IDADisassemblyInstruction.from_IDA(head)
                                        for head in Heads(block.startEA, block.endEA)
                                        if isCode(GetFlags(head))]

        # # Iterate through the instructions of the IDA basic block
        # for head in Heads(block.startEA, block.endEA):
        #
        #     # Check that  this item is an instruction
        #     if not isCode(GetFlags(head)):
        #         continue
        #
        #     # Create the disassembly instruction object
        #     ida_disassembly_instruction = IDADisassemblyInstruction.from_IDA(item_ea)
        #
        #     # Append disassembly instruction object to function
        #     ida_disassembly_function.append_disassembly_instruct(ida_disassembly_instruction)

        ida_disassembly_basicblock = cls(start_address, end_address,  disassembly_instruction_list)

        return ida_disassembly_basicblock

class IDADisassemblyInstruction(DisassemblyInstruction):
    def __init__(self, address, opcode_bytes, mnemonic):
        super(IDADisassemblyInstruction, self).__init__(address, opcode_bytes, mnemonic)

    @classmethod
    def from_IDA(cls, instruction_ea):

        # Make sure we have the address of an actual instruction
        assert isCode(GetFlags(instruction_ea)), "Expected an address for an instruction:0x{0:x}".format(instruction_ea)

        # Generate the opcode string
        opcode_byte_array = GetManyBytes(instruction_ea, ItemSize(instruction_ea))
        opcode_bytes = bytes(opcode_byte_array)

        # Get the mnemonic
        mnemonic = str(GetMnem(instruction_ea))

        logger.debug("0x{0:x} Opcode Bytes: '{1}'".format(instruction_ea, repr(opcode_bytes)))

        # Create the disassembly instruction object
        ida_disassembly_instruction = cls(instruction_ea, opcode_bytes, mnemonic)

        return ida_disassembly_instruction


def main():
    # Note: An example of the arguments needed to run script on command line is as follows:
    #       C:\Program Files (x86)\IDA 6.95>idaw64.exe -a -A  -S"C:\Users\malachi\Documents\Projects\Targaryen\
    #       targaryen\Disassemblies\IDADisassembly.py C:\tmp\scratch\test.pb" C:\tmp\scratch\executable.notepad.exe_7004.exe

    logger.info("*******IDA Disassembler*****************")

    output_dir_path = None
    if len(idc.ARGV) > 1:
        output_dir_path = idc.ARGV[1]
        logger.info("Output directory passed in {}".format(output_dir_path))

    IDADisassemblyBinary.serialize_to_file_from_IDA(output_dir_path)

    #ida_disassembly_binary = IDADisassemblyBinary.from_IDA()

    #ida_disassembly_binary.serialize_to_file(file_path)

    logger.info("*******END IDA Disassembler**************")

    #logger.info("Closing IDA and saving database")
    #idc.Exit(0)

    pass


if __name__ == "__main__":
    main()
