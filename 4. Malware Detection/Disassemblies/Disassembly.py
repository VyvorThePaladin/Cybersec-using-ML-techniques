from enum import Enum
import time
import os
import pickle
import zlib

import logging


import Disassemblies.disassembly_pb2  as disassembly_pb2

# Set logging for this module
logger = logging.getLogger("Disassemblies.Disassemblies")
logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)

# IDA SDK Information: https://www.hex-rays.com/products/ida/support/sdkdoc/nalt_8hpp.html

class ProcessorType(Enum):
    x86 = 1
    x86_64 = 2
    ARM = 2
    PPC = 3


class Endness(Enum):
    BIG_ENDIAN = 1
    LITTLE_ENDIAN =2


class FileType(Enum):
    PE32 = 1
    PE64 = 2
    ELF32 = 3
    ELF64 = 4


class ArchWordSize(Enum):

    BITS_32 = 1
    BITS_64 = 2
    BITS_16 = 3


class ImportSymbol(object):

    def __init__(self, import_name, library_name, address):

        # Import Symbol name
        self._import_name = import_name

        # Library
        self._library_name = library_name

        # Address of symbol
        self._address = address

    def to_pb(self, import_symbol_pb=None):

        if import_symbol_pb is None:

            # Create the disassembly function pb message
            import_symbol_pb = disassembly_pb2.ImportSymbol()

        # ***Set the message values***

        # Import Name
        import_symbol_pb.import_name = self._import_name

        # Library Name
        import_symbol_pb.library_name = self._library_name

        # Import Address
        import_symbol_pb.address = self._address

        return import_symbol_pb

    @classmethod
    def from_pb(cls, import_symbol_pb):
        assert isinstance(import_symbol_pb, disassembly_pb2.ImportSymbol), \
            "Expected a protobuf object of type ImportSymbol"

        # Import Name
        import_name = import_symbol_pb.import_name

        # Library Name
        library_name = import_symbol_pb.library_name

        # Address
        address = import_symbol_pb.address

        import_symbol = cls(import_name, library_name, address)

        return import_symbol

    @property
    def import_name(self):
        return self._import_name

    @property
    def library_name(self):
        return self._library_name

    @property
    def address(self):
        return self._address


class DisassemblyBinary(object):

    def __init__(self,
                 binary_name,
                 binary_sha256_hash,
                 proc_type,
                 file_type,
                 word_size,
                 endness,
                 disassembly_func_list=None,
                 segment_index=0,
                 total_segments=1,
                 import_symbol_list=None):
    
        # Set the binary's name
        self._binary_name = binary_name

        # Set the sha1 hash
        self._binary_sha256_hash = binary_sha256_hash

        # List of the disassembly functions
        self._disassembly_func_list = []

        # Set the processor type (e.g. x86 vs ARM)
        assert isinstance(proc_type, ProcessorType)
        self._proc_type = proc_type

        # Set the File type (e.g. ELF vs PE)
        assert isinstance(file_type, FileType)
        self._file_type = file_type

        # Set the word size (e.g. 32-bit vs 64-bit)
        assert isinstance(word_size, ArchWordSize)
        self._word_size = word_size

        # Set the endness (e.g. Big endian vs little endian)
        assert isinstance(endness, Endness)
        self._endness = endness

        # Disassemblies function list
        self._disassembly_func_list = disassembly_func_list

        # Indicates segment index for the respective disassembly
        self._segment_index = segment_index

        # Number of total segments
        self._total_segments = total_segments

        # Import symbol list
        self._import_symbol_list = import_symbol_list

        pass

    def append_disassembly_func(self, disassembly_func):
        self._disassembly_func_list.append(disassembly_func)

    @classmethod
    def from_pb(cls, disassembly_binary_pb):

        assert isinstance(disassembly_binary_pb,disassembly_pb2.DisassemblyBinary), \
            "Expected a protobuf object of type DisassemblyBinary"

        # Binary Name
        binary_name = disassembly_binary_pb.binary_name

        # Sha256 hash
        binary_sha256_hash = disassembly_binary_pb.binary_sha256_hash

        # Processor type
        proc_type = ProcessorType(disassembly_binary_pb.proc_type)

        # File type
        file_type = FileType(disassembly_binary_pb.file_type)

        # Word Size
        word_size = ArchWordSize(disassembly_binary_pb.word_size)

        # Endness
        endness = Endness(disassembly_binary_pb.endness)

        # Segment index
        segment_index = disassembly_binary_pb.segment_index

        # Total number of segments
        total_segments = disassembly_binary_pb.total_segments

        # Disassemblies function list
        disassembly_func_list = [DisassemblyFunction.from_pb(disassembly_function_pb)
                                 for disassembly_function_pb in disassembly_binary_pb.disassembly_func_list]

        # Import symbol ist
        import_symbol_list = [ImportSymbol.from_pb(import_symbol_pb)
                              for import_symbol_pb in disassembly_binary_pb.import_symbol_list]

        # Create the Disassemblies binary object
        disassembly_binary = cls(binary_name,
                                 binary_sha256_hash,
                                 proc_type,
                                 file_type,
                                 word_size,
                                 endness,
                                 disassembly_func_list,
                                 segment_index,
                                 total_segments,
                                 import_symbol_list)

        return disassembly_binary

    def to_pb(self):

        disassembly_binary_pb = disassembly_pb2.DisassemblyBinary()

        # Set binary name
        disassembly_binary_pb.binary_name = self._binary_name

        # Sha256 hash
        disassembly_binary_pb.binary_sha256_hash = self._binary_sha256_hash

        # Processor type
        disassembly_binary_pb.proc_type = self._proc_type.value

        # File type
        disassembly_binary_pb.file_type = self._word_size.value

        # Word size
        disassembly_binary_pb.word_size = self._word_size.value

        # Endness
        disassembly_binary_pb.endness = self._endness.value

        # Segment index
        disassembly_binary_pb.segment_index = self._segment_index

        # Total number of segments
        disassembly_binary_pb.total_segments = self._total_segments

        # Add the repeated disassembly function list
        for disassembly_function in self._disassembly_func_list:

            # Create the disassembly function pb message
            disassembly_function_pb = disassembly_binary_pb.disassembly_func_list.add()

            # Merge the disassembly function message
            disassembly_function.to_pb(disassembly_function_pb)

        # Add the repeated import symbol list
        for import_symbol in self._import_symbol_list:

            # Create the import symbol pb message
            import_symbol_pb = disassembly_binary_pb.import_symbol_list.add()

            # Merge the import symbol message
            import_symbol.to_pb(import_symbol_pb)

        return disassembly_binary_pb

    @staticmethod
    def deserialize_from_file(disassembly_binary_msg_file_path):


        # Check if we have pickled the Disassembly binary object
        pickle_file_path_of_disaassembly_binary = os.path.splitext(disassembly_binary_msg_file_path)[0]+".p"

        if os.path.exists(pickle_file_path_of_disaassembly_binary):
            # We have a pickled disassembly object, so load that instead
            logger.info("\nFound cached pickle disassembly binary object corresponding to {}".format(disassembly_binary_msg_file_path))
            disassembly_binary = pickle.load(open(pickle_file_path_of_disaassembly_binary, "rb"))

            return disassembly_binary


        # Read the file
        serialized_disassembly = None
        with open(disassembly_binary_msg_file_path, "rb") as f:
            serialized_disassembly = f.read()

        # Uncompress if it is compressed
        if disassembly_binary_msg_file_path.endswith("z"):

            # Message is compressed. Need to decompress
            serialized_disassembly = zlib.decompress(serialized_disassembly)

        logger.info("Serialized disassembly size: '{} kb'".format(len(serialized_disassembly)/1000))

        # Create the protobuf object
        disassembly_binary_pb = disassembly_pb2.DisassemblyBinary()

        # Populate the protobuf object
        disassembly_binary_pb.ParseFromString(serialized_disassembly)

        # Get the disassembly binary object
        disassembly_binary = DisassemblyBinary.from_pb(disassembly_binary_pb)


        # Caching the disassembly_binary object via pickle
        logger.info("\nCaching a pickle disassembly binary object corresponding to {}".format(
            disassembly_binary_msg_file_path))
        pickle.dump(disassembly_binary, open(pickle_file_path_of_disaassembly_binary, "wb"))

        return disassembly_binary

    def serialize_to_file(self, file_path=None, compress=True):

        start_time = time.time()

        serialized_message = self.to_pb().SerializeToString()

        if file_path is None:
            file_path = "{}_Disassembly_{}.pb".format(self._binary_name, self._binary_sha256_hash)

        if compress:
            serialized_message = zlib.compress(serialized_message)
            file_path += ".z"

        logger.info("(Size {})Writing disassembly to the following path: {}".format(len(serialized_message),
                                                                                    file_path))
        with open(file_path, "wb") as f:
            f.write(serialized_message)
            f.flush()
            os.fsync(f)

        end_time = time.time()
        elapsed_time = end_time - start_time
        logger.debug("(Serialization/Write to file) Elapsed time: {}".format(elapsed_time))

    @staticmethod
    def generate_file_sha256_hash(binary_file_path):
        import hashlib
        block_size = 65536
        hasher = hashlib.sha256()
        with open(binary_file_path, 'rb') as bin_file:
            buf = bin_file.read(block_size)
            while len(buf) > 0:
                hasher.update(buf)
                buf = bin_file.read(block_size)

        return hasher.hexdigest()

    @property
    def binary_sha256_hash(self):
        return self._binary_sha256_hash

    @property
    def binary_name(self):
        return self._binary_name

    @property
    def disassembly_func_list(self):
        return self._disassembly_func_list

    @disassembly_func_list.setter
    def disassembly_func_list(self, value):
        self._disassembly_func_list = value

    @property
    def endness(self):
        return self._endness

    @property
    def proc_type(self):
        return self._proc_type

    @property
    def segment_index(self):
        return self._segment_index

    @segment_index.setter
    def segment_index(self, value):
        self._segment_index = value

    @property
    def total_segments(self):
        return self._total_segments

    @total_segments.setter
    def total_segments(self, value):
        self._total_segments = value

    @property
    def word_size(self):
        return self._word_size

    @property
    def import_symbol_list(self):
        return self._import_symbol_list

    @import_symbol_list.setter
    def import_symbol_list(self, value):

        self._import_symbol_list = value



class DisassemblyFunction(object):

    __slots__ = ['name', 'start_address', 'end_address', 'segment_name', 'disassembly_basicblock_list']

    def __init__(self,
                 name,
                 start_address,
                 end_address,
                 segment_name,
                 disassembly_basicblock_list=None):

        # Name of function
        self.name = name
        
        # Function start address
        self.start_address = start_address
        
        # Function end address
        self.end_address = end_address
        
        # Name of the segment in the binary that the function is located
        # (e.g. text, plt)
        self.segment_name = segment_name
                
        # List of the disassembly instructions
        if disassembly_basicblock_list is None:
            self.disassembly_basicblock_list = []
        else:
            self.disassembly_basicblock_list = disassembly_basicblock_list
        
    def append_disassembly_basicblock(self, disassembly_basicblock):
        self.disassembly_basicblock_list.append(disassembly_basicblock)

    @classmethod
    def from_pb(cls, disassembly_function_pb):

        assert isinstance(disassembly_function_pb, disassembly_pb2.DisassemblyFunction), \
            "Expected a protobuf object of type DisassemblyFunction"

        # Function name
        name = disassembly_function_pb.name

        # Start address
        start_address = disassembly_function_pb.start_address

        # End address
        end_address = disassembly_function_pb.end_address

        # Segment name
        segment_name = disassembly_function_pb.segment_name

        # Disassemblies BasicBlock list
        disassembly_basicblock_list = [DisassemblyBasicBlock.from_pb(disassembly_basicblock_pb)
                                     for disassembly_basicblock_pb in disassembly_function_pb.disassembly_basicblock_list ]

        # Create the disassembly function object
        dis_function = cls(name, start_address, end_address, segment_name, disassembly_basicblock_list)

        return dis_function

    def to_pb(self, disassembly_function_pb=None):

        if disassembly_function_pb is None:

            # Create the disassembly function pb message
            disassembly_function_pb = disassembly_pb2.DisassemblyFunction()

        # Function name
        disassembly_function_pb.name = self.name

        # Start address
        disassembly_function_pb.start_address = self.start_address

        # End address
        disassembly_function_pb.end_address = self.end_address

        # Segment name
        disassembly_function_pb.segment_name = self.segment_name

        # Add the disassembly basicblock messages to the function
        for disassembly_basicblock in self.disassembly_basicblock_list:

            # Add a disassembly basicblock message
            disassembly_basicblock_pb = disassembly_function_pb.disassembly_basicblock_list.add()

            # populate the disassembly instruction message
            disassembly_basicblock.to_pb(disassembly_basicblock_pb)

        return disassembly_function_pb


class DisassemblyBasicBlock(object):

    __slots__ = ['start_address', 'end_address','disassembly_instruct_list']

    def __init__(self,
                 start_address,
                 end_address,
                 disassembly_instruct_list=None):

        # Basic Block start address
        self.start_address = start_address

        # Basic Block end address
        self.end_address = end_address

        # List of the disassembly instructions
        if disassembly_instruct_list is None:
            self.disassembly_instruct_list = []
        else:
            self.disassembly_instruct_list = disassembly_instruct_list

    def append_disassembly_instruct(self, disassembly_instruction):
        self.disassembly_instruct_list.append(disassembly_instruction)

    @classmethod
    def from_pb(cls, disassembly_basicblock_pb):

        assert isinstance(disassembly_basicblock_pb, disassembly_pb2.DisassemblyBasicBlock), \
            "Expected a protobuf object of type DisassemblyBasicBlock"

        # Start address
        start_address = disassembly_basicblock_pb.start_address

        # End address
        end_address = disassembly_basicblock_pb.end_address

        # Disassemblies instruction list
        disassembly_instruct_list = [DisassemblyInstruction.from_pb(disassembly_instruction_pb)
                                     for disassembly_instruction_pb in
                                     disassembly_basicblock_pb.disassembly_instruct_list]

        # Create the disassembly function object
        dis_basicblock = cls(start_address, end_address,disassembly_instruct_list)

        return dis_basicblock

    def to_pb(self, disassembly_basicblock_pb=None):

        if disassembly_basicblock_pb is None:

            # Create the disassembly function pb message
            disassembly_basicblock_pb = disassembly_pb2.DisassemblyBasicBlock()

        # Start address
        disassembly_basicblock_pb.start_address = self.start_address

        # End address
        disassembly_basicblock_pb.end_address = self.end_address

        # Add the disassembly instruction messages to the function
        for disassembly_instruction in self.disassembly_instruct_list:

            # Add a disassembly instruction message
            disassembly_instruction_pb = disassembly_basicblock_pb.disassembly_instruct_list.add()

            # populate the disassembly instruction message
            disassembly_instruction.to_pb(disassembly_instruction_pb)

        return disassembly_basicblock_pb


class DisassemblyInstruction(object):

    __slots__ = ['address', 'opcode_bytes', 'size', 'mnemonic']

    def __init__(self, address, opcode_bytes, mnemonic=None):
        
        # Instruction address
        self.address = address

        # Opcode bytes
        self.opcode_bytes = opcode_bytes

        # Get the length of the opcode
        self.size = len(opcode_bytes)

        # Mnemonic
        self.mnemonic = mnemonic

    @classmethod
    def from_pb(cls, disassembly_instruction_pb):
        assert isinstance(disassembly_instruction_pb, disassembly_pb2.DisassemblyInstruction), \
            "Expected a protobuf object of type DisassemblyInstruction"

        # Address
        address = disassembly_instruction_pb.address

        # Opcode bytes
        opcode_bytes = disassembly_instruction_pb.opcode_bytes

        # Mnemonic
        mnemonic = disassembly_instruction_pb.mnemonic

        disassembly_instruction = cls(address,opcode_bytes, mnemonic)

        return disassembly_instruction

    def to_pb(self, disassembly_instruction_pb=None):

        # Create the disassembly instruction pb message is one is not passed in
        if disassembly_pb2 is None:
            disassembly_instruction_pb = disassembly_pb2.DisassemblyInstruction()

        # Address
        disassembly_instruction_pb.address = self.address

        # Opcode
        disassembly_instruction_pb.opcode_bytes = self.opcode_bytes

        # Mnemonic
        disassembly_instruction_pb.mnemonic = self.mnemonic

        return disassembly_instruction_pb



def tst_harness():

    print("*******Test Harness*****************")

    TEST_DISASSEMBLY_PB_FILE_PATH = "../explorer.exe_Disassembly_299ce4c04f31320b15c8c1bbabc69e148964eaeb1f244070c575c5cf90b57279.pb.z"

    # =====Deserialize a disassembly binary message=====
    start_time = time.time()

    disassembly_binary = DisassemblyBinary.deserialize_from_file(TEST_DISASSEMBLY_PB_FILE_PATH)
    assert isinstance(disassembly_binary, DisassemblyBinary)

    end_time = time.time()
    elapsed_time = end_time - start_time

    logger.info("Elapsed time to deserialize disassembly: {}".format(elapsed_time))

    print("*******END Test Harness**************")
    pass

if __name__ == "__main__":
    tst_harness()
