import logging
import time
import os
from Vex import vex
from DynamicBinaryAnalysis.FunctionCallTraceGenerator import FunctionCallTraceGenerator



# Set logging for this module
logger = logging.getLogger("BinaryCallTraceGenerator")
#logging.basicConfig(level=logging.INFO)
#logger.setLevel(logging.INFO)


logFormatter = logging.Formatter("%(asctime)s [%(module)s - %(funcName)s()] [%(levelname)-5.5s]  %(message)s")

fileHandler = logging.FileHandler("{0}.log".format(os.path.splitext(os.path.basename(__file__))[0]), mode='w')
logger.addHandler(fileHandler)


#consoleHandler = logging.StreamHandler()
#consoleHandler.setFormatter(logFormatter)
#logger.addHandler(consoleHandler)
logger.setLevel(logging.INFO)
fileHandler.setFormatter(logFormatter)


class BinaryCallTraceGenerator(object):

    def __init__(self,disassembly_binary_file_path):
        # Path to binary file
        self._disassembly_binary_file_path = disassembly_binary_file_path

        # Create the vex objection
        self._vex_obj = vex.Vex.from_disassembly_binary_file(disassembly_binary_file_path)

        # Get binary name
        self._binary_name = self._vex_obj.binary_name

        self._binary_sha256_hash = self._vex_obj.binary_sha256_hash

        # Total number of functions that we need to analyze
        self._total_num_functions = self._vex_obj.num_functions

        # Stores the current number of functions that have already been analyzed
        self._curr_num_analyzed_functions = 0

        # Import symbol map, where the address is the key
        self._import_symbol_map = dict()

        self._init_import_symbol_map()

    def generate_call_traces(self):

        logger.info("Generating Call Traces for binary '{}'...".format(self._binary_name))

        counter = 0

        # # #@Todo: Remove...Debug only
        # for angr_func in self._vex_obj.functions:
        #
        #     if counter == 6:
        #         self._generate_function_call_traces(angr_func)
        #         break
        #
        #     counter += 1

        self._generate_function_call_traces_by_func_address(0x10020c8)

        return

        function_call_trace_list = [self._generate_function_call_traces(angr_func)
                                    for angr_func in self._vex_obj.functions]

        pass

    def _init_import_symbol_map(self):

        for import_symbol in self._vex_obj.import_symbol_list:

            self._import_symbol_map[import_symbol.address] = import_symbol

    def _generate_function_call_traces_by_func_address(self, func_address):

        angr_func = self._vex_obj.get_angr_function(func_address)

        return self._generate_function_call_traces(angr_func)



    def _generate_function_call_traces(self, angr_func):

        start_time = time.time()

        #if self._curr_num_analyzed_functions % 100 == 1:
        logger.info("[{}/{}] Generating Call Traces for function: '{}'".format(self._curr_num_analyzed_functions,
                                                             self._total_num_functions,
                                                             angr_func.name))

        function_call_trace_generator = FunctionCallTraceGenerator(angr_func, self._import_symbol_map, self._vex_obj)

        function_call_trace_generator.perform_call_trace_generation()

        self._curr_num_analyzed_functions += 1

        elapsed_time = time.time() - start_time
        logger.info("Elapsed Time: {}".format(elapsed_time))


def test_harness():
    logger.info("****************Test Harness*****************")


    TEST_DISASSEMBLY_PB_FILE_PATH = "../explorer.exe_Disassembly_299ce4c04f31320b15c8c1bbabc69e148964eaeb1f244070c575c5cf90b57279.pb.z"

    # Build the disassembly object from an xml file
    binary_call_trace_gen  = BinaryCallTraceGenerator(TEST_DISASSEMBLY_PB_FILE_PATH)


    binary_call_trace_gen.generate_call_traces()


    logger.info("***************END Test Harness****************")


if __name__ == "__main__":
    test_harness()