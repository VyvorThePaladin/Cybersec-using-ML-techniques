import logging
import os
import subprocess
import glob
import tempfile
import shutil
import zlib
import exceptions
import time

# ========================================CONSTANTS======================================
IDA_FILE_PATH = 'C:/Program Files (x86)/IDA 6.95/idaw64.exe'

IDA_PYTHON_DISASM_SCRIPT_FILE_PATH = "C:/Users/malachi/Documents/Projects/Targaryen/targaryen/Disassemblies/IDADisassembly.py"
# ======================================END CONSTANTS=====================================

# Set logging for this module
logger = logging.getLogger("Disassemblies.Disassemblies")
logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)


class IDABatchDisassemblyGen(object):

    def __init__(self):
        pass

    def generate_batch_disassembly(self, binary_directory_path, disassem_out_dir_path):

        # Create a temporary directory to store intermediate artifacts
        temp_dump_dir = os.path.normpath(tempfile.mkdtemp())
        logger.info("Created temp directory {}".format(temp_dump_dir))

        total_elapsed_time = 0

        logger.info("Processing binaries for disassembly in folder {}".format(binary_directory_path))

        try:

            for binary_file_path in glob.glob(os.path.join(binary_directory_path, '*')):

                cur_iteration_start_time = time.time()

                binary_base_name = os.path.basename(binary_file_path)

                logger.info("\nBeginning the  disassembly process for binary '{}'".format(binary_base_name))

                # Copy the zipped binary to the temp directory
                shutil.copy(binary_file_path, temp_dump_dir)

                # Get the basename
                binary_base_name = os.path.basename(binary_file_path)

                temp_binary_file_path = os.path.join(temp_dump_dir,binary_base_name)

                # Uncompress the binary if compressed
                if binary_file_path.endswith("z"):
                    compressed_dump = None
                    with open(temp_binary_file_path,"rb") as f:
                        compressed_dump = f.read()

                    # Delete the compressed file since we no longer need it
                    os.remove(temp_binary_file_path)

                    # Uncompress the dump
                    uncompressed_dump = zlib.decompress(compressed_dump)

                    # Remove the '.z' extension
                    temp_binary_file_path = os.path.splitext(temp_binary_file_path)[0]

                    # Write the uncompressed file to disk
                    with open(temp_binary_file_path,"wb") as f:
                        f.write(uncompressed_dump)
                        f.flush()
                        os.fsync(f)

                # Disassemble the binary
                # Need to replace the slashes to work in Windows properly
                temp_binary_file_path = temp_binary_file_path.replace('\\', '/')

                try:
                    self.generate_binary_disassembly(temp_binary_file_path,disassem_out_dir_path )

                except subprocess.CalledProcessError as ex:

                    logger.error("Error encountered disassembling '{}' with IDA: \n{}".format(binary_base_name,ex))
                    # @Todo: Save off problem files so they can be examined later

                # **Cleanup the intermediate stuff**
                os.remove(temp_binary_file_path)

                cur_iteration_elapsed_time = time.time() - cur_iteration_start_time
                logger.info("Current disassembly elapsed time {}".format(cur_iteration_elapsed_time))

                total_elapsed_time += cur_iteration_elapsed_time

                # Try to remove the ida database
                try:
                    temp_binary_ida_db_file_path_i64 = os.path.splitext(temp_binary_file_path)[0]+".i64"
                    os.remove(temp_binary_ida_db_file_path_i64)

                except exceptions.Exception as ex:
                    # For some reason, the idb was not generated.
                    # Ignore this since the fail happens on the delete
                    pass

        finally:

            logger.info("Total elapsed time for disassembly process: {}".format(total_elapsed_time))
            shutil.rmtree(temp_dump_dir)
            logger.debug("Deleted temp directory {}".format(temp_dump_dir))


    @staticmethod
    def generate_binary_disassembly(binary_file_path, disam_out_dir):
        # Note: An example of the arguments needed to run script on command line is as follows:
        #       C:\Program Files (x86)\IDA 6.95>idaw64.exe -a -A  -S"C:\Users\malachi\Documents\Projects\Targaryen\
        #       targaryen\Disassemblies\IDADisassembly.py C:\tmp\scratch\" C:\tmp\scratch\executable.notepad.exe_7004.exe

        command = [IDA_FILE_PATH,
                   '-A',
                   '-S{} {}'.format(IDA_PYTHON_DISASM_SCRIPT_FILE_PATH, disam_out_dir),
                   binary_file_path]

        logger.debug("cmd-> {}".format(' '.join(command)))

        # Make sure the ida command runs successfully (by returning 0)
        subprocess.check_call(command)


def tst_harness():

    logger.info("*******Test Harness*************")

    #TEST_BINARY_DIR_PATH = "C:/Users/malachi/Documents/Projects/Targaryen/targaryen/test/binaries/laptop_proc_dump_sample/"

    TEST_BINARY_DIR_PATH = "C:/Users/malachi/Documents/Projects/Targaryen/memdumps/client_malachi_pc_1/"

    OUTPUT_DISASSEMBLY_DIR_PATH = "C:/tmp/scratch/output/"

    ida_batch_gen = IDABatchDisassemblyGen()

    #binary_file_path = os.path.join(TEST_BINARY_DIR_PATH,"executable.notepad.exe_3968.exe")
    #binary_file_path = os.path.join(TEST_BINARY_DIR_PATH, "explorer.exe")

    #ida_batch_gen.generate_binary_disassembly(binary_file_path, OUTPUT_DISASSEMBLY_DIR_PATH)

    ida_batch_gen.generate_batch_disassembly(TEST_BINARY_DIR_PATH, OUTPUT_DISASSEMBLY_DIR_PATH)


    logger.info("*******END Test Harness**************")


if __name__ == "__main__":
    tst_harness()