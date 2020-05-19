import queue
import logging
import re
import os
from copy import copy, deepcopy

import pyvex

from DynamicBinaryAnalysis.TempRegisterContext import TempRegisterContext
from DynamicBinaryAnalysis.ExpressionContext import  ExpressionContext
from Vex.vex import AngrFunction, BlockNode
from Disassemblies.Disassembly import ImportSymbol

# Set logging for this module
logger = logging.getLogger("FunctionCallGenerator")


logFormatter = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s")

fileHandler = logging.FileHandler("{0}.log".format(os.path.splitext(os.path.basename(__file__))[0]), mode='w')
logger.addHandler(fileHandler)


#consoleHandler = logging.StreamHandler()
#consoleHandler.setFormatter(logFormatter)
#logger.addHandler(consoleHandler)
logger.setLevel(logging.INFO)
fileHandler.setFormatter(logFormatter)

# ================================CONSTANTS =========================================
MAX_NUMBER_VISITS_TO_IRSB = 1

MAX_NUMBER_ANCESTORS = 100


# ===============================END CONSTANTS =======================================

class CallTraceNodeInfo(object):

    __slots__ = ['is_import', 'name','library_name' ,'addr','native_instr_address']

    def __init__(self, is_import, name, addr, native_instr_address,library_name=None):

        # True if called function is imported
        self.is_import = is_import

        # Name of the called function
        self.name = name

        # Address of the instruction where call occurs
        self.native_instr_address = native_instr_address

        # Address of called function or import symbol
        self.addr = addr

        # library name if one exists
        self.library_name = library_name

    def pretty_print_str(self):

        return "[0x{0:x}] Name:'{1}' is_import='{2}' library_name: '{3}' call_address: 0x{4:x}".format(self.native_instr_address,
                                                                                                     self.name,
                                                                                                     self.is_import,
                                                                                                     self.library_name,
                                                                                                     self.addr)
    @classmethod
    def from_import_symbol(cls, import_symbol, native_instr_address):

        assert isinstance(import_symbol, ImportSymbol), "Expected an object of type 'ImportSymbol'"

        is_import = True

        name = import_symbol.import_name

        library_name = import_symbol.library_name

        addr = import_symbol.address

        call_trace_node_info = cls(is_import, name, addr,native_instr_address, library_name)

        return call_trace_node_info

    @classmethod
    def from_angr_func(cls, angr_func, native_instr_address):

        assert isinstance(angr_func, AngrFunction), "Expected an object of type 'AngrFunction'"

        is_import = False

        name = angr_func.name

        library_name = None

        addr = angr_func.addr

        call_trace_node_info = cls(is_import, name, addr, native_instr_address, library_name)

        return call_trace_node_info


class IRSBContext(object):

    __slots__ = ['irsb', 'addr', 'parent_irsb_context', 'num_visits', 'num_ancestors','curr_native_instr_address',
                 '_temp_register_context_map','import_symbol_map','curr_native_instr_size','call_trace_list','parent_func',
                 'return_addr_stack']

    def __init__(self, block, parent_irsb_context, import_symbol_map, parent_func):

        assert isinstance(block, BlockNode), "Expected an object of type blocknode"

        self.irsb = block.vex

        # IRSB address
        self.addr = block.addr

        self.parent_irsb_context = parent_irsb_context

        # Number of visits to this IRSB
        self.num_visits = 0

        # Number of ancestors of irsb
        self.num_ancestors = 0

        self.call_trace_list =[]

        # Current native instruction being analyzed
        self.curr_native_instr_address = None

        self.curr_native_instr_size = None

        # Import Symbol Map
        self.import_symbol_map = import_symbol_map

        # The parent function of this irsb
        self.parent_func = parent_func

        # Return address stack
        self.return_addr_stack = []

        # Temp register context map, where register index is key
        self._temp_register_context_map = dict()

        # Items from the parent that we will inherit
        if self.parent_irsb_context is not None:

            # Num ancestors is parent's num ancestors + 1
            self.num_ancestors = self.parent_irsb_context.num_ancestors + 1

            # Inherit the parent's call trace
            self.call_trace_list = list(self.parent_irsb_context.call_trace_list)

            # Inherit the parent's return address stack
            self.return_addr_stack = list(self.parent_irsb_context.return_addr_stack)

        else:

            # If this irsb is the entry irsb for the entry function, then initialize the call trace list
            self.call_trace_list.append(CallTraceNodeInfo.from_angr_func(parent_func, parent_func.addr))

    def add_temp_register(self, temp_reg_index, value, size):

        # Note: Temp registers can only be written to once.  If we are doing a second write, something went wrong
        assert temp_reg_index not in self._temp_register_context_map,\
            "Trying to create a temp register with index {} that already exists".format(temp_reg_index)

        self._temp_register_context_map[temp_reg_index] = TempRegisterContext(temp_reg_index, value, size)

    def get_temp_register_context(self, temp_reg_index):

        try:

            return self._temp_register_context_map[temp_reg_index]

        except KeyError as ex:

            logger.debug("Trying to access a temp register with key '{}' that doesn't exist\n: {}".
                           format(temp_reg_index, ex))
            return None

    def get_next_native_instruction_addr(self):

        return self.curr_native_instr_size + self.curr_native_instr_address


class FunctionCallTraceGenerator(object):

    def __init__(self, entry_angr_func, import_symbol_map, vex_obj):

        assert isinstance(entry_angr_func, AngrFunction ), "Expected an AngrFunction object"

        # IRSB context queue that stores next irsb to process
        self._irsb_context_queue = queue.Queue()

        # Entry angr function
        self._entry_angr_func = entry_angr_func

        # Import symbol map
        self._import_symbol_map = import_symbol_map

        # Vex object
        self._vex_obj = vex_obj

        # List of function addresses in binary where the current entry function resides
        self._func_addr_list = vex_obj.function_addrs

        self._imark_string = None

        # Stores the number of visits to irsb, where the address is the key
        self._num_visits_to_irsb_map = dict()

    def perform_call_trace_generation(self):

        # Create irsb_context for entry irsb
        entry_irsb_context = IRSBContext(self._entry_angr_func.entry_block,
                                         None,
                                         self._import_symbol_map,
                                         self._entry_angr_func)

        # Push the entry irsb_context onto queue
        self._irsb_context_queue.put(entry_irsb_context)

        while not self._irsb_context_queue.empty():

            # ***Get the next irsb context in queue***
            irsb_context = self._irsb_context_queue.get()

            # ***Detect if we've exceeded the max number of visits to irsb***
            if irsb_context.addr not in self._num_visits_to_irsb_map:
                self._num_visits_to_irsb_map[irsb_context.addr] = 0

            if self._num_visits_to_irsb_map[irsb_context.addr] > MAX_NUMBER_VISITS_TO_IRSB:

                logger.debug("Max number of visits {0} to irsb exceeded".format(MAX_NUMBER_VISITS_TO_IRSB))

                # Reached the end of this code flow path...Do post-processing of path
                self._post_code_flow_path_processing(irsb_context)
                continue

            if irsb_context.num_ancestors > MAX_NUMBER_ANCESTORS:

                logger.debug("Max depth of  {0} to irsb exceeded".format(MAX_NUMBER_ANCESTORS))

                # Reached the end of this code flow path...Do post-processing of path
                self._post_code_flow_path_processing(irsb_context)
                continue

            # Increment the visit counter
            self._num_visits_to_irsb_map[irsb_context.addr] += 1

            # ***Detect if there is a cycle***
            if self._detect_if_cycle_exists(irsb_context):

                # Processing along the current code path has completed
                # @Todo: Handle this case
                logger.info("Cycle detected (0x{0:x})... Processing along the current code path completed".format(irsb_context.addr))
                logger.debug(irsb_context.irsb._pp_str())

                # Reached the end of this code flow path...Do post-processing of path
                self._post_code_flow_path_processing(irsb_context)
                continue

            logger.debug(irsb_context.irsb._pp_str())

            for stmt in irsb_context.irsb.statements:

                # Log the current statement that we will process
                logger.debug("****************Statement*****************")

                self._statement_logger(stmt, irsb_context)

                # Analyze the vex stmt
                self._analyze_vex_stmt(stmt, irsb_context)

                logger.debug("***************END Statement**************\n")

            # Analyze the unconditional exit statement
            self._analyze_unconditional_exit_stmt(irsb_context)

    def _analyze_vex_stmt(self, stmt, irsb_context):

        """
         Pass each type of vex statement to its appropriate handler for analysis
        :param stmt:
        :param irsb_context:
        :return:
        """

        # ** AbiHint **
        if isinstance(stmt, pyvex.stmt.AbiHint):

            # Do nothing with this statement
            pass

            # ** Exit **
        elif isinstance(stmt, pyvex.stmt.Exit):

            self._analyze_exit_stmt(stmt, irsb_context)

        # ** IMark **
        elif isinstance(stmt, pyvex.stmt.IMark):

            # IMark maps this current vex statement to the associated native instruction
            imark_string = str(stmt)

            # Set the current native instruction that the vex ir is associated with
            irsb_context.curr_native_instr_address = self._get_address_from_IMark(imark_string)
            irsb_context.curr_native_instr_size = self._get_instruction_size_from_IMark(imark_string)
            logger.debug("Current Native instruction address: 0x{0:x} (size {1})".
                         format(irsb_context.curr_native_instr_address, irsb_context.curr_native_instr_size))

        # ** Put **
        elif isinstance(stmt, pyvex.stmt.Put):

            self._analyze_put_stmt(stmt, irsb_context)

        # ** PutI **
        elif isinstance(stmt, pyvex.stmt.PutI):

            self._analyze_puti_stmt(stmt, irsb_context)

        # ** Store **
        elif isinstance(stmt, pyvex.stmt.Store):

            self._analyze_store_stmt(stmt, irsb_context)

        # ** WrTmp **
        elif isinstance(stmt, pyvex.stmt.WrTmp):

            self._analyze_wrtmp_stmt(stmt, irsb_context)

            pass

        elif isinstance(stmt, pyvex.stmt.CAS):

            self._analyze_cas_stmt(stmt, irsb_context)

        elif isinstance(stmt, pyvex.stmt.Dirty):

            self._analyze_dirty_stmt(stmt, irsb_context)

        elif isinstance(stmt, pyvex.stmt.MBE):

            self._analyze_mbe_stmt(stmt, irsb_context)

        else:

            raise ValueError("Unsupported statement of type: {}".format(type(stmt)))

    def _analyze_cas_stmt(self, cas_stmt, irsb_context):

        # @Todo: Figure out what type of statement this is and how to categorize

        pass

    def _analyze_dirty_stmt(self, dirty_stmt, irsb_context):

        pass

    def _analyze_exit_stmt(self, exit_stmt, irsb_context):

        if exit_stmt.jumpkind == "Ijk_Boring":

            target_addr = exit_stmt.dst.value
            logger.debug("Ijk_Boring jump target: 0x{0:x}".format(target_addr))

            # If we have the jump target irsb, then put it in the queue
            jump_target_block = irsb_context.parent_func.get_block(target_addr)
            if jump_target_block:
                jump_target_irsb_context = IRSBContext(jump_target_block,
                                                       irsb_context,
                                                       self._import_symbol_map,
                                                       irsb_context.parent_func)

                self._irsb_context_queue.put(jump_target_irsb_context)

            else:
                logger.warning(irsb_context.irsb._pp_str())
                logger.warning("Unable to obtain irsb with start address 0x{0:x}".format(target_addr))

        elif exit_stmt.jumpkind == "Ijk_SigSEGV":

            # @Todo: Add support for this jumpkind
            pass

        else:
            logger.warning(irsb_context.irsb._pp_str())
            #raise ValueError("Unsupported jumpkind: {}".format(exit_stmt.jumpkind))



        pass

    def _analyze_mbe_stmt(self, stmt, irsb_context):

        # @Todo: Figure out what type of statement this is and how to categorize

        pass

    def _analyze_put_stmt(self, put_stmt, irsb_context):

        pass

    def _analyze_puti_stmt(self, puti_stmt, irsb_context):

        pass

    def _analyze_store_stmt(self, store_stmt, irsb_context):


        pass

    def _analyze_unconditional_exit_stmt(self, irsb_context):

        irsb = irsb_context.irsb

        if irsb.jumpkind == "Ijk_Boring":

            # Get the jump target
            jump_target = self._get_unconditional_jump_target(irsb_context)

            if jump_target:
                logger.debug("jump target: 0x{0:x}".format(jump_target))

            else:
                logger.debug("Unable to compute the jump target")
                return

            # Check if jump target is an import
            if jump_target in self._import_symbol_map:

                import_symbol = self._import_symbol_map[jump_target]

                logger.debug("Jump to import function '{0}' in library '{1}' with symbol address 0x{2:x}".
                            format(import_symbol.import_name, import_symbol.library_name, import_symbol.address))

                # Append import symbol to call trace list
                call_trace_node_info = CallTraceNodeInfo.from_import_symbol(import_symbol,
                                                                            irsb_context.curr_native_instr_address)

                irsb_context.call_trace_list.append(call_trace_node_info)

                # Since we are jumping to an import call within a thunk.... we need to simulate the return to the next
                # instruction after the call to thunk

                # First, get the parent context (which is the irsb that made the call to thunk)
                parent_context = irsb_context.parent_irsb_context

                if parent_context is None:
                    # This is the entry irsb making a jump to a symbol ==> thunk
                    # Not much to analysis since this is a thunk
                    return

                # Get the next instruction after the call, which is effectively the jump target to the the next basic
                # block in sequrence
                jump_target = parent_context.get_next_native_instruction_addr()

                logger.debug("Jump target: 0x{0:x}".format(jump_target))

                # Get the jump target irsb
                return_jump_target_block = parent_context.parent_func.get_block(jump_target)

                # If we have the jump target irsb, then put it in the queue
                if return_jump_target_block:
                    return_addr_irsb_context = IRSBContext(return_jump_target_block,
                                                                    irsb_context,
                                                                    self._import_symbol_map,
                                                                    parent_context.parent_func)

                    self._irsb_context_queue.put(return_addr_irsb_context)

                else:
                    logger.warning("Unable to obtain the jump target irsb for target 0x{0:x}".format(jump_target))


            else:

                # Get the jump target irsb
                return_jump_target_block = irsb_context.parent_func.get_block(jump_target)

                # If we have the jump target irsb, then put it in the queue
                if return_jump_target_block:
                    return_addr_irsb_context = IRSBContext(return_jump_target_block,
                                                           irsb_context,
                                                           self._import_symbol_map,
                                                           irsb_context.parent_func)

                    self._irsb_context_queue.put(return_addr_irsb_context)

                else:
                    logger.debug("Unable to obtain the jump target irsb for target 0x{0:x}".format(jump_target))

        elif irsb.jumpkind == "Ijk_Call":

            # Get the jump target
            jump_target = self._get_unconditional_jump_target(irsb_context)

            if jump_target:
                logger.debug("jump target: 0x{0:x}".format(jump_target))

            # Determine if this is a call to a defined function or an external call
            if jump_target is None:

                logger.debug("Unable to determine jump target for Ijk_Call")

            # Check if jump target is an import
            elif jump_target in self._import_symbol_map:

                import_symbol = self._import_symbol_map[jump_target]

                logger.debug("Call to import function '{0}' in library '{1}' with symbol address 0x{2:x}".
                            format(import_symbol.import_name, import_symbol.library_name, import_symbol.address))

                # Append import symbol to call trace list
                call_trace_node_info = CallTraceNodeInfo.from_import_symbol(import_symbol, irsb_context.curr_native_instr_address)

                irsb_context.call_trace_list.append(call_trace_node_info)

                pass

            elif jump_target in self._func_addr_list:

                angr_function = self._get_angr_function(jump_target)

                # Append import symbol to call trace list
                call_trace_node_info = CallTraceNodeInfo.from_angr_func(angr_function,
                                                                        irsb_context.curr_native_instr_address)

                irsb_context.call_trace_list.append(call_trace_node_info)

                # Get the 'external' jump target irsb context
                logger.debug("[0x{0:x}] External jump from function {1} to function {2}".format(irsb_context.curr_native_instr_address,
                                                                                              irsb_context.parent_func.name,
                                                                                              angr_function.name))

                return_address = irsb_context.get_next_native_instruction_addr()

                return_addr_irsb_context = IRSBContext(angr_function.entry_block,
                                                       irsb_context,
                                                       self._import_symbol_map,
                                                       angr_function)

                # Push the return address on the return address stack
                return_addr_irsb_context.return_addr_stack.append((return_address, irsb_context.parent_func))

                self._irsb_context_queue.put(return_addr_irsb_context)


                pass

            else:
                logger.warning("Jump target '0x{0:x}' could not be found in import symbol map".format(jump_target))


            # Note: Since this is a call that occurs at an unconditional exit, we need to get the next irsb
            #       This irsb will have a start address that is the next instruction after the call
            #       We can use the imark to compute the next instruction, which is the start adddress of irsb
            next_irsb_start_address = irsb_context.get_next_native_instruction_addr()

            # Get the jump target irsb
            next_irsb = irsb_context.parent_func.get_block(next_irsb_start_address)

            # If we have the jump target irsb, then put it in the queue
            if next_irsb:
                return_addr_irsb_context = IRSBContext(next_irsb,
                                                       irsb_context,
                                                       self._import_symbol_map,
                                                       irsb_context.parent_func)

                self._irsb_context_queue.put(return_addr_irsb_context)

            else:
                logger.warning("Unable to obtain irsb with start address 0x{0:x}".format(next_irsb_start_address))

        elif irsb.jumpkind == "Ijk_Ret":

            if len(irsb_context.return_addr_stack) == 0:

                logger.debug("We've completing analyzing code flow along current path")
                self._post_code_flow_path_processing(irsb_context)
                return

            (return_address, return_addr_func) = irsb_context.return_addr_stack.pop()

            # Get the jump target irsb
            return_jump_target_block = return_addr_func.get_block(return_address)

            # If we have the jump target irsb, then put it in the queue
            if return_jump_target_block:
                return_addr_irsb_context = IRSBContext(return_jump_target_block,
                                                       irsb_context,
                                                       self._import_symbol_map,
                                                       return_addr_func)

                self._irsb_context_queue.put(return_addr_irsb_context)

            else:
                logger.warning("Unable to obtain the jump target irsb for target 0x{0:x}".format(return_address))
            pass

        elif irsb.jumpkind == "Ijk_SigTRAP":

            # @Todo: Add support for this jumpkind
            pass

        else:

            raise ValueError("Unsupported jumpkind: {}".format(irsb.jumpkind))


        pass

    def _detect_if_cycle_exists(self, irsb_context):

        assert isinstance(irsb_context, IRSBContext), "Expected an object of type IRSBContext"

        # Get parent irsb context
        parent_irsb_context = irsb_context.parent_irsb_context

        while parent_irsb_context:

            if irsb_context.addr == parent_irsb_context.addr:

                # A child's ancestor is the child, therefore, cycle detected
                return True

            # Get the next ancestor (i.e. the parent's parent)
            parent_irsb_context = parent_irsb_context.parent_irsb_context

        return False

    def _post_code_flow_path_processing(self, irsb_context):

        """
        The current irsb is last irsb along this code flow path.  This is where we can do call
        trace post-processing for this path
        :param irsb_context:
        :return:
        """
        logger.info("============Call Trace ==================")
        counter = 1
        for call_trace_node in irsb_context.call_trace_list:

            logger.info("\t {}) {}".format(counter, call_trace_node.pretty_print_str()))
            counter += 1

        logger.info("==========END Call Trace ================\n")
        pass


    def _get_angr_function(self, addr):

        return self._vex_obj.get_angr_function(addr)

    def _get_unconditional_jump_target(self, irsb_context):

        jump_target = None

        irsb = irsb_context.irsb

        if irsb.next.tag == "Iex_RdTmp":

            '''
                Need to handle this:
               20 | ------ IMark(0x100001058, 6, 0) ------
               21 | t13 = LDle:I64(0x00000001000ba9b0)
               22 | t42 = Sub64(t16,0x0000000000000008)
               23 | PUT(rsp) = t42
               24 | STle(t42) = 0x000000010000105e
               25 | t44 = Sub64(t42,0x0000000000000080)
               26 | ====== AbiHint(0xt44, 128, t13) ======
               NEXT: PUT(rip) = t13; Ijk_Call
            '''

            # Indirect jump

            temp_reg_index = irsb.next.tmp  # temp register index
            temp_register_context = irsb_context.get_temp_register_context(temp_reg_index)

            if temp_register_context:

                temp_register_value = temp_register_context.value

                jump_target = temp_register_value

            else:

                logger.debug("Unable to compute jump target. Temp register index {} does not exist".format(temp_reg_index))
                return jump_target


        else:

            # Direct Jump

            # Get the jump target
            jump_target = irsb.next.constants[0].value

        return jump_target

    def _analyze_wrtmp_stmt(self, wrtmp_stmt, irsb_context):

        # Get the expression
        expression_data = wrtmp_stmt.data

        # Get the expression context for this expression
        expression_context= self._analyze_expression_data(expression_data, irsb_context)

        if expression_context:

            # Perform the write to the temporary register
            tmp_reg_index = int(wrtmp_stmt.tmp)

            irsb_context.add_temp_register(tmp_reg_index, expression_context.value, expression_context.value)

        pass

    def _analyze_expression_data(self, expression_data, irsb_context):

        # Get the expression tag
        expression_tag = expression_data.tag

        # get the expression class from the expression tag
        # expr_class = pyvex.expr.tag_to_class[pyvex.expr.enums_to_ints[expression_tag]]
        pyvex.expr.tag_to_expr_class(expression_tag)

        expr_class =  pyvex.expr.tag_to_expr_class(expression_tag)
        # Handle based on the expression class type and


        # ** Binop **
        if expr_class == pyvex.expr.Binop:

            expression_context_result = self._analyze_bin_op_expr_data(expression_data, irsb_context)

        # ** Const **
        elif expr_class ==pyvex.expr.Const:

            expression_context_result = self._analyze_const_expr_data(expression_data,irsb_context)

        # ** Get **
        elif expr_class == pyvex.expr.Get:

            expression_context_result = self._analyze_get_expr_data(expression_data, irsb_context)

        # ** ITE **
        elif expr_class == pyvex.expr.ITE:

            expression_context_result = self._analyze_ITE_expr_data(expression_data, irsb_context)

        # ** Load **
        elif expr_class == pyvex.expr.Load:

            expression_context_result = self._analyze_load_expr_data(expression_data, irsb_context)

        # ** RdTmp **
        elif expr_class == pyvex.expr.RdTmp:

            expression_context_result = self._analyze_rd_tmp_expr_data(expression_data, irsb_context)

        # ** Unop **
        elif expr_class == pyvex.expr.Unop:

            expression_context_result = self._analyze_unop_expr_data(expression_data, irsb_context)

        # ** CCall **
        elif expr_class == pyvex.expr.CCall:

            expression_context_result = self._analyze_ccall_expr_data(expression_data, irsb_context)

        # ** GetI **
        elif expr_class == pyvex.expr.GetI:

            expression_context_result = self._analyze_geti_expr_data(expression_data, irsb_context)

        elif expr_class == pyvex.expr.Triop:

            expression_context_result = self._analyze_triop_expr_data(expression_data, irsb_context)

        elif expr_class == pyvex.expr.Qop:

            expression_context_result = self._analyze_qop_expr_data(expression_data, irsb_context)

        else:
            raise ValueError("Unsupported expression class: {}".format(str(expr_class)))

        return expression_context_result

    @staticmethod
    def _analyze_bin_op_expr_data(bin_op_expr_data, irsb_context):

        # The ir category that this binary operation falls under
        ir_category = None

        bin_op = bin_op_expr_data.op

        # if "Add" in bin_op:
        #
        #     ir_category = IRCategory.arithmetic
        #
        # elif "And" in bin_op:
        #
        #     ir_category = IRCategory.bit_logic
        #
        # elif "Sub" in bin_op:
        #
        #     ir_category = IRCategory.arithmetic
        #
        # elif "Mul" in bin_op:
        #
        #     ir_category = IRCategory.arithmetic
        #
        # elif "Cmp" in bin_op:
        #
        #     ir_category = IRCategory.compare
        #
        # elif "Iop_Sar" in bin_op:
        #
        #     ir_category = IRCategory.bit_logic
        #
        # elif "Iop_Sh" in bin_op:
        #
        #     ir_category = IRCategory.bit_shift
        #
        # elif "Iop_Xor" in bin_op:
        #     ir_category = IRCategory.bit_logic
        #
        # elif "Iop_Or" in bin_op:
        #     ir_category = IRCategory.bit_logic
        #
        # elif "Iop_Div" in bin_op:
        #     ir_category = IRCategory.arithmetic
        #
        # elif "Iop_Interleave" in bin_op:
        #     # Note: (Iop_Interleave)
        #     #       Interleave odd/even lanes of operands
        #     ir_category = IRCategory.bit_transform
        #
        # elif "Iop_Cat" in bin_op:
        #     # Note: (Iop_Cat{Odd/Even}Lanes)
        #     #       Build a new value by concatenating either  the even or odd lanes of both operands
        #     #       https://github.com/angr/vex/blob/master/pub/libvex_ir.h
        #     ir_category = IRCategory.bit_transform
        #
        # elif "Iop_Perm" in bin_op:
        #
        #     # Note: (Iop_Perm)
        #     #       PERMUTING -- copy src bytes to dst
        #     ir_category = IRCategory.bit_transform
        #
        # elif "Iop_Round" in bin_op:
        #     ir_category = IRCategory.bit_transform
        #
        # elif "Iop_Set" in bin_op:
        #     # @Todo: Find out what this does
        #     ir_category = IRCategory.other
        #
        # elif "Iop_Cos" in bin_op:
        #     ir_category = IRCategory.arithmetic
        #
        # elif "Iop_Sin" in bin_op:
        #     ir_category = IRCategory.arithmetic
        #
        # elif "Iop_Min" in bin_op:
        #     ir_category = IRCategory.arithmetic
        #
        # elif "Iop_Max" in bin_op:
        #     ir_category = IRCategory.arithmetic
        #
        # elif "Iop_Sqrt" in bin_op:
        #     ir_category = IRCategory.arithmetic
        #
        # elif "Iop_2xm1F64" in bin_op:
        #
        #     # Note : Rounding to Float
        #     ir_category = IRCategory.bit_transform
        #
        # elif "Iop_QNarrowBin" in bin_op:
        #     ir_category = IRCategory.bit_transform
        #
        # elif re.compile(".*Iop_[VIFS]?(\d*)[HS]?L?to[VIF]?(\d*)[S]?").match(bin_op) is not None:
        #
        #     # e.g. 32HLto64 ; F64toF32
        #     p = re.compile(".*Iop_[VIFS]?(\d*)[HS]?L?to[VIF]?(\d*)[S]?").match(bin_op)
        #
        #     logger.debug("bin_op: '{}'".format(bin_op))
        #
        #     operand_0 = int(p.group(1), 0)
        #
        #     operand_1 = int(p.group(2), 0)
        #
        #     if operand_0 < operand_1:
        #
        #         ir_category = IRCategory.bit_extend
        #
        #     elif operand_0 > operand_1:
        #
        #         ir_category = IRCategory.bit_trunc
        #
        #     else:
        #         # Case with equality (i.e. operand_0 == operand_1)
        #         ir_category = IRCategory.other
        #
        # else:
        #     raise ValueError("Unsupported binary operation '{}'".format(bin_op))

        pass

    @staticmethod
    def _analyze_const_expr_data(const_expr_data, irsb_context):

        pass

    @staticmethod
    def _analyze_ccall_expr_data(ccall_expr_data, irsb_context):

        pass

    @staticmethod
    def _analyze_get_expr_data(get_expr_data, irsb_context):

        pass

    @staticmethod
    def _analyze_geti_expr_data(expression_data, irsb_context):

        pass

    @staticmethod
    def _analyze_ITE_expr_data(ite_expr_data, irsb_context):

        pass

    @staticmethod
    def _analyze_load_expr_data(load_expr_data, irsb_context):

        load_address = None

        expression_context_result = None

        load_expr_tag = load_expr_data.child_expressions[0].tag

        if load_expr_tag == "Iex_Const":

            # Constant value

            load_address = load_expr_data.child_expressions[0].constants[0].value

        # else:
        #
        #     # Temp register value
        #
        #     load_address_tmp_register

        # Check that we were able to get a valid load address
        if load_address:

            data_size_in_bits = FunctionCallTraceGenerator._get_data_size_in_bits(load_expr_data)

            data_size_in_bytes = data_size_in_bits / 8

            # For the purpose of identifying import symbols, we'll bypass resolving where the actual
            # location of the library resides in memory.  All we care about is the symbol. So we'll
            # load the symbol address as the the value loaded from memory.
            if load_address in irsb_context.import_symbol_map:

                expression_context_result = ExpressionContext(load_address, data_size_in_bytes)

        return expression_context_result


    @staticmethod
    def _analyze_rd_tmp_expr_data(rd_tmp_expr_data, irsb_context):

        pass

    @staticmethod
    def _analyze_triop_expr_data(triop_expr_data, irsb_context):

        pass

    @staticmethod
    def _analyze_qop_expr_data(qop_expr_data, irsb_context):

        pass

    @staticmethod
    def _analyze_unop_expr_data(unop_expr_data, irsb_context):

        # # The ir category that this read temp expression falls under
        # ir_category = None
        #
        # unary_op = unop_expr_data.op
        #
        # # Handle the extend and truncate unary expressions
        # # e.g. "Iop_64HIto32", "Iop_I32StoF64"
        # p = re.compile(".*Iop_[VH]?[FI]?(\d*)[SUH]?[I]?to[FV]?(\d*)")
        # m = p.match(unary_op)
        # if m:
        #     first_int = int(m.group(1),0)
        #     second_int = int(m.group(2),0)
        #
        #     if first_int < second_int:
        #         ir_category = IRCategory.bit_extend
        #
        #     else:
        #         ir_category = IRCategory.bit_trunc
        #
        # elif "Iop_Not" in unary_op:
        #
        #     ir_category = IRCategory.bit_logic
        #
        # elif "Iop_Neg" in unary_op:
        #
        #     ir_category = IRCategory.bit_logic
        #
        # elif "Iop_GetMSBs" in unary_op:
        #
        #     # @Todo: Does this belong to a new category?
        #     ir_category = IRCategory.other
        #
        # elif "Iop_Ctz" in unary_op:
        #
        #     # @Todo: Does this belong to a new category?
        #     ir_category = IRCategory.other
        #
        # elif "Iop_Clz" in unary_op:
        #
        #     # @Todo: Does this belong to a new category?
        #     ir_category = IRCategory.other
        #
        # elif "Iop_Reinterp" in unary_op:
        #
        #     ir_category = IRCategory.bit_transform
        #
        # elif "Iop_Sqrt" in unary_op:
        #
        #     ir_category = IRCategory.arithmetic
        #
        # elif "Iop_Abs" in unary_op:
        #
        #     ir_category = IRCategory.arithmetic
        #
        # else:
        #     raise ValueError("Unsupported unary operation '{}'".format(unary_op))
        #
        # return ir_category
        pass

    @staticmethod
    def _statement_logger(stmt, irsb_context):

        curr_native_instr_address = irsb_context.curr_native_instr_address

        if curr_native_instr_address and not isinstance(stmt, pyvex.stmt.IMark):
            logger.debug("\tAddress: 0x{0:x}".format(curr_native_instr_address))

        logger.debug("\tType: {}".format(type(stmt)))
        logger.debug("\t{0}".format(str(stmt)))

    @staticmethod
    def _get_data_size_in_bits(expr_data):

        expr_data_type = expr_data.type

        p = re.compile('Ity_[FIV]([0-9]*)')

        m = p.match(expr_data_type)

        assert m is not None, 'Failed to parse data type string {}'.format(expr_data_type)

        # Data size is the first regex group
        data_size_in_bits = int(m.group(1))

        return data_size_in_bits

    @staticmethod
    def _get_instruction_size_from_IMark(imark_string):

        p = re.compile('.*IMark\(0x([0-9a-f]*),.*(\d)+,')
        m = p.match(imark_string)

        assert m is not None, "Failed to parse Imark string {}".format(imark_string)

        instruction_size = int(m.group(2))

        return instruction_size

    @staticmethod
    def _get_address_from_IMark(imark_string):

        p = re.compile('.*IMark\(0x([0-9a-f]*),.*(\d)+,')
        m = p.match(imark_string)

        assert m is not None, "Failed to parse Imark string {}".format(imark_string)

        # Instruction address is in the first regex group
        instruction_address = int(m.group(1), 16)

        return instruction_address