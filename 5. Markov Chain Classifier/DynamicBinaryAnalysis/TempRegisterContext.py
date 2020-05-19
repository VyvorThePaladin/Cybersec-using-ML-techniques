from DynamicBinaryAnalysis.ExpressionContext import ExpressionContext


class TempRegisterContext(ExpressionContext):
    def __init__(self, temp_reg_index, value, size):

        # Temporary Register Index
        self._temp_reg_index = temp_reg_index

        super(TempRegisterContext, self).__init__(value, size)

    @property
    def temp_reg_index(self):

        return self._temp_reg_index
