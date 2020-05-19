

class ExpressionContext(object):

    def __init__(self, value, size):

        # Expression value
        self._value = value

        # Value size (in bytes)
        self._size = size

    @property
    def value(self):

        return self._value

    @value.setter
    def value(self, value):

        self._value = value

    @property
    def size(self):

        return self._size

    @size.setter
    def size(self, value):

        self._size = value