import numpy as np

class Perceptron(object):

    """
    Perceptron classifier

    Parameters
    --------------
    eta : float
     Learning rate (between 0.0 and 1.0)


    n_iter : int
     Passes over the training dataset

    random_state : int
     Random number generator seed for random weight initialization


    Attributes
    ---------------
    _w: 1d-array
     Weights after fitting

    _errors_ : list
     Number of misapplications (updates) in each epoch

    """

    def __init__(self, eta=0.01, n_iter=50, random_state=1):

        self.eta =eta
        self.n_iter = n_iter
        self.random_state = random_state

        self._w = []
        self._errors = []

    def fit(self, X, y):
        """
        Fit training data

        :param X: {array-like, shape = [n_samples, n_features]
                   Training vectors, where n_samples is the number of samples and
                                           n_features  is the number of features
        :param y: array-like, shape = [n_samples]
                  Target values
        :return:  self: object
        """

        rgen = np.random.RandomState(self.random_state)

        self._w = rgen.normal(loc=0.0, scale=0.01, size=1 + X.shape[1])

        for _ in range(self.n_iter):
            errors = 0

            for x_i, target in zip(X,y):
                update = self.eta * (target - self.predict(x_i))
                self._w[1:]  += update *x_i
                self._w[0] +update
                errors += int(update != 0.0)
            self._errors.append(errors)

        return self

    def net_input(self, X):
        """Calculate net input"""
        return np.dot(X, self._w[1:]) + self._w[0]

    def predict(self, X):
        """Return class label after unit step"""
        return np.where(self.net_input(X) >= 0.0, 1, -1)
