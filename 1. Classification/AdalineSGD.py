import numpy as np

class AdalineSGD(object):

    """
    ADAptive LInear NEuron classifier

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

    def __init__(self, eta=0.01, n_iter=50, shuffle=True, random_state=None):

        self.eta =eta
        self.n_iter = n_iter
        self.random_state = random_state
        self.shuffle = shuffle
        self.w_initialized = False


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

        self._initialize_weights(X.shape[1])
        self._cost = []

        for i in range(self.n_iter):

            if self.shuffle:
                X, y = self._shuffle(X,y)

            cost = []

            for xi, target in zip(X,y):
                cost.append(self._update_weights(xi,target))
            avg_cost = sum(cost) / len(y)
            self._cost.append(avg_cost)
        return self

    def partial_fit(self, X, y):
        """
         Fit training data without reinitializing the weights
        """

        if not self.w_initialized:
            self._initialize_weights(X.shape[1])

        if y.ravel().shape[0] > 1:
            for xi, target in zip (X,y):
                self._update_weights(xi, target)
        else:
            self._update_weights(X,y)

        return self

    def _shuffle(self,X, y):
        """Shuffle training data"""
        r = self.rgen.permutation(len(y))
        return X[r], y[r]

    def _initialize_weights(self,m):
        """Initialize weights to small random numbers"""
        self.rgen = np.random.RandomState(self.random_state)
        self._w = self.rgen.normal(loc=0.0, scale=0.01, size=1+m)

        self.w_initialized = True

    def _update_weights(self, xi, target):
        """ Apply Adaline learning rule to update the weights"""
        output = self.activation(self.net_input(xi))
        error = (target - output)
        self._w[1:] += self.eta * xi.dot(error)
        self._w[0] += self.eta * error
        cost = 0.5 * error **2
        return cost

    def net_input(self, X):
        """Calculate net input"""
        return np.dot(X, self._w[1:]) + self._w[0]

    def activation(self, X):
        """Compute linear activation"""
        return X

    def predict(self, X):
        """Return class label after unit step"""
        return np.where(self.net_input(X) >= 0.0, 1, -1)

    def predict_w_conf_score(self,X):
        """Returns a tuple where the first element is the class label and the second
           element is the 'confidence' score
        """

        confidence = self.net_input(X)

        return (np.where(confidence >= 0.0, 1, -1), confidence)
