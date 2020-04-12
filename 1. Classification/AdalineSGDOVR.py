import numpy as np
import logging

from AdalineSGD import AdalineSGD
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)



class AdalineSGDOVR(object):

    """
    ADAptive LInear NEuron classifier Stochasit Gradient Descent w/ OVR

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
        # Additional hint about the incoming data types
        if not isinstance(X, np.ndarray) or not isinstance(y, np.ndarray):
            raise TypeError("Input must be an numpy.ndarray")

        logger.warning("@Todo: Need to follow OVR steps in lecture material to create K Adaline classifiers")

        """
            Hint:    Let fk denote a classifier that is trained to  classify class k
                     For each class k in K
                          Create a new label vector yk
                          Update yk such that all data points that are of class k are set to 1
                          Update yk such that all other data points not in class k to be -1
                          Train an AdalineSGD classifier with the yk labels
        """

        return self

    def predict(self, X):
        """Return class label

        :param X: numpy nd-array

        """

        if not isinstance(X, np.ndarray):
            raise TypeError("Input must be an numpy.ndarray")


        y_ovr = np.zeros(len(X))

        logger.warning("@Todo: Implement the OvR Classification Algorithm as outlined in lecture")

        """
            Hint:    1. Apply all classifiers fk(x) to an unseen sample x
                     2. Each classifier fk(x) will produce a confidence score
                     3. Select the fk(x) with the highest confidence score
                     4. The sample x will inherit the label associated with the fk(x)

        """

        return y_ovr