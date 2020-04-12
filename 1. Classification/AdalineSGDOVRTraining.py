import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import ListedColormap
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

from AdalineSGDOVR import AdalineSGDOVR


def plot_decision_regions(X, y, classifier, resolution=0.02):
    # setup marker generator and color map
    markers = ('s', 'x', 'o', '^', 'v')
    colors = ('red', 'blue', 'lightgreen', 'gray', 'cyan')
    cmap = ListedColormap(colors[:len(np.unique(y))])

    # plot the decision surface
    x1_min, x1_max = X[:, 0].min() - 1, X[:, 0].max() + 1
    x2_min, x2_max = X[:, 1].min() - 1, X[:, 1].max() + 1
    xx1, xx2 = np.meshgrid(np.arange(x1_min, x1_max, resolution),
                           np.arange(x2_min, x2_max, resolution))

    Z = classifier.predict(np.array([xx1.ravel(), xx2.ravel()]).T)
    Z = Z.reshape(xx1.shape)

    plt.contourf(xx1, xx2, Z, alpha=.3, cmap=cmap)
    plt.xlim(xx1.min(), xx1.max())
    plt.ylim(xx2.min(), xx2.max())

    # plot class samples
    for idx, c1 in enumerate(np.unique(y)):
        plt.scatter(x=X[y == c1, 0],
                    y=X[y == c1, 1],
                    alpha=.8,
                    c=colors[idx],
                    marker=markers[idx],
                    label=c1,
                    edgecolor='black'
                    )

# Load the iris data into a "data frame"
df = pd.read_csv("iris.data", header=None)

# Map the string labels to integers that we will then pass into the classifier
y = df.iloc[:, 4].values
y[y == 'Iris-setosa'] = 0
y[y == 'Iris-versicolor'] = 1
y[y == 'Iris-virginica'] = 2

# extract the four iris features for each of the samples to build the sample set X
X = df.iloc[:, [0, 1, 2, 3]].values


# We need to normalize the the dataset
standard_scaler = StandardScaler()
X_std = standard_scaler.fit_transform(X)

# Since we are using 4 features and would like to project into a 2-d space, we'll use
# PCA to accomplish this.
X_pca = PCA(n_components=2).fit_transform(X_std)

# Create our model
ada = AdalineSGDOVR(n_iter=15, eta=0.01, random_state=1).fit(X_pca, y)

# Plot the decision boundaries decided by our model
plot_decision_regions(X_std, y, classifier=ada)
plt.title('Adaline - Stochastic Gradient Descent w/ OvR')
plt.xlabel('PC 1')
plt.ylabel('PC 2')
plt.legend(loc='upper left')
plt.tight_layout()
plt.show()

plt.close()
