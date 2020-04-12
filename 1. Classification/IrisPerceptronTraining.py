import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from Perceptron import Perceptron
from matplotlib.colors import ListedColormap

"""
Notes: Multiple figures --> https://stackoverflow.com/questions/6916978/how-do-i-tell-matplotlib-to-create-a-second-new-plot-then-later-plot-on-the-os

"""
def plot_decision_regions(X,y, classifier, resolution=0.02):

    # setup marker generator and color map
    markers = ('s','x','o', '^', 'v')
    colors = ('red', 'blue', 'lightgreen', 'gray', 'cyan')
    cmap = ListedColormap(colors[:len(np.unique(y))])

    # plot the decision surface
    x1_min, x1_max =  X[:,0].min() - 1, X[:, 0].max() +1
    x2_min, x2_max = X[:, 1].min() - 1, X[:, 1].max() + 1
    xx1, xx2 = np.meshgrid(np.arange(x1_min, x1_max, resolution),
                           np.arange(x2_min, x2_max, resolution))

    Z = classifier.predict(np.array([xx1.ravel(), xx2.ravel()]).T)
    Z = Z.reshape(xx1.shape)

    plt.contourf(xx1, xx2, Z, alpha=.3, cmap=cmap)
    plt.xlim(xx1.min(), xx1.max())
    plt.ylim(xx2.min(), xx2.max())

    #plot class samples
    for idx, c1 in enumerate(np.unique(y)):
        plt.scatter(x=X[y == c1, 0],
                    y=X[y == c1, 1],
                    alpha=.8,
                    c=colors[idx],
                    marker=markers[idx],
                    label=c1,
                    edgecolor='black'
                    )

df = pd.read_csv("iris.data", header=None)

df.tail()

print(df.tail())

# select setosa and versicolor
y = df.iloc[0:100,4].values
y = np.where(y =='Iris-setosa', -1, 1)

# extract sepal length and petal length
X = df.iloc[0:100, [0, 2]].values

plt.figure()
# plot data
plt.scatter(X[:50, 0], X[:50, 1], color='red', marker='o', label='setosa')

plt.scatter(X[50:100, 0], X[50:100,1], color='blue', marker='x', label='versicolor')

plt.xlabel('sepal length [cm]')
plt.ylabel('petal length [cm]')
plt.legend(loc='upper left')
#plt.show()

plt.figure()
ppn = Perceptron(eta=.1, n_iter=10)
ppn.fit(X,y)
plt.plot(range(1, len(ppn._errors)+1), ppn._errors, marker='o')

plt.xlabel('Epochs')
plt.ylabel('Number of updates')
#plt.show()

plt.figure()
plot_decision_regions(X,y, classifier=ppn)
plt.xlabel('sepal length [cm]')
plt.ylabel('petal length [cm]')
plt.legend(loc='upper left')
#plt.show()

pass
plt.show(1)
plt.show(2)
plt.show(3)

# close figures
#plt.close(1)
#plt.close(2)

pass