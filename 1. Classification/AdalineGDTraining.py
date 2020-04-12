import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from AdalineGD import AdalineGD
from matplotlib.colors import ListedColormap


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


#=================Standardized data ######################

X_std = np.copy(X)

X_std[:,0] = (X_std[:,0] - X_std[:,0].mean()) / (X_std[:,0].std())
X_std[:,1] = (X_std[:,1] - X_std[:,1].mean()) / (X_std[:,1].std())

ada = AdalineGD(n_iter=50, eta= 0.01).fit(X_std,y)

plt.figure()

plt.plot(range(1, len(ada._cost)+1), np.log10(ada._cost), marker='o')

plt.xlabel('Epochs')
plt.ylabel('log(Sum-squared-error')


pass
plt.figure()
plot_decision_regions(X_std,y, classifier=ada)
plt.title('Adaline - Gradient Descent')
plt.xlabel('sepal length [standardized]')
plt.ylabel('petal length [standardized]')
plt.legend(loc='upper left')
plt.tight_layout()


plt.show(1)
plt.show(2)





pass

plt.close()







