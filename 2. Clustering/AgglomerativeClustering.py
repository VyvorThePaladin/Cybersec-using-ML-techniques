
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import pandas as pd
import numpy as np
from sklearn.cluster import AgglomerativeClustering
import time


# Load the dataset from file
df = pd.read_csv("lab1bsamples_large.csv", header=None)
df.tail()
print(df.tail())

# get all of the points from the dataset as an array of 2-dimensional vectors
X = df.iloc[:].values

X_std = np.copy(X)
X_std[:, 0] = (X_std[:, 0] - X_std[:, 0].mean()) / (X_std[:, 0].std())
X_std[:, 1] = (X_std[:, 1] - X_std[:, 1].mean()) / (X_std[:, 1].std())

# Value that you want to adjust
num_clusters=2

# Initialize KMeans
ac = AgglomerativeClustering(n_clusters=num_clusters,
            affinity='euclidean',
            linkage='complete')

# Perform the clustering
start_time = time.time()
y_km = ac.fit_predict(X_std)
elapsed_time = time.time() - start_time

print("Runtime: {} seconds".format(elapsed_time))



# Plotting
plt.figure()
colors = cm.rainbow(np.linspace(0,1,num_clusters))
for k, color in zip(range(num_clusters), colors):

    # plot points for cluster i
    plt.scatter(X[y_km == k, 0],
                X[y_km == k, 1],
                s=50,
                c=color,
                marker='o',
                label="cluster {}".format(k+1))


plt.legend(scatterpoints=1)
plt.grid()
plt.show()

pass


