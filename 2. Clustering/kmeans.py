
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
import time


MAX_NUMBER_OF_CLUSTERS = 50


def elbow_method_plot(X):

    sse = {}
    for k in range(1, MAX_NUMBER_OF_CLUSTERS):
        kmeans = KMeans(n_clusters=k, init='k-means++', max_iter=1000).fit(X)

        labels = kmeans.labels_

        sse[k] = kmeans.inertia_  # Inertia: Sum of distances of samples to their closest cluster center

        if k > 1:

            sil_coeff = silhouette_score(X, labels, metric='euclidean')

            print("For n_clusters={}, The Silhouette Coefficient is {}".format(k, sil_coeff))

    plt.figure()

    plt.plot(list(sse.keys()), list(sse.values()))

    plt.xlabel("Number of cluster")

    plt.ylabel("SSE")

    plt.show()

def perform_k_means_clustering(X, num_clusters):
    # Initialize KMeans
    km = KMeans(n_clusters=num_clusters,
                init='k-means++',
                n_init=10,
                max_iter=300,
                tol=1e-04,
                random_state=0)

    # Perform the clustering
    start_time = time.time()
    y_km = km.fit_predict(X)
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

    plt.scatter(km.cluster_centers_[:, 0],
                km.cluster_centers_[:,1],
                s=250,
                marker= '*',
                c='black',
                label='centroids')


    plt.legend(scatterpoints=1)
    plt.grid()
    plt.show()


def main():

    # Load the dataset from file
    df = pd.read_csv("lab1bsamples_large.csv", header=None)
    df.tail()
    print(df.tail())

    # get all of the points from the dataset as an array of 2-dimensional vectors
    X = df.iloc[:].values

    # Value that you want to adjust
    num_clusters=4

    perform_k_means_clustering(X, num_clusters)

    #elbow_method_plot(X)

    print("Number of clusters is '{}'".format(num_clusters))



main()


