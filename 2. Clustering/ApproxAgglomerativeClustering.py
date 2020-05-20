import logging
import operator
import time
import os

import matplotlib.cm as cm
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd



logger = logging.getLogger(os.path.splitext(os.path.basename(__file__))[0])
logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)

MAX_DISTANCE = 5000


MAX_DISTANCE_FROM_PROTOTYPE = .01

MAX_CLUSTER_DISTANCE = .7


class ClusterNode(object):

    def __init__(self, data_point, nearest_prototype_cluster_node=None):
        # data point
        self._data_point = data_point

        self._assigned_cluster = None

        # prototype node this node is associated with;
        self._nearest_prototype_cluster_node = nearest_prototype_cluster_node

    @staticmethod
    def distance(node_a, node_b):
        node_a_data_point = node_a.data_point
        node_b_data_point = node_b.data_point

        distance = np.sqrt( (node_a_data_point[0]-node_b_data_point[0])**2 + (node_a_data_point[1]-node_b_data_point[1])**2 )

        return distance

    @staticmethod
    def similarity(node_a, node_b):
        return 1 / (1 + ClusterNode.distance(node_a, node_b))

    @property
    def assigned_cluster(self):
        """
         Cluster that this node belongs to
        :return:
        """
        return self._assigned_cluster

    @assigned_cluster.setter
    def assigned_cluster(self, value):
        self._assigned_cluster = value

    @property
    def cluster_id(self):
        if self._assigned_cluster is None:
            return None

        return self._assigned_cluster.cluster_id

    @property
    def is_prototype(self):
        return self == self._nearest_prototype_cluster_node

    @property
    def data_point(self):
        return self._data_point

    @property
    def nearest_prototype_cluster_node(self):
        return self._nearest_prototype_cluster_node

    @nearest_prototype_cluster_node.setter
    def nearest_prototype_cluster_node(self, value):
        self._nearest_prototype_cluster_node = value


class Cluster(object):

    def __init__(self, cluster_node_list=[]):

        self._cluster_id = id(self)

        self._cluster_node_list = []

        for cluster_node in cluster_node_list:
            self.add_node_to_cluster(cluster_node)

    def add_node_to_cluster(self, cluster_node):

        # Update node's cluster assignment
        cluster_node.assigned_cluster = self

        # Add node to cluster's node list
        self._cluster_node_list.append(cluster_node)

    def merge_cluster(self, cluster_2_merge):

        for cluster_2_merge_node in cluster_2_merge.cluster_nodes:
            self.add_node_to_cluster(cluster_2_merge_node)

    @property
    def cluster_nodes(self):

        for cluster_node in self._cluster_node_list:
            yield cluster_node

    @staticmethod
    def complete_linkage_distance(cluster_a, cluster_b):

        """
         Computes the complete linkage distance of two clusters
        :param cluster_a:
        :param cluster_b:
        :return:
        """

        # Note: Complete linkage computes the maximum distance of a pair of nodes from cluster a
        #       and cluster b

        max_distance = 0

        list_a = cluster_a._cluster_node_list
        list_b = cluster_b._cluster_node_list

        dist_list = []
        for i in range(len(list_a)):
            dist_list.append(ClusterNode.distance(list_a[i], list_b[i]))

        max_distance = max(dist_list)
        return max_distance

    @property
    def cluster_id(self):
        return self._cluster_id


class ApproxAgglomerativeClustering(object):

    def __init__(self, data_set=None):

        self._data_set = data_set

        self._cluster_node_list = []

        self._cluster_list = []

    def load_dataset_from_file(self, file_path):

        # Load the dataset from file
        df = pd.read_csv(file_path, header=None)

        # get all of the points from the dataset as an array of n-dimensional vectors
        X = df.iloc[:].values

        # Standardize the data set
        X_std = np.copy(X)
        X_std[:, 0] = (X_std[:, 0] - X_std[:, 0].mean()) / (X_std[:, 0].std())
        X_std[:, 1] = (X_std[:, 1] - X_std[:, 1].mean()) / (X_std[:, 1].std())

        self._data_set = X_std

        # Create the cluster node list
        self._cluster_node_list = [ClusterNode(data_point) for data_point in self._data_set]

        return self._cluster_node_list

    def perform_clustering(self):

        # Step 1: Determine the prototypes
        prototype_list = self._get_prototypes()

        # Step 2: Cluster Prototypes
        self._cluster_list = self.cluster_nodes(prototype_list)

        counter = 0

        number_nodes = len(self._cluster_node_list)

        # Step 3: Propagate Cluster assignments to nearest prototype
        for cluster_node in self._cluster_node_list:

            counter += 1

            if cluster_node.is_prototype:
                continue

            # Get cluster assignment from nearest prototype
            nearest_prototype_assigned_cluster = cluster_node.nearest_prototype_cluster_node.assigned_cluster

            # Add cluster node to cluster
            nearest_prototype_assigned_cluster.add_node_to_cluster(cluster_node)

            if counter % 10 == 0:
                print("\n[ {}/{} ] Cluster node {} assigned to cluster {}".format(counter, number_nodes,
                                                                                  repr(cluster_node.data_point),
                                                                                  nearest_prototype_assigned_cluster.cluster_id))

    def cluster_nodes(self, cluster_node_list):

        # Note: Initially, every cluster node is its own cluster in agglomerative hierarchical clustering
        cluster_list = [Cluster([cluster_node]) for cluster_node in cluster_node_list]

        while True:

            print("\n**** Current number of clusters: {}*****".format(len(cluster_list)))

            # Step 1: Compute distances of the clusters
            cluster_distance_dict = self._compute_cluster_distances(cluster_list)

            # Step 2:  Get the minimum cluster distances

            (min_cluster_pair, min_cluster_distance_value) = self.get_min_cluster_distance(cluster_distance_dict)

            if len(min_cluster_pair) <= 1:
                logger.warning("get_min_cluster_distance() has not been implemented correctly. Expecting a tuple of size 2"
                               "where the elements of the tuple are the two clusters that have the minimum distance")

                break


            print(
                "Minimum Distance of {} is between current cluster {} and cluster {}".format(min_cluster_distance_value,
                                                                                             min_cluster_pair[
                                                                                                 0].cluster_id,
                                                                                             min_cluster_pair[
                                                                                                 1].cluster_id))

            if min_cluster_distance_value >= MAX_CLUSTER_DISTANCE:
                break

            # Step 3: Merge the min pair clusters
            min_cluster_a = min_cluster_pair[0]
            min_cluster_b = min_cluster_pair[1]

            min_cluster_a.merge_cluster(min_cluster_b)

            print("Merging cluster {} into cluster {}; Distance: {}".format(min_cluster_b.cluster_id,
                                                                            min_cluster_a.cluster_id,
                                                                            min_cluster_distance_value))
            cluster_list.remove(min_cluster_b)

        return cluster_list

    def _compute_cluster_distances(self, cluster_list):

        cluster_distance_dict = dict()
        for cluster_a in cluster_list:

            cluster_distance_dict[cluster_a] = {}

            for cluster_b in cluster_list:
                distance = Cluster.complete_linkage_distance(cluster_a, cluster_b)

                # print("Distance between current cluster {} and cluster {} is {}".format(cluster_a.cluster_id,
                #                                                                         cluster_b.cluster_id,
                #                                                                         distance))
                cluster_distance_dict[cluster_a][cluster_b] = distance

        return cluster_distance_dict

    def plot(self):

        num_clusters = len(self._cluster_list)

        # Plotting
        plt.figure()
        colors = cm.rainbow(np.linspace(0, 1, num_clusters))

        cluster_index = 0

        for color, cluster in zip(colors, self._cluster_list):

            X = []
            Y = []

            for cluster_node in cluster.cluster_nodes:
                x = cluster_node.data_point[0]
                y = cluster_node.data_point[1]

                X.append(x)
                Y.append(y)

            plt.scatter(X, Y, s=50, c=color, marker='o', label="cluster {}".format(cluster_index + 1))
            cluster_index += 1

        plt.legend(scatterpoints=1)
        plt.grid()
        plt.show()

        pass

    def _get_prototypes(self):

        prototype_set = set()

        prototype_distance_map = dict()

        # Initalize prototype distance map, where the key is the prototype and the
        # value is that prototypes distance.
        # Note: The distance will be initialized to MAX_DISTANCE, which is the maximum distance
        prototype_distance_map = {key: value for (key, value) in
                                  [(cluster_node, MAX_DISTANCE) for cluster_node in self._cluster_node_list]}

        pass

        (curr_max_distance_cluster_node, current_max_distance_value) = self.compute_max_distance_from_prototype(
            prototype_distance_map)
        while True:

            print("\nCurrent max distance: {}".format(current_max_distance_value))

            # All of the elements are less than 'MAX_DISTANCE_FROM_PROTOTYPE' away from a prototype
            if current_max_distance_value < MAX_DISTANCE_FROM_PROTOTYPE:
                break

            for cluster_node in self._cluster_node_list:

                if cluster_node == curr_max_distance_cluster_node or cluster_node in prototype_set:
                    continue

                # if the current distance from a prototype is greater than that of the curr_max_distance_analysis_report,
                # then we'll use the curr_max_distance_analysis_reports distance
                dist_from_curr_max_dist_cluster_node = ClusterNode.distance(curr_max_distance_cluster_node,
                                                                            cluster_node)

                if prototype_distance_map[cluster_node] > dist_from_curr_max_dist_cluster_node:
                    prototype_distance_map[cluster_node] = dist_from_curr_max_dist_cluster_node

                    # update the clusters  nodes nearest prototype
                    cluster_node.nearest_prototype_cluster_node = curr_max_distance_cluster_node

            # The current prototype candidate is its own prototype
            curr_max_distance_cluster_node.nearest_prototype_cluster_node = curr_max_distance_cluster_node

            # Add the current_prototype candidate to the prototype list
            prototype_set.add(curr_max_distance_cluster_node)

            print("(Current total:{}) Added the following cluster node as prototype: {}".format(len(prototype_set),
                                                                                                curr_max_distance_cluster_node.data_point))

            # Since the candidate is a prototype, its distance to a prototype is 0 because it is a prototype
            prototype_distance_map[curr_max_distance_cluster_node] = 0

            # Find the next potential prototype candidate
            (curr_max_distance_cluster_node, current_max_distance_value) = self.compute_max_distance_from_prototype(
                prototype_distance_map)

        return prototype_set

    @staticmethod
    def compute_max_distance_from_prototype(prototype_distance_map):

        """ Returns (key, value) tuple where the value is the max value in dictionary

        :param prototype_distance_map:
        :return: (key, value) tuple where the value is the max value in dictionary
        """

        max_distance = max(prototype_distance_map.items(), key=operator.itemgetter(1))

        return max_distance

    @staticmethod
    def get_min_cluster_distance(cluster_distance_dict):

        """
        :param cluster_distance_dict: 2-dimmensional dictionary that stores the distance of a pair of cluster nodes
                                      Example: To retrieve the distance of cluster_a and cluster, do the following:
                                               cluster_distance = cluster_distance_dict[cluster_a][cluster_b]

        :return: A tuple, where the first element of tuple is itself a tuple of the pair of clusters who have the smallest distance.
                 The second element of tuple is the distance of those two tuples
        """

        min_cluster_distance = 0

        min_cluster_pair = ()

        logger.warning(
            "@Todo: return a tuple where the first element is the a pair of clusters who has the minimal distance "
            "and the second element of tuple is the distance")

        return (min_cluster_pair, min_cluster_distance)

    @property
    def cluster_list(self):
        return self._cluster_list


def test_harness():
    approx_clustering = ApproxAgglomerativeClustering()

    # Load the dataset
    approx_clustering.load_dataset_from_file("lab1bsamples_large.csv")

    start_time = time.time()
    approx_clustering.perform_clustering()
    elapsed_time = time.time() - start_time

    print("\nRuntime: {} seconds".format(elapsed_time))

    approx_clustering.plot()

    pass


if __name__ == "__main__":
    test_harness()
