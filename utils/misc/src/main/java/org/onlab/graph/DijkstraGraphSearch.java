package org.onlab.graph;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Set;

/**
 * Dijkstra shortest-path graph search algorithm capable of finding not just
 * one, but all shortest paths between the source and destinations.
 */
public class DijkstraGraphSearch<V extends Vertex, E extends Edge<V>>
        extends AbstractGraphPathSearch<V, E> {

    @Override
    public Result<V, E> search(Graph<V, E> graph, V src, V dst,
                               EdgeWeight<V, E> weight) {
        checkArguments(graph, src, dst);

        // Use the default result to remember cumulative costs and parent
        // edges to each each respective vertex.
        DefaultResult result = new DefaultResult(src, dst);

        // Cost to reach the source vertex is 0 of course.
        result.updateVertex(src, null, 0.0, false);

        // Use the min priority queue to progressively find each nearest
        // vertex until we reach the desired destination, if one was given,
        // or until we reach all possible destinations.
        Heap<V> minQueue = createMinQueue(graph.getVertexes(),
                                          new PathCostComparator(result));
        while (!minQueue.isEmpty()) {
            // Get the nearest vertex
            V nearest = minQueue.extractExtreme();
            if (nearest.equals(dst)) {
                break;
            }

            // Find its cost and use it to determine if the vertex is reachable.
            double cost = result.cost(nearest);
            if (cost < Double.MAX_VALUE) {
                // If the vertex is reachable, relax all its egress edges.
                for (E e : graph.getEdgesFrom(nearest)) {
                    result.relaxEdge(e, cost, weight);
                }
            }

            // Re-prioritize the min queue.
            minQueue.heapify();
        }

        // Now construct a set of paths from the results.
        result.buildPaths();
        return result;
    }

    // Compares path weights using their accrued costs; used for sorting the
    // min priority queue.
    private final class PathCostComparator implements Comparator<V> {
        private final DefaultResult result;

        private PathCostComparator(DefaultResult result) {
            this.result = result;
        }

        @Override
        public int compare(V v1, V v2) {
            double delta = result.cost(v2) - result.cost(v1);
            return delta < 0 ? -1 : (delta > 0 ? 1 : 0);
        }
    }

    // Creates a min priority queue from the specified vertexes and comparator.
    private Heap<V> createMinQueue(Set<V> vertexes, Comparator<V> comparator) {
        return new Heap<>(new ArrayList<>(vertexes), comparator);
    }

}
