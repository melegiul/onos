package org.onlab.graph;

import java.util.HashSet;
import java.util.Set;

/**
 * Implementation of the BFS algorithm.
 */
public class BreadthFirstSearch<V extends Vertex, E extends Edge<V>>
        extends AbstractGraphPathSearch<V, E> {

    @Override
    public Result<V, E> search(Graph<V, E> graph, V src, V dst,
                               EdgeWeight<V, E> weight) {
        checkArguments(graph, src, dst);

        // Prepare the graph result.
        DefaultResult result = new DefaultResult(src, dst);

        // Setup the starting frontier with the source as the sole vertex.
        Set<V> frontier = new HashSet<>();
        result.updateVertex(src, null, 0.0, true);
        frontier.add(src);

        boolean reachedEnd = false;
        while (!reachedEnd && !frontier.isEmpty()) {
            // Prepare the next frontier.
            Set<V> next = new HashSet<>();

            // Visit all vertexes in the current frontier.
            for (V vertex : frontier) {
                double cost = result.cost(vertex);

                // Visit all egress edges of the current frontier vertex.
                for (E edge : graph.getEdgesFrom(vertex)) {
                    V nextVertex = edge.dst();
                    if (!result.hasCost(nextVertex)) {
                        // If this vertex has not been visited yet, update it.
                        double newCost = cost + (weight == null ? 1.0 : weight.weight(edge));
                        result.updateVertex(nextVertex, edge, newCost, true);
                        // If we have reached our intended destination, bail.
                        if (nextVertex.equals(dst)) {
                            reachedEnd = true;
                            break;
                        }
                        next.add(nextVertex);
                    }

                    if (reachedEnd) {
                        break;
                    }
                }
            }

            // Promote the next frontier.
            frontier = next;
        }

        // Finally, but the paths on the search result and return.
        result.buildPaths();
        return result;
    }

}
