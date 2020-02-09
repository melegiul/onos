/*
 * Copyright 2014-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.onosproject.net.intent;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.annotations.Beta;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.FilteredConnectPoint;
import org.onosproject.net.Link;
import org.onosproject.net.NetworkResource;
import org.onosproject.net.ResourceGroup;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;

import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableSet;
import org.slf4j.Logger;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Abstraction of a connectivity intent that is implemented by a set of path
 * segments.
 */
@Beta
public final class LinkCollectionIntent extends ConnectivityIntent {

    private final Set<Link> links;

    private final Set<FilteredConnectPoint> ingressPoints;
    private final Set<FilteredConnectPoint> egressPoints;
    private final boolean egressTreatmentFlag;
    private final double cost;
    private static final int DEFAULT_COST = 1;

    private final boolean isFilterIntent;

    /**
     * Creates a new actionable intent capable of funneling the selected
     * traffic along the specified convergent tree and out the given egress
     * point satisfying the specified constraints.
     *
     * @param appId       application identifier
     * @param key         key to use for the intent
     * @param selector    traffic match
     * @param treatment   action
     * @param links       traversed links
     * @param ingressPoints filtered ingress points
     * @param egressPoints filtered egress points
     * @param constraints optional list of constraints
     * @param priority    priority to use for the flows generated by this intent
     * @param egressTreatment true if treatment should be applied by the egress device
     * @param cost the cost of the links
     * @param resourceGroup resource group for this intent
     * @throws NullPointerException {@code path} is null
     */
    private LinkCollectionIntent(ApplicationId appId,
                                 Key key,
                                 TrafficSelector selector,
                                 TrafficTreatment treatment,
                                 Collection<NetworkResource> resources,
                                 Set<Link> links,
                                 Set<FilteredConnectPoint> ingressPoints,
                                 Set<FilteredConnectPoint> egressPoints,
                                 List<Constraint> constraints,
                                 int priority,
                                 boolean egressTreatment,
                                 double cost,
                                 ResourceGroup resourceGroup,
                                 boolean isFilterIntent) {
        super(appId, key, resources(resources, links), selector, treatment, constraints, priority, resourceGroup);
        this.links = links;
        this.ingressPoints = ingressPoints;
        this.egressPoints = egressPoints;
        this.egressTreatmentFlag = egressTreatment;
        this.cost = cost;
        this.isFilterIntent = isFilterIntent;
    }

    /**
     * Constructor for serializer.
     */
    protected LinkCollectionIntent() {
        this.links = null;
        this.ingressPoints = null;
        this.egressPoints = null;
        this.egressTreatmentFlag = false;
        this.cost = DEFAULT_COST;
        isFilterIntent = false;
    }

    /**
     * Returns a new link collection intent builder. The application id,
     * ingress point and egress points are required fields.  If they are
     * not set by calls to the appropriate methods, an exception will
     * be thrown.
     *
     * @return single point to multi point builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder of a single point to multi point intent.
     */
    public static final class Builder extends ConnectivityIntent.Builder {
        private final Logger log = getLogger(getClass());
        private Set<Link> links;
        private Set<FilteredConnectPoint> ingressPoints;
        private Set<FilteredConnectPoint> egressPoints;
        private boolean egressTreatmentFlag;
        private double cost;

        private boolean isFilterIntent = false;


        private Builder() {
            // Hide constructor
        }

        @Override
        public Builder appId(ApplicationId appId) {
            return (Builder) super.appId(appId);
        }

        @Override
        public Builder key(Key key) {
            return (Builder) super.key(key);
        }

        @Override
        public Builder selector(TrafficSelector selector) {
            return (Builder) super.selector(selector);
        }

        @Override
        public Builder treatment(TrafficTreatment treatment) {
            return (Builder) super.treatment(treatment);
        }

        @Override
        public Builder constraints(List<Constraint> constraints) {
            return (Builder) super.constraints(constraints);
        }

        @Override
        public Builder priority(int priority) {
            return (Builder) super.priority(priority);
        }

        @Override
        public Builder resources(Collection<NetworkResource> resources) {
            return (Builder) super.resources(resources);
        }

        @Override
        public Builder resourceGroup(ResourceGroup resourceGroup) {
            return (Builder) super.resourceGroup(resourceGroup);
        }

        /**
         * Sets the filtered ingress point of the single point to multi point intent
         * that will be built.
         *
         * @param ingressPoints ingress connect points
         * @return this builder
         */
        public Builder filteredIngressPoints(Set<FilteredConnectPoint> ingressPoints) {
            this.ingressPoints = ImmutableSet.copyOf(ingressPoints);
            return this;
        }

        /**
         * Sets the filtered egress points of the single point to multi point intent
         * that will be built.
         *
         * @param egressPoints egress connect points
         * @return this builder
         */
        public Builder filteredEgressPoints(Set<FilteredConnectPoint> egressPoints) {
            this.egressPoints = ImmutableSet.copyOf(egressPoints);
            return this;
        }

        /**
         * Sets the links of the link collection intent
         * that will be built.
         *
         * @param links links for the intent
         * @return this builder
         */
        public Builder links(Set<Link> links) {
            this.links = ImmutableSet.copyOf(links);
            return this;
        }

        /**
         * Sets the intent to apply treatment at the egress rather than the
         * ingress.
         *
         * @param treatmentOnEgress true applies treatment on egress device
         * @return this builder
         */
        public Builder applyTreatmentOnEgress(boolean treatmentOnEgress) {
            this.egressTreatmentFlag = treatmentOnEgress;
            return this;
        }

        /**
         * Sets the cost for the links of the Intent.
         *
         * @param cost the cost of the links
         * @return this builder
         */
        public Builder cost(double cost) {
            this.cost = cost;
            return this;
        }

        /*
        * marks filter intents
        * @param filter mark
        * @return this builder
        */

        public Builder isFilterIntent(boolean isFilterIntent) {
            this.isFilterIntent = isFilterIntent;
            return this;
        }

        /**
         * Builds a single point to multi point intent from the
         * accumulated parameters.
         *
         * @return point to point intent
         */
        public LinkCollectionIntent build() {

            return new LinkCollectionIntent(
                    appId,
                    key,
                    selector,
                    treatment,
                    resources,
                    links,
                    ingressPoints,
                    egressPoints,
                    constraints,
                    priority,
                    egressTreatmentFlag,
                    cost,
                    resourceGroup,
                    isFilterIntent
            );
        }
    }

    /**
     * Returns the set of links that represent the network connections needed
     * by this intent.
     *
     * @return Set of links for the network hops needed by this intent
     */
    public Set<Link> links() {
        return links;
    }

    /**
     * Returns the ingress points of the intent.
     *
     * @return the ingress points
     */
    public Set<ConnectPoint> ingressPoints() {
        if (this.ingressPoints == null) {
            return null;
        }
        return ingressPoints.stream()
                .map(FilteredConnectPoint::connectPoint)
                .collect(Collectors.toSet());
    }

    /**
     * Returns the egress points of the intent.
     *
     * @return the egress points
     */
    public Set<ConnectPoint> egressPoints() {
        if (this.egressPoints == null) {
            return null;
        }
        return egressPoints.stream()
                .map(FilteredConnectPoint::connectPoint)
                .collect(Collectors.toSet());
    }

    /**
     * Returns the filtered ingress points of the intent.
     *
     * @return the ingress points
     */
    public Set<FilteredConnectPoint> filteredIngressPoints() {
        return ingressPoints;
    }

    /**
     * Returns the egress points of the intent.
     *
     * @return the egress points
     */
    public Set<FilteredConnectPoint> filteredEgressPoints() {
        return egressPoints;
    }

    /**
     * Returns whether treatment should be applied on egress.
     *
     * @return the egress treatment flag
     */
    public boolean applyTreatmentOnEgress() {
        return egressTreatmentFlag;
    }

    /**
     * Returns the cost of the links of this intent.
     *
     * @return the cost of the links
     */
    public double cost() {
        return cost;
    }

    /*
    * return the filter intent mark
    *
    * @return the filter intent mark
    */
    public boolean isFilterIntent() {return isFilterIntent;}

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(getClass())
                .add("id", id())
                .add("key", key())
                .add("appId", appId())
                .add("priority", priority())
                .add("resources", resources())
                .add("selector", selector())
                .add("treatment", treatment())
                .add("links", links())
                .add("ingress", ingressPoints())
                .add("egress", egressPoints())
                .add("treatmentOnEgress", applyTreatmentOnEgress())
                .add("resourceGroup", resourceGroup())
                .add("cost", cost())
                .toString();
    }
}
