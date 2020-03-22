package org.onosproject.net.intent.impl.compiler;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.intent.Intent;
import org.onosproject.net.intent.IntentException;
import org.onosproject.net.intent.LinkCollectionIntent;
import org.onosproject.net.intent.FirewallIntent;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.onosproject.net.intent.constraint.PartialFailureConstraint.intentAllowsPartialFailure;


/**
 * An intent compiler for
 * {@link org.onosproject.net.intent.MultiPointToSinglePointIntent}.
 */
@Component(immediate = true)
public class FirewallIntentCompiler
        extends ConnectivityIntentCompiler<FirewallIntent> {

    @Activate
    public void activate() {
        intentManager.registerCompiler(FirewallIntent.class, this);
    }

    @Deactivate
    public void deactivate() {
        intentManager.unregisterCompiler(FirewallIntent.class);
    }

    @Override
    public List<Intent> compile(FirewallIntent intent, List<Intent> installable) {
        Map<DeviceId, Link> links = new HashMap<>();

        Intent result = LinkCollectionIntent.builder()
                .appId(intent.appId())
                .key(intent.key())
                .treatment(intent.treatment())
                .selector(intent.selector())
                .links(ImmutableSet.of())
                .filteredIngressPoints(intent.filteredIngressPoints())
                .priority(intent.priority())
                .constraints(intent.constraints())
                .cost(1)
                .resourceGroup(intent.resourceGroup())
                .isFilterIntent(true)
                .build();

        return Collections.singletonList(result);
    }
}
