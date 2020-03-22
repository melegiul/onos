package org.onosproject.cli.net;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.FilteredConnectPoint;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.intent.Constraint;
import org.onosproject.net.intent.Intent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.FirewallIntent;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Installs firewall at multiple Ingress Connection Points.
 */
@Service
@Command(scope = "onos", name = "add-firewall-intent",
        description = "Installs firewall at multiple Ingress Connection Points")
public class AddFirewallIntentCommand extends FilterIntentCommand {

    @Argument(index = 0, name = "ingressDevices",
            description = "ingressDevice/Port..ingressDevice/Port",
            required = true, multiValued = true)
    @Completion(ConnectPointCompleter.class)
    String[] deviceStrings = null;

    @Override
    protected void doExecute() {
        IntentService service = get(IntentService.class);

        if (deviceStrings.length < 1) {
            return;
        }

        /*String egressDeviceString = deviceStrings[deviceStrings.length - 1];
        FilteredConnectPoint egress = new FilteredConnectPoint(ConnectPoint.deviceConnectPoint(egressDeviceString));*/

        Set<FilteredConnectPoint> ingressPoints = new HashSet<>();
        for (int index = 0; index < deviceStrings.length; index++) {
            String ingressDeviceString = deviceStrings[index];
            ConnectPoint ingress = ConnectPoint.deviceConnectPoint(ingressDeviceString);
            ingressPoints.add(new FilteredConnectPoint(ingress));
        }

        TrafficSelector selector = buildTrafficSelector();
        TrafficTreatment treatment = buildTrafficTreatment();
        List<Constraint> constraints = buildConstraints();

        Intent intent = FirewallIntent.builder()
                .appId(appId())
                .key(key())
                .selector(selector)
                .treatment(treatment)
                .filteredIngressPoints(ingressPoints)
                .constraints(constraints)
                .priority(priority())
                .resourceGroup(resourceGroup())
                .build();
        service.submit(intent);
        print("Firewall intent submitted:\n%s", intent.toString());
    }
}