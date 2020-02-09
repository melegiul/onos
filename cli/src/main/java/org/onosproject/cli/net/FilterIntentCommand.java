package org.onosproject.cli.net;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TpPort;
import org.onlab.packet.VlanId;
import org.onlab.util.Bandwidth;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.cli.app.AllApplicationNamesCompleter;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.EncapsulationType;
import org.onosproject.net.PortNumber;
import org.onosproject.net.ResourceGroup;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.intent.Constraint;
import org.onosproject.net.intent.Intent;
import org.onosproject.net.intent.Key;
import org.onosproject.net.intent.constraint.BandwidthConstraint;
import org.onosproject.net.intent.constraint.DomainConstraint;
import org.onosproject.net.intent.constraint.EncapsulationConstraint;
import org.onosproject.net.intent.constraint.HashedPathSelectionConstraint;
import org.onosproject.net.intent.constraint.LatencyConstraint;
import org.onosproject.net.intent.constraint.PartialFailureConstraint;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.LinkedList;
import java.util.List;

import static com.google.common.base.Strings.isNullOrEmpty;
import static org.onosproject.net.flow.DefaultTrafficTreatment.builder;

/**
 * Base class for command line operations for filter intents.
 */
public abstract class FilterIntentCommand extends AbstractShellCommand {

    // Selectors
    @Option(name = "-s", aliases = "--ethSrc", description = "Source MAC Address",
            required = false, multiValued = false)
    private String srcMacString = null;

    @Option(name = "-d", aliases = "--ethDst", description = "Destination MAC Address",
            required = false, multiValued = false)
    private String dstMacString = null;

    @Option(name = "-t", aliases = "--ethType", description = "Ethernet Type",
            required = false, multiValued = false)
    @Completion(EthTypeCompleter.class)
    private String ethTypeString = null;

    @Option(name = "-v", aliases = "--vlan", description = "VLAN ID",
            required = false, multiValued = false)
    private String vlanString = null;

    @Option(name = "--ipProto", description = "IP Protocol",
            required = false, multiValued = false)
    @Completion(IpProtocolCompleter.class)
    private String ipProtoString = null;

    @Option(name = "--ipSrc", description = "Source IP Prefix",
            required = false, multiValued = false)
    private String srcIpString = null;

    @Option(name = "--ipDst", description = "Destination IP Prefix",
            required = false, multiValued = false)
    private String dstIpString = null;

    @Option(name = "--fLabel", description = "IPv6 Flow Label",
            required = false, multiValued = false)
    private String fLabelString = null;

    @Option(name = "--icmp6Type", description = "ICMPv6 Type",
            required = false, multiValued = false)
    @Completion(Icmp6TypeCompleter.class)
    private String icmp6TypeString = null;

    @Option(name = "--icmp6Code", description = "ICMPv6 Code",
            required = false, multiValued = false)
    @Completion(Icmp6CodeCompleter.class)
    private String icmp6CodeString = null;

    @Option(name = "--ndTarget", description = "IPv6 Neighbor Discovery Target Address",
            required = false, multiValued = false)
    private String ndTargetString = null;

    @Option(name = "--ndSLL", description = "IPv6 Neighbor Discovery Source Link-Layer",
            required = false, multiValued = false)
    private String ndSllString = null;

    @Option(name = "--ndTLL", description = "IPv6 Neighbor Discovery Target Link-Layer",
            required = false, multiValued = false)
    private String ndTllString = null;

    @Option(name = "--tcpSrc", description = "Source TCP Port",
            required = false, multiValued = false)
    private String srcTcpString = null;

    @Option(name = "--tcpDst", description = "Destination TCP Port",
            required = false, multiValued = false)
    private String dstTcpString = null;

    @Option(name = "--extHdr", description = "IPv6 Extension Header Pseudo-field",
            required = false, multiValued = true)
    @Completion(ExtHeaderCompleter.class)
    private List<String> extHdrStringList = null;

    @Option(name = "-a", aliases = "--appId", description = "Application Id",
            required = false, multiValued = false)
    @Completion(AllApplicationNamesCompleter.class)
    private String appId = null;

    @Option(name = "-k", aliases = "--key", description = "Intent Key",
            required = false, multiValued = false)
    private String intentKey = null;

    // Priorities
    @Option(name = "-p", aliases = "--priority", description = "Priority",
            required = false, multiValued = false)
    private int priority = Intent.DEFAULT_INTENT_PRIORITY;

    // Constraints
    @Option(name = "--partial", description = "Allow partial installation",
            required = false, multiValued = false)
    private boolean partial = false;

    @Option(name = "--domains", description = "Allow domain delegation",
            required = false, multiValued = false)
    private boolean domains = false;

    // Resource Group
    @Option(name = "-r", aliases = "--resourceGroup", description = "Resource Group Id",
            required = false, multiValued = false)
    private String resourceGroupId = null;


    /**
     * Constructs a traffic selector based on the command line arguments
     * presented to the command.
     * @return traffic selector
     */
    protected TrafficSelector buildTrafficSelector() {
        IpPrefix srcIpPrefix = null;
        IpPrefix dstIpPrefix = null;

        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();

        if (!isNullOrEmpty(srcIpString)) {
            srcIpPrefix = IpPrefix.valueOf(srcIpString);
            if (srcIpPrefix.isIp4()) {
                selectorBuilder.matchIPSrc(srcIpPrefix);
            } else {
                selectorBuilder.matchIPv6Src(srcIpPrefix);
            }
        }

        if (!isNullOrEmpty(dstIpString)) {
            dstIpPrefix = IpPrefix.valueOf(dstIpString);
            if (dstIpPrefix.isIp4()) {
                selectorBuilder.matchIPDst(dstIpPrefix);
            } else {
                selectorBuilder.matchIPv6Dst(dstIpPrefix);
            }
        }

        if ((srcIpPrefix != null) && (dstIpPrefix != null) &&
                (srcIpPrefix.version() != dstIpPrefix.version())) {
            // ERROR: IP src/dst version mismatch
            throw new IllegalArgumentException(
                    "IP source and destination version mismatch");
        }

        //
        // Set the default EthType based on the IP version if the matching
        // source or destination IP prefixes.
        //
        Short ethType = null;
        if ((srcIpPrefix != null) && srcIpPrefix.isIp6()) {
            ethType = EthType.IPV6.value();
        }
        if ((dstIpPrefix != null) && dstIpPrefix.isIp6()) {
            ethType = EthType.IPV6.value();
        }
        if (!isNullOrEmpty(ethTypeString)) {
            ethType = EthType.parseFromString(ethTypeString);
        }
        if (ethType != null) {
            selectorBuilder.matchEthType(ethType);
        }
        if (!isNullOrEmpty(vlanString)) {
            selectorBuilder.matchVlanId(VlanId.vlanId(Short.parseShort(vlanString)));
        }
        if (!isNullOrEmpty(srcMacString)) {
            selectorBuilder.matchEthSrc(MacAddress.valueOf(srcMacString));
        }

        if (!isNullOrEmpty(dstMacString)) {
            selectorBuilder.matchEthDst(MacAddress.valueOf(dstMacString));
        }

        if (!isNullOrEmpty(ipProtoString)) {
            short ipProtoShort = IpProtocol.parseFromString(ipProtoString);
            selectorBuilder.matchIPProtocol((byte) ipProtoShort);
        }

        if (!isNullOrEmpty(fLabelString)) {
            selectorBuilder.matchIPv6FlowLabel(Integer.parseInt(fLabelString));
        }

        if (!isNullOrEmpty(icmp6TypeString)) {
            byte icmp6Type = Icmp6Type.parseFromString(icmp6TypeString);
            selectorBuilder.matchIcmpv6Type(icmp6Type);
        }

        if (!isNullOrEmpty(icmp6CodeString)) {
            byte icmp6Code = Icmp6Code.parseFromString(icmp6CodeString);
            selectorBuilder.matchIcmpv6Code(icmp6Code);
        }

        if (!isNullOrEmpty(ndTargetString)) {
            selectorBuilder.matchIPv6NDTargetAddress(Ip6Address.valueOf(ndTargetString));
        }

        if (!isNullOrEmpty(ndSllString)) {
            selectorBuilder.matchIPv6NDSourceLinkLayerAddress(MacAddress.valueOf(ndSllString));
        }

        if (!isNullOrEmpty(ndTllString)) {
            selectorBuilder.matchIPv6NDTargetLinkLayerAddress(MacAddress.valueOf(ndTllString));
        }

        if (!isNullOrEmpty(srcTcpString)) {
            selectorBuilder.matchTcpSrc(TpPort.tpPort(Integer.parseInt(srcTcpString)));
        }

        if (!isNullOrEmpty(dstTcpString)) {
            selectorBuilder.matchTcpDst(TpPort.tpPort(Integer.parseInt(dstTcpString)));
        }

        if (extHdrStringList != null) {
            short extHdr = 0;
            for (String extHdrString : extHdrStringList) {
                extHdr = (short) (extHdr | ExtHeader.parseFromString(extHdrString));
            }
            selectorBuilder.matchIPv6ExthdrFlags(extHdr);
        }

        return selectorBuilder.build();
    }

    /**
     * Generates a empty Treatment for dropping all packages
     * matching the selected criteria
     *
     * @return traffic treatment
     */
    protected TrafficTreatment buildTrafficTreatment() {
        return DefaultTrafficTreatment.emptyTreatment();
    }

    /**
     * Builds the constraint list for this command based on the command line
     * parameters.
     *
     * @return List of constraint objects describing the constraints requested
     */
    protected List<Constraint> buildConstraints() {
        final List<Constraint> constraints = new LinkedList<>();

        // Check for partial failure specification
        if (partial) {
            constraints.add(new PartialFailureConstraint());
        }

        // Check for domain processing
        if (domains) {
            constraints.add(DomainConstraint.domain());
        }

        return constraints;
    }

    @Override
    protected ApplicationId appId() {
        ApplicationId appIdForIntent;
        if (appId == null) {
            appIdForIntent = super.appId();
        } else {
            CoreService service = get(CoreService.class);
            appIdForIntent = service.getAppId(appId);
        }
        return appIdForIntent;
    }

    protected ResourceGroup resourceGroup() {
        if (resourceGroupId != null) {
            if (resourceGroupId.toLowerCase().startsWith("0x")) {
                return ResourceGroup.of(Long.parseUnsignedLong(resourceGroupId.substring(2), 16));
            } else {
                return ResourceGroup.of(Long.parseUnsignedLong(resourceGroupId));
            }
        } else {
            return null;
        }
    }

    /**
     * Creates a key for an intent based on command line arguments.  If a key
     * has been specified, it is returned.  If no key is specified, null
     * is returned.
     *
     * @return intent key if specified, null otherwise
     */
    protected Key key() {
        Key key = null;

        if (intentKey != null) {
            key = Key.of(intentKey, appId());
        }
        return key;
    }

    /**
     * Gets the priority to use for the intent.
     *
     * @return priority
     */
    protected int priority() {
        return priority;
    }
}
