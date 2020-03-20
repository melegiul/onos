package org.onosproject.cli.net;

import org.onlab.packet.ICMP;

/**
 * Known values for ICMP type field that can be supplied to the CLI.
 */
public enum IcmpType {

    ECHO_REPLY(ICMP.TYPE_ECHO_REPLY),

    DEST_UNREACH(ICMP.DEST_UNREACH),

    ECHO_REQUEST(ICMP.TYPE_ECHO_REQUEST),

    TIME_EXCEED(ICMP.TIME_EXCEED);

    private byte value;

    /**
     * Constructs an IcmpType with the given value.
     *
     * @param value value to use when this IcmpType is seen
     */
    private IcmpType(byte value) {
        this.value = value;
    }

    /**
     * Gets the value to use for this IcmpType.
     *
     * @return short value to use for this IcmpType
     */
    public byte value() {
        return this.value;
    }

    /**
     * Parse a string input that could contain an IcmpType value.
     *
     * @param input the input string to parse
     * @return the numeric value of the parsed ICMP type
     * @throws IllegalArgumentException if the input string does not contain a
     * value that can be parsed into an ICMPv6 type
     */
    public static byte parseFromString(String input) {
        try {
            return valueOf(input).value();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Icmp6Type value must be either a string type name");
        }
    }
}
