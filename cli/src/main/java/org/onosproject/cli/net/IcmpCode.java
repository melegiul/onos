package org.onosproject.cli.net;

import org.onlab.packet.ICMP;
import org.onlab.packet.ICMP6;

/**
 * Known values for ICMPv6 code field that can be supplied to the CLI.
 */
public enum IcmpCode {

    // Code for ECHO_REPLY
    ECHO_REPLY(ICMP.CODE_ECHO_REPLY),
    // Code for ECHO_REQUEST
    ECHO_REQUEST(ICMP.CODE_ECHO_REQEUST),
    // Code for TIME_EXCEED
    HOP_LIMIT_EXCEED(ICMP.HOP_LIMIT_EXCEED);

    private byte value;

    /**
     * Constructs an IcmpCode with the given value.
     *
     * @param value value to use when this IcmpCode is seen
     */
    private IcmpCode(byte value) {
        this.value = value;
    }

    /**
     * Gets the value to use for this IcmpCode.
     *
     * @return short value to use for this IcmpCode
     */
    public byte value() {
        return this.value;
    }

    /**
     * Parse a string input that could contain an IcmpCode value.
     *
     * @param input the input string to parse
     * @return the numeric value of the parsed ICMPv6 code
     * @throws IllegalArgumentException if the input string does not contain a
     * value that can be parsed into an ICMPv6 code
     */
    public static byte parseFromString(String input) {
        try {
            return valueOf(input).value();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Icmp6Code value must be either a string code name");
        }
    }
}
