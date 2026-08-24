/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.constants;

public class MiscRfcConstants {

    public static final int SMALLEST_MAX_DATAGRAM_SIZE = 1200;

    public static final int MAX_ENCODED_PACKETNUMBER_LENGTH = 4;

    public static final int HEADER_PROTECTION_SAMPLE_LENGTH = 16;

    /**
     * Maximum length of a connection ID in QUIC version 1, in bytes (RFC 9000 section 17.2). A
     * zero-length connection ID is also permitted, so valid lengths span 0..20.
     */
    public static final int MAX_CONNECTION_ID_LENGTH = 20;

    /**
     * The Key Phase bit of a short header's first byte (RFC 9000 section 17.3.1). It indicates
     * which generation of 1-RTT packet protection keys protects the packet: RFC 9001 section 6 sets
     * it to 0 for the first set of 1-RTT keys and toggles it on every key update.
     */
    public static final int KEY_PHASE_BIT = 0x04;

    // TODO: actually rfc constant?
    public static final int AUTH_TAG_LENGTH = 16;

    public static final int RETRY_TOKEN_INTEGRITY_TAG_LENGTH = 16;

    public static final int STATELESS_RESET_TOKEN_LENGTH = 16;
}
