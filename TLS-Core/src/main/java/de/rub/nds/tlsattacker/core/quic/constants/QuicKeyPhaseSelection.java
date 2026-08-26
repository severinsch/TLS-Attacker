/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.constants;

/** Which generation of 1-RTT keys protects one outgoing packet (RFC 9001 section 6). */
public enum QuicKeyPhaseSelection {

    /** The generation this endpoint currently writes with; the default. */
    CURRENT,

    /**
     * The generation replaced by the last key update. A packet sent with it after the update is
     * what RFC 9001 section 6.4 requires a receiver to reject with KEY_UPDATE_ERROR. Fails if no
     * key update happened yet.
     */
    PREVIOUS
}
