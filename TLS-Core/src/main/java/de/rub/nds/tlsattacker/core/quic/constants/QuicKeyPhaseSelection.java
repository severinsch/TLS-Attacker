/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.constants;

/**
 * Which generation of 1-RTT packet protection keys protects one outgoing packet (RFC 9001 section
 * 6).
 *
 * <p>The selection is made per packet rather than as a mode of the endpoint, because RFC 9001
 * section 6.4 states the rule it exists to break in terms of individual packets: "Packets with
 * higher packet numbers MUST be protected with either the same or newer packet protection keys than
 * packets with lower packet numbers." Only a single packet has to deviate for a peer to owe the
 * KEY_UPDATE_ERROR that the same section requires, and every other packet of the connection must
 * stay conforming for the peer's answer to mean anything.
 */
public enum QuicKeyPhaseSelection {

    /**
     * The generation this endpoint currently writes with. This is what a conforming endpoint always
     * uses, and what every packet uses unless the sender asks for something else.
     */
    CURRENT,

    /**
     * The generation replaced by the most recent key update, retained by the endpoint rather than
     * discarded.
     *
     * <p>RFC 9001 section 6.4 permits, but does not require, discarding it: "Keys used for
     * protecting packets can be discarded immediately after switching to newer keys." Selecting it
     * for a packet sent after an update produces a packet that carries the previous Key Phase bit
     * at a packet number above one already sent in the current phase, which is precisely what
     * section 6.4 tells a receiver to treat "as a connection error of type KEY_UPDATE_ERROR". There
     * is no conforming reason to send such a packet; there is no other way to find out whether a
     * peer implements the rule.
     *
     * <p>Requires a key update to have happened, so that a previous generation exists. Protecting a
     * packet with this selection before that fails rather than silently falling back to the current
     * generation, because a fallback would answer the question the packet was sent to ask.
     */
    PREVIOUS
}
