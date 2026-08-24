/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.packet;

import de.rub.nds.tlsattacker.core.quic.constants.MiscRfcConstants;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.packet.OneRTTPacket;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class OneRTTPacketPreparator extends QuicPacketPreparator<OneRTTPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public OneRTTPacketPreparator(Chooser chooser, OneRTTPacket packet) {
        super(chooser, packet);
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing 1-RTT Packet");
        prepareUnprotectedPacketNumber();
        preparePacketNumberLength();
        prepareUnprotectedFlags();
        prepareQuicPacket();
    }

    private void prepareUnprotectedPacketNumber() {
        if (packet.getUnprotectedPacketNumber() == null) {
            packet.setUnprotectedPacketNumber(context.getOneRTTPacketPacketNumber());
            context.setOneRTTPacketPacketNumber(context.getOneRTTPacketPacketNumber() + 1);
            LOGGER.debug(
                    "Unprotected Packet Number: {}",
                    packet.getUnprotectedPacketNumber().getValue());
        }
    }

    /**
     * The first byte of the short header (RFC 9000 section 17.3.1), which carries the Key Phase bit
     * in addition to the packet type and the encoded packet number length.
     *
     * <p>RFC 9001 section 6: "The Key Phase bit indicates which packet protection keys are used to
     * protect the packet. The Key Phase bit is initially set to 0 for the first set of 1-RTT
     * packets and toggled to signal each subsequent key update." It is therefore the low bit of the
     * generation of write keys this endpoint currently protects packets with, and stays 0 for as
     * long as no key update has been performed.
     */
    private void prepareUnprotectedFlags() {
        byte packetType = QuicPacketType.ONE_RTT_PACKET.getHeader(context.getQuicVersion());
        int packetNumber = packet.getPacketNumberLength().getValue();
        byte flags = (byte) (packetType ^ (packetNumber - 1));
        int writeKeyPhase =
                context.getApplicationKeyPhase(context.getConnection().getLocalConnectionEndType());
        if ((writeKeyPhase & 1) == 1) {
            flags |= (byte) MiscRfcConstants.KEY_PHASE_BIT;
        }
        packet.setUnprotectedFlags(flags);
        LOGGER.debug("Unprotected Flags: {}", packet.getUnprotectedFlags().getValue());
    }
}
