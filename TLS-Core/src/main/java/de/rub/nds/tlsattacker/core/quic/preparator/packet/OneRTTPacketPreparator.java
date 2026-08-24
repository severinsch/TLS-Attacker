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
     * The first byte of the short header. Its Key Phase bit is the low bit of the current write
     * generation (RFC 9001 section 6), so it stays 0 until a key update.
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
