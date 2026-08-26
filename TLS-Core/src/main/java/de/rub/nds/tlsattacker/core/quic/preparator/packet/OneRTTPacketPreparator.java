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
import de.rub.nds.tlsattacker.core.quic.constants.QuicKeyPhaseSelection;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.packet.OneRTTPacket;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
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
     * The first byte of the short header. Its Key Phase bit is the low bit of the write generation
     * protecting this packet (RFC 9001 section 6), so it stays 0 until a key update.
     */
    private void prepareUnprotectedFlags() {
        byte packetType = QuicPacketType.ONE_RTT_PACKET.getHeader(context.getQuicVersion());
        int packetNumber = packet.getPacketNumberLength().getValue();
        byte flags = (byte) (packetType ^ (packetNumber - 1));
        if ((resolveWriteKeyPhase() & 1) == 1) {
            flags |= (byte) MiscRfcConstants.KEY_PHASE_BIT;
        }
        packet.setUnprotectedFlags(flags);
        LOGGER.debug("Unprotected Flags: {}", packet.getUnprotectedFlags().getValue());
    }

    /**
     * The write generation protecting this packet, which its Key Phase bit must announce.
     *
     * @return the number of key updates the selected generation is
     */
    private int resolveWriteKeyPhase() {
        ConnectionEndType writeEndType = chooser.getTalkingConnectionEnd();
        int currentKeyPhase = context.getApplicationKeyPhase(writeEndType);
        if (packet.getKeyPhaseSelection() != QuicKeyPhaseSelection.PREVIOUS) {
            return currentKeyPhase;
        }
        if (currentKeyPhase == 0) {
            LOGGER.warn(
                    "The previous key phase was selected for a 1-RTT packet, but the {} application keys have never been replaced by a key update, so there is no previous generation",
                    writeEndType);
            return currentKeyPhase;
        }
        return currentKeyPhase - 1;
    }
}
