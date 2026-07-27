/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.packet;

import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.quic.constants.MiscCustomConstants;
import de.rub.nds.tlsattacker.core.quic.constants.MiscRfcConstants;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class QuicPacketPreparator<T extends QuicPacket> extends Preparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected QuicContext context;
    protected T packet;

    public QuicPacketPreparator(Chooser chooser, T packet) {
        super(chooser, packet);
        this.packet = packet;
        this.context = chooser.getContext().getQuicContext();
    }

    protected void prepareQuicPacket() {
        prepareDestinationConnectionId();
        prepareDestinationConnectionIdLength();
        preparePadding();
        prepareUnprotectedPayload();
        preparePacketLength();
        packet.updateFlagsWithEncodedPacketNumber();
        packet.buildUnprotectedPacketHeader();
    }

    private void preparePacketLength() {
        packet.setPacketLength(
                packet.getUnprotectedPayload().getValue().length
                        + packet.getPacketNumberLength().getValue()
                        + MiscRfcConstants.AUTH_TAG_LENGTH);
        LOGGER.debug("Packet Length: {}", packet.getPacketLength().getValue());
    }

    private void prepareUnprotectedPayload() {
        SilentByteArrayOutputStream outputStream = new SilentByteArrayOutputStream();
        outputStream.write(packet.getUnprotectedPayload().getValue());
        if (packet.getPadding().getValue() != null && packet.getPadding().getValue() > 0) {
            outputStream.write(new byte[packet.getPadding().getValue()]);
        }
        packet.setUnprotectedPayload(outputStream.toByteArray());
        LOGGER.debug("Unprotected Payload: {}", packet.getUnprotectedPayload().getValue());
    }

    protected void prepareDestinationConnectionId() {
        if (packet.getDestinationConnectionIdConfig() != null
                && packet.getDestinationConnectionIdConfig().length > 0) {
            packet.setDestinationConnectionId(packet.getDestinationConnectionIdConfig());
        } else {
            packet.setDestinationConnectionId(chooseDestinationConnectionId());
        }
        LOGGER.debug(
                "Destination Connection ID: {}", packet.getDestinationConnectionId().getValue());
    }

    /**
     * The connection ID to address the peer with. The context holds none until the peer has been
     * heard from. A client addresses its first Initial to the unpredictable value it chose itself
     * (RFC 9000 section 7.2), which is also what both sides derive the Initial secrets from; a
     * server has nothing to address until the client's first Initial arrives. Either way a header
     * has to encode a connection ID, and a zero-length one is valid (RFC 9000 section 17.2).
     */
    private byte[] chooseDestinationConnectionId() {
        if (context.getDestinationConnectionId() != null) {
            return context.getDestinationConnectionId();
        }
        if (context.getConnection().getLocalConnectionEndType() == ConnectionEndType.CLIENT
                && context.getFirstDestinationConnectionId() != null) {
            return context.getFirstDestinationConnectionId();
        }
        return new byte[0];
    }

    protected void prepareDestinationConnectionIdLength() {
        packet.setDestinationConnectionIdLength(
                (byte) packet.getDestinationConnectionId().getValue().length);
        LOGGER.debug(
                "Destination Connection ID Length: {}",
                packet.getDestinationConnectionIdLength().getValue());
    }

    protected void preparePacketNumberLength() {
        packet.setPacketNumberLength(packet.getUnprotectedPacketNumber().getValue().length);
        LOGGER.debug("Packet Number Length: {}", packet.getPacketNumberLength().getValue());
    }

    private void preparePadding() {
        if (packet.getPadddingConfig() != null) {
            packet.setPadding(packet.getPadddingConfig());
        } else if (context.getConfig().isQuicDoNotPadPackets()) {
            packet.setPadding(0);
        } else if (packet.getPadding() != null) {
            packet.setPadding(packet.getPadding().getValue());
        } else {
            packet.setPadding(calculatePadding());
        }
        LOGGER.debug("Padding: {}", packet.getPadding().getValue());
    }

    protected int calculatePadding() {
        return Math.max(
                0,
                MiscCustomConstants.MIN_PACKET_CONTENT_SIZE
                        - packet.getUnprotectedPayload().getValue().length);
    }
}
