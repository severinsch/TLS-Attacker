/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.packet;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.core.quic.constants.QuicCryptoSecrets;
import de.rub.nds.tlsattacker.core.quic.constants.QuicKeyPhaseSelection;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.handler.packet.OneRTTPacketHandler;
import de.rub.nds.tlsattacker.core.quic.parser.packet.OneRTTPacketParser;
import de.rub.nds.tlsattacker.core.quic.preparator.packet.OneRTTPacketPreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.packet.OneRTTPacketSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A 1-RTT packet uses a short packet header. It is used after the version and 1-RTT keys are
 * negotiated.
 */
@XmlRootElement
public class OneRTTPacket extends QuicPacket {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Which generation of application packet protection keys protects this packet, or null for the
     * generation this endpoint currently writes with.
     *
     * <p>Left unset rather than initialized to {@link QuicKeyPhaseSelection#CURRENT}, so that a
     * packet nobody made a selection on serializes exactly as it did before the selection existed.
     * {@link #getKeyPhaseSelection()} resolves the null.
     */
    private QuicKeyPhaseSelection keyPhaseSelection;

    public OneRTTPacket() {
        super(QuicPacketType.ONE_RTT_PACKET);
        this.packetSecret = QuicCryptoSecrets.APPLICATION_SECRET;
    }

    public OneRTTPacket(byte flags) {
        super(QuicPacketType.ONE_RTT_PACKET);
        this.setProtectedFlags(flags);
        protectedHeaderHelper.write(flags);
        this.packetSecret = QuicCryptoSecrets.APPLICATION_SECRET;
    }

    /**
     * The generation of application packet protection keys this packet is to be protected with. RFC
     * 9001 section 6 gives an endpoint more than one: the generation it currently writes with, and
     * the one a key update replaced, which section 6.4 allows but does not oblige it to discard.
     *
     * @return the selection, never null; {@link QuicKeyPhaseSelection#CURRENT} when none was made
     */
    public QuicKeyPhaseSelection getKeyPhaseSelection() {
        return keyPhaseSelection == null ? QuicKeyPhaseSelection.CURRENT : keyPhaseSelection;
    }

    /**
     * Selects the generation of application packet protection keys this packet is to be protected
     * with. {@link QuicKeyPhaseSelection#PREVIOUS} produces a packet a conforming endpoint never
     * sends: see that constant for what RFC 9001 section 6.4 has a receiver do with it.
     *
     * @param keyPhaseSelection the selection, or null for {@link QuicKeyPhaseSelection#CURRENT}
     */
    public void setKeyPhaseSelection(QuicKeyPhaseSelection keyPhaseSelection) {
        this.keyPhaseSelection = keyPhaseSelection;
    }

    @Override
    public void buildUnprotectedPacketHeader() {
        offsetToPacketNumber = 0;
        unprotectedHeaderHelper.reset();

        unprotectedHeaderHelper.write(unprotectedFlags.getValue());
        offsetToPacketNumber++;

        unprotectedHeaderHelper.write(destinationConnectionId.getValue());
        offsetToPacketNumber += destinationConnectionIdLength.getValue();

        unprotectedHeaderHelper.writeBytes(getUnprotectedPacketNumber().getValue());
        offsetToPacketNumber += getUnprotectedPacketNumber().getValue().length;

        completeUnprotectedHeader =
                ModifiableVariableFactory.safelySetValue(
                        completeUnprotectedHeader, unprotectedHeaderHelper.toByteArray());
    }

    @Override
    public void convertCompleteProtectedHeader() {
        byte[] protectedHeaderBytes = protectedHeaderHelper.toByteArray();
        protectedHeaderBytes[0] = unprotectedFlags.getValue();
        offsetToPacketNumber = 1 + destinationConnectionId.getValue().length;
        this.completeUnprotectedHeader =
                ModifiableVariableFactory.safelySetValue(
                        this.completeUnprotectedHeader, protectedHeaderBytes);
    }

    @Override
    public OneRTTPacketHandler getHandler(Context context) {
        return new OneRTTPacketHandler(context.getQuicContext());
    }

    @Override
    public OneRTTPacketSerializer getSerializer(Context context) {
        return new OneRTTPacketSerializer(this);
    }

    @Override
    public OneRTTPacketPreparator getPreparator(Context context) {
        return new OneRTTPacketPreparator(context.getChooser(), this);
    }

    @Override
    public OneRTTPacketParser getParser(Context context, InputStream stream) {
        return new OneRTTPacketParser(stream, context.getQuicContext());
    }

    @Override
    public String toShortString() {
        return "1-RTT";
    }
}
