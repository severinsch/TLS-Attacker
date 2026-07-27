/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.packet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.QuicDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

public class QuicPacketPreparatorTest {

    private static Context clientContext() {
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);
        return new State(config).getContext();
    }

    private static Context serverContext() {
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);
        ServerDelegate serverDelegate = new ServerDelegate();
        serverDelegate.setPort(4433);
        serverDelegate.applyDelegate(config);
        return new State(config).getContext();
    }

    private static InitialPacket prepareInitialPacket(Context context) {
        InitialPacket packet = new InitialPacket();
        packet.setUnprotectedPayload(new byte[] {0x01});
        packet.getPreparator(context).prepare();
        return packet;
    }

    @Test
    public void testClientAddressesFirstInitialToItsOwnChosenConnectionId() {
        Context context = clientContext();
        byte[] chosenConnectionId = context.getQuicContext().getFirstDestinationConnectionId();

        InitialPacket packet = prepareInitialPacket(context);

        assertArrayEquals(chosenConnectionId, packet.getDestinationConnectionId().getValue());
        assertEquals(
                chosenConnectionId.length,
                packet.getDestinationConnectionIdLength().getValue() & 0xff);
    }

    @Test
    public void testServerPreparesZeroLengthConnectionIdBeforeTheFirstInitial() {
        Context context = serverContext();

        InitialPacket packet = assertDoesNotThrow(() -> prepareInitialPacket(context));

        assertEquals(0, packet.getDestinationConnectionId().getValue().length);
        assertEquals(0, packet.getDestinationConnectionIdLength().getValue() & 0xff);
    }

    @Test
    public void testKnownPeerConnectionIdTakesPrecedence() {
        Context context = serverContext();
        byte[] peerConnectionId = new byte[] {0x0a, 0x0b, 0x0c, 0x0d};
        context.getQuicContext().setDestinationConnectionId(peerConnectionId);

        InitialPacket packet = prepareInitialPacket(context);

        assertArrayEquals(peerConnectionId, packet.getDestinationConnectionId().getValue());
        assertEquals(
                peerConnectionId.length,
                packet.getDestinationConnectionIdLength().getValue() & 0xff);
    }
}
