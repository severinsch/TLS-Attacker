/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.handler.packet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.QuicDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

public class InitialPacketHandlerTest {

    private static final byte[] ORIGINAL_DCID = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    private static final byte[] RETRY_SCID = {0x11, 0x12, 0x13, 0x14};
    private static final byte[] CLIENT_SCID = {0x21, 0x22, 0x23, 0x24};

    private static QuicContext serverContext() {
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);
        ServerDelegate serverDelegate = new ServerDelegate();
        serverDelegate.setPort(4433);
        serverDelegate.applyDelegate(config);
        return new State(config).getContext().getQuicContext();
    }

    private static void receiveInitial(QuicContext quicContext, byte[] dcid) {
        InitialPacket packet = new InitialPacket();
        packet.setDestinationConnectionId(dcid);
        packet.setSourceConnectionId(CLIENT_SCID);
        new InitialPacketHandler(quicContext).adjustContext(packet);
    }

    /**
     * A server that sends a Retry addresses the client to a new connection ID, and the client's
     * next Initial carries it. The Initial secrets must then be derived from that new connection ID
     * (RFC 9001 section 5.2), while the Original Destination Connection ID keeps identifying the
     * first Initial (RFC 9000 section 18.2).
     */
    @Test
    public void testInitialAfterRetryRederivesSecretsFromTheNewConnectionId() {
        QuicContext quicContext = serverContext();

        receiveInitial(quicContext, ORIGINAL_DCID);
        byte[] preRetryClientKey = quicContext.getInitialClientKey();

        // Sending a Retry invalidates the Initial secrets; the client will address its next
        // Initial to the Retry Source Connection ID.
        quicContext.setRetrySourceConnectionId(RETRY_SCID);
        quicContext.setInitialSecretsInitialized(false);
        receiveInitial(quicContext, RETRY_SCID);

        assertArrayEquals(
                ORIGINAL_DCID,
                quicContext.getFirstDestinationConnectionId(),
                "The Original Destination Connection ID must survive a Retry");
        assertArrayEquals(
                RETRY_SCID,
                quicContext.getInitialSecretsConnectionId(),
                "Initial secrets must derive from the connection ID the Initial is addressed to");
        assertFalse(
                Arrays.equals(preRetryClientKey, quicContext.getInitialClientKey()),
                "Initial secrets must actually change after a Retry");
    }

    /** Without a Retry, a retransmitted Initial must not disturb the derived secrets. */
    @Test
    public void testRepeatedInitialKeepsTheSameSecrets() {
        QuicContext quicContext = serverContext();

        receiveInitial(quicContext, ORIGINAL_DCID);
        byte[] clientKey = quicContext.getInitialClientKey();
        receiveInitial(quicContext, ORIGINAL_DCID);

        assertArrayEquals(ORIGINAL_DCID, quicContext.getFirstDestinationConnectionId());
        assertArrayEquals(clientKey, quicContext.getInitialClientKey());
    }
}
