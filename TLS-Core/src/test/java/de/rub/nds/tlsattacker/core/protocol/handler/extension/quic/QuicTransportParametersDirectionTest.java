/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension.quic;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.QuicDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameterEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameters;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParametersExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * quic_transport_parameters is sent by BOTH endpoints (RFC 9001, Section 8.2), and extension
 * handlers run on the send path as well as the receive path.
 * QuicContext.receivedTransportParameters must therefore only ever be written from what the peer
 * sent.
 */
public class QuicTransportParametersDirectionTest {

    private static State serverModeState() {
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);
        new ServerDelegate() {
            {
                setPort(4433);
            }
        }.applyDelegate(config);
        return new State(config);
    }

    /** The parameters as they arrive from the peer: built the way the parser builds them. */
    private static QuicTransportParametersExtensionMessage peerParameters(long initialMaxData) {
        QuicTransportParametersExtensionMessage message =
                new QuicTransportParametersExtensionMessage();
        QuicTransportParameterEntry entry =
                new QuicTransportParameterEntry(
                        QuicTransportParameterEntryTypes.INITIAL_MAX_DATA, initialMaxData);
        message.setTransportParameterEntries(List.of(entry));
        message.setQuicTransportParameters(new QuicTransportParameters(List.of(entry)));
        return message;
    }

    @Test
    public void testPeerSentParametersAreRecorded() {
        State state = serverModeState();
        TlsContext tlsContext = state.getContext().getTlsContext();
        QuicContext quicContext = state.getContext().getQuicContext();

        tlsContext.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        new QuicTransportParametersExtensionsHandler(tlsContext)
                .adjustTLSExtensionContext(peerParameters(15728640L));

        assertNotNull(quicContext.getReceivedTransportParameters());
        assertEquals(
                15728640L,
                quicContext.getReceivedTransportParameters().getInitialMaxData(),
                "the client's advertised initial_max_data must reach the QUIC context");
    }

    @Test
    public void testSendingOurOwnParametersDoesNotClobberThePeers() {
        // The regression. A locally prepared extension carries no parsed parameters
        // (only the parser ever populates the POJO), so before the direction check
        // every EncryptedExtensions we sent set receivedTransportParameters to null
        // and every later read of the peer's limits saw "not advertised".
        State state = serverModeState();
        TlsContext tlsContext = state.getContext().getTlsContext();
        QuicContext quicContext = state.getContext().getQuicContext();
        QuicTransportParametersExtensionsHandler handler =
                new QuicTransportParametersExtensionsHandler(tlsContext);

        tlsContext.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustTLSExtensionContext(peerParameters(15728640L));
        assertNotNull(quicContext.getReceivedTransportParameters());

        // Now we, the server, send our own — exactly as EncryptedExtensions does.
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        handler.adjustTLSExtensionContext(new QuicTransportParametersExtensionMessage());

        assertNotNull(
                quicContext.getReceivedTransportParameters(),
                "sending our own transport parameters must not erase the peer's");
        assertEquals(
                15728640L,
                quicContext.getReceivedTransportParameters().getInitialMaxData(),
                "the peer's initial_max_data must survive our own EncryptedExtensions");
    }

    @Test
    public void testAnUnparsedPeerExtensionDoesNotErasePreviousParameters() {
        // Defence in depth: even from the peer, a message with nothing parsed out of
        // it says nothing about what the peer advertised, so it must not replace what
        // is already known with null.
        State state = serverModeState();
        TlsContext tlsContext = state.getContext().getTlsContext();
        QuicContext quicContext = state.getContext().getQuicContext();
        QuicTransportParametersExtensionsHandler handler =
                new QuicTransportParametersExtensionsHandler(tlsContext);

        tlsContext.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustTLSExtensionContext(peerParameters(15728640L));
        handler.adjustTLSExtensionContext(new QuicTransportParametersExtensionMessage());

        assertNotNull(quicContext.getReceivedTransportParameters());
        assertEquals(15728640L, quicContext.getReceivedTransportParameters().getInitialMaxData());
    }
}
