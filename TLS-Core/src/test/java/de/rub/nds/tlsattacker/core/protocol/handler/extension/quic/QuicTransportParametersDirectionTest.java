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

/** Only the peer's quic_transport_parameters are recorded (RFC 9001 section 8.2). */
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
        State state = serverModeState();
        TlsContext tlsContext = state.getContext().getTlsContext();
        QuicContext quicContext = state.getContext().getQuicContext();
        QuicTransportParametersExtensionsHandler handler =
                new QuicTransportParametersExtensionsHandler(tlsContext);

        tlsContext.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustTLSExtensionContext(peerParameters(15728640L));
        assertNotNull(quicContext.getReceivedTransportParameters());

        // The server sends its own parameters.
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
        // A peer message with nothing parsed must not erase known parameters.
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
