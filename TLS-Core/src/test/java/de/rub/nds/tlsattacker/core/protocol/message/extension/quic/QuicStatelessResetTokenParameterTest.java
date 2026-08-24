/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.quic;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.QuicDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.quic.QuicTransportParametersExtensionsHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.quic.QuicTransportParametersExtensionParser;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * stateless_reset_token, RFC 9000 Section 18.2 parameter 0x02 — the only token bound to a
 * connection ID the peer is certainly using, and therefore the only one that lets a server exercise
 * a client's Section 10.3 stateless reset detection at all.
 *
 * <p>The framework already parses the parameter (it feeds {@link
 * QuicContext#addStatelessResetToken}); before this it could not send one.
 */
public class QuicStatelessResetTokenParameterTest {

    private static final byte[] TOKEN = {
        (byte) 0xa0, (byte) 0xa1, (byte) 0xa2, (byte) 0xa3,
        (byte) 0xa4, (byte) 0xa5, (byte) 0xa6, (byte) 0xa7,
        (byte) 0xa8, (byte) 0xa9, (byte) 0xaa, (byte) 0xab,
        (byte) 0xac, (byte) 0xad, (byte) 0xae, (byte) 0xaf
    };

    private static Optional<QuicTransportParameterEntry> tokenEntry(
            List<QuicTransportParameterEntry> entries) {
        return entries.stream()
                .filter(
                        entry ->
                                entry.getEntryType()
                                        == QuicTransportParameterEntryTypes.STATELESS_RESET_TOKEN)
                .findFirst();
    }

    /**
     * The default-path invariance property every existing QUIC run rests on: unset means not one
     * byte on the wire changes.
     */
    @Test
    public void testTheDefaultParametersAdvertiseNoToken() {
        QuicTransportParameters defaults = QuicTransportParameters.getDefaultParameters();

        assertNull(defaults.getStatelessResetToken());
        assertTrue(
                tokenEntry(defaults.toListOfEntries()).isEmpty(),
                "a server that does not configure a token must not advertise the parameter");
    }

    @Test
    public void testAConfiguredTokenIsEmittedAsA16ByteEntry() {
        QuicTransportParameters parameters = QuicTransportParameters.getDefaultParameters();
        parameters.setStatelessResetToken(TOKEN);

        QuicTransportParameterEntry entry =
                tokenEntry(parameters.toListOfEntries())
                        .orElseThrow(
                                () -> new AssertionError("the configured token was not emitted"));

        assertArrayEquals(TOKEN, entry.getEntryValue().getValue());
        assertEquals(16, entry.getEntryLength().getValue(), "Section 18.2 fixes the length at 16");
    }

    /** Entry list to POJO and back: the token used to fall through into extraEntries. */
    @Test
    public void testTheTokenSurvivesTheEntryListRoundTrip() {
        QuicTransportParameters parameters = QuicTransportParameters.getDefaultParameters();
        parameters.setStatelessResetToken(TOKEN);

        QuicTransportParameters reparsed =
                new QuicTransportParameters(parameters.toListOfEntries());

        assertArrayEquals(TOKEN, reparsed.getStatelessResetToken());
        assertTrue(
                reparsed.getExtraEntries().isEmpty(),
                "a modelled parameter must not also be kept as an unknown extra entry");
        assertEquals(parameters, reparsed, "equals() must account for the token");
        assertEquals(parameters.hashCode(), reparsed.hashCode());
    }

    @Test
    public void testTwoParameterSetsDifferingOnlyInTheTokenAreNotEqual() {
        QuicTransportParameters withToken = QuicTransportParameters.getDefaultParameters();
        withToken.setStatelessResetToken(TOKEN);
        QuicTransportParameters withoutToken = QuicTransportParameters.getDefaultParameters();

        assertNotEquals(withToken, withoutToken);
    }

    /**
     * The end-to-end property that matters: what a server prepares reaches a peer's parser as the
     * token, and lands in the store its stateless reset detection reads.
     */
    @Test
    public void testAPreparedServerExtensionCarriesTheTokenToAPeersContext() {
        byte[] extensionBody = prepareServerExtensionBody(TOKEN);

        QuicTransportParametersExtensionMessage received =
                new QuicTransportParametersExtensionMessage();
        new QuicTransportParametersExtensionParser(new ByteArrayInputStream(extensionBody), null)
                .parse(received);

        assertArrayEquals(
                TOKEN,
                received.getQuicTransportParameters().getStatelessResetToken(),
                "the peer must parse the advertised token");

        // And the receiving side stores it, which is what turns an undecryptable
        // datagram ending in these bytes into a recognised stateless reset.
        State peer = serverModeState();
        TlsContext peerTlsContext = peer.getContext().getTlsContext();
        peerTlsContext.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        new QuicTransportParametersExtensionsHandler(peerTlsContext)
                .adjustTLSExtensionContext(received);

        assertTrue(
                peer.getContext().getQuicContext().isStatelessResetToken(TOKEN),
                "the parsed token must reach the stateless reset token store");
    }

    @Test
    public void testAServerThatConfiguresNoTokenPreparesNoSuchParameter() {
        byte[] extensionBody = prepareServerExtensionBody(null);

        QuicTransportParametersExtensionMessage received =
                new QuicTransportParametersExtensionMessage();
        new QuicTransportParametersExtensionParser(new ByteArrayInputStream(extensionBody), null)
                .parse(received);

        assertNull(received.getQuicTransportParameters().getStatelessResetToken());
        assertTrue(tokenEntry(received.getTransportParameterEntries()).isEmpty());
    }

    private static State serverModeState() {
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);
        ServerDelegate serverDelegate = new ServerDelegate();
        serverDelegate.setPort(4433);
        serverDelegate.applyDelegate(config);
        return new State(config);
    }

    /** Runs the real preparator in the server direction and returns the extension body. */
    private static byte[] prepareServerExtensionBody(byte[] token) {
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);
        ServerDelegate serverDelegate = new ServerDelegate();
        serverDelegate.setPort(4433);
        serverDelegate.applyDelegate(config);
        config.getDefaultQuicTransportParameters().setStatelessResetToken(token);

        State state = new State(config);
        state.getContext().getTlsContext().setTalkingConnectionEndType(ConnectionEndType.SERVER);
        QuicContext quicContext = state.getContext().getQuicContext();
        quicContext.setSourceConnectionId(new byte[] {1, 2, 3, 4, 5, 6, 7, 8});
        quicContext.setFirstDestinationConnectionId(new byte[] {8, 7, 6, 5, 4, 3, 2, 1});

        QuicTransportParametersExtensionMessage message =
                new QuicTransportParametersExtensionMessage();
        message.getPreparator(state.getContext()).prepare();
        return message.getParameterExtensions().getValue();
    }
}
