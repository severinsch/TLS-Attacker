/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension.quic;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParametersExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class QuicTransportParametersExtensionsHandler
        extends ExtensionHandler<QuicTransportParametersExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public QuicTransportParametersExtensionsHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(QuicTransportParametersExtensionMessage message) {
        // quic_transport_parameters travels in BOTH directions: the client sends its
        // own in the ClientHello and the server sends its own in EncryptedExtensions
        // (RFC 9001, Section 8.2). Extension handlers run on the send path as well as
        // the receive path, but QuicContext.receivedTransportParameters holds what the
        // PEER advertised, so it may only be written while the peer is the one
        // talking. This is the same condition RecordSizeLimitExtensionHandler applies
        // before recording the peer's advertised record size limit.
        //
        // Without the check, sending our own extension overwrote the peer's
        // parameters: getQuicTransportParameters() is populated only by the parser, so
        // a locally prepared message carries none and the context was set to null.
        // Every subsequent read of the peer's limits then saw "not advertised".
        if (tlsContext.getTalkingConnectionEndType()
                != tlsContext.getChooser().getMyConnectionPeer()) {
            LOGGER.debug("Not recording locally sent QUIC transport parameters as the peer's");
            return;
        }
        if (message.getQuicTransportParameters() == null) {
            // Nothing was parsed out of this extension, so there is nothing the peer
            // advertised. Keeping what is already in the context is strictly better
            // than replacing it with null.
            LOGGER.warn(
                    "Received a quic_transport_parameters extension that carries no parsed "
                            + "parameters; keeping the previously recorded ones");
            return;
        }
        LOGGER.debug("Adjust Quic Transport Parameters in Context to:\n{}", message);
        // Write all transport parameters
        tlsContext
                .getContext()
                .getQuicContext()
                .setReceivedTransportParameters(message.getQuicTransportParameters());
        // Collect all stateless reset tokens
        message.getTransportParameterEntries()
                .forEach(
                        (entry) -> {
                            if (entry.getEntryType()
                                    == QuicTransportParameterEntryTypes.STATELESS_RESET_TOKEN) {
                                tlsContext
                                        .getContext()
                                        .getQuicContext()
                                        .addStatelessResetToken(entry.getEntryValue().getValue());
                            }
                            if (entry.getEntryType()
                                    == QuicTransportParameterEntryTypes.PREFERRED_ADDRESS) {
                                byte[] value = entry.getEntryValue().getValue();
                                tlsContext
                                        .getContext()
                                        .getQuicContext()
                                        .addStatelessResetToken(
                                                Arrays.copyOfRange(
                                                        value, value.length - 16, value.length));
                            }
                        });
    }
}
