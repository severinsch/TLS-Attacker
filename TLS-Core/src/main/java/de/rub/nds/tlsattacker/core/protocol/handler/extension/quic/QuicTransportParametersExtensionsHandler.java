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
        // Both endpoints send this extension (RFC 9001 section 8.2); record only the peer's.
        if (tlsContext.getTalkingConnectionEndType()
                != tlsContext.getChooser().getMyConnectionPeer()) {
            LOGGER.debug("Not recording locally sent QUIC transport parameters as the peer's");
            return;
        }
        if (message.getQuicTransportParameters() == null) {
            // Nothing parsed: keep what is already known.
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
