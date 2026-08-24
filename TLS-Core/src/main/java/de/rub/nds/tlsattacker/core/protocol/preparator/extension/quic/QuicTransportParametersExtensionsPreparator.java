/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension.quic;

import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameterEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameters;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParametersExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.quic.QuicTransportParametersEntrySerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class QuicTransportParametersExtensionsPreparator
        extends ExtensionPreparator<QuicTransportParametersExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final QuicTransportParametersExtensionMessage msg;

    public QuicTransportParametersExtensionsPreparator(
            Chooser chooser,
            QuicTransportParametersExtensionMessage message,
            ExtensionSerializer<QuicTransportParametersExtensionMessage> serializer) {
        super(chooser, message, serializer);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        QuicTransportParameters configuredParameters =
                chooser.getConfig().getDefaultQuicTransportParameters();
        warnAboutServerOnlyParametersSentByAClient(configuredParameters);
        List<QuicTransportParameterEntry> quicTransportEntrys =
                configuredParameters.toListOfEntries();
        quicTransportEntrys = new ArrayList<>(quicTransportEntrys);
        quicTransportEntrys.add(
                new QuicTransportParameterEntry(
                        QuicTransportParameterEntryTypes.INITIAL_SOURCE_CONNECTION_ID,
                        chooser.getContext().getQuicContext().getSourceConnectionId()));
        if (chooser.getContext().getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            quicTransportEntrys.add(
                    new QuicTransportParameterEntry(
                            QuicTransportParameterEntryTypes.ORIGINAL_DESTINATION_CONNECTION_ID,
                            chooser.getContext()
                                    .getQuicContext()
                                    .getFirstDestinationConnectionId()));
            // A server that sent a Retry must also report its Source Connection ID (RFC 9000
            // section 18.2); clients that check close with TRANSPORT_PARAMETER_ERROR if it is
            // missing.
            byte[] retrySourceConnectionId =
                    chooser.getContext().getQuicContext().getRetrySourceConnectionId();
            if (retrySourceConnectionId != null) {
                quicTransportEntrys.add(
                        new QuicTransportParameterEntry(
                                QuicTransportParameterEntryTypes.RETRY_SOURCE_CONNECTION_ID,
                                retrySourceConnectionId));
            }
        }
        SilentByteArrayOutputStream stream = new SilentByteArrayOutputStream();

        for (QuicTransportParameterEntry parameterEntry : quicTransportEntrys) {
            QuicTransportParametersEntrySerializer serializer =
                    new QuicTransportParametersEntrySerializer(parameterEntry);
            stream.write(serializer.serialize());
        }
        msg.setParameterExtensions(stream.toByteArray());
        msg.setParameterExtensionsLength(stream.toByteArray().length);
    }

    /**
     * RFC 9000, Section 18.2 makes four transport parameters server-only, and a server "MUST treat
     * receipt of any of these transport parameters as a connection error of type
     * TRANSPORT_PARAMETER_ERROR". Configuring one of them and then talking as the client is
     * therefore a deliberate probe of that check, so the value is still sent — dropping what the
     * user configured would make the probe silently untestable. It is loud, because the far more
     * likely cause is a configuration copied from a server run, and the resulting handshake failure
     * would otherwise look unexplained.
     */
    private void warnAboutServerOnlyParametersSentByAClient(QuicTransportParameters parameters) {
        if (chooser.getContext().getTalkingConnectionEndType() != ConnectionEndType.CLIENT) {
            return;
        }
        List<String> serverOnly = new ArrayList<>();
        if (parameters.getOriginalDestinationConnectionId() != null) {
            serverOnly.add("original_destination_connection_id");
        }
        if (parameters.getStatelessResetToken() != null) {
            serverOnly.add("stateless_reset_token");
        }
        if (parameters.getPreferredAddress() != null) {
            serverOnly.add("preferred_address");
        }
        if (parameters.getRetrySourceConnectionId() != null) {
            serverOnly.add("retry_source_connection_id");
        }
        if (!serverOnly.isEmpty()) {
            LOGGER.warn(
                    "Sending server-only QUIC transport parameter(s) {} as the client. RFC 9000 "
                            + "section 18.2 forbids this and a conformant server answers "
                            + "TRANSPORT_PARAMETER_ERROR.",
                    serverOnly);
        }
    }
}
