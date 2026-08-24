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
