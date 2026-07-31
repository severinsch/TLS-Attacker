/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.quic.QuicTransportParametersExtensionsHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameterEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameters;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParametersExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.*;
import org.junit.jupiter.api.Test;

public class QuicTransportParametersExtensionsHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                QuicTransportParametersExtensionMessage, QuicTransportParametersExtensionsHandler> {

    public QuicTransportParametersExtensionsHandlerTest() {
        super(
                QuicTransportParametersExtensionMessage::new,
                QuicTransportParametersExtensionsHandler::new);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        QuicTransportParametersExtensionMessage msg = new QuicTransportParametersExtensionMessage();

        QuicTransportParameters params = QuicTransportParameters.getDefaultParameters();
        msg.setQuicTransportParameters(params);

        List<QuicTransportParameterEntry> paramentries =
                new ArrayList<QuicTransportParameterEntry>();
        paramentries.add(
                new QuicTransportParameterEntry(
                        QuicTransportParameterEntryTypes.STATELESS_RESET_TOKEN,
                        DataConverter.hexStringToByteArray(
                                "123456781234567812345678123456781234567812345678")));
        paramentries.add(
                new QuicTransportParameterEntry(
                        QuicTransportParameterEntryTypes.PREFERRED_ADDRESS,
                        DataConverter.hexStringToByteArray(
                                "1234567812345678123456781234567812345678123456781234567812345678123456781234567812"))); // 41 byte long -> minimum length
        msg.setTransportParameterEntries(paramentries);

        // The context this harness builds is an OutboundConnection, so the local end
        // is the client and talkingConnectionEndType defaults to CLIENT too — i.e. it
        // modelled US sending our own transport parameters, and then asserted they had
        // been recorded as the ones we RECEIVED. quic_transport_parameters is sent by
        // both endpoints (RFC 9001, Section 8.2), so that is the one case the handler
        // must not record. Point the test at what it means to test: the peer talking.
        tlsContext.getContext().setTalkingConnectionEndType(ConnectionEndType.SERVER);

        handler.adjustTLSExtensionContext(msg);

        assertEquals(
                tlsContext.getContext().getQuicContext().getReceivedTransportParameters(),
                QuicTransportParameters.getDefaultParameters());

        msg.getTransportParameterEntries()
                .forEach(
                        (entry) -> {
                            if (entry.getEntryType()
                                    == QuicTransportParameterEntryTypes.STATELESS_RESET_TOKEN) {

                                assertTrue(
                                        tlsContext
                                                .getContext()
                                                .getQuicContext()
                                                .isStatelessResetToken(
                                                        entry.getEntryValue().getValue()));
                            }
                            if (entry.getEntryType()
                                    == QuicTransportParameterEntryTypes.PREFERRED_ADDRESS) {
                                byte[] value = entry.getEntryValue().getValue();

                                assertTrue(
                                        tlsContext
                                                .getContext()
                                                .getQuicContext()
                                                .isStatelessResetToken(
                                                        Arrays.copyOfRange(
                                                                value,
                                                                value.length - 16,
                                                                value.length)));
                            }
                        });
    }
}
