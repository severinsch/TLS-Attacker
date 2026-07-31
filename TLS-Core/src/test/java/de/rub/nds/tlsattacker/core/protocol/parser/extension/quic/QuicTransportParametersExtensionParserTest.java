/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension.quic;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParametersExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes;
import de.rub.nds.tlsattacker.core.quic.util.VariableLengthIntegerEncoding;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.Test;

public class QuicTransportParametersExtensionParserTest {

    private static final long GREASE_ID = 31 * 33 + 27; // 1050, a two byte varint
    private static final long INITIAL_MAX_DATA = 15728640L;

    private static void appendParameter(ByteArrayOutputStream out, long id, byte[] value) {
        out.writeBytes(VariableLengthIntegerEncoding.encodeVariableLengthInteger(id));
        out.writeBytes(VariableLengthIntegerEncoding.encodeVariableLengthInteger(value.length));
        out.writeBytes(value);
    }

    private static QuicTransportParametersExtensionMessage parse(byte[] extensionBody) {
        QuicTransportParametersExtensionMessage msg = new QuicTransportParametersExtensionMessage();
        new QuicTransportParametersExtensionParser(new ByteArrayInputStream(extensionBody), null)
                .parse(msg);
        return msg;
    }

    @Test
    public void testParameterAfterAnUnknownOneIsStillParsed() {
        // A GREASE parameter (RFC 9000 section 18.1) before initial_max_data.
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        appendParameter(body, GREASE_ID, new byte[] {0x01, 0x02, 0x03});
        appendParameter(
                body,
                QuicTransportParameterEntryTypes.INITIAL_MAX_DATA.getValue(),
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(INITIAL_MAX_DATA));
        appendParameter(
                body,
                QuicTransportParameterEntryTypes.ACTIVE_CONNECTION_ID_LIMIT.getValue(),
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(4L));

        QuicTransportParametersExtensionMessage msg = parse(body.toByteArray());

        assertEquals(
                3,
                msg.getTransportParameterEntries().size(),
                "the unknown parameter must be skipped, not swallow the rest of the extension");
        assertEquals(
                QuicTransportParameterEntryTypes.UNKNOWN,
                msg.getTransportParameterEntries().get(0).getEntryType());
        assertEquals(
                INITIAL_MAX_DATA,
                msg.getQuicTransportParameters().getInitialMaxData(),
                "initial_max_data must survive a preceding unknown parameter");
        assertEquals(
                4L,
                msg.getQuicTransportParameters().getActiveConnectionIdLimit(),
                "active_connection_id_limit must survive a preceding unknown parameter");
    }

    @Test
    public void testMultiByteLengthIsReadAsAVarint() {
        // A length of 128 or more used to be read as a negative signed byte.
        byte[] longValue = new byte[200];
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        appendParameter(body, GREASE_ID, longValue);
        appendParameter(
                body,
                QuicTransportParameterEntryTypes.INITIAL_MAX_DATA.getValue(),
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(INITIAL_MAX_DATA));

        QuicTransportParametersExtensionMessage msg = parse(body.toByteArray());

        assertEquals(200, msg.getTransportParameterEntries().get(0).getEntryLength().getValue());
        assertEquals(INITIAL_MAX_DATA, msg.getQuicTransportParameters().getInitialMaxData());
    }

    @Test
    public void testKnownParametersStillParseUnchanged() {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        appendParameter(
                body,
                QuicTransportParameterEntryTypes.MAX_IDLE_TIMEOUT.getValue(),
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(45000L));
        appendParameter(
                body,
                QuicTransportParameterEntryTypes.INITIAL_MAX_DATA.getValue(),
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(INITIAL_MAX_DATA));

        QuicTransportParametersExtensionMessage msg = parse(body.toByteArray());

        assertEquals(2, msg.getTransportParameterEntries().size());
        assertEquals(45000L, msg.getQuicTransportParameters().getMaxIdleTimeout());
        assertEquals(INITIAL_MAX_DATA, msg.getQuicTransportParameters().getInitialMaxData());
    }

    @Test
    public void testALengthPastTheEndOfTheExtensionStopsTheParse() {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.writeBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        QuicTransportParameterEntryTypes.INITIAL_MAX_DATA.getValue()));
        body.writeBytes(VariableLengthIntegerEncoding.encodeVariableLengthInteger(32L));
        body.writeBytes(new byte[] {0x01, 0x02});

        QuicTransportParametersExtensionMessage msg = parse(body.toByteArray());

        assertTrue(msg.getTransportParameterEntries().isEmpty());
    }

    @Test
    public void testLegacyByteKeyedTypesAreNotDecodedIds() {
        assertEquals(
                QuicTransportParameterEntryTypes.UNKNOWN,
                QuicTransportParameterEntryTypes.getParameterEntryType(0x47L));
        assertEquals(
                QuicTransportParameterEntryTypes.UNKNOWN,
                QuicTransportParameterEntryTypes.getParameterEntryType(0x31L));
        assertEquals(
                QuicTransportParameterEntryTypes.MAX_DATAGRAM_FRAME_SIZE,
                QuicTransportParameterEntryTypes.getParameterEntryType(0x20L));
    }
}
