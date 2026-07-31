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

/**
 * Transport parameter IDs and lengths are variable-length integers, and an unrecognised parameter
 * must be skipped by its length rather than ending the parse (RFC 9000, Sections 16, 18 and 18.1).
 */
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
        // The regression. A GREASE parameter (RFC 9000 Section 18.1 reserves IDs of the
        // form 31*N+27 so that peers exercise the skip-unknown path) sits before
        // initial_max_data, exactly as deployed clients emit it. Reading the ID as a
        // single byte and abandoning the extension on the first unrecognised value
        // discarded every parameter after it, so the peer's flow control and connection
        // ID limits silently read as "not advertised".
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
        // The length is a varint too, and it used to be read into a signed byte, so any
        // value of 128 or more became negative. A 200 byte parameter is well formed.
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
        // Non-regression: every ID defined by RFC 9000 is below 64 and so encodes as a
        // single byte, which is what made the old single byte reader work at all.
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
        // A declared length longer than what is left must not read past the extension.
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.writeBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        QuicTransportParameterEntryTypes.INITIAL_MAX_DATA.getValue()));
        body.writeBytes(VariableLengthIntegerEncoding.encodeVariableLengthInteger(32L));
        body.writeBytes(new byte[] {0x01, 0x02});

        QuicTransportParametersExtensionMessage msg = parse(body.toByteArray());

        assertTrue(msg.getTransportParameterEntries().isEmpty());
    }
}
