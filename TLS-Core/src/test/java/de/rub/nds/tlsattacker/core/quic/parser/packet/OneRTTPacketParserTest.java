/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.packet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.QuicDelegate;
import de.rub.nds.tlsattacker.core.quic.packet.OneRTTPacket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.io.ByteArrayInputStream;
import org.junit.jupiter.api.Test;

/**
 * A short header carries no Destination Connection ID length field (RFC 9000 section 17.3), so the
 * parser takes it either from the local source connection ID or from an explicit override. The
 * override is what lets the receive path re-parse a packet after the peer changes the length of the
 * connection ID it uses.
 */
public class OneRTTPacketParserTest {

    // The flags byte is consumed by the layer before the parser runs, so the parser stream begins
    // at the Destination Connection ID. The trailing bytes stand in for the protected packet
    // number and payload.
    private static final byte[] POST_FLAG_BYTES =
            DataConverter.hexStringToByteArray("00112233445566778899aabbccddeeff0123456789");

    private static QuicContext contextWithSourceConnectionIdLength(int length) {
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);
        QuicContext quicContext = new State(config).getContext().getQuicContext();
        quicContext.setSourceConnectionId(new byte[length]);
        return quicContext;
    }

    @Test
    public void testParsesDcidLengthFromSourceConnectionIdByDefault() {
        QuicContext quicContext = contextWithSourceConnectionIdLength(8);
        OneRTTPacket packet = new OneRTTPacket((byte) 0x40);

        new OneRTTPacketParser(new ByteArrayInputStream(POST_FLAG_BYTES), quicContext)
                .parse(packet);

        assertEquals(8, packet.getDestinationConnectionIdLength().getValue() & 0xff);
        assertArrayEquals(
                DataConverter.hexStringToByteArray("0011223344556677"),
                packet.getDestinationConnectionId().getValue());
        assertArrayEquals(
                DataConverter.hexStringToByteArray("8899aabbccddeeff0123456789"),
                packet.getProtectedPacketNumberAndPayload().getValue());
    }

    /** The peer retired every issued connection ID and now uses a zero-length one. */
    @Test
    public void testOverrideOfZeroYieldsEmptyDcidAndFullPayload() {
        QuicContext quicContext = contextWithSourceConnectionIdLength(16);
        OneRTTPacket packet = new OneRTTPacket((byte) 0x40);

        new OneRTTPacketParser(new ByteArrayInputStream(POST_FLAG_BYTES), quicContext, 0)
                .parse(packet);

        assertEquals(0, packet.getDestinationConnectionIdLength().getValue() & 0xff);
        assertEquals(0, packet.getDestinationConnectionId().getValue().length);
        assertArrayEquals(POST_FLAG_BYTES, packet.getProtectedPacketNumberAndPayload().getValue());
    }

    @Test
    public void testOverrideTakesPrecedenceOverContext() {
        QuicContext quicContext = contextWithSourceConnectionIdLength(0);
        OneRTTPacket packet = new OneRTTPacket((byte) 0x40);

        new OneRTTPacketParser(new ByteArrayInputStream(POST_FLAG_BYTES), quicContext, 4)
                .parse(packet);

        assertEquals(4, packet.getDestinationConnectionIdLength().getValue() & 0xff);
        assertArrayEquals(
                DataConverter.hexStringToByteArray("00112233"),
                packet.getDestinationConnectionId().getValue());
        assertArrayEquals(
                DataConverter.hexStringToByteArray("445566778899aabbccddeeff0123456789"),
                packet.getProtectedPacketNumberAndPayload().getValue());
    }
}
