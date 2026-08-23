/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.frame;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.modifiablevariable.longint.LongExplicitValueModification;
import de.rub.nds.protocol.exception.EndOfStreamException;
import de.rub.nds.tlsattacker.core.quic.parser.frame.MaxStreamsFrameParser;
import de.rub.nds.tlsattacker.core.quic.parser.frame.StreamFrameParser;
import de.rub.nds.tlsattacker.core.quic.parser.frame.StreamsBlockedFrameParser;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.MaxStreamsFrameSerializer;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.StreamFrameSerializer;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.StreamsBlockedFrameSerializer;
import de.rub.nds.tlsattacker.core.quic.util.VariableLengthIntegerEncoding;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import org.junit.jupiter.api.Test;

class QuicDataPlaneVarintFrameTest {

    private static final long ABOVE_MAX_STREAMS_LIMIT = (1L << 60) + 1;
    private static final long MAX_VARINT = (1L << 62) - 1;

    @Test
    void maxStreamsCanSerializeValuesAboveTheRfcLimitThreshold() {
        MaxStreamsFrame frame = new MaxStreamsFrame(true, ABOVE_MAX_STREAMS_LIMIT);

        frame.getPreparator(new State().getContext()).prepare();

        assertEquals(ABOVE_MAX_STREAMS_LIMIT, frame.getMaximumStreams().getValue());
        assertArrayEquals(
                new byte[] {0x12, (byte) 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
                new MaxStreamsFrameSerializer(frame).serialize());
    }

    @Test
    void streamsBlockedCanSerializeValuesAboveTheRfcLimitThreshold() {
        StreamsBlockedFrame frame = new StreamsBlockedFrame(false, ABOVE_MAX_STREAMS_LIMIT);

        frame.getPreparator(new State().getContext()).prepare();

        assertEquals(ABOVE_MAX_STREAMS_LIMIT, frame.getMaximumStreams().getValue());
        assertArrayEquals(
                new byte[] {0x17, (byte) 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
                new StreamsBlockedFrameSerializer(frame).serialize());
    }

    @Test
    void streamCanSerializeAnOffsetAtThe62BitCeiling() {
        StreamFrame frame = new StreamFrame(new byte[] {0x41}, 3, MAX_VARINT, false);

        frame.getPreparator(new State().getContext()).prepare();

        assertEquals(MAX_VARINT, frame.getOffset().getValue());
        assertArrayEquals(
                new byte[] {
                    0x0e,
                    0x03,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    0x01,
                    0x41
                },
                new StreamFrameSerializer(frame).serialize());
    }

    @Test
    void longExplicitModificationsSurvivePreparatorOverwrite() {
        StreamFrame frame = new StreamFrame(new byte[] {0x41}, 3, 0, false);
        frame.setOffset(0);
        frame.getOffset().setModifications(new LongExplicitValueModification(MAX_VARINT));

        frame.getPreparator(new State().getContext()).prepare();

        assertEquals(MAX_VARINT, frame.getOffset().getValue());
    }

    @Test
    void parsersPreserveValuesAbove32Bits() {
        MaxStreamsFrame maxStreams = new MaxStreamsFrame(true);
        MaxStreamsFrameParser maxStreamsParser =
                new MaxStreamsFrameParser(
                        new ByteArrayInputStream(
                                new byte[] {
                                    0x12, (byte) 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
                                }));
        maxStreamsParser.parseFrameType(maxStreams);
        maxStreamsParser.parse(maxStreams);
        assertEquals(ABOVE_MAX_STREAMS_LIMIT, maxStreams.getMaximumStreams().getValue());

        StreamsBlockedFrame streamsBlocked = new StreamsBlockedFrame(false);
        StreamsBlockedFrameParser streamsBlockedParser =
                new StreamsBlockedFrameParser(
                        new ByteArrayInputStream(
                                new byte[] {
                                    0x17, (byte) 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
                                }));
        streamsBlockedParser.parseFrameType(streamsBlocked);
        streamsBlockedParser.parse(streamsBlocked);
        assertEquals(ABOVE_MAX_STREAMS_LIMIT, streamsBlocked.getMaximumStreams().getValue());

        StreamFrame stream = new StreamFrame();
        StreamFrameParser streamParser =
                new StreamFrameParser(
                        new ByteArrayInputStream(
                                new byte[] {
                                    0x0e,
                                    0x03,
                                    (byte) 0xff,
                                    (byte) 0xff,
                                    (byte) 0xff,
                                    (byte) 0xff,
                                    (byte) 0xff,
                                    (byte) 0xff,
                                    (byte) 0xff,
                                    (byte) 0xff,
                                    0x01,
                                    0x41
                                }));
        streamParser.parseFrameType(stream);
        streamParser.parse(stream);
        assertEquals(MAX_VARINT, stream.getOffset().getValue());
        assertArrayEquals(new byte[] {0x41}, stream.getData().getValue());
    }

    @Test
    void negativeLongModificationIsRejectedDuringSerialization() {
        MaxStreamsFrame frame = new MaxStreamsFrame(true, ABOVE_MAX_STREAMS_LIMIT);
        frame.getPreparator(new State().getContext()).prepare();
        frame.getMaximumStreams().setModifications(new LongExplicitValueModification(-1L));

        assertThrows(
                IllegalArgumentException.class,
                () -> new MaxStreamsFrameSerializer(frame).serialize());
    }

    @Test
    void declaredStreamLengthLargerThanRemainingBytesIsRejectedBeforeAllocation() {
        byte[] length = VariableLengthIntegerEncoding.encodeVariableLengthInteger(1L << 30);
        byte[] encoded = new byte[3 + length.length];
        encoded[0] = 0x0a;
        encoded[1] = 0x03;
        System.arraycopy(length, 0, encoded, 2, length.length);
        encoded[encoded.length - 1] = 0x41;

        StreamFrame stream = new StreamFrame();
        StreamFrameParser parser = new StreamFrameParser(new ByteArrayInputStream(encoded));
        parser.parseFrameType(stream);

        assertThrows(EndOfStreamException.class, () -> parser.parse(stream));
    }

    @Test
    void encodingRejectsNegativeValues() {
        assertThrows(
                IllegalArgumentException.class,
                () -> VariableLengthIntegerEncoding.encodeVariableLengthInteger(-1));
    }

    @Test
    void decodingRejectsTruncatedByteArrays() {
        assertThrows(
                IllegalArgumentException.class,
                () -> VariableLengthIntegerEncoding.decodeVariableLengthInteger(new byte[0]));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        VariableLengthIntegerEncoding.decodeVariableLengthInteger(
                                new byte[] {(byte) 0x40}));
    }
}
