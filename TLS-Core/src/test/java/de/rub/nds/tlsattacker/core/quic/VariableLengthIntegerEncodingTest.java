/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.protocol.exception.EndOfStreamException;
import de.rub.nds.tlsattacker.core.quic.util.VariableLengthIntegerEncoding;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.junit.jupiter.api.Test;

public class VariableLengthIntegerEncodingTest {

    @Test
    public void testEncodeVariableLengthInteger() {
        // 1 byte length min
        assertArrayEquals(
                new byte[] {0b00000000},
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(0));
        // 1 byte length max
        assertArrayEquals(
                new byte[] {0b00111111},
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(63));
        // 2 byte length min
        assertArrayEquals(
                new byte[] {0b01000000, 0b01000000},
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(64));
        // 2 byte length max
        assertArrayEquals(
                new byte[] {0b01111111, (byte) 0xff},
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(16383));
        // 4 byte length min
        assertArrayEquals(
                new byte[] {(byte) 0b10000000, 0x00, 0b01000000, 0x00},
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(16384));
        // 4 byte length max
        assertArrayEquals(
                new byte[] {(byte) 0b10111111, (byte) 0xff, (byte) 0xff, (byte) 0xff},
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(1073741823));
        // 8 byte length min
        assertArrayEquals(
                new byte[] {(byte) 0b11000000, 0x00, 0x00, 0x00, 0b01000000, 0x00, 0x00, 0x00},
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(1073741824));
        // 8 byte length max
        assertArrayEquals(
                new byte[] {
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff
                },
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(4611686018427387903L));
    }

    @Test
    public void testDecodeVariableLengthInteger() {
        // 1 byte length min
        byte[] bytesToDecode = new byte[] {0b00000000};
        assertEquals(0, VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
        // 1 byte length max
        bytesToDecode = new byte[] {0b00111111};
        assertEquals(63, VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
        // 2 byte length min
        bytesToDecode = new byte[] {(byte) 0b01000000, 0x00};
        assertEquals(0, VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
        // 2 byte length max
        bytesToDecode = new byte[] {(byte) 0b01111111, (byte) 0xff};
        assertEquals(
                16383, VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
        // 4 byte length min
        bytesToDecode = new byte[] {(byte) 0b10000000, 0x00, 0x00, 0x00};
        assertEquals(0, VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
        // 4 byte length max
        bytesToDecode = new byte[] {(byte) 0b10111111, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        assertEquals(
                1073741823,
                VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
        // 8 byte length min
        bytesToDecode = new byte[] {(byte) 0b11000000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        assertEquals(0, VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
        // 8 byte length max
        bytesToDecode =
                new byte[] {
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff
                };
        assertEquals(
                4611686018427387903L,
                VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
    }

    @Test
    public void testReadVariableLengthIntegerReadsWellFormedValues() throws IOException {
        for (long value : new long[] {0, 63, 64, 16383, 16384, 1073741823, 1073741824}) {
            byte[] encoded = VariableLengthIntegerEncoding.encodeVariableLengthInteger(value);
            ByteArrayInputStream stream = new ByteArrayInputStream(encoded);
            assertEquals(value, VariableLengthIntegerEncoding.readVariableLengthInteger(stream));
            assertEquals(0, stream.available());
        }
    }

    @Test
    public void testReadVariableLengthIntegerThrowsOnEmptyStream() {
        ByteArrayInputStream empty = new ByteArrayInputStream(new byte[0]);
        assertThrows(
                EndOfStreamException.class,
                () -> VariableLengthIntegerEncoding.readVariableLengthInteger(empty));
    }

    @Test
    public void testReadVariableLengthIntegerThrowsOnTruncatedValue() {
        // 0x40 announces a two byte integer but only the prefix byte is present.
        ByteArrayInputStream truncated = new ByteArrayInputStream(new byte[] {(byte) 0x40});
        assertThrows(
                EndOfStreamException.class,
                () -> VariableLengthIntegerEncoding.readVariableLengthInteger(truncated));
    }

    @Test
    public void testEncodeVariableLengthIntegerRejectsNegativeValues() {
        assertThrows(
                IllegalArgumentException.class,
                () -> VariableLengthIntegerEncoding.encodeVariableLengthInteger(-1));
    }

    @Test
    public void testDecodeVariableLengthIntegerRejectsTruncatedByteArrays() {
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
