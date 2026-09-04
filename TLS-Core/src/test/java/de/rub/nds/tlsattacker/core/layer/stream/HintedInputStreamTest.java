/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.junit.jupiter.api.Test;

public class HintedInputStreamTest {

    private static HintedInputStream streamOf(byte... bytes) {
        return new HintedInputStreamAdapterStream(null, new ByteArrayInputStream(bytes));
    }

    /** Default path: a chunk that is fully available is returned unchanged. */
    @Test
    public void testReadChunkReturnsTheRequestedBytes() throws IOException {
        HintedInputStream stream = streamOf((byte) 1, (byte) 2, (byte) 3, (byte) 4);
        assertArrayEquals(new byte[] {1, 2, 3}, stream.readChunk(3));
        assertEquals(1, stream.available());
    }

    /** Default path: a zero-length chunk consumes nothing. */
    @Test
    public void testReadChunkOfSizeZeroReturnsAnEmptyArray() throws IOException {
        HintedInputStream stream = streamOf((byte) 1);
        assertArrayEquals(new byte[0], stream.readChunk(0));
        assertEquals(1, stream.available());
    }

    /**
     * The bytes consumed before the stream ended are gone from the stream, so they have to be
     * reported. Discarding them makes a truncated message look like a message that never arrived.
     */
    @Test
    public void testReadChunkKeepsTheBytesItConsumedWhenTheStreamEndsEarly() {
        HintedInputStream stream = streamOf((byte) 0x0a, (byte) 0x0b, (byte) 0x0c);
        IncompleteChunkException exception =
                assertThrows(IncompleteChunkException.class, () -> stream.readChunk(5));
        assertArrayEquals(new byte[] {0x0a, 0x0b, 0x0c}, exception.getPartiallyReadBytes());
    }

    /** readInt is readChunk, so it carries the same guarantee. */
    @Test
    public void testReadIntKeepsTheBytesItConsumedWhenTheStreamEndsEarly() {
        HintedInputStream stream = streamOf((byte) 0x0a, (byte) 0x0b);
        IncompleteChunkException exception =
                assertThrows(IncompleteChunkException.class, () -> stream.readInt(4));
        assertArrayEquals(new byte[] {0x0a, 0x0b}, exception.getPartiallyReadBytes());
    }

    /**
     * A failure of the underlying stream in the middle of a chunk must not destroy the bytes that
     * were already consumed either, and the failure itself has to stay visible as the cause.
     */
    @Test
    public void testReadChunkKeepsTheBytesItConsumedWhenTheStreamFailsMidChunk() {
        IOException failure = new IOException("simulated mid-chunk failure");
        HintedInputStream stream = new FailingStream(new byte[] {0x0a, 0x0b}, failure);
        IncompleteChunkException exception =
                assertThrows(IncompleteChunkException.class, () -> stream.readChunk(4));
        assertArrayEquals(new byte[] {0x0a, 0x0b}, exception.getPartiallyReadBytes());
        assertSame(failure, exception.getCause());
    }

    /**
     * A failure before the first byte of the chunk consumed nothing, so it stays the IOException
     * readChunk declares - callers recover from that one.
     */
    @Test
    public void testReadChunkPropagatesAFailureBeforeTheFirstByte() {
        IOException failure = new IOException("simulated immediate failure");
        HintedInputStream stream = new FailingStream(new byte[0], failure);
        assertSame(failure, assertThrows(IOException.class, () -> stream.readChunk(4)));
    }

    /** A stream that hands out a fixed prefix and then fails. */
    private static final class FailingStream extends HintedInputStream {

        private final byte[] data;

        private final IOException failure;

        private int position;

        private FailingStream(byte[] data, IOException failure) {
            super(null);
            this.data = data;
            this.failure = failure;
        }

        @Override
        public int read() throws IOException {
            if (position < data.length) {
                return data[position++] & 0xFF;
            }
            throw failure;
        }

        @Override
        public int available() {
            return data.length - position;
        }

        @Override
        protected InputStream getDataSource() {
            throw new UnsupportedOperationException("Not needed for this test");
        }

        @Override
        public void extendStream(byte[] bytes) {
            throw new UnsupportedOperationException("Not needed for this test");
        }
    }
}
