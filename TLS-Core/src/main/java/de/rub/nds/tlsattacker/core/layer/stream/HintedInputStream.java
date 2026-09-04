/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.stream;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.exception.EndOfStreamException;
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * InputStream that contains a LayerProcessingHint. Also provides methods useful when parsing data
 * from byteArrays.
 */
public abstract class HintedInputStream extends InputStream {

    private LayerProcessingHint hint;

    public HintedInputStream(LayerProcessingHint hint) {
        this.hint = hint;
    }

    public LayerProcessingHint getHint() {
        return hint;
    }

    public byte readByte() throws IOException {
        return (byte) read();
    }

    public int readInt(int size) throws IOException {
        if (size < 0 || size > 4) {
            throw new ParserException("Cannot read Integer of size " + size);
        }
        byte[] readChunk = readChunk(size);
        return DataConverter.bytesToInt(readChunk);
    }

    /**
     * Reads exactly <code>size</code> bytes from the stream. Every caller of this method treats the
     * result as being exactly <code>size</code> bytes long, so a short read is a failure and not a
     * result. The read is continued until the requested number of bytes has been read or the stream
     * ends.
     *
     * <p>If the stream ends first, the bytes that were already consumed cannot be put back, so they
     * are carried on the thrown {@link IncompleteChunkException} instead of being dropped. Dropping
     * them made a truncated message indistinguishable from a message that never arrived.
     *
     * @param size the number of bytes to read
     * @return exactly <code>size</code> bytes
     * @throws IOException if the underlying stream fails before the first byte of the chunk was
     *     read
     * @throws IncompleteChunkException if the stream ended, or failed, after some but not all of
     *     the requested bytes were read
     */
    public byte[] readChunk(int size) throws IOException {
        if (size == 0) {
            return new byte[0];
        }
        byte[] chunk = new byte[size];
        int bytesRead = 0;
        Exception readFailure = null;
        try {
            while (bytesRead < size) {
                int nextByte = read();
                if (nextByte == -1) {
                    break;
                }
                chunk[bytesRead] = (byte) nextByte;
                bytesRead++;
            }
        } catch (IOException | EndOfStreamException ex) {
            // nothing consumed yet: the chunk is untouched, so keep the exception the caller
            // already handles. Afterwards the consumed bytes have to survive the failure, which
            // only the thrown exception can carry
            if (bytesRead == 0) {
                throw ex;
            }
            readFailure = ex;
        }
        if (bytesRead != size) {
            throw new IncompleteChunkException(
                    "Could not read "
                            + size
                            + " bytes from the stream. Only "
                            + bytesRead
                            + " bytes available",
                    Arrays.copyOf(chunk, bytesRead),
                    readFailure);
        }
        return chunk;
    }

    protected abstract InputStream getDataSource();

    public abstract void extendStream(byte[] bytes);

    public void setHint(LayerProcessingHint hint) {
        this.hint = hint;
    }
}
