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
     * Reads exactly <code>size</code> bytes from the stream.
     *
     * @param size the number of bytes to read
     * @return exactly <code>size</code> bytes
     * @throws IOException if the underlying stream fails before the first byte is read
     * @throws IncompleteChunkException if the stream ends or fails after a partial read; it carries
     *     the bytes read so far
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
