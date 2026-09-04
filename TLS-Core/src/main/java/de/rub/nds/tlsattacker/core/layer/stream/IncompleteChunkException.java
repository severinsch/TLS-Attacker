/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.stream;

import de.rub.nds.protocol.exception.EndOfStreamException;
import java.util.Arrays;

/**
 * Thrown by {@link HintedInputStream#readChunk(int)} when the stream ends before the requested
 * number of bytes was read. Carries the bytes that were already consumed.
 */
public class IncompleteChunkException extends EndOfStreamException {

    private final byte[] partiallyReadBytes;

    public IncompleteChunkException(String message, byte[] partiallyReadBytes, Throwable cause) {
        super(message, cause);
        this.partiallyReadBytes =
                partiallyReadBytes == null
                        ? new byte[0]
                        : Arrays.copyOf(partiallyReadBytes, partiallyReadBytes.length);
    }

    /**
     * @return the bytes consumed before the stream ended, never null
     */
    public byte[] getPartiallyReadBytes() {
        return Arrays.copyOf(partiallyReadBytes, partiallyReadBytes.length);
    }
}
