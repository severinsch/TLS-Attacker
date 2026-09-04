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
 * Thrown by {@link HintedInputStream#readChunk(int)} when the stream ended before the requested
 * number of bytes could be read.
 *
 * <p>The bytes that were read before the stream ended have been consumed and cannot be read again.
 * They are carried on the exception so that the caller can account for them - discarding them makes
 * a truncated message indistinguishable from a message that never arrived.
 *
 * <p>This is an {@link EndOfStreamException}, so every existing handler of a short read keeps
 * catching it unchanged.
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
     * Returns the bytes that were consumed from the stream before it ended. Never null, possibly
     * empty. These bytes are no longer in the stream.
     *
     * @return the bytes consumed before the stream ended
     */
    public byte[] getPartiallyReadBytes() {
        return Arrays.copyOf(partiallyReadBytes, partiallyReadBytes.length);
    }
}
