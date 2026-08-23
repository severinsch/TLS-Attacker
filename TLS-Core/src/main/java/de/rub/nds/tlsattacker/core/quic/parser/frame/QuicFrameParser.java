/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class QuicFrameParser<T extends QuicFrame> extends Parser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public QuicFrameParser(InputStream stream) {
        super(stream);
    }

    public void parseFrameType(QuicFrame frame) {
        frame.setFrameType(parseVariableLengthInteger());
        LOGGER.debug("Frame Type: {}", frame.getFrameType().getValue());
    }

    protected int checkedVarintLength(long value, String fieldName) {
        if (value < 0 || value > Integer.MAX_VALUE) {
            throw new ParserException(fieldName + " exceeds Java array limits: " + value);
        }
        if (value > getBytesLeft()) {
            throw new ParserException(
                    fieldName
                            + " exceeds remaining QUIC frame bytes: "
                            + value
                            + " > "
                            + getBytesLeft());
        }
        return (int) value;
    }
}
