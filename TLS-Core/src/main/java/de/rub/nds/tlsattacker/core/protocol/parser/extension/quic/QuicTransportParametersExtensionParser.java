/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension.quic;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameterEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameters;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParametersExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class QuicTransportParametersExtensionParser
        extends ExtensionParser<QuicTransportParametersExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public QuicTransportParametersExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    /**
     * Each transport parameter is an ID, a length and a value, where the ID and the length are both
     * variable-length integers (RFC 9000, Section 18 and Section 16). An endpoint must skip over a
     * parameter it does not recognise using that length and carry on: reserved "GREASE" parameter
     * IDs (Section 18.1) exist precisely so that peers exercise this path, and several widely
     * deployed clients send them.
     */
    @Override
    public void parse(QuicTransportParametersExtensionMessage msg) {
        while (getBytesLeft() > 0) {
            long id = parseVariableLengthInteger();
            long length = parseVariableLengthInteger();
            if (length < 0 || length > getBytesLeft()) {
                LOGGER.warn(
                        "QUIC transport parameter {} declares a length of {} with {} bytes left; "
                                + "stopping the parse rather than reading past the extension",
                        id,
                        length,
                        getBytesLeft());
                break;
            }
            byte[] value = parseByteArrayField((int) length);

            QuicTransportParameterEntry entry = new QuicTransportParameterEntry();
            entry.setEntryType(QuicTransportParameterEntryTypes.getParameterEntryType(id));
            entry.setEntryLength((int) length);
            entry.setEntryValue(value);
            msg.getTransportParameterEntries().add(entry);
        }
        msg.setQuicTransportParameters(
                new QuicTransportParameters(msg.getTransportParameterEntries()));
    }
}
