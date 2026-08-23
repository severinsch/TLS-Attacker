/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.packet;

import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.exception.EndOfStreamException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.QuicDelegate;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.io.ByteArrayInputStream;
import org.junit.jupiter.api.Test;

public class InitialPacketParserTest {

    // DCID length and DCID, SCID length and SCID, as the parser sees them after the version
    private static final String CONNECTION_IDS = "080011223344556677080011223344556677";

    private static QuicContext quicContext() {
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);
        return new State(config).getContext().getQuicContext();
    }

    private static void parse(String hex) {
        new InitialPacketParser(
                        new ByteArrayInputStream(DataConverter.hexStringToByteArray(hex)),
                        quicContext())
                .parse(new InitialPacket());
    }

    @Test
    public void testPacketLengthBeyondTheDatagramIsAnEndOfStream() {
        // token length 0, packet length 1024, four bytes present
        assertThrows(
                EndOfStreamException.class,
                () -> parse(CONNECTION_IDS + "00" + "4400" + "01020304"));
    }

    @Test
    public void testTokenLengthBeyondTheDatagramIsAnEndOfStream() {
        // token length 1024, four bytes present
        assertThrows(EndOfStreamException.class, () -> parse(CONNECTION_IDS + "4400" + "01020304"));
    }
}
