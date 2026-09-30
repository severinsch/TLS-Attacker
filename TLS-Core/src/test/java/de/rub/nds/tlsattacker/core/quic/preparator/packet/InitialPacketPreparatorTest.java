/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.packet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.QuicDelegate;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

public class InitialPacketPreparatorTest {

    private static final byte[] NEW_TOKEN = new byte[] {1, 2, 3};

    private static InitialPacket prepareInitial(RunningModeType runningMode) {
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);
        config.setDefaultRunningMode(runningMode);
        config.setDefaultQuicNewToken(NEW_TOKEN);
        Context context = new State(config).getContext();
        context.getQuicContext().setSourceConnectionId(new byte[8]);
        context.getQuicContext().setDestinationConnectionId(new byte[8]);
        InitialPacket packet = new InitialPacket(new byte[] {0x01});
        packet.getPreparator(context).prepare();
        return packet;
    }

    @Test
    public void testServerInitialCarriesNoToken() {
        InitialPacket packet = prepareInitial(RunningModeType.SERVER);
        assertEquals(0, packet.getTokenLength().getValue());
        assertArrayEquals(new byte[0], packet.getToken().getValue());
    }

    @Test
    public void testClientInitialCarriesTheConfiguredToken() {
        InitialPacket packet = prepareInitial(RunningModeType.CLIENT);
        assertArrayEquals(NEW_TOKEN, packet.getToken().getValue());
    }
}
