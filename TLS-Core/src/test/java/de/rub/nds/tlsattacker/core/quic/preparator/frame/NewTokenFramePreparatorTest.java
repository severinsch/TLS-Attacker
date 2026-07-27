/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.frame;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.QuicDelegate;
import de.rub.nds.tlsattacker.core.quic.frame.NewTokenFrame;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

public class NewTokenFramePreparatorTest {

    @Test
    public void testTokenIsPreparedFromTheNewTokenDefault() {
        byte[] newToken = DataConverter.hexStringToByteArray("00112233445566778899aabb");
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);
        config.setDefaultQuicNewToken(newToken);
        config.setDefaultQuicPathChallange(DataConverter.hexStringToByteArray("ffffffffffffffff"));
        Context context = new State(config).getContext();

        NewTokenFrame frame = new NewTokenFrame();
        frame.getPreparator(context).prepare();

        assertArrayEquals(
                newToken,
                frame.getToken().getValue(),
                "NEW_TOKEN carries defaultQuicNewToken, not the path-challenge default");
        assertEquals(newToken.length, frame.getTokenLength().getValue().longValue());
    }
}
