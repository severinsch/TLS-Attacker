/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.packet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.quic.constants.MiscRfcConstants;
import org.junit.jupiter.api.Test;

public class QuicPacketTest {

    private static final int SAMPLE_START =
            MiscRfcConstants.MAX_ENCODED_PACKETNUMBER_LENGTH
                    + MiscRfcConstants.HEADER_PROTECTION_SAMPLE_LENGTH;

    @Test
    public void testCanSampleHeaderProtectionOnReceivedPacket() {
        OneRTTPacket tooShort = new OneRTTPacket();
        tooShort.setProtectedPacketNumberAndPayload(new byte[SAMPLE_START - 1]);
        assertFalse(tooShort.canSampleHeaderProtection());

        OneRTTPacket longEnough = new OneRTTPacket();
        longEnough.setProtectedPacketNumberAndPayload(new byte[SAMPLE_START]);
        assertTrue(longEnough.canSampleHeaderProtection());
    }

    @Test
    public void testCanSampleHeaderProtectionAccountsForPacketNumberLength() {
        int packetNumberLength = 1;
        int sampleStart = SAMPLE_START - packetNumberLength;

        OneRTTPacket tooShort = new OneRTTPacket();
        tooShort.setPacketNumberLength(packetNumberLength);
        tooShort.setProtectedPayload(new byte[sampleStart - 1]);
        assertFalse(tooShort.canSampleHeaderProtection());

        OneRTTPacket longEnough = new OneRTTPacket();
        longEnough.setPacketNumberLength(packetNumberLength);
        longEnough.setProtectedPayload(new byte[sampleStart]);
        assertTrue(longEnough.canSampleHeaderProtection());
    }

    @Test
    public void testCanSampleHeaderProtectionWithoutProtectedBytes() {
        assertFalse(new OneRTTPacket().canSampleHeaderProtection());
    }
}
