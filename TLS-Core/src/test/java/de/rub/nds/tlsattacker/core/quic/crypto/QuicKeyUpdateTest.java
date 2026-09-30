/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.QuicDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.quic.constants.MiscRfcConstants;
import de.rub.nds.tlsattacker.core.quic.constants.QuicKeyPhaseSelection;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.packet.OneRTTPacket;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations.ApplicationKeyMaterial;
import de.rub.nds.tlsattacker.core.quic.parser.packet.OneRTTPacketParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import de.rub.nds.tlsattacker.core.workflow.action.InitiateQuicKeyUpdateAction;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * QUIC key update (RFC 9001 section 6), with two endpoints driven against each other through the
 * real preparator, encryptor, parser and decryptor.
 */
public class QuicKeyUpdateTest {

    /** RFC 9001 Appendix A.5 (AEAD_CHACHA20_POLY1305, HKDF-SHA256). */
    private static final byte[] A5_SECRET =
            DataConverter.hexStringToByteArray(
                    "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");

    private static final byte[] A5_KEY =
            DataConverter.hexStringToByteArray(
                    "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");

    private static final byte[] A5_IV =
            DataConverter.hexStringToByteArray("e0459b3474bdd0e44a41c144");

    private static final byte[] A5_HP =
            DataConverter.hexStringToByteArray(
                    "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");

    /** ku = HKDF-Expand-Label(secret, "quic ku", "", 32), the next generation's secret. */
    private static final byte[] A5_KU =
            DataConverter.hexStringToByteArray(
                    "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9");

    private static final byte[] CLIENT_CONNECTION_ID =
            DataConverter.hexStringToByteArray("0102030405060708");

    private static final byte[] SERVER_CONNECTION_ID =
            DataConverter.hexStringToByteArray("1112131415161718");

    private static final byte[] CLIENT_APPLICATION_SECRET =
            DataConverter.hexStringToByteArray(
                    "1122334455667788990011223344556677889900112233445566778899001122");

    private static final byte[] SERVER_APPLICATION_SECRET =
            DataConverter.hexStringToByteArray(
                    "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");

    private static final byte[] PAYLOAD = new byte[] {0x01, 0x02, 0x03, 0x04};

    /** Recorded from a build without key update support. */
    private static final String GOLDEN_DEFAULT_PATH_PACKET =
            "49111213141516171838888D82084D4C8DA884E402015F60E9E5C4FA567A7AD1A902A69D70"
                    + "09D92546B0CAFF28D10B1D3E597D499D31A2C5DD647652E2D7C5F8748E1E7625AC9151E"
                    + "C81DB48DC5841BF3CDDF6D3C5E62CF4F70BB10A45FCD1ABAA3DD5B2F08257E6D2FF8899"
                    + "18C2666BDAA4652E0540186519403244D71B";

    /**
     * Recorded from a build without write key retention, with the generation-1 client key and IV.
     */
    private static final String GOLDEN_AFTER_UPDATE_PACKET =
            "451112131415161718E97017E5EF69138076CD18B0C41E2A2622F0DD58581A91BFF34B1131"
                    + "DF4760E23D92AD285DD5A4BBA385402FE155B8D3D984A7815E218C95F49B4FEEE573906"
                    + "5D33E9D512F1BA06354BAE412A68079A2C3B9DCFCB14F8B420F79716AFB3801D6574278"
                    + "ADF6B382EC1F4EAB952DBB0FBA82A5D4C336";

    private static final String GOLDEN_AFTER_UPDATE_CLIENT_KEY = "68415B7F47063215B9ED8CF3D82460CF";
    private static final String GOLDEN_AFTER_UPDATE_CLIENT_IV = "8B5DFEB83DA37C552E5DEDBF";

    private static final String GOLDEN_CLIENT_KEY = "72E75FDFADB4C2EC96F37F8EB1F3B2E8";
    private static final String GOLDEN_CLIENT_IV = "190D992E8AC5A7970B75071B";
    private static final String GOLDEN_CLIENT_HP = "F0B19DF1C7AA20E98E9623B45A57B5A5";
    private static final String GOLDEN_SERVER_KEY = "0CF0D785C7837B946EEF3C2142EFDAE6";
    private static final String GOLDEN_SERVER_IV = "557D0466B70ADC2EEE53A72D";
    private static final String GOLDEN_SERVER_HP = "5A2573F61D9FC274B67F294F921DD704";

    /** An endpoint with 1-RTT keys for both directions, using TLS_AES_128_GCM_SHA256. */
    private static Context endpoint(ConnectionEndType localEndType)
            throws CryptoException, NoSuchAlgorithmException {
        return endpointState(localEndType).getContext();
    }

    private static State endpointState(ConnectionEndType localEndType)
            throws CryptoException, NoSuchAlgorithmException {
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);
        if (localEndType == ConnectionEndType.SERVER) {
            ServerDelegate serverDelegate = new ServerDelegate();
            serverDelegate.setPort(4433);
            serverDelegate.applyDelegate(config);
        }
        State state = new State(config);
        Context context = state.getContext();
        assertEquals(localEndType, context.getConnection().getLocalConnectionEndType());

        context.getTlsContext().setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.getTlsContext().setClientApplicationTrafficSecret(CLIENT_APPLICATION_SECRET);
        context.getTlsContext().setServerApplicationTrafficSecret(SERVER_APPLICATION_SECRET);

        QuicContext quicContext = context.getQuicContext();
        quicContext.setHkdfAlgorithm(HKDFAlgorithm.TLS_HKDF_SHA256);
        quicContext.setAeadCipher("AES/GCM/NoPadding");
        quicContext.setHeaderProtectionCipher("AES/ECB/NoPadding");
        QuicPacketCryptoComputations.calculateApplicationSecrets(context);

        if (localEndType == ConnectionEndType.CLIENT) {
            quicContext.setSourceConnectionId(CLIENT_CONNECTION_ID);
            quicContext.setDestinationConnectionId(SERVER_CONNECTION_ID);
        } else {
            quicContext.setSourceConnectionId(SERVER_CONNECTION_ID);
            quicContext.setDestinationConnectionId(CLIENT_CONNECTION_ID);
        }
        return state;
    }

    /** Prepares, protects and serializes one 1-RTT packet, as the packet layer does. */
    private static byte[] send(Context sender, int packetNumber) throws CryptoException {
        return send(sender, packetNumber, null);
    }

    /** As above, with an explicit key generation selection; null is the default path. */
    private static byte[] send(
            Context sender, int packetNumber, QuicKeyPhaseSelection keyPhaseSelection)
            throws CryptoException {
        sender.setTalkingConnectionEndType(sender.getConnection().getLocalConnectionEndType());
        OneRTTPacket packet = new OneRTTPacket();
        packet.setKeyPhaseSelection(keyPhaseSelection);
        packet.setUnprotectedPayload(PAYLOAD);
        packet.setUnprotectedPacketNumber(packetNumber);
        packet.getPreparator(sender).prepare();
        QuicEncryptor encryptor = new QuicEncryptor(sender.getChooser());
        encryptor.encryptOneRRTPacket(packet);
        encryptor.addHeaderProtectionOneRRT(packet);
        return packet.getSerializer(sender).serialize();
    }

    /** Parses and unprotects one 1-RTT packet, as the packet layer does. */
    private static OneRTTPacket receive(Context receiver, byte[] datagram) throws CryptoException {
        receiver.setTalkingConnectionEndType(
                receiver.getConnection().getLocalConnectionEndType().getPeer());
        OneRTTPacket packet = new OneRTTPacket(datagram[0]);
        new OneRTTPacketParser(
                        new ByteArrayInputStream(Arrays.copyOfRange(datagram, 1, datagram.length)),
                        receiver.getQuicContext())
                .parse(packet);
        QuicDecryptor decryptor = new QuicDecryptor(receiver.getChooser());
        decryptor.removeHeaderProtectionOneRTT(packet);
        packet.convertCompleteProtectedHeader();
        decryptor.decryptOneRTTPacket(packet);
        receiver.getQuicContext().addReceivedOneRTTPacketNumber(packet.getPlainPacketNumber());
        return packet;
    }

    private static void assertCarriesPayload(OneRTTPacket packet) {
        byte[] decrypted = packet.getUnprotectedPayload().getValue();
        assertTrue(decrypted.length >= PAYLOAD.length);
        assertArrayEquals(PAYLOAD, Arrays.copyOf(decrypted, PAYLOAD.length));
    }

    private static int keyPhaseBitOf(OneRTTPacket packet) {
        return (packet.getUnprotectedFlags().getValue() & MiscRfcConstants.KEY_PHASE_BIT) == 0
                ? 0
                : 1;
    }

    @Test
    public void testNextApplicationSecretMatchesTheAppendixA5Vector() throws Exception {
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);
        Context context = new State(config).getContext();
        context.getTlsContext().setSelectedCipherSuite(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        context.getTlsContext().setClientApplicationTrafficSecret(A5_SECRET);
        context.getTlsContext().setServerApplicationTrafficSecret(A5_SECRET);
        QuicContext quicContext = context.getQuicContext();
        quicContext.setHkdfAlgorithm(HKDFAlgorithm.TLS_HKDF_SHA256);
        QuicPacketCryptoComputations.calculateApplicationSecrets(context);

        // Generation 0, to show the fixture really is the appendix's.
        assertArrayEquals(A5_KEY, quicContext.getApplicationServerKey());
        assertArrayEquals(A5_IV, quicContext.getApplicationServerIv());
        assertArrayEquals(A5_HP, quicContext.getApplicationServerHeaderProtectionKey());

        ApplicationKeyMaterial next =
                QuicPacketCryptoComputations.calculateNextApplicationSecrets(
                        quicContext, ConnectionEndType.SERVER);

        assertArrayEquals(A5_KU, next.secret());
        // The appendix stops at the secret; key and IV follow from section 5.1.
        assertEquals(A5_KEY.length, next.key().length);
        assertEquals(A5_IV.length, next.iv().length);
        assertFalse(Arrays.equals(A5_KEY, next.key()));
        assertFalse(Arrays.equals(A5_IV, next.iv()));

        // Deriving must not change the context (RFC 9001 section 6.3).
        assertArrayEquals(A5_SECRET, quicContext.getApplicationServerSecret());
        assertArrayEquals(A5_KEY, quicContext.getApplicationServerKey());
        assertEquals(0, quicContext.getApplicationKeyPhase(ConnectionEndType.SERVER));
    }

    @Test
    public void testKeyUpdateLeavesTheHeaderProtectionKeysUntouched() throws Exception {
        Context context = endpoint(ConnectionEndType.CLIENT);
        QuicContext quicContext = context.getQuicContext();
        byte[] clientHeaderProtectionKey = quicContext.getApplicationClientHeaderProtectionKey();
        byte[] serverHeaderProtectionKey = quicContext.getApplicationServerHeaderProtectionKey();
        byte[] clientKey = quicContext.getApplicationKey(ConnectionEndType.CLIENT);
        byte[] clientIv = quicContext.getApplicationIv(ConnectionEndType.CLIENT);
        byte[] serverKey = quicContext.getApplicationKey(ConnectionEndType.SERVER);
        byte[] serverIv = quicContext.getApplicationIv(ConnectionEndType.SERVER);

        QuicPacketCryptoComputations.initiateKeyUpdate(quicContext);

        assertArrayEquals(
                clientHeaderProtectionKey, quicContext.getApplicationClientHeaderProtectionKey());
        assertArrayEquals(
                serverHeaderProtectionKey, quicContext.getApplicationServerHeaderProtectionKey());
        assertFalse(
                Arrays.equals(clientKey, quicContext.getApplicationKey(ConnectionEndType.CLIENT)));
        assertFalse(
                Arrays.equals(serverKey, quicContext.getApplicationKey(ConnectionEndType.SERVER)));

        // Both directions move (RFC 9001 section 6.1).
        assertEquals(1, quicContext.getApplicationKeyPhase(ConnectionEndType.CLIENT));
        assertEquals(1, quicContext.getApplicationKeyPhase(ConnectionEndType.SERVER));

        // Both directions keep the generation they replaced.
        assertArrayEquals(
                clientKey, quicContext.getPreviousApplicationKey(ConnectionEndType.CLIENT));
        assertArrayEquals(clientIv, quicContext.getPreviousApplicationIv(ConnectionEndType.CLIENT));
        assertArrayEquals(
                serverKey, quicContext.getPreviousApplicationKey(ConnectionEndType.SERVER));
        assertArrayEquals(serverIv, quicContext.getPreviousApplicationIv(ConnectionEndType.SERVER));
    }

    @Test
    public void testRoundTripAcrossAKeyUpdate() throws Exception {
        Context client = endpoint(ConnectionEndType.CLIENT);
        Context server = endpoint(ConnectionEndType.SERVER);

        // Generation 0 first, so the receiver has a packet number in the current key phase.
        OneRTTPacket beforeUpdate = receive(server, send(client, 5));
        assertEquals(0, keyPhaseBitOf(beforeUpdate));
        assertCarriesPayload(beforeUpdate);

        QuicPacketCryptoComputations.initiateKeyUpdate(client.getQuicContext());
        OneRTTPacket afterUpdate = receive(server, send(client, 6));

        assertEquals(1, keyPhaseBitOf(afterUpdate));
        assertCarriesPayload(afterUpdate);

        // The responder updated both directions (RFC 9001 section 6.2).
        assertEquals(1, server.getQuicContext().getApplicationKeyPhase(ConnectionEndType.CLIENT));
        assertEquals(1, server.getQuicContext().getApplicationKeyPhase(ConnectionEndType.SERVER));
        assertArrayEquals(
                client.getQuicContext().getApplicationKey(ConnectionEndType.CLIENT),
                server.getQuicContext().getApplicationKey(ConnectionEndType.CLIENT));
        assertArrayEquals(
                client.getQuicContext().getApplicationKey(ConnectionEndType.SERVER),
                server.getQuicContext().getApplicationKey(ConnectionEndType.SERVER));

        // And the responder's own next packet goes out at the new key phase and is readable.
        OneRTTPacket response = receive(client, send(server, 3));
        assertEquals(1, keyPhaseBitOf(response));
        assertCarriesPayload(response);
    }

    @Test
    public void testDelayedPacketOfThePreviousGenerationStillDecrypts() throws Exception {
        Context client = endpoint(ConnectionEndType.CLIENT);
        Context server = endpoint(ConnectionEndType.SERVER);

        // Protected with generation 0, but held back by the network.
        byte[] delayed = send(client, 4);

        receive(server, send(client, 5));
        QuicPacketCryptoComputations.initiateKeyUpdate(client.getQuicContext());
        receive(server, send(client, 6));
        assertEquals(1, server.getQuicContext().getApplicationKeyPhase(ConnectionEndType.CLIENT));

        OneRTTPacket recovered = receive(server, delayed);

        assertEquals(0, keyPhaseBitOf(recovered));
        assertCarriesPayload(recovered);
        // It is read as the previous generation, not as a further key update.
        assertEquals(1, server.getQuicContext().getApplicationKeyPhase(ConnectionEndType.CLIENT));
        assertEquals(1, server.getQuicContext().getApplicationKeyPhase(ConnectionEndType.SERVER));
    }

    @Test
    public void testForgedKeyPhaseBitDoesNotRotateKeys() throws Exception {
        Context client = endpoint(ConnectionEndType.CLIENT);
        Context server = endpoint(ConnectionEndType.SERVER);
        receive(server, send(client, 5));

        // Key Phase 1 on a packet protected with generation 0.
        client.getQuicContext().setApplicationKeyPhase(ConnectionEndType.CLIENT, 1);
        byte[] forged = send(client, 6);
        client.getQuicContext().setApplicationKeyPhase(ConnectionEndType.CLIENT, 0);

        byte[] clientKeyBefore =
                server.getQuicContext().getApplicationKey(ConnectionEndType.CLIENT);
        byte[] serverKeyBefore =
                server.getQuicContext().getApplicationKey(ConnectionEndType.SERVER);

        assertThrows(CryptoException.class, () -> receive(server, forged));

        assertEquals(0, server.getQuicContext().getApplicationKeyPhase(ConnectionEndType.CLIENT));
        assertEquals(0, server.getQuicContext().getApplicationKeyPhase(ConnectionEndType.SERVER));
        assertArrayEquals(
                clientKeyBefore,
                server.getQuicContext().getApplicationKey(ConnectionEndType.CLIENT));
        assertArrayEquals(
                serverKeyBefore,
                server.getQuicContext().getApplicationKey(ConnectionEndType.SERVER));
        assertNull(server.getQuicContext().getPreviousApplicationKey(ConnectionEndType.CLIENT));

        // The connection is undamaged: the peer's next genuine packet still arrives.
        OneRTTPacket afterForgery = receive(server, send(client, 7));
        assertEquals(0, keyPhaseBitOf(afterForgery));
        assertCarriesPayload(afterForgery);
    }

    @Test
    public void testPacketMayBeProtectedWithThePreviousKeyPhase() throws Exception {
        Context client = endpoint(ConnectionEndType.CLIENT);
        Context server = endpoint(ConnectionEndType.SERVER);
        receive(server, send(client, 5));

        QuicPacketCryptoComputations.initiateKeyUpdate(client.getQuicContext());
        assertEquals(1, client.getQuicContext().getApplicationKeyPhase(ConnectionEndType.CLIENT));

        byte[] datagram = send(client, 6, QuicKeyPhaseSelection.PREVIOUS);
        OneRTTPacket sentWithOldKeys = receive(server, datagram);

        // The bit announces the generation the packet was protected with.
        assertEquals(0, keyPhaseBitOf(sentWithOldKeys));
        assertCarriesPayload(sentWithOldKeys);
        // The peer never saw a key update, so nothing about its key state moved.
        assertEquals(0, server.getQuicContext().getApplicationKeyPhase(ConnectionEndType.CLIENT));
        assertEquals(0, server.getQuicContext().getApplicationKeyPhase(ConnectionEndType.SERVER));

        // The selection applies to one packet only.
        OneRTTPacket afterwards = receive(server, send(client, 7));
        assertEquals(1, client.getQuicContext().getApplicationKeyPhase(ConnectionEndType.CLIENT));
        assertEquals(1, keyPhaseBitOf(afterwards));
        assertCarriesPayload(afterwards);
    }

    @Test
    public void testPreviousKeyPhaseIsRefusedBeforeAnyKeyUpdate() throws Exception {
        Context client = endpoint(ConnectionEndType.CLIENT);

        CryptoException refused =
                assertThrows(
                        CryptoException.class,
                        () -> send(client, 5, QuicKeyPhaseSelection.PREVIOUS));
        assertTrue(refused.getMessage().contains("previous key phase"));

        // The refusal changed nothing.
        assertEquals(0, client.getQuicContext().getApplicationKeyPhase(ConnectionEndType.CLIENT));
        Context server = endpoint(ConnectionEndType.SERVER);
        assertCarriesPayload(receive(server, send(client, 5)));
    }

    @Test
    public void testKeyPhaseRetentionDoesNotMoveThePacketSentAfterAnUpdate() throws Exception {
        Context client = endpoint(ConnectionEndType.CLIENT);
        QuicPacketCryptoComputations.initiateKeyUpdate(client.getQuicContext());

        byte[] datagram = send(client, 6);

        assertEquals(GOLDEN_AFTER_UPDATE_PACKET, DataConverter.bytesToRawHexString(datagram));
        assertEquals(
                GOLDEN_AFTER_UPDATE_CLIENT_KEY,
                DataConverter.bytesToRawHexString(
                        client.getQuicContext().getApplicationClientKey()));
        assertEquals(
                GOLDEN_AFTER_UPDATE_CLIENT_IV,
                DataConverter.bytesToRawHexString(
                        client.getQuicContext().getApplicationClientIv()));

        assertEquals(
                GOLDEN_CLIENT_KEY,
                DataConverter.bytesToRawHexString(
                        client.getQuicContext()
                                .getPreviousApplicationKey(ConnectionEndType.CLIENT)));
        assertEquals(
                GOLDEN_CLIENT_IV,
                DataConverter.bytesToRawHexString(
                        client.getQuicContext()
                                .getPreviousApplicationIv(ConnectionEndType.CLIENT)));
    }

    @Test
    public void testSelectingTheCurrentKeyPhaseIsTheDefaultPath() throws Exception {
        Context beforeUpdateDefault = endpoint(ConnectionEndType.CLIENT);
        Context beforeUpdateExplicit = endpoint(ConnectionEndType.CLIENT);
        assertArrayEquals(
                send(beforeUpdateDefault, 5),
                send(beforeUpdateExplicit, 5, QuicKeyPhaseSelection.CURRENT));

        Context afterUpdateDefault = endpoint(ConnectionEndType.CLIENT);
        Context afterUpdateExplicit = endpoint(ConnectionEndType.CLIENT);
        QuicPacketCryptoComputations.initiateKeyUpdate(afterUpdateDefault.getQuicContext());
        QuicPacketCryptoComputations.initiateKeyUpdate(afterUpdateExplicit.getQuicContext());
        assertArrayEquals(
                send(afterUpdateDefault, 6),
                send(afterUpdateExplicit, 6, QuicKeyPhaseSelection.CURRENT));
    }

    @Test
    public void testDefaultPathIsUnchangedWhenNoKeyUpdateHappens() throws Exception {
        Context client = endpoint(ConnectionEndType.CLIENT);
        Context server = endpoint(ConnectionEndType.SERVER);

        byte[] datagram = send(client, 5);

        assertEquals(GOLDEN_DEFAULT_PATH_PACKET, DataConverter.bytesToRawHexString(datagram));
        assertGoldenApplicationKeys(client.getQuicContext());
        assertGoldenApplicationKeys(server.getQuicContext());

        OneRTTPacket received = receive(server, datagram);
        assertCarriesPayload(received);

        // The pre-patch expression for the first byte, spelled out.
        byte expectedFlags =
                (byte)
                        (QuicPacketType.ONE_RTT_PACKET.getHeader(
                                        client.getQuicContext().getQuicVersion())
                                ^ (received.getPacketNumberLength().getValue() - 1));
        assertEquals(expectedFlags, received.getUnprotectedFlags().getValue());
        assertEquals(0, received.getUnprotectedFlags().getValue() & MiscRfcConstants.KEY_PHASE_BIT);

        // No key phase moved and no previous keys were retained on either side.
        for (Context context : new Context[] {client, server}) {
            QuicContext quicContext = context.getQuicContext();
            for (ConnectionEndType endType : ConnectionEndType.values()) {
                assertEquals(0, quicContext.getApplicationKeyPhase(endType));
                assertNull(quicContext.getPreviousApplicationKey(endType));
                assertNull(quicContext.getPreviousApplicationIv(endType));
            }
        }

        assertGoldenApplicationKeys(client.getQuicContext());
        assertGoldenApplicationKeys(server.getQuicContext());
    }

    private static void assertGoldenApplicationKeys(QuicContext quicContext) {
        assertEquals(
                GOLDEN_CLIENT_KEY,
                DataConverter.bytesToRawHexString(quicContext.getApplicationClientKey()));
        assertEquals(
                GOLDEN_CLIENT_IV,
                DataConverter.bytesToRawHexString(quicContext.getApplicationClientIv()));
        assertEquals(
                GOLDEN_CLIENT_HP,
                DataConverter.bytesToRawHexString(
                        quicContext.getApplicationClientHeaderProtectionKey()));
        assertEquals(
                GOLDEN_SERVER_KEY,
                DataConverter.bytesToRawHexString(quicContext.getApplicationServerKey()));
        assertEquals(
                GOLDEN_SERVER_IV,
                DataConverter.bytesToRawHexString(quicContext.getApplicationServerIv()));
        assertEquals(
                GOLDEN_SERVER_HP,
                DataConverter.bytesToRawHexString(
                        quicContext.getApplicationServerHeaderProtectionKey()));
    }

    @Test
    public void testInitiateQuicKeyUpdateActionUpdatesTheKeys() throws Exception {
        State state = endpointState(ConnectionEndType.CLIENT);
        QuicContext quicContext = state.getContext().getQuicContext();

        new InitiateQuicKeyUpdateAction(state.getContext().getConnection().getAlias())
                .execute(state);

        assertEquals(1, quicContext.getApplicationKeyPhase(ConnectionEndType.CLIENT));
        assertEquals(1, quicContext.getApplicationKeyPhase(ConnectionEndType.SERVER));
    }
}
