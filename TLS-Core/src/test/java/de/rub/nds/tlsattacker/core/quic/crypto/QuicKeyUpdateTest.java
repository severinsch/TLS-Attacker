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
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * QUIC key update, RFC 9001 section 6.
 *
 * <p>Two endpoints are built over one fixed pair of application traffic secrets and driven against
 * each other through the real preparator, encryptor, parser and decryptor, so what these tests
 * exercise is the packet as it goes on the wire rather than the key schedule alone.
 */
public class QuicKeyUpdateTest {

    /**
     * The application write secret of RFC 9001 Appendix A.5, together with everything that appendix
     * derives from it. The appendix uses AEAD_CHACHA20_POLY1305, so the key length is 32 and the
     * KDF is HKDF-SHA256.
     */
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

    /**
     * The packet and the key material {@link #testDefaultPathIsUnchangedWhenNoKeyUpdateHappens}
     * produces, recorded by running the same fixture against this code with the key update change
     * reverted. Any change to them means the default path moved.
     */
    private static final String GOLDEN_DEFAULT_PATH_PACKET =
            "49111213141516171838888D82084D4C8DA884E402015F60E9E5C4FA567A7AD1A902A69D70"
                    + "09D92546B0CAFF28D10B1D3E597D499D31A2C5DD647652E2D7C5F8748E1E7625AC9151E"
                    + "C81DB48DC5841BF3CDDF6D3C5E62CF4F70BB10A45FCD1ABAA3DD5B2F08257E6D2FF8899"
                    + "18C2666BDAA4652E0540186519403244D71B";

    /**
     * The packet {@link #testKeyPhaseRetentionDoesNotMoveThePacketSentAfterAnUpdate} produces,
     * recorded by running the same fixture against this code with the write key retention reverted,
     * and the generation-1 client key and IV that protect it. Retaining a key an endpoint used to
     * write with cannot change what it writes, and this is what says so in bytes.
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

    // region fixtures

    /**
     * An endpoint with 1-RTT keys in place for both directions, derived from the fixed secrets
     * above with TLS_AES_128_GCM_SHA256.
     */
    private static Context endpoint(ConnectionEndType localEndType)
            throws CryptoException, NoSuchAlgorithmException {
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);
        if (localEndType == ConnectionEndType.SERVER) {
            ServerDelegate serverDelegate = new ServerDelegate();
            serverDelegate.setPort(4433);
            serverDelegate.applyDelegate(config);
        }
        Context context = new State(config).getContext();
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
        return context;
    }

    /** Prepares, protects and serializes one 1-RTT packet, as the packet layer does. */
    private static byte[] send(Context sender, int packetNumber) throws CryptoException {
        return send(sender, packetNumber, null);
    }

    /**
     * The same, with an explicit selection of the generation of application keys to protect the
     * packet with. A null selection is the default path: nobody touched the packet's key phase.
     */
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

    // endregion

    /**
     * The key schedule of RFC 9001 section 6.1, against the vectors of Appendix A.5. The appendix
     * publishes the key, the IV, the header protection key and the next generation's secret ("ku")
     * for one concrete application secret, which pins both the generation an endpoint starts from
     * and the one a key update produces.
     */
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
        // The appendix stops at the secret. The key and IV of the next generation are section 5.1
        // applied to it, which is the derivation the appendix's own key and IV above just pinned.
        assertEquals(A5_KEY.length, next.key().length);
        assertEquals(A5_IV.length, next.iv().length);
        assertFalse(Arrays.equals(A5_KEY, next.key()));
        assertFalse(Arrays.equals(A5_IV, next.iv()));

        // Deriving must not have touched the context: RFC 9001 section 6.3 requires the next keys
        // to be usable for a trial decryption before anything is committed.
        assertArrayEquals(A5_SECRET, quicContext.getApplicationServerSecret());
        assertArrayEquals(A5_KEY, quicContext.getApplicationServerKey());
        assertEquals(0, quicContext.getApplicationKeyPhase(ConnectionEndType.SERVER));
    }

    /**
     * RFC 9001 section 6.1: "The header protection key is not updated." A key update replaces the
     * secret, the key and the IV of both directions and leaves both header protection keys alone.
     */
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

        // Both directions move: "The endpoint that initiates a key update also updates the keys
        // that it uses for receiving packets" (section 6.1).
        assertEquals(1, quicContext.getApplicationKeyPhase(ConnectionEndType.CLIENT));
        assertEquals(1, quicContext.getApplicationKeyPhase(ConnectionEndType.SERVER));

        // Both directions retain the generation they replaced: the read direction because RFC 9001
        // sections 6.1 and 6.5 require it, the write direction because section 6.4 permits it and
        // nothing else can produce the packet that section tells a receiver to reject.
        assertArrayEquals(
                clientKey, quicContext.getPreviousApplicationKey(ConnectionEndType.CLIENT));
        assertArrayEquals(clientIv, quicContext.getPreviousApplicationIv(ConnectionEndType.CLIENT));
        assertArrayEquals(
                serverKey, quicContext.getPreviousApplicationKey(ConnectionEndType.SERVER));
        assertArrayEquals(serverIv, quicContext.getPreviousApplicationIv(ConnectionEndType.SERVER));
    }

    /**
     * A packet protected with the second generation of keys carries Key Phase 1 (RFC 9001 section
     * 6) and is unprotected by a peer that had not updated yet, which responds by updating its own
     * send keys (section 6.2).
     */
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

        // The responding endpoint updated both directions (section 6.2), so both endpoints hold
        // the same material again and the connection keeps working.
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

    /**
     * RFC 9001 section 6.5: "A recovered packet number that is lower than any packet number from
     * the current key phase uses the previous packet protection keys." A packet the network delayed
     * across the update still decrypts, and is not mistaken for a second key update.
     */
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

    /**
     * RFC 9001 sections 6.3 and 9.5: the Key Phase bit is not authenticated and "Packets containing
     * apparent key updates are easy to forge". A packet whose Key Phase bit claims an update it was
     * not protected with must be rejected and must leave every key and every key phase where it
     * was; otherwise anyone able to send a datagram could rotate this endpoint's keys.
     */
    @Test
    public void testForgedKeyPhaseBitDoesNotRotateKeys() throws Exception {
        Context client = endpoint(ConnectionEndType.CLIENT);
        Context server = endpoint(ConnectionEndType.SERVER);
        receive(server, send(client, 5));

        // Announce key phase 1 without deriving the second generation, so the packet is protected
        // with generation 0 while its header claims generation 1.
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

    /**
     * RFC 9001 section 6.4, the send side. A packet may be protected with the generation a key
     * update replaced, and it then carries that generation's Key Phase bit rather than the
     * endpoint's current one - which is the whole point, since the bit is what tells the receiver
     * which keys to try.
     *
     * <p>A conforming endpoint never sends this packet: "An endpoint never sends packets that are
     * protected with old keys." Its receiver, however, owes an answer to it, and that answer is a
     * MUST: "Packets with higher packet numbers MUST be protected with either the same or newer
     * packet protection keys than packets with lower packet numbers. An endpoint that successfully
     * removes protection with old keys when newer keys were used for packets with lower packet
     * numbers MUST treat this as a connection error of type KEY_UPDATE_ERROR." Nothing else can
     * produce the stimulus that rule is about.
     *
     * <p>That the packet really is protected with the replaced generation is shown by a peer that
     * has not seen the update yet: the replaced generation is still its current one, so it reads
     * the packet with the keys it already had.
     */
    @Test
    public void testPacketMayBeProtectedWithThePreviousKeyPhase() throws Exception {
        Context client = endpoint(ConnectionEndType.CLIENT);
        Context server = endpoint(ConnectionEndType.SERVER);
        receive(server, send(client, 5));

        QuicPacketCryptoComputations.initiateKeyUpdate(client.getQuicContext());
        assertEquals(1, client.getQuicContext().getApplicationKeyPhase(ConnectionEndType.CLIENT));

        byte[] datagram = send(client, 6, QuicKeyPhaseSelection.PREVIOUS);
        OneRTTPacket sentWithOldKeys = receive(server, datagram);

        // The bit announces the generation the packet was protected with, not the one the sender
        // has moved on to.
        assertEquals(0, keyPhaseBitOf(sentWithOldKeys));
        assertCarriesPayload(sentWithOldKeys);
        // The peer never saw a key update, so nothing about its key state moved.
        assertEquals(0, server.getQuicContext().getApplicationKeyPhase(ConnectionEndType.CLIENT));
        assertEquals(0, server.getQuicContext().getApplicationKeyPhase(ConnectionEndType.SERVER));

        // And the sender is unchanged by it: the selection is a property of that one packet, so
        // the next packet goes out at the current generation again and the peer follows it.
        OneRTTPacket afterwards = receive(server, send(client, 7));
        assertEquals(1, client.getQuicContext().getApplicationKeyPhase(ConnectionEndType.CLIENT));
        assertEquals(1, keyPhaseBitOf(afterwards));
        assertCarriesPayload(afterwards);
    }

    /**
     * The previous generation cannot be selected before a key update has produced one. Falling back
     * to the current generation would send a conforming packet in answer to a request for a
     * non-conforming one, and the peer's reply would then be read as evidence about RFC 9001
     * section 6.4 while having nothing to do with it.
     */
    @Test
    public void testPreviousKeyPhaseIsRefusedBeforeAnyKeyUpdate() throws Exception {
        Context client = endpoint(ConnectionEndType.CLIENT);

        CryptoException refused =
                assertThrows(
                        CryptoException.class,
                        () -> send(client, 5, QuicKeyPhaseSelection.PREVIOUS));
        assertTrue(refused.getMessage().contains("previous key phase"));

        // Nothing was consumed by the refusal: the endpoint is still on generation 0 and still
        // sends normally.
        assertEquals(0, client.getQuicContext().getApplicationKeyPhase(ConnectionEndType.CLIENT));
        Context server = endpoint(ConnectionEndType.SERVER);
        assertCarriesPayload(receive(server, send(client, 5)));
    }

    /**
     * The default path after a key update, in bytes. Retaining the write keys a key update replaced
     * adds a value to the context and nothing else: the packet an endpoint sends once it has
     * updated is byte for byte the packet the same fixture produces with the retention reverted,
     * and it is protected with the new generation, not the retained one.
     */
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

        // The retained generation is the one the golden values are NOT, which is what makes the
        // comparison mean something.
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

    /**
     * The selection is the only thing that changes anything. A packet that asks for the current
     * generation is byte for byte a packet that asks for nothing, both before and after a key
     * update, so retaining the replaced write keys cannot move a run that never selects them.
     */
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

    /**
     * The default path. With no key update anywhere, the first byte is exactly what it was before
     * the Key Phase bit existed in this code, the serialized packet is byte for byte the recorded
     * one, and no key phase state moves.
     */
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

    /**
     * Re-deriving the generation-0 application secrets must also reset the key update state.
     *
     * <p>Regression test for a defect found in review: {@code calculateApplicationSecrets} wrote
     * generation-0 key material back into the context while leaving the key phase counters at
     * whatever generation a previous update had reached. The result is a context that sets the Key
     * Phase bit on packets protected with the OLD key, and decrypts the peer's genuine new-phase
     * packets with it - the connection dies in both directions and looks exactly like the peer
     * going silent. Reachable because {@code FinishedHandler} re-derives on a retransmitted
     * Finished flight.
     */
    @Test
    public void testRederivingApplicationSecretsResetsTheKeyUpdateState() throws Exception {
        Context client = endpoint(ConnectionEndType.CLIENT);
        QuicContext clientQuic = client.getQuicContext();

        QuicPacketCryptoComputations.initiateKeyUpdate(clientQuic);
        assertEquals(1, clientQuic.getApplicationKeyPhase(ConnectionEndType.CLIENT));
        assertEquals(1, clientQuic.getApplicationKeyPhase(ConnectionEndType.SERVER));
        // Both directions have a previous generation after an update.
        assertNotNull(clientQuic.getPreviousApplicationKey(ConnectionEndType.CLIENT));
        assertNotNull(clientQuic.getPreviousApplicationKey(ConnectionEndType.SERVER));

        QuicPacketCryptoComputations.calculateApplicationSecrets(client);

        assertEquals(
                0,
                clientQuic.getApplicationKeyPhase(ConnectionEndType.CLIENT),
                "generation-0 keys were installed, so the client phase must say generation 0");
        assertEquals(
                0,
                clientQuic.getApplicationKeyPhase(ConnectionEndType.SERVER),
                "generation-0 keys were installed, so the server phase must say generation 0");
        assertNull(
                clientQuic.getPreviousApplicationKey(ConnectionEndType.CLIENT),
                "there is no previous generation once generation 0 is reinstalled");
        assertNull(
                clientQuic.getPreviousApplicationIv(ConnectionEndType.CLIENT),
                "there is no previous generation once generation 0 is reinstalled");
        assertNull(
                clientQuic.getPreviousApplicationKey(ConnectionEndType.SERVER),
                "there is no previous generation once generation 0 is reinstalled");
        assertEquals(
                Integer.MAX_VALUE,
                clientQuic.getLowestReceivedOneRTTPacketNumberInCurrentKeyPhase(),
                "the phase boundary must not survive a re-derivation");
    }
}
