/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.crypto;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.quic.constants.MiscRfcConstants;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.packet.HandshakePacket;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The QuicDecryptor decrypts {@link QuicPacket} objects. It uses the {@link Chooser} to get the
 * necessary keys and cipher.
 */
public class QuicDecryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Chooser chooser;
    private final QuicContext quicContext;

    public QuicDecryptor(Chooser chooser) {
        this.chooser = chooser;
        this.quicContext = chooser.getContext().getQuicContext();
    }

    public void removeHeaderProtectionInitial(InitialPacket packet) throws CryptoException {
        this.removeHeaderProtection(
                packet,
                QuicPacketCryptoComputations.generateHeaderProtectionMask(
                        chooser.getQuicInitialHeaderProtectionCipher(),
                        chooser.getQuicInitialServerHpKey(),
                        packet.getHeaderProtectionSample()),
                QuicPacketCryptoComputations.generateHeaderProtectionMask(
                        chooser.getQuicInitialHeaderProtectionCipher(),
                        chooser.getQuicInitialClientHpKey(),
                        packet.getHeaderProtectionSample()));
    }

    public void removeHeaderProtectionHandshake(HandshakePacket packet) throws CryptoException {
        this.removeHeaderProtection(
                packet,
                QuicPacketCryptoComputations.generateHeaderProtectionMask(
                        chooser.getQuicHeaderProtectionCipher(),
                        chooser.getQuicHandshakeServerHpKey(),
                        packet.getHeaderProtectionSample()),
                QuicPacketCryptoComputations.generateHeaderProtectionMask(
                        chooser.getQuicHeaderProtectionCipher(),
                        chooser.getQuicHandshakeClientHpKey(),
                        packet.getHeaderProtectionSample()));
    }

    public void removeHeaderProtectionZeroRTT(QuicPacket packet) throws CryptoException {
        this.removeHeaderProtection(
                packet,
                QuicPacketCryptoComputations.generateHeaderProtectionMask(
                        chooser.getQuicZeroRTTHeaderProtectionCipher(),
                        chooser.getQuicZeroRTTServerHpKey(),
                        packet.getHeaderProtectionSample()),
                QuicPacketCryptoComputations.generateHeaderProtectionMask(
                        chooser.getQuicZeroRTTHeaderProtectionCipher(),
                        chooser.getQuicZeroRTTClientHpKey(),
                        packet.getHeaderProtectionSample()));
    }

    public void removeHeaderProtectionOneRTT(QuicPacket packet) throws CryptoException {
        this.removeHeaderProtection(
                packet,
                QuicPacketCryptoComputations.generateHeaderProtectionMask(
                        chooser.getQuicHeaderProtectionCipher(),
                        chooser.getQuicApplicationServerHpKey(),
                        packet.getHeaderProtectionSample()),
                QuicPacketCryptoComputations.generateHeaderProtectionMask(
                        chooser.getQuicHeaderProtectionCipher(),
                        chooser.getQuicApplicationClientHpKey(),
                        packet.getHeaderProtectionSample()));
    }

    public void removeHeaderProtection(
            QuicPacket packet,
            byte[] serverHeaderProtectionMask,
            byte[] clientHeaderProtectionMask) {
        ConnectionEndType connectionEndType = chooser.getTalkingConnectionEnd();
        byte[] headerProtectionMask;

        // when attempting to read echoed ClientHello messages we have to use our keys for static
        // decryption
        if (chooser.getConfig().isEchoQuic()) {
            connectionEndType = connectionEndType.getPeer();
        }

        switch (connectionEndType) {
            case SERVER:
                headerProtectionMask = serverHeaderProtectionMask;
                break;
            case CLIENT:
                headerProtectionMask = clientHeaderProtectionMask;
                break;
            default:
                LOGGER.error("Unknown connectionEndType: {}", connectionEndType);
                return;
        }

        byte unprotectedFlags;
        byte flags = packet.getProtectedFlags().getValue();
        byte hpMask = headerProtectionMask[0];

        if (QuicPacketType.isShortHeaderPacket(flags)) {
            unprotectedFlags = (byte) (flags ^ hpMask & (byte) 0x1f);
        } else {
            unprotectedFlags = (byte) (flags ^ hpMask & (byte) 0x0f);
        }
        packet.setUnprotectedFlags(unprotectedFlags);

        int length = (unprotectedFlags & 0x03) + 1;
        packet.setPacketNumberLength(length);
        byte[] protectedPacketNumber = new byte[length];
        System.arraycopy(
                packet.getProtectedPacketNumberAndPayload().getValue(),
                0,
                protectedPacketNumber,
                0,
                length);
        packet.setProtectedPacketNumber(protectedPacketNumber);

        byte[] result = new byte[packet.getPacketNumberLength().getValue()];
        for (int i = 0; i < packet.getPacketNumberLength().getValue(); i++) {
            result[i] = (byte) (headerProtectionMask[i + 1] ^ protectedPacketNumber[i]);
        }
        packet.protectedHeaderHelper.write(result);
        packet.setUnprotectedPacketNumber(result);
        restorePacketNumber(packet);
    }

    private void restorePacketNumber(QuicPacket packet) {
        int largest_Pn = 0;
        switch (packet.getPacketType()) {
            case INITIAL_PACKET:
                if (!quicContext.getReceivedInitialPacketNumbers().isEmpty()) {
                    largest_Pn = quicContext.getReceivedInitialPacketNumbers().getLast();
                }
                break;
            case HANDSHAKE_PACKET:
                if (!quicContext.getReceivedHandshakePacketNumbers().isEmpty()) {
                    largest_Pn = quicContext.getReceivedHandshakePacketNumbers().getLast();
                }
                break;
            case ONE_RTT_PACKET:
                if (!quicContext.getReceivedOneRTTPacketNumbers().isEmpty()) {
                    largest_Pn = quicContext.getReceivedOneRTTPacketNumbers().getLast();
                }
                break;
            default:
                break;
        }

        int truncated_Pn = DataConverter.bytesToInt(packet.getUnprotectedPacketNumber().getValue());
        int pn_nBits = packet.getPacketNumberLength().getValue() * 8;
        long decodedPn = packet.decodePacketNumber(truncated_Pn, largest_Pn, pn_nBits);
        LOGGER.debug(
                "Decoded pktNumber: {}, raw pktNumber: {}",
                decodedPn,
                DataConverter.bytesToInt(packet.getUnprotectedPacketNumber().getValue()));

        packet.setRestoredPacketNumber((int) decodedPn);
        packet.setPlainPacketNumber((int) decodedPn);

        if (packet.getUnprotectedPacketNumber().getValue().length
                >= packet.getRestoredPacketNumber().getValue().length) {
            packet.setRestoredPacketNumber(packet.getUnprotectedPacketNumber().getValue());
            packet.setPlainPacketNumber(
                    DataConverter.bytesToInt(packet.getUnprotectedPacketNumber().getValue()));
        }
    }

    public void decryptInitialPacket(InitialPacket packet) throws CryptoException {
        this.decrypt(
                packet,
                chooser.getQuicInitialServerIv(),
                chooser.getQuicInitialServerKey(),
                chooser.getQuicInitialClientIv(),
                chooser.getQuicInitialClientKey(),
                chooser.getQuicInitialAeadCipher());
    }

    public void decryptHandshakePacket(HandshakePacket packet) throws CryptoException {
        this.decrypt(
                packet,
                chooser.getQuicHandshakeServerIv(),
                chooser.getQuicHandshakeServerKey(),
                chooser.getQuicHandshakeClientIv(),
                chooser.getQuicHandshakeClientKey(),
                chooser.getQuicAeadCipher());
    }

    /**
     * Removes the packet protection of a 1-RTT packet, selecting the key generation the Key Phase
     * bit and the packet number point at (RFC 9001 sections 6.2 and 6.5).
     *
     * <p>The Key Phase bit is protected (RFC 9001 section 5.4.1 lists it among the bits header
     * protection covers), so this can only run after {@link #removeHeaderProtectionOneRTT}, which
     * also recovers the full packet number this method needs.
     *
     * <p>Three cases, in the order the RFC resolves them:
     *
     * <ol>
     *   <li>The bit matches the generation currently read with: the normal case, and the only one
     *       that occurs while neither endpoint ever updates its keys.
     *   <li>The bit differs and the packet number is lower than any unprotected so far in the
     *       current generation: RFC 9001 section 6.5, "A recovered packet number that is lower than
     *       any packet number from the current key phase uses the previous packet protection keys".
     *       Packets the network delayed across a key update land here.
     *   <li>The bit differs otherwise: an apparent peer-initiated key update. The next generation
     *       is derived and tried, and the update is committed only if the packet authenticates
     *       under it (RFC 9001 section 6.2). A packet that does not authenticate leaves every key
     *       and every key phase untouched, which is what stops a forged Key Phase bit from being a
     *       denial of service against this endpoint (sections 6.3 and 9.5).
     * </ol>
     *
     * @param packet the packet to decrypt, with header protection already removed
     * @throws CryptoException if the packet does not authenticate under the selected keys
     */
    public void decryptOneRTTPacket(QuicPacket packet) throws CryptoException {
        ConnectionEndType protectingEndType = resolveProtectingConnectionEnd();
        if (protectingEndType == null) {
            LOGGER.error("Unknown connectionEndType: {}", chooser.getTalkingConnectionEnd());
            return;
        }
        byte[] currentIv;
        byte[] currentKey;
        if (protectingEndType == ConnectionEndType.SERVER) {
            currentIv = chooser.getQuicApplicationServerIv();
            currentKey = chooser.getQuicApplicationServerKey();
        } else {
            currentIv = chooser.getQuicApplicationClientIv();
            currentKey = chooser.getQuicApplicationClientKey();
        }
        String cipherAlgorithm = chooser.getQuicAeadCipher();

        int receivedKeyPhase =
                (packet.getUnprotectedFlags().getValue() & MiscRfcConstants.KEY_PHASE_BIT) == 0
                        ? 0
                        : 1;
        int currentKeyPhase = quicContext.getApplicationKeyPhase(protectingEndType) & 1;

        if (receivedKeyPhase == currentKeyPhase) {
            decryptWith(packet, currentIv, currentKey, cipherAlgorithm);
            noteCurrentKeyPhasePacketNumber(packet);
            return;
        }

        byte[] previousIv = quicContext.getPreviousApplicationIv(protectingEndType);
        byte[] previousKey = quicContext.getPreviousApplicationKey(protectingEndType);
        if (previousIv != null
                && previousKey != null
                && packet.getPlainPacketNumber()
                        < quicContext.getLowestReceivedOneRTTPacketNumberInCurrentKeyPhase()) {
            LOGGER.debug(
                    "1-RTT packet {} carries the previous key phase, decrypting it with the retained keys",
                    packet.getPlainPacketNumber());
            decryptWith(packet, previousIv, previousKey, cipherAlgorithm);
            return;
        }

        QuicPacketCryptoComputations.ApplicationKeyMaterial nextKeys;
        try {
            nextKeys =
                    QuicPacketCryptoComputations.calculateNextApplicationSecrets(
                            quicContext, protectingEndType);
        } catch (CryptoException | NoSuchAlgorithmException unavailable) {
            // Without the peer's current application secret there is no next generation to try.
            // Fall back to the current keys, which is what this endpoint did with every 1-RTT
            // packet before key updates were implemented. The packet number is deliberately not
            // recorded as belonging to the current key phase: its Key Phase bit says it does not.
            LOGGER.debug(
                    "Cannot derive the next application secrets, decrypting with the current ones",
                    unavailable);
            decryptWith(packet, currentIv, currentKey, cipherAlgorithm);
            return;
        }

        // Throws if the packet does not authenticate, before anything is committed.
        decryptWith(packet, nextKeys.iv(), nextKeys.key(), cipherAlgorithm);
        try {
            QuicPacketCryptoComputations.completePeerInitiatedKeyUpdate(
                    quicContext, protectingEndType, nextKeys);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Could not update the send keys after a key update", e);
        }
        noteCurrentKeyPhasePacketNumber(packet);
    }

    /**
     * Records a packet number as belonging to the key phase currently read with, which is what RFC
     * 9001 section 6.5 compares a later packet's number against to tell the previous generation
     * from the next one.
     *
     * @param packet a packet just unprotected with the current generation's keys
     */
    private void noteCurrentKeyPhasePacketNumber(QuicPacket packet) {
        int packetNumber = packet.getPlainPacketNumber();
        if (packetNumber < quicContext.getLowestReceivedOneRTTPacketNumberInCurrentKeyPhase()) {
            quicContext.setLowestReceivedOneRTTPacketNumberInCurrentKeyPhase(packetNumber);
        }
    }

    public void decryptZeroRTTPacket(QuicPacket packet) throws CryptoException {
        this.decrypt(
                packet,
                chooser.getQuicZeroRTTServerIv(),
                chooser.getQuicZeroRTTServerKey(),
                chooser.getQuicZeroRTTClientIv(),
                chooser.getQuicZeroRTTClientKey(),
                chooser.getQuicZeroRTTAeadCipher());
    }

    /**
     * The connection end whose packet protection keys protect the packets currently being read.
     *
     * @return that connection end, or null if it is unknown
     */
    private ConnectionEndType resolveProtectingConnectionEnd() {
        ConnectionEndType connectionEndType = chooser.getTalkingConnectionEnd();
        if (connectionEndType == null) {
            return null;
        }
        // when attempting to read echoed ClientHello messages we have to use our keys for static
        // decryption
        if (chooser.getConfig().isEchoQuic()) {
            connectionEndType = connectionEndType.getPeer();
        }
        return connectionEndType;
    }

    private void decrypt(
            QuicPacket packet,
            byte[] serverIv,
            byte[] serverKey,
            byte[] clientIv,
            byte[] clientKey,
            String cipherAlgorithm)
            throws CryptoException {
        ConnectionEndType connectionEndType = resolveProtectingConnectionEnd();
        byte[] decryptionIv;
        byte[] decryptionKey;

        if (connectionEndType == ConnectionEndType.SERVER) {
            decryptionIv = serverIv;
            decryptionKey = serverKey;
        } else if (connectionEndType == ConnectionEndType.CLIENT) {
            decryptionIv = clientIv;
            decryptionKey = clientKey;
        } else {
            LOGGER.error("Unknown connectionEndType: {}", connectionEndType);
            return;
        }
        decryptWith(packet, decryptionIv, decryptionKey, cipherAlgorithm);
    }

    /**
     * Removes the packet protection of a packet with one specific key and IV. Every caller has
     * already resolved which connection end, and for 1-RTT packets which key generation, the
     * material belongs to.
     *
     * @param packet the packet to decrypt
     * @param decryptionIv the packet protection IV
     * @param decryptionKey the packet protection key
     * @param cipherAlgorithm the AEAD algorithm
     * @throws CryptoException if the packet does not authenticate under this material
     */
    private void decryptWith(
            QuicPacket packet, byte[] decryptionIv, byte[] decryptionKey, String cipherAlgorithm)
            throws CryptoException {
        byte[] encryptedPayload =
                new byte
                        [packet.getPacketLength().getValue()
                                - packet.getPacketNumberLength().getValue()];
        System.arraycopy(
                packet.getProtectedPacketNumberAndPayload().getValue(),
                packet.getPacketNumberLength().getValue(),
                encryptedPayload,
                0,
                packet.getPacketLength().getValue() - packet.getPacketNumberLength().getValue());

        byte[] nonce = new byte[12];
        byte[] paddedPacketNumber = new byte[12];

        for (int i = 0; i < (12 - packet.getRestoredPacketNumber().getValue().length); i++) {
            paddedPacketNumber[i] = 0x00;
        }
        for (int i = (12 - packet.getRestoredPacketNumber().getValue().length), x = 0;
                i < 12;
                i++, x++) {
            paddedPacketNumber[i] = packet.getRestoredPacketNumber().getValue()[x];
        }
        for (int i = 0; i < nonce.length; i++) {
            nonce[i] = (byte) (decryptionIv[i] ^ paddedPacketNumber[i]);
        }

        byte[] associatedData =
                new byte
                        [packet.offsetToPacketNumber
                                + packet.getUnprotectedPacketNumber().getValue().length];
        System.arraycopy(
                packet.completeUnprotectedHeader.getValue(),
                0,
                associatedData,
                0,
                packet.offsetToPacketNumber
                        + packet.getUnprotectedPacketNumber().getValue().length);

        try {
            byte[] decryptedPayload =
                    aeadDecrypt(
                            associatedData,
                            encryptedPayload,
                            nonce,
                            decryptionKey,
                            cipherAlgorithm);
            packet.setUnprotectedPayload(decryptedPayload);
        } catch (IllegalStateException
                | IllegalBlockSizeException
                | BadPaddingException
                | InvalidKeyException
                | IllegalArgumentException
                | InvalidAlgorithmParameterException
                | NoSuchPaddingException
                | NoSuchAlgorithmException ex) {
            throw new CryptoException("Could not decrypt " + packet.getPacketType().getName(), ex);
        }
    }

    public byte[] aeadDecrypt(
            byte[] associatedData,
            byte[] ciphertext,
            byte[] nonce,
            byte[] key,
            String cipherAlgorithm)
            throws InvalidAlgorithmParameterException,
                    InvalidKeyException,
                    IllegalBlockSizeException,
                    BadPaddingException,
                    NoSuchPaddingException,
                    NoSuchAlgorithmException {
        AlgorithmParameterSpec parameterSpec;
        String algo;
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        if (cipherAlgorithm.equals("ChaCha20-Poly1305")) {
            algo = "ChaCha20";
            parameterSpec = new IvParameterSpec(nonce);
        } else {
            algo = "AES";
            parameterSpec = new GCMParameterSpec(128, nonce);
        }
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algo), parameterSpec);
        cipher.updateAAD(associatedData);
        return cipher.doFinal(ciphertext);
    }
}
