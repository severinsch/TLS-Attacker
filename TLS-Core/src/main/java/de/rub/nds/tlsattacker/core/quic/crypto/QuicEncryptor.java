/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.crypto;

import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.quic.constants.QuicKeyPhaseSelection;
import de.rub.nds.tlsattacker.core.quic.packet.HandshakePacket;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.quic.packet.OneRTTPacket;
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
 * The QuicEncryptor encrypts {@link QuicPacket} objects. It uses the {@link Chooser} to get the
 * necessary keys and cipher.
 */
public class QuicEncryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Chooser chooser;

    public QuicEncryptor(Chooser chooser) {
        this.chooser = chooser;
    }

    public void addHeaderProtectionInitial(InitialPacket packet) throws CryptoException {
        this.addHeaderProtection(
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

    public void addHeaderProtectionHandshake(HandshakePacket packet) throws CryptoException {
        this.addHeaderProtection(
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

    public void addHeaderProtectionZeroRTT(QuicPacket packet) throws CryptoException {
        this.addHeaderProtection(
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

    public void addHeaderProtectionOneRRT(QuicPacket packet) throws CryptoException {
        this.addHeaderProtection(
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

    private void addHeaderProtection(
            QuicPacket packet,
            byte[] serverHeaderProtectionMask,
            byte[] clientHeaderProtectionMask) {
        ConnectionEndType connectionEndType = chooser.getTalkingConnectionEnd();
        byte[] headerProtectionMask;

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

        byte encryptedFlags;
        byte flags = packet.getUnprotectedFlags().getValue();
        byte hpMask = headerProtectionMask[0];

        if (packet instanceof OneRTTPacket) {
            encryptedFlags = (byte) (flags ^ hpMask & (byte) 0x1f);
        } else {
            encryptedFlags = (byte) (flags ^ hpMask & (byte) 0x0f);
        }
        packet.setProtectedFlags(encryptedFlags);

        byte[] unprotectedPacketNumber = packet.getUnprotectedPacketNumber().getValue();
        byte[] result = new byte[packet.getPacketNumberLength().getValue()];
        for (int i = 0; i < packet.getPacketNumberLength().getValue(); i++) {
            result[i] = (byte) (unprotectedPacketNumber[i] ^ headerProtectionMask[i + 1]);
        }
        packet.setProtectedPacketNumber(result);
    }

    public void encryptInitialPacket(InitialPacket packet) throws CryptoException {
        this.encrypt(
                packet,
                chooser.getQuicInitialServerIv(),
                chooser.getQuicInitialServerKey(),
                chooser.getQuicInitialClientIv(),
                chooser.getQuicInitialClientKey(),
                chooser.getQuicInitialAeadCipher());
    }

    public void encryptHandshakePacket(HandshakePacket packet) throws CryptoException {
        this.encrypt(
                packet,
                chooser.getQuicHandshakeServerIv(),
                chooser.getQuicHandshakeServerKey(),
                chooser.getQuicHandshakeClientIv(),
                chooser.getQuicHandshakeClientKey(),
                chooser.getQuicAeadCipher());
    }

    /**
     * Protects a 1-RTT packet with the key generation it selects, by default the current one.
     *
     * @param packet the packet to protect
     * @throws CryptoException if the packet cannot be protected with the selected generation
     */
    public void encryptOneRRTPacket(QuicPacket packet) throws CryptoException {
        if (packet instanceof OneRTTPacket oneRTTPacket
                && oneRTTPacket.getKeyPhaseSelection() == QuicKeyPhaseSelection.PREVIOUS) {
            this.encryptWithPreviousApplicationKeys(oneRTTPacket);
            return;
        }
        this.encrypt(
                packet,
                chooser.getQuicApplicationServerIv(),
                chooser.getQuicApplicationServerKey(),
                chooser.getQuicApplicationClientIv(),
                chooser.getQuicApplicationClientKey(),
                chooser.getQuicAeadCipher());
    }

    /**
     * Protects a 1-RTT packet with the keys the last key update replaced. They are read from the
     * context, not the chooser, whose fallback to configured defaults would silently use unrelated
     * keys.
     *
     * @param packet the packet to protect
     * @throws CryptoException if there are no previous keys, or the packet cannot be protected
     */
    private void encryptWithPreviousApplicationKeys(OneRTTPacket packet) throws CryptoException {
        QuicContext quicContext = chooser.getContext().getQuicContext();
        ConnectionEndType writeEndType = chooser.getTalkingConnectionEnd();
        byte[] previousIv = quicContext.getPreviousApplicationIv(writeEndType);
        byte[] previousKey = quicContext.getPreviousApplicationKey(writeEndType);
        if (previousIv == null || previousKey == null) {
            throw new CryptoException(
                    "Cannot protect a 1-RTT packet with the previous key phase: no key update has"
                            + " replaced the "
                            + writeEndType
                            + " application keys, so there is no previous generation");
        }
        LOGGER.debug(
                "Protecting a 1-RTT packet with the previous key phase, which RFC 9001 section 6.4 tells the peer to answer with KEY_UPDATE_ERROR");
        this.encryptWith(packet, previousIv, previousKey, chooser.getQuicAeadCipher());
    }

    public void encryptZeroRTTPacket(QuicPacket packet) throws CryptoException {
        this.encrypt(
                packet,
                chooser.getQuicZeroRTTServerIv(),
                chooser.getQuicZeroRTTServerKey(),
                chooser.getQuicZeroRTTClientIv(),
                chooser.getQuicZeroRTTClientKey(),
                chooser.getQuicZeroRTTAeadCipher());
    }

    private void encrypt(
            QuicPacket packet,
            byte[] serverIv,
            byte[] serverKey,
            byte[] clientIv,
            byte[] clientKey,
            String cipherAlgorithm)
            throws CryptoException {
        ConnectionEndType connectionEndType = chooser.getTalkingConnectionEnd();
        byte[] encryptionIv;
        byte[] encryptionKey;

        switch (connectionEndType) {
            case SERVER:
                encryptionIv = serverIv;
                encryptionKey = serverKey;
                break;
            case CLIENT:
                encryptionIv = clientIv;
                encryptionKey = clientKey;
                break;
            default:
                LOGGER.error("Unknown connectionEndType: {}", connectionEndType);
                return;
        }
        encryptWith(packet, encryptionIv, encryptionKey, cipherAlgorithm);
    }

    /**
     * Protects a packet with the given key and IV.
     *
     * @param packet the packet to protect
     * @param encryptionIv the packet protection IV
     * @param encryptionKey the packet protection key
     * @param cipherAlgorithm the AEAD algorithm
     * @throws CryptoException if the packet cannot be protected
     */
    private void encryptWith(
            QuicPacket packet, byte[] encryptionIv, byte[] encryptionKey, String cipherAlgorithm)
            throws CryptoException {
        byte[] decryptedPayload = packet.getUnprotectedPayload().getValue();
        byte[] nonce = new byte[12];
        byte[] paddedPacketNumber = new byte[12];

        for (int i = 0; i < (12 - packet.getUnprotectedPacketNumber().getValue().length); i++) {
            paddedPacketNumber[i] = 0x00;
        }
        for (int i = (12 - packet.getUnprotectedPacketNumber().getValue().length), x = 0;
                i < 12;
                i++, x++) {
            paddedPacketNumber[i] = packet.getUnprotectedPacketNumber().getValue()[x];
        }
        for (int i = 0; i < nonce.length; i++) {
            nonce[i] = (byte) (encryptionIv[i] ^ paddedPacketNumber[i]);
        }

        byte[] associatedData = packet.completeUnprotectedHeader.getValue();

        try {
            byte[] encryptedPayload =
                    aeadEncrypt(
                            associatedData,
                            decryptedPayload,
                            nonce,
                            encryptionKey,
                            cipherAlgorithm);
            packet.setProtectedPayload(encryptedPayload);
        } catch (IllegalStateException
                | IllegalBlockSizeException
                | BadPaddingException
                | InvalidKeyException
                | IllegalArgumentException ex) {
            throw new CryptoException("Could not encrypt " + packet.getPacketType().getName(), ex);
        } catch (InvalidAlgorithmParameterException ex) {
            LOGGER.info("Ignoring InvalidArgumentException");
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new CryptoException("Could not encrypt " + packet.getPacketType().getName(), e);
        }
    }

    private byte[] aeadEncrypt(
            byte[] associatedData,
            byte[] plaintext,
            byte[] nonce,
            byte[] key,
            String cipherAlgorithm)
            throws InvalidKeyException,
                    IllegalBlockSizeException,
                    BadPaddingException,
                    NoSuchPaddingException,
                    NoSuchAlgorithmException,
                    InvalidAlgorithmParameterException {
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
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algo), parameterSpec);
        cipher.updateAAD(associatedData);
        return cipher.doFinal(plaintext);
    }
}
