/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.packet;

import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.quic.constants.QuicRetryConstants;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class QuicPacketCryptoComputations extends ModifiableVariableHolder {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int INITIAL_KEY_LENGTH = 16;
    private static final int IV_LENGTH = 12;

    public QuicPacketCryptoComputations() {}

    /** Generates header protection mask. */
    public static byte[] generateHeaderProtectionMask(
            String cipherAlgorithm, byte[] headerProtectionKey, byte[] sample)
            throws CryptoException {
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            byte[] mask;
            if (cipherAlgorithm.equals("ChaCha20")) {
                // Based on RFC 9001 Section 5.4.4
                // https://www.rfc-editor.org/rfc/rfc9001#name-chacha20-based-header-prote
                ByteBuffer wrapped = ByteBuffer.wrap(Arrays.copyOfRange(sample, 0, 4));
                wrapped.order(ByteOrder.LITTLE_ENDIAN);
                int counter = wrapped.getInt();
                byte[] nonce = Arrays.copyOfRange(sample, 4, 16);
                ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, counter);
                SecretKeySpec keySpec = new SecretKeySpec(headerProtectionKey, cipherAlgorithm);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, param);
                mask = cipher.doFinal(new byte[] {0, 0, 0, 0, 0});
            } else {
                // Based on RFC 9001 Section 5.4.3
                // https://www.rfc-editor.org/rfc/rfc9001#name-aes-based-header-protection
                SecretKeySpec keySpec = new SecretKeySpec(headerProtectionKey, "AES");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
                mask = cipher.doFinal(sample);
            }
            return mask;
        } catch (BadPaddingException
                | IllegalBlockSizeException
                | InvalidKeyException
                | InvalidAlgorithmParameterException
                | NoSuchAlgorithmException
                | NoSuchPaddingException e) {
            throw new CryptoException("Could not generate header protection mask", e);
        }
    }

    public static byte[] generateInitialClientHeaderProtectionMask(
            QuicContext context, byte[] sample) throws CryptoException {
        return generateHeaderProtectionMask(
                context.getInitalHeaderProtectionCipher(),
                context.getInitialClientHeaderProtectionKey(),
                sample);
    }

    public static byte[] generateInitialServerHeaderProtectionMask(
            QuicContext context, byte[] sample) throws CryptoException {
        return generateHeaderProtectionMask(
                context.getInitalHeaderProtectionCipher(),
                context.getInitialServerHeaderProtectionKey(),
                sample);
    }

    public static byte[] generateHandshakeClientHeaderProtectionMask(
            QuicContext context, byte[] sample) throws CryptoException {
        return generateHeaderProtectionMask(
                context.getHeaderProtectionCipher(),
                context.getHandshakeClientHeaderProtectionKey(),
                sample);
    }

    public static byte[] generateHandshakeServerHeaderProtectionMask(
            QuicContext context, byte[] sample) throws CryptoException {
        return generateHeaderProtectionMask(
                context.getHeaderProtectionCipher(),
                context.getHandshakeServerHeaderProtectionKey(),
                sample);
    }

    public static byte[] generateOneRRTClientHeaderProtectionMask(
            QuicContext context, byte[] sample) throws CryptoException {
        return generateHeaderProtectionMask(
                context.getHeaderProtectionCipher(),
                context.getApplicationClientHeaderProtectionKey(),
                sample);
    }

    public static byte[] generateOneRTTServerHeaderProtectionMask(
            QuicContext context, byte[] sample) throws CryptoException {
        return generateHeaderProtectionMask(
                context.getHeaderProtectionCipher(),
                context.getApplicationServerHeaderProtectionKey(),
                sample);
    }

    public static byte[] generateZeroRTTClientHeaderProtectionMask(
            QuicContext context, byte[] sample) throws CryptoException {
        return generateHeaderProtectionMask(
                context.getZeroRTTHeaderProtectionCipher(),
                context.getZeroRTTClientHeaderProtectionKey(),
                sample);
    }

    public static byte[] generateZeroRTTServerHeaderProtectionMask(
            QuicContext context, byte[] sample) throws CryptoException {
        return generateHeaderProtectionMask(
                context.getZeroRTTHeaderProtectionCipher(),
                context.getZeroRTTServerHeaderProtectionKey(),
                sample);
    }

    /**
     * Calculates all initial client and server secrets including key, IV, and the key for header
     * protection.
     */
    public static void calculateInitialSecrets(QuicContext context)
            throws CryptoException, NoSuchAlgorithmException {
        LOGGER.debug("Initialize Quic Initial Secrets");

        QuicVersion version = context.getQuicVersion();
        if (version == QuicVersion.NEGOTIATION_VERSION) {
            LOGGER.debug(
                    "Version Negotiation Packets do not have initial secrets. They are not encrypted.");
            context.setInitialSecretsInitialized(false);
            return;
        }

        HKDFAlgorithm hkdfAlgorithm = context.getInitialHKDFAlgorithm();
        Mac mac = Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName());

        context.setInitialSecret(
                HKDFunction.extract(
                        hkdfAlgorithm,
                        context.getInitialSalt(),
                        context.getInitialSecretsConnectionId()));

        // client
        context.setInitialClientSecret(
                HKDFunction.expandLabel(
                        hkdfAlgorithm,
                        context.getInitialSecret(),
                        HKDFunction.CLIENT_IN,
                        new byte[0],
                        mac.getMacLength(),
                        ProtocolVersion.TLS13));
        context.setInitialClientKey(
                deriveKeyFromSecret(
                        version,
                        hkdfAlgorithm,
                        context.getInitialClientSecret(),
                        INITIAL_KEY_LENGTH));
        context.setInitialClientIv(
                deriveIvFromSecret(version, hkdfAlgorithm, context.getInitialClientSecret()));
        context.setInitialClientHeaderProtectionKey(
                deriveHeaderProtectionKeyFromSecret(
                        version,
                        hkdfAlgorithm,
                        context.getInitialClientSecret(),
                        INITIAL_KEY_LENGTH));

        // server
        context.setInitialServerSecret(
                HKDFunction.expandLabel(
                        hkdfAlgorithm,
                        context.getInitialSecret(),
                        HKDFunction.SERVER_IN,
                        new byte[0],
                        mac.getMacLength(),
                        ProtocolVersion.TLS13));
        context.setInitialServerKey(
                deriveKeyFromSecret(
                        version,
                        hkdfAlgorithm,
                        context.getInitialServerSecret(),
                        INITIAL_KEY_LENGTH));
        context.setInitialServerIv(
                deriveIvFromSecret(version, hkdfAlgorithm, context.getInitialServerSecret()));
        context.setInitialServerHeaderProtectionKey(
                deriveHeaderProtectionKeyFromSecret(
                        version,
                        hkdfAlgorithm,
                        context.getInitialServerSecret(),
                        INITIAL_KEY_LENGTH));

        context.setInitialSecretsInitialized(true);
    }

    public static void resolveQuicAeadCipher(QuicContext quicContext, CipherSuite cipherSuite) {
        quicContext.setAeadCipher(AlgorithmResolver.getCipher(cipherSuite).getJavaName());
    }

    /**
     * Calculates all handshake client and server secrets including key, IV, and the key for header
     * protection.
     */
    public static void calculateHandshakeSecrets(Context context)
            throws NoSuchAlgorithmException, CryptoException {
        LOGGER.debug("Initialize Quic Handshake Secrets");
        QuicContext quicContext = context.getQuicContext();
        resolveQuicAeadCipher(quicContext, context.getTlsContext().getSelectedCipherSuite());

        int keyLength =
                resolveQuicHeaderCipher(
                        quicContext, context.getTlsContext().getSelectedCipherSuite());

        quicContext.setHkdfAlgorithm(
                AlgorithmResolver.getHKDFAlgorithm(
                        context.getTlsContext().getSelectedCipherSuite()));

        HKDFAlgorithm hkdfAlgorithm = context.getQuicContext().getHkdfAlgorithm();
        QuicVersion version = quicContext.getQuicVersion();

        // client
        quicContext.setHandshakeClientSecret(
                context.getTlsContext().getClientHandshakeTrafficSecret());
        quicContext.setHandshakeClientKey(
                deriveKeyFromSecret(
                        version, hkdfAlgorithm, quicContext.getHandshakeClientSecret(), keyLength));
        quicContext.setHandshakeClientIv(
                deriveIvFromSecret(version, hkdfAlgorithm, quicContext.getHandshakeClientSecret()));
        quicContext.setHandshakeClientHeaderProtectionKey(
                deriveHeaderProtectionKeyFromSecret(
                        version, hkdfAlgorithm, quicContext.getHandshakeClientSecret(), keyLength));

        // server
        quicContext.setHandshakeServerSecret(
                context.getTlsContext().getServerHandshakeTrafficSecret());
        quicContext.setHandshakeServerKey(
                deriveKeyFromSecret(
                        version, hkdfAlgorithm, quicContext.getHandshakeServerSecret(), keyLength));
        quicContext.setHandshakeServerIv(
                deriveIvFromSecret(version, hkdfAlgorithm, quicContext.getHandshakeServerSecret()));
        quicContext.setHandshakeServerHeaderProtectionKey(
                deriveHeaderProtectionKeyFromSecret(
                        version, hkdfAlgorithm, quicContext.getHandshakeServerSecret(), keyLength));

        quicContext.setHandshakeSecretsInitialized(true);
    }

    public static int resolveQuicHeaderCipher(QuicContext quicContext, CipherSuite cipherSuite) {
        int keyLength = 16;
        switch (cipherSuite) {
            case TLS_AES_128_CCM_SHA256:
            case TLS_AES_128_GCM_SHA256:
                keyLength = 16;
                quicContext.setHeaderProtectionCipher("AES/ECB/NoPadding");
                break;
            case TLS_AES_256_GCM_SHA384:
                keyLength = 32;
                quicContext.setHeaderProtectionCipher("AES/ECB/NoPadding");
                break;
            case TLS_CHACHA20_POLY1305_SHA256:
                keyLength = 32;
                quicContext.setHeaderProtectionCipher("ChaCha20");
                break;
            default:
                LOGGER.warn("Unsupported Cipher Suite: {}", cipherSuite);
                break;
        }
        return keyLength;
    }

    /**
     * Calculates all application client and server secrets including key, IV, and the key for
     * header protection.
     *
     * <p>This installs <b>generation 0</b> material, so it also resets the RFC 9001 section 6 key
     * update state. That reset is not bookkeeping: the key phase counters exist to say which
     * generation the key fields currently hold, and this method is the one writer besides {@link
     * #installNextApplicationKeys} that replaces those fields. Leaving the counters alone here
     * would leave a context whose phase says "generation 1" over generation-0 keys, which breaks
     * the connection in both directions at once - we would set the Key Phase bit on packets
     * protected with the old key, and we would decrypt the peer's genuine new-generation packets
     * with it. Neither end can recover, and to an observer it is indistinguishable from the peer
     * falling silent.
     *
     * <p>Reachable because {@code FinishedHandler} calls this whenever a Finished message is
     * processed, which a retransmitted flight can do after the application keys already exist.
     */
    public static void calculateApplicationSecrets(Context context)
            throws NoSuchAlgorithmException, CryptoException {
        LOGGER.debug("Initialize Quic Application Secrets");
        QuicContext quicContext = context.getQuicContext();
        int keyLength =
                resolveApplicationKeyLength(context.getTlsContext().getSelectedCipherSuite());

        HKDFAlgorithm hkdfAlgorithm = quicContext.getHkdfAlgorithm();
        QuicVersion version = quicContext.getQuicVersion();

        // client
        quicContext.setApplicationClientSecret(
                context.getTlsContext().getClientApplicationTrafficSecret());
        quicContext.setApplicationClientKey(
                deriveKeyFromSecret(
                        version,
                        hkdfAlgorithm,
                        quicContext.getApplicationClientSecret(),
                        keyLength));
        quicContext.setApplicationClientIv(
                deriveIvFromSecret(
                        version, hkdfAlgorithm, quicContext.getApplicationClientSecret()));
        quicContext.setApplicationClientHeaderProtectionKey(
                deriveHeaderProtectionKeyFromSecret(
                        version,
                        hkdfAlgorithm,
                        quicContext.getApplicationClientSecret(),
                        keyLength));

        // server
        quicContext.setApplicationServerSecret(
                context.getTlsContext().getServerApplicationTrafficSecret());
        quicContext.setApplicationServerKey(
                deriveKeyFromSecret(
                        version,
                        hkdfAlgorithm,
                        quicContext.getApplicationServerSecret(),
                        keyLength));
        quicContext.setApplicationServerIv(
                deriveIvFromSecret(
                        version, hkdfAlgorithm, quicContext.getApplicationServerSecret()));
        quicContext.setApplicationServerHeaderProtectionKey(
                deriveHeaderProtectionKeyFromSecret(
                        version,
                        hkdfAlgorithm,
                        quicContext.getApplicationServerSecret(),
                        keyLength));

        // Generation 0 is now installed, so the key update state must describe generation 0
        // too. See this method's javadoc for why a stale counter is not a cosmetic defect.
        quicContext.setApplicationKeyPhase(ConnectionEndType.CLIENT, 0);
        quicContext.setApplicationKeyPhase(ConnectionEndType.SERVER, 0);
        quicContext.setPreviousApplicationKey(ConnectionEndType.CLIENT, null);
        quicContext.setPreviousApplicationIv(ConnectionEndType.CLIENT, null);
        quicContext.setPreviousApplicationKey(ConnectionEndType.SERVER, null);
        quicContext.setPreviousApplicationIv(ConnectionEndType.SERVER, null);
        quicContext.setLowestReceivedOneRTTPacketNumberInCurrentKeyPhase(Integer.MAX_VALUE);

        quicContext.setApplicationSecretsInitialized(true);
    }

    /**
     * The length of an application (1-RTT) packet protection key for the given cipher suite.
     *
     * @param cipherSuite the negotiated cipher suite
     * @return the key length in bytes
     */
    private static int resolveApplicationKeyLength(CipherSuite cipherSuite) {
        switch (cipherSuite) {
            case TLS_AES_128_CCM_SHA256:
            case TLS_AES_128_GCM_SHA256:
                return 16;
            case TLS_AES_256_GCM_SHA384:
            case TLS_CHACHA20_POLY1305_SHA256:
                return 32;
            default:
                LOGGER.warn("Unsupported Cipher Suite: {}", cipherSuite);
                return 16;
        }
    }

    /**
     * One generation of application (1-RTT) packet protection material: the traffic secret, and the
     * key and IV derived from it.
     *
     * <p>The header protection key is deliberately absent. RFC 9001 section 6.1 states that "The
     * header protection key is not updated", so it survives every key phase unchanged and is not
     * part of what a key update produces.
     *
     * @param secret the traffic secret of this generation
     * @param key the packet protection key derived from it
     * @param iv the packet protection IV derived from it
     */
    public record ApplicationKeyMaterial(byte[] secret, byte[] key, byte[] iv) {}

    /**
     * Derives the next generation of application (1-RTT) packet protection material for one
     * connection end, without changing anything in the context.
     *
     * <p>RFC 9001 section 6.1: "The endpoint creates a new write secret from the existing write
     * secret as performed in Section 7.2 of [TLS13]. This uses the KDF function provided by TLS
     * with a label of 'quic ku'. The corresponding key and IV are created from that secret as
     * defined in Section 5.1. The header protection key is not updated." That is
     *
     * <pre>secret_&lt;n+1&gt; = HKDF-Expand-Label(secret_&lt;n&gt;, "quic ku", "", Hash.length)
     * </pre>
     *
     * <p>Deriving without installing is what lets a receiver satisfy RFC 9001 section 6.3: the Key
     * Phase bit is not authenticated, so an endpoint must be able to attempt removal of packet
     * protection with the next generation and discard the result when it does not authenticate,
     * rather than let a forged bit rotate its keys.
     *
     * @param context the QUIC context holding the current generation
     * @param endType the connection end whose packet protection keys are updated
     * @return the next generation's secret, key and IV
     * @throws CryptoException if the current secret is unknown or the derivation fails
     * @throws NoSuchAlgorithmException if the negotiated HKDF algorithm is unavailable
     */
    public static ApplicationKeyMaterial calculateNextApplicationSecrets(
            QuicContext context, ConnectionEndType endType)
            throws CryptoException, NoSuchAlgorithmException {
        byte[] currentSecret = context.getApplicationSecret(endType);
        if (currentSecret == null) {
            throw new CryptoException(
                    "Cannot update the "
                            + endType
                            + " application secret before it has been calculated");
        }
        HKDFAlgorithm hkdfAlgorithm = context.getHkdfAlgorithm();
        if (hkdfAlgorithm == null) {
            throw new CryptoException(
                    "Cannot update application secrets before the HKDF algorithm is known");
        }
        QuicVersion version = context.getQuicVersion();
        Mac mac = Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName());

        byte[] nextSecret =
                HKDFunction.expandLabel(
                        hkdfAlgorithm,
                        currentSecret,
                        version.getKeyUpdateLabel(),
                        new byte[0],
                        mac.getMacLength(),
                        ProtocolVersion.TLS13);
        int keyLength =
                resolveApplicationKeyLength(
                        context.getContext().getTlsContext().getSelectedCipherSuite());
        return new ApplicationKeyMaterial(
                nextSecret,
                deriveKeyFromSecret(version, hkdfAlgorithm, nextSecret, keyLength),
                deriveIvFromSecret(version, hkdfAlgorithm, nextSecret));
    }

    /**
     * Initiates a key update as described by RFC 9001 section 6.1: the endpoint updates the packet
     * protection secret it writes with, toggles the Key Phase bit it sends, and updates the secret
     * it reads with as well, because "The endpoint that initiates a key update also updates the
     * keys that it uses for receiving packets. These keys will be needed to process packets the
     * peer sends after updating."
     *
     * <p>The replaced read key and IV are retained (RFC 9001 sections 6.1 and 6.5), so packets the
     * network delayed across the update still decrypt. The replaced write key and IV are not: "An
     * endpoint never sends packets that are protected with old keys. Only the current keys are
     * used. Keys used for protecting packets can be discarded immediately after switching to newer
     * keys" (section 6.4).
     *
     * <p>Section 6.1 additionally forbids initiating a key update before the handshake is confirmed
     * and before an acknowledgment for a packet of the current key phase has been received. Those
     * are conditions on when a conforming endpoint chooses to update, not on whether an update can
     * be performed, and they are deliberately not enforced here: sending what a conforming endpoint
     * would not send is what this framework exists for. Callers that want conforming behaviour test
     * the conditions themselves.
     *
     * @param context the QUIC context to update
     * @throws CryptoException if the current secrets are unknown or a derivation fails
     * @throws NoSuchAlgorithmException if the negotiated HKDF algorithm is unavailable
     */
    public static void initiateKeyUpdate(QuicContext context)
            throws CryptoException, NoSuchAlgorithmException {
        ConnectionEndType writeEndType = context.getConnection().getLocalConnectionEndType();
        ConnectionEndType readEndType = writeEndType.getPeer();

        // Both generations are derived before either is installed, so a failure leaves the
        // context on the generation it was on rather than half updated.
        ApplicationKeyMaterial nextWriteKeys =
                calculateNextApplicationSecrets(context, writeEndType);
        ApplicationKeyMaterial nextReadKeys = calculateNextApplicationSecrets(context, readEndType);

        installNextApplicationKeys(context, writeEndType, nextWriteKeys, false);
        installNextApplicationKeys(context, readEndType, nextReadKeys, true);
        LOGGER.debug(
                "Initiated QUIC key update, now writing with key phase {}",
                context.getApplicationKeyPhase(writeEndType) & 1);
    }

    /**
     * Completes a key update the peer initiated, as described by RFC 9001 section 6.2: "If a packet
     * is successfully processed using the next key and IV, then the peer has initiated a key
     * update. The endpoint MUST update its send keys to the corresponding key phase in response, as
     * described in Section 6.1. Sending keys MUST be updated before sending an acknowledgment for
     * the packet that was received with updated keys."
     *
     * <p>Must be called only once a packet has actually been unprotected with {@code nextPeerKeys}.
     * The Key Phase bit is not authenticated, and RFC 9001 sections 6.3 and 9.5 warn that packets
     * carrying an apparent key update are easy to forge, so committing an update on anything less
     * than a successful authentication would let anyone able to send a datagram discard this
     * endpoint's keys.
     *
     * <p>The send keys are advanced only when their Key Phase bit does not already match the peer's
     * new one. An endpoint that initiated the update itself has already advanced them, and section
     * 6.4 requires packets with higher packet numbers to be protected with the same or newer keys.
     *
     * @param context the QUIC context to update
     * @param peerEndType the connection end that protected the packet which carried the update
     * @param nextPeerKeys the material that successfully unprotected that packet
     * @throws CryptoException if the local secret is unknown or a derivation fails
     * @throws NoSuchAlgorithmException if the negotiated HKDF algorithm is unavailable
     */
    public static void completePeerInitiatedKeyUpdate(
            QuicContext context, ConnectionEndType peerEndType, ApplicationKeyMaterial nextPeerKeys)
            throws CryptoException, NoSuchAlgorithmException {
        ConnectionEndType localEndType = peerEndType.getPeer();
        int newPeerKeyPhase = context.getApplicationKeyPhase(peerEndType) + 1;
        // Derived before anything is installed, for the same reason as in initiateKeyUpdate.
        ApplicationKeyMaterial nextLocalKeys =
                (context.getApplicationKeyPhase(localEndType) & 1) != (newPeerKeyPhase & 1)
                        ? calculateNextApplicationSecrets(context, localEndType)
                        : null;

        installNextApplicationKeys(context, peerEndType, nextPeerKeys, true);
        if (nextLocalKeys != null) {
            installNextApplicationKeys(context, localEndType, nextLocalKeys, false);
        }
        LOGGER.debug(
                "Peer initiated a QUIC key update, now reading with key phase {} and writing with key phase {}",
                context.getApplicationKeyPhase(peerEndType) & 1,
                context.getApplicationKeyPhase(localEndType) & 1);
    }

    /**
     * Installs one generation of application packet protection material and advances that end's key
     * phase.
     *
     * @param context the QUIC context to update
     * @param endType the connection end whose keys are replaced
     * @param nextKeys the material to install
     * @param receiveDirection whether {@code endType} is the end this endpoint decrypts packets
     *     from. Only then are the replaced key and IV retained (RFC 9001 sections 6.1 and 6.5); a
     *     sender discards its old keys immediately (section 6.4).
     */
    private static void installNextApplicationKeys(
            QuicContext context,
            ConnectionEndType endType,
            ApplicationKeyMaterial nextKeys,
            boolean receiveDirection) {
        if (receiveDirection) {
            context.setPreviousApplicationKey(endType, context.getApplicationKey(endType));
            context.setPreviousApplicationIv(endType, context.getApplicationIv(endType));
            // No packet of the new generation has been unprotected yet, so every packet number is
            // still "lower than any packet number from the current key phase" (RFC 9001 section
            // 6.5) and a packet carrying the old Key Phase bit belongs to the previous generation.
            context.setLowestReceivedOneRTTPacketNumberInCurrentKeyPhase(Integer.MAX_VALUE);
        }
        context.setApplicationSecret(endType, nextKeys.secret());
        context.setApplicationKey(endType, nextKeys.key());
        context.setApplicationIv(endType, nextKeys.iv());
        context.setApplicationKeyPhase(endType, context.getApplicationKeyPhase(endType) + 1);
    }

    /**
     * Calculates all zero rtt client and server secrets including key, IV, and the key for header
     * protection.
     *
     * @param context
     * @throws CryptoException
     * @throws NoSuchAlgorithmException
     */
    public static void calculateZeroRTTSecrets(Context context)
            throws CryptoException, NoSuchAlgorithmException {
        LOGGER.debug("Initialize Quic 0-RTT Secrets");
        QuicContext quicContext = context.getQuicContext();
        quicContext.setZeroRTTCipherSuite(context.getTlsContext().getEarlyDataCipherSuite());
        quicContext.setZeroRTTAeadCipher(
                context.getTlsContext()
                        .getEarlyDataCipherSuite()
                        .getCipherAlgorithm()
                        .getJavaName());

        int keyLength = 16;
        switch (quicContext.getZeroRTTCipherSuite()) {
            case TLS_AES_128_CCM_SHA256:
            case TLS_AES_128_GCM_SHA256:
                keyLength = 16;
                quicContext.setZeroRTTHeaderProtectionCipher("AES/ECB/NoPadding");
                break;
            case TLS_AES_256_GCM_SHA384:
                keyLength = 32;
                quicContext.setZeroRTTHeaderProtectionCipher("AES/ECB/NoPadding");
                break;
            case TLS_CHACHA20_POLY1305_SHA256:
                keyLength = 32;
                quicContext.setZeroRTTHeaderProtectionCipher("ChaCha20");
                break;
            default:
                LOGGER.warn("Unsupported Cipher Suite: {}", quicContext.getZeroRTTCipherSuite());
                break;
        }

        quicContext.setZeroRTTHKDFAlgorithm(
                AlgorithmResolver.getHKDFAlgorithm(quicContext.getZeroRTTCipherSuite()));

        HKDFAlgorithm hkdfAlgorithm = quicContext.getZeroRTTHKDFAlgorithm();
        QuicVersion version = quicContext.getQuicVersion();

        // client
        quicContext.setZeroRTTClientSecret(context.getTlsContext().getClientEarlyTrafficSecret());
        quicContext.setZeroRTTClientKey(
                deriveKeyFromSecret(
                        version, hkdfAlgorithm, quicContext.getZeroRTTClientSecret(), keyLength));
        quicContext.setZeroRTTClientIv(
                deriveIvFromSecret(version, hkdfAlgorithm, quicContext.getZeroRTTClientSecret()));
        quicContext.setZeroRTTClientHeaderProtectionKey(
                deriveHeaderProtectionKeyFromSecret(
                        version, hkdfAlgorithm, quicContext.getZeroRTTClientSecret(), keyLength));

        // server
        quicContext.setZeroRTTServerSecret(context.getTlsContext().getClientEarlyTrafficSecret());
        quicContext.setZeroRTTServerKey(
                deriveKeyFromSecret(
                        version, hkdfAlgorithm, quicContext.getZeroRTTServerSecret(), keyLength));
        quicContext.setZeroRTTServerIv(
                deriveIvFromSecret(version, hkdfAlgorithm, quicContext.getZeroRTTServerSecret()));
        quicContext.setZeroRTTServerHeaderProtectionKey(
                deriveHeaderProtectionKeyFromSecret(
                        version, hkdfAlgorithm, quicContext.getZeroRTTServerSecret(), keyLength));

        quicContext.setZeroRTTSecretsInitialized(true);
    }

    private static byte[] deriveKeyFromSecret(
            QuicVersion version, HKDFAlgorithm hkdfAlgorithm, byte[] secret, int keyLength)
            throws CryptoException {
        return HKDFunction.expandLabel(
                hkdfAlgorithm,
                secret,
                version.getKeyLabel(),
                new byte[0],
                keyLength,
                ProtocolVersion.TLS13);
    }

    private static byte[] deriveIvFromSecret(
            QuicVersion version, HKDFAlgorithm hkdfAlgorithm, byte[] secret)
            throws CryptoException {
        return HKDFunction.expandLabel(
                hkdfAlgorithm,
                secret,
                version.getIvLabel(),
                new byte[0],
                IV_LENGTH,
                ProtocolVersion.TLS13);
    }

    private static byte[] deriveHeaderProtectionKeyFromSecret(
            QuicVersion version, HKDFAlgorithm hkdfAlgorithm, byte[] secret, int keyLength)
            throws CryptoException {
        return HKDFunction.expandLabel(
                hkdfAlgorithm,
                secret,
                version.getHeaderProtectionLabel(),
                new byte[0],
                keyLength,
                ProtocolVersion.TLS13);
    }

    /**
     * Calculates the Integrity Tag for the given Retry Packet.
     *
     * @param context Current QUIC Context
     * @param packet The Retry Packet
     * @return Retry Integrity Tag for the packet
     */
    public static byte[] calculateRetryIntegrityTag(QuicContext context, RetryPacket packet) {
        // For construction of QUIC Retry Packet Integrity Pseudo Packet, see 5.8, RFC 9001
        byte[] pseudoPacket =
                ByteBuffer.allocate(
                                1 /* ODCID length field */
                                        + context.getFirstDestinationConnectionId().length
                                        + 1 /* Flags Byte */
                                        + 4 /* Version Field */
                                        + 1 /* DCID length field */
                                        + packet.getDestinationConnectionId().getValue().length
                                        + 1 /* SCID length field */
                                        + packet.getSourceConnectionId().getValue().length
                                        + packet.retryToken.getValue().length)
                        .put((byte) (context.getFirstDestinationConnectionId().length & 0xff))
                        .put(context.getFirstDestinationConnectionId())
                        .put(packet.getUnprotectedFlags().getValue())
                        .put(context.getQuicVersion().getByteValue())
                        .put(packet.getDestinationConnectionIdLength().getValue())
                        .put(packet.getDestinationConnectionId().getValue())
                        .put(packet.getSourceConnectionIdLength().getValue())
                        .put(packet.getSourceConnectionId().getValue())
                        .put(packet.retryToken.getValue())
                        .array();
        LOGGER.trace("Build Integrity Check Pseudo Packet {}", pseudoPacket);

        byte[] computedTag;
        try {
            // Secret Key is fixed value from 5.8, RFC 9001 (or 3.3.3, RFC 9369 for QUICv2)
            SecretKey secretKey =
                    new SecretKeySpec(
                            QuicRetryConstants.getRetryIntegrityTagKey(context.getQuicVersion()),
                            "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            // IV is fixed value from 5.8, RFC 9001 (or 3.3.3, RFC 9369 for QUICv2)
            GCMParameterSpec gcmParameterSpec =
                    new GCMParameterSpec(
                            128,
                            QuicRetryConstants.getRetryIntegrityTagIv(context.getQuicVersion()));
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
            cipher.updateAAD(pseudoPacket);
            computedTag = cipher.doFinal();
        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException
                | InvalidKeyException
                | InvalidAlgorithmParameterException
                | IllegalBlockSizeException
                | BadPaddingException e) {
            throw new CryptoException("Error while computing Retry Integrity Tag", e);
        }
        if (computedTag.length == 0) {
            throw new CryptoException(
                    "Attempted to compute Retry Integrity Tag for verification but result is empty!");
        }
        return computedTag;
    }
}
