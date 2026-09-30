/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.security.NoSuchAlgorithmException;

/**
 * Initiates a QUIC key update (RFC 9001 section 6.1): the next 1-RTT packets are protected with the
 * next key generation. The conditions of section 6.1 on when an endpoint may do so are not checked.
 */
@XmlRootElement
public class InitiateQuicKeyUpdateAction extends ConnectionBoundAction {

    public InitiateQuicKeyUpdateAction() {}

    public InitiateQuicKeyUpdateAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        try {
            QuicPacketCryptoComputations.initiateKeyUpdate(
                    state.getContext(getConnectionAlias()).getQuicContext());
        } catch (CryptoException | NoSuchAlgorithmException e) {
            throw new ActionExecutionException("Could not initiate a QUIC key update", e);
        }
        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
