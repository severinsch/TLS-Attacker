/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.frame;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.handler.frame.StopSendingFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.StopSendingFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.StopSendingFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.StopSendingFrameSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class StopSendingFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableLong streamId;

    @ModifiableVariableProperty protected ModifiableLong applicationProtocolErrorCode;

    private long streamIdConfig;
    private long applicationProtocolErrorCodeConfig;

    public StopSendingFrame() {
        super(QuicFrameType.STOP_SENDING_FRAME);
    }

    public StopSendingFrame(long streamIdConfig, long applicationProtocolErrorCodeConfig) {
        this();
        this.streamIdConfig = streamIdConfig;
        this.applicationProtocolErrorCodeConfig = applicationProtocolErrorCodeConfig;
    }

    public StopSendingFrame(int streamIdConfig, int applicationProtocolErrorCodeConfig) {
        this((long) streamIdConfig, (long) applicationProtocolErrorCodeConfig);
    }

    @Override
    public StopSendingFrameHandler getHandler(Context context) {
        return new StopSendingFrameHandler(context.getQuicContext());
    }

    @Override
    public StopSendingFrameSerializer getSerializer(Context context) {
        return new StopSendingFrameSerializer(this);
    }

    @Override
    public StopSendingFramePreparator getPreparator(Context context) {
        return new StopSendingFramePreparator(context.getChooser(), this);
    }

    @Override
    public StopSendingFrameParser getParser(Context context, InputStream stream) {
        return new StopSendingFrameParser(stream);
    }

    public ModifiableLong getStreamId() {
        return streamId;
    }

    public void setStreamId(ModifiableLong streamId) {
        this.streamId = streamId;
    }

    public void setStreamId(long streamId) {
        this.streamId = ModifiableVariableFactory.safelySetValue(this.streamId, streamId);
    }

    public void setStreamId(int streamId) {
        setStreamId((long) streamId);
    }

    public ModifiableLong getApplicationProtocolErrorCode() {
        return applicationProtocolErrorCode;
    }

    public void setApplicationProtocolErrorCode(ModifiableLong applicationProtocolErrorCode) {
        this.applicationProtocolErrorCode = applicationProtocolErrorCode;
    }

    public void setApplicationProtocolErrorCode(long applicationProtocolErrorCode) {
        this.applicationProtocolErrorCode =
                ModifiableVariableFactory.safelySetValue(
                        this.applicationProtocolErrorCode, applicationProtocolErrorCode);
    }

    public void setApplicationProtocolErrorCode(int applicationProtocolErrorCode) {
        setApplicationProtocolErrorCode((long) applicationProtocolErrorCode);
    }

    public long getStreamIdConfig() {
        return streamIdConfig;
    }

    public void setStreamIdConfig(long streamIdConfig) {
        this.streamIdConfig = streamIdConfig;
    }

    public void setStreamIdConfig(int streamIdConfig) {
        setStreamIdConfig((long) streamIdConfig);
    }

    public long getApplicationProtocolErrorCodeConfig() {
        return applicationProtocolErrorCodeConfig;
    }

    public void setApplicationProtocolErrorCodeConfig(long applicationProtocolErrorCodeConfig) {
        this.applicationProtocolErrorCodeConfig = applicationProtocolErrorCodeConfig;
    }

    public void setApplicationProtocolErrorCodeConfig(int applicationProtocolErrorCodeConfig) {
        setApplicationProtocolErrorCodeConfig((long) applicationProtocolErrorCodeConfig);
    }

    @Override
    public String toShortString() {
        return "SS";
    }
}
