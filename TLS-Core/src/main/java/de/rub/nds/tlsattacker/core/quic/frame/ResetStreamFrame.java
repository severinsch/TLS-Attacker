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
import de.rub.nds.tlsattacker.core.quic.handler.frame.ResetStreamFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.ResetStreamFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.ResetStreamFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.ResetStreamFrameSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class ResetStreamFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableLong streamId;

    @ModifiableVariableProperty protected ModifiableLong applicationProtocolErrorCode;

    @ModifiableVariableProperty protected ModifiableLong finalSize;

    private long streamIdConfig;
    private long applicationProtocolErrorCodeConfig;
    private long finalSizeConfig;

    public ResetStreamFrame() {
        super(QuicFrameType.RESET_STREAM_FRAME);
    }

    public ResetStreamFrame(
            long streamIdConfig, long applicationProtocolErrorCodeConfig, long finalSizeConfig) {
        this();
        this.streamIdConfig = streamIdConfig;
        this.applicationProtocolErrorCodeConfig = applicationProtocolErrorCodeConfig;
        this.finalSizeConfig = finalSizeConfig;
    }

    public ResetStreamFrame(
            int streamIdConfig, int applicationProtocolErrorCodeConfig, int finalSizeConfig) {
        this(
                (long) streamIdConfig,
                (long) applicationProtocolErrorCodeConfig,
                (long) finalSizeConfig);
    }

    @Override
    public ResetStreamFrameHandler getHandler(Context context) {
        return new ResetStreamFrameHandler(context.getQuicContext());
    }

    @Override
    public ResetStreamFrameSerializer getSerializer(Context context) {
        return new ResetStreamFrameSerializer(this);
    }

    @Override
    public ResetStreamFramePreparator getPreparator(Context context) {
        return new ResetStreamFramePreparator(context.getChooser(), this);
    }

    @Override
    public ResetStreamFrameParser getParser(Context context, InputStream stream) {
        return new ResetStreamFrameParser(stream);
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

    public ModifiableLong getFinalSize() {
        return finalSize;
    }

    public void setFinalSize(ModifiableLong finalSize) {
        this.finalSize = finalSize;
    }

    public void setFinalSize(long finalSize) {
        this.finalSize = ModifiableVariableFactory.safelySetValue(this.finalSize, finalSize);
    }

    public void setFinalSize(int finalSize) {
        setFinalSize((long) finalSize);
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

    public long getFinalSizeConfig() {
        return finalSizeConfig;
    }

    public void setFinalSizeConfig(long finalSizeConfig) {
        this.finalSizeConfig = finalSizeConfig;
    }

    public void setFinalSizeConfig(int finalSizeConfig) {
        setFinalSizeConfig((long) finalSizeConfig);
    }

    @Override
    public String toShortString() {
        return "RS";
    }
}
