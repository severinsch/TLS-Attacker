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
import de.rub.nds.tlsattacker.core.quic.handler.frame.StreamDataBlockedFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.StreamDataBlockedFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.StreamDataBlockedFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.StreamDataBlockedFrameSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class StreamDataBlockedFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableLong streamId;

    @ModifiableVariableProperty protected ModifiableLong maximumStreamData;

    private long streamIdConfig;

    private long maximumStreamDataConfig;

    public StreamDataBlockedFrame() {
        super(QuicFrameType.STREAM_DATA_BLOCKED_FRAME);
    }

    public StreamDataBlockedFrame(long streamIdConfig, long maximumStreamDataConfig) {
        this();
        this.streamIdConfig = streamIdConfig;
        this.maximumStreamDataConfig = maximumStreamDataConfig;
    }

    public StreamDataBlockedFrame(int streamIdConfig, int maximumStreamDataConfig) {
        this((long) streamIdConfig, (long) maximumStreamDataConfig);
    }

    @Override
    public StreamDataBlockedFrameHandler getHandler(Context context) {
        return new StreamDataBlockedFrameHandler(context.getQuicContext());
    }

    @Override
    public StreamDataBlockedFrameSerializer getSerializer(Context context) {
        return new StreamDataBlockedFrameSerializer(this);
    }

    @Override
    public StreamDataBlockedFramePreparator getPreparator(Context context) {
        return new StreamDataBlockedFramePreparator(context.getChooser(), this);
    }

    @Override
    public StreamDataBlockedFrameParser getParser(Context context, InputStream stream) {
        return new StreamDataBlockedFrameParser(stream);
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

    public ModifiableLong getMaximumStreamData() {
        return maximumStreamData;
    }

    public void setMaximumStreamData(ModifiableLong maximumStreamData) {
        this.maximumStreamData = maximumStreamData;
    }

    public void setMaximumStreamData(long maximumStreamData) {
        this.maximumStreamData =
                ModifiableVariableFactory.safelySetValue(this.maximumStreamData, maximumStreamData);
    }

    public void setMaximumStreamData(int maximumStreamData) {
        setMaximumStreamData((long) maximumStreamData);
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

    public long getMaximumStreamDataConfig() {
        return maximumStreamDataConfig;
    }

    public void setMaximumStreamDataConfig(long maximumStreamDataConfig) {
        this.maximumStreamDataConfig = maximumStreamDataConfig;
    }

    public void setMaximumStreamDataConfig(int maximumStreamDataConfig) {
        setMaximumStreamDataConfig((long) maximumStreamDataConfig);
    }

    @Override
    public String toShortString() {
        return "SDB";
    }
}
