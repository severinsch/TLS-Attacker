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
import de.rub.nds.tlsattacker.core.quic.handler.frame.DataBlockedFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.DataBlockedFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.DataBlockedFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.DataBlockedFrameSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class DataBlockedFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableLong maximumData;

    private long maximumDataConfig;

    public DataBlockedFrame() {
        super(QuicFrameType.DATA_BLOCKED_FRAME);
    }

    public DataBlockedFrame(long maximumDataConfig) {
        this();
        this.maximumDataConfig = maximumDataConfig;
    }

    public DataBlockedFrame(int maximumDataConfig) {
        this((long) maximumDataConfig);
    }

    @Override
    public DataBlockedFrameHandler getHandler(Context context) {
        return new DataBlockedFrameHandler(context.getQuicContext());
    }

    @Override
    public DataBlockedFrameSerializer getSerializer(Context context) {
        return new DataBlockedFrameSerializer(this);
    }

    @Override
    public DataBlockedFramePreparator getPreparator(Context context) {
        return new DataBlockedFramePreparator(context.getChooser(), this);
    }

    @Override
    public DataBlockedFrameParser getParser(Context context, InputStream stream) {
        return new DataBlockedFrameParser(stream);
    }

    public ModifiableLong getMaximumData() {
        return maximumData;
    }

    public void setMaximumData(ModifiableLong maximumData) {
        this.maximumData = maximumData;
    }

    public void setMaximumData(long maximumData) {
        this.maximumData = ModifiableVariableFactory.safelySetValue(this.maximumData, maximumData);
    }

    public void setMaximumData(int maximumData) {
        setMaximumData((long) maximumData);
    }

    public long getMaximumDataConfig() {
        return maximumDataConfig;
    }

    public void setMaximumDataConfig(long maximumDataConfig) {
        this.maximumDataConfig = maximumDataConfig;
    }

    public void setMaximumDataConfig(int maximumDataConfig) {
        setMaximumDataConfig((long) maximumDataConfig);
    }

    @Override
    public String toShortString() {
        return "DB";
    }
}
