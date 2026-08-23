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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.handler.frame.DatagramFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.DatagramFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.DatagramFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.DatagramFrameSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class DatagramFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableLong length;

    @ModifiableVariableProperty protected ModifiableByteArray data;

    private long lengthConfig;
    private byte[] dataConfig;

    private boolean hasLengthField;

    @SuppressWarnings("unused") // JAXB
    private DatagramFrame() {}

    public DatagramFrame(boolean hasLengthField) {
        this.hasLengthField = hasLengthField;
        if (hasLengthField) {
            setFrameType(QuicFrameType.DATAGRAM_FRAME_LEN);
        } else {
            setFrameType(QuicFrameType.DATAGRAM_FRAME);
        }
    }

    public DatagramFrame(boolean isLengthField, long length, byte[] dataConfig) {
        this(isLengthField);
        this.lengthConfig = length;
        this.dataConfig = dataConfig;
    }

    public DatagramFrame(boolean isLengthField, int length, byte[] dataConfig) {
        this(isLengthField, (long) length, dataConfig);
    }

    @Override
    public DatagramFrameHandler getHandler(Context context) {
        return new DatagramFrameHandler(context.getQuicContext());
    }

    @Override
    public DatagramFrameSerializer getSerializer(Context context) {
        return new DatagramFrameSerializer(this);
    }

    @Override
    public DatagramFramePreparator getPreparator(Context context) {
        return new DatagramFramePreparator(context.getChooser(), this);
    }

    @Override
    public DatagramFrameParser getParser(Context context, InputStream stream) {
        return new DatagramFrameParser(stream);
    }

    public ModifiableLong getLength() {
        return length;
    }

    public void setLength(ModifiableLong length) {
        this.length = length;
    }

    public void setLength(long length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public void setLength(int length) {
        setLength((long) length);
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(ModifiableByteArray data) {
        this.data = data;
    }

    public void setData(byte[] data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    public long getLengthConfig() {
        return lengthConfig;
    }

    public void setLengthConfig(long lengthConfig) {
        this.lengthConfig = lengthConfig;
    }

    public void setLengthConfig(int lengthConfig) {
        setLengthConfig((long) lengthConfig);
    }

    public byte[] getDataConfig() {
        return dataConfig;
    }

    public void setDataConfig(byte[] dataConfig) {
        this.dataConfig = dataConfig;
    }

    public boolean isLengthField() {
        return hasLengthField;
    }

    public void setLengthField(boolean hasLengthField) {
        this.hasLengthField = hasLengthField;
    }

    @Override
    public String toShortString() {
        return "DG";
    }
}
