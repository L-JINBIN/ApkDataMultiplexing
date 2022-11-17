package bin.mt.apksign.data;

import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;

public class ByteArrayDataSource implements DataSource {
    private byte[] data;
    private int start;
    private int size;
    private int pos;

    ByteArrayDataSource(byte[] data, int start, int size) {
        if (start + size > data.length)
            throw new IllegalArgumentException();
        this.data = data;
        this.start = start;
        this.size = size;
        this.pos = 0;
    }

    @Override
    public long size() {
        return size;
    }

    @Override
    public long pos() {
        return pos;
    }

    @Override
    public void reset() {
        pos = 0;
    }

    @Override
    public void copyTo(OutputStream os, long length) throws IOException {
        if (length > remaining())
            throw new EOFException();
        os.write(data, start + pos, (int) length);
        pos += length;
    }

    public byte[] getBuffer() {
        return data;
    }

    public int getStart() {
        return start;
    }
}
