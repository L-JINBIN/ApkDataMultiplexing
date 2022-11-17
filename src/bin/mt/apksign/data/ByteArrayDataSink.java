package bin.mt.apksign.data;

import java.io.EOFException;
import java.io.IOException;

public class ByteArrayDataSink implements DataSink {
    private byte[] data;
    private int pos;
    private int limit;

    ByteArrayDataSink(byte[] data, int pos, int limit) {
        this.data = data;
        this.pos = pos;
        this.limit = limit;
    }

    @Override
    public void consume(byte[] buf, int offset, int length) throws IOException {
        if (pos + length > limit) {
            throw new EOFException();
        }
        System.arraycopy(buf, offset, data, pos, length);
        pos += length;
    }
}
