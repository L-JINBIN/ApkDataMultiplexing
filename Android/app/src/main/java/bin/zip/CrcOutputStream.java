package bin.zip;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.CRC32;

/**
 * @author Bin
 */
public class CrcOutputStream extends OutputStream {
    private OutputStream os;
    private CRC32 crc32 = new CRC32();
    private long count = 0;

    public CrcOutputStream(OutputStream os) {
        this.os = os;
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        os.write(b, off, len);
        crc32.update(b, off, len);
        count += len;
    }

    @Override
    public void write(int b) throws IOException {
        os.write(b);
        crc32.update(b);
        count++;
    }

    public long getCount() {
        return count;
    }

    public int getCrc() {
        return (int) crc32.getValue();
    }

    @Override
    public void close() throws IOException {
        os.close();
    }
}
