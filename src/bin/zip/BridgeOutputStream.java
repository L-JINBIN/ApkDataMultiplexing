package bin.zip;

import bin.io.RandomAccessFile;

import java.io.IOException;
import java.io.OutputStream;

/**
 * @author Bin
 */
public class BridgeOutputStream extends OutputStream {
    private final RandomAccessFile archive;
    private long count = 0;

    public BridgeOutputStream(RandomAccessFile archive) {
        this.archive = archive;
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (len > 0) {
            archive.write(b, off, len);
            count += len;
        }
    }

    @Override
    public void write(int b) throws IOException {
        archive.write(b);
        count++;
    }

    public long getCount() {
        return count;
    }

}
