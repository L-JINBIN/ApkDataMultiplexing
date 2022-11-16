package bin.zip;

import bin.io.RandomAccessFile;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author Bin
 */
public class BridgeInputStream extends InputStream {
    private final RandomAccessFile archive;
    private long remaining;
    private long loc;

    public BridgeInputStream(RandomAccessFile archive, long start, long remaining) {
        this.archive = archive;
        this.remaining = remaining;
        loc = start;
    }

    public int read() throws IOException {
        if (remaining-- <= 0) {
            return -1;
        }
        synchronized (archive) {
            archive.seek(loc++);
            return archive.read();
        }
    }

    @Override
    public int available() {
        return (int) (remaining & Integer.MAX_VALUE);
    }

    public int read(byte[] b, int off, int len) throws IOException {
        if (remaining <= 0) {
            return -1;
        }

        if (len <= 0) {
            return 0;
        }

        if (len > remaining) {
            len = (int) remaining;
        }
        int ret;
        synchronized (archive) {
            archive.seek(loc);
            ret = archive.read(b, off, len);
        }
        if (ret > 0) {
            loc += ret;
            remaining -= ret;
        }
        return ret;
    }

}