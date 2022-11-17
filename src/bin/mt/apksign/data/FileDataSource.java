package bin.mt.apksign.data;

import bin.io.RandomAccessFile;

import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;

public class FileDataSource implements DataSource {
    private RandomAccessFile randomAccessFile;
    private long start;
    private long size;
    private long pos;

    FileDataSource(RandomAccessFile randomAccessFile, long start, long size) {
        this.randomAccessFile = randomAccessFile;
        this.start = start;
        this.size = size;
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
        byte[] buf = new byte[4096];
        int readLen;
        randomAccessFile.seek(start + pos);
        while (length > 0 && (readLen = randomAccessFile.read(buf, 0, (int) Math.min(length, buf.length))) != -1) {
            os.write(buf, 0, readLen);
            length -= readLen;
            pos += readLen;
        }
        if (length != 0)
            throw new IllegalStateException("Remaining length: " + length);
    }
}
