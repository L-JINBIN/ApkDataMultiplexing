package bin.mt.apksign.data;

import bin.io.RandomAccessFile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;

public interface DataSource {

    long size();

    long pos();

    default long remaining() {
        return size() - pos();
    }

    void reset() throws IOException;

    void copyTo(OutputStream os, long length) throws IOException;

    default void copyTo(MessageDigest digest, long length) throws IOException {
        OutputStream os = new OutputStream() {
            @Override
            public void write(int b) {
                digest.update((byte) b);
            }

            @Override
            public void write(byte[] b, int off, int len) {
                digest.update(b, off, len);
            }
        };
        copyTo(os, length);
    }

    default void copyTo(RandomAccessFile accessFile, long length) throws IOException {
        OutputStream os = new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                accessFile.write(b);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                accessFile.write(b, off, len);
            }
        };
        copyTo(os, length);
    }

    default DataSource align(int align) {
        return DataSources.align(this, align);
    }

    default ByteArrayDataSource toMemory() throws IOException {
        long remaining = remaining();
        if (remaining > Integer.MAX_VALUE) {
            throw new IOException("Data too large");
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream((int) remaining);
        copyTo(baos, remaining);
        return (ByteArrayDataSource) DataSources.fromData(baos.toByteArray());
    }

}
