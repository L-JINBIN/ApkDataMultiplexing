package bin.io;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;

/**
 * @author Bin
 */
public interface RandomAccessFile extends Closeable {

    void write(int value) throws IOException;

    void write(byte[] data) throws IOException;

    void write(byte[] data, int off, int len) throws IOException;

    int read() throws IOException;

    int read(byte[] data) throws IOException;

    int read(byte[] data, int off, int len) throws IOException;

    void readFully(byte[] data) throws IOException;

    void readFully(byte[] data, int off, int len) throws IOException;

    long length() throws IOException;

    void setLength(long newLength) throws IOException;

    void seek(long pos) throws IOException;

    int skipBytes(int n) throws IOException;

    long getFilePointer() throws IOException;

    String getName();

    RandomAccessFile getAnotherInSameParent(String name) throws IOException;

    RandomAccessFile newSameInstance() throws IOException;

    RandomAccessFile newFragment(long offset, long length) throws IOException;

    void flush() throws IOException;

    boolean isClosed();

    default void writeByte(byte b) throws IOException {
        write(b);
    }

    default void writeUShort(int i) throws IOException {
        write(i & 0xFF);
        write(i >>> 8 & 0xFF);
    }

    default void writeShort(short i) throws IOException {
        writeUShort(i);
    }

    default void writeChar(char c) throws IOException {
        writeUShort(c);
    }

    default void writeInt(int i) throws IOException {
        write(i & 0xFF);
        write(i >>> 8 & 0xFF);
        write(i >>> 16 & 0xFF);
        write(i >>> 24 & 0xFF);
    }

    default void writeLong(long l) throws IOException {
        write((int) (l & 0xFF));
        write((int) (l >>> 8 & 0xFF));
        write((int) (l >>> 16 & 0xFF));
        write((int) (l >>> 24 & 0xFF));
        write((int) (l >>> 32 & 0xFF));
        write((int) (l >>> 40 & 0xFF));
        write((int) (l >>> 48 & 0xFF));
        write((int) (l >>> 56 & 0xFF));
    }

    default byte readByte() throws IOException {
        int ret = read();
        if (ret == -1) {
            throw new EOFException();
        }
        return (byte) ret;
    }

    default int readUShort() throws IOException {
        return readByte() & 0xFF | (readByte() & 0xFF) << 8;
    }

    default short readShort() throws IOException {
        return (short) readUShort();
    }

    default char readChar() throws IOException {
        return (char) readUShort();
    }

    default int readInt() throws IOException {
        return readByte() & 0xFF | (readByte() & 0xFF) << 8 | (readByte() & 0xFF) << 16 | (readByte() & 0xFF) << 24;
    }

    default long readLong() throws IOException {
        return readByte() & 0xFFL | (readByte() & 0xFFL) << 8 | (readByte() & 0xFFL) << 16 | (readByte() & 0xFFL) << 24
                | (readByte() & 0xFFL) << 32 | (readByte() & 0xFFL) << 40 | (readByte() & 0xFFL) << 48 | (readByte() & 0xFFL) << 56;
    }


}