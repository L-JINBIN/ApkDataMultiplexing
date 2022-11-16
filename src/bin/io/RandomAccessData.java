package bin.io;

import java.io.Closeable;
import java.io.IOException;

/**
 * @author Bin
 */
public interface RandomAccessData extends Closeable {

    void seek(long pos) throws IOException;

    int read(byte[] data, int off, int len) throws IOException;

    void write(byte[] data, int off, int len) throws IOException;

    long length() throws IOException;

    void setLength(long newLength) throws IOException;

    long position() throws IOException;

    void sync() throws IOException;

    String getName();

    RandomAccessData getAnotherInSameParent(String name) throws IOException;

    RandomAccessData newSameInstance() throws IOException;

    default RandomAccessData newFragment(long offset, long length) throws IOException {
        return new FragmentRandomAccessData(newSameInstance(), offset, length);
    }
}
