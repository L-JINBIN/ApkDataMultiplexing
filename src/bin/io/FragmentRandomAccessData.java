package bin.io;

import java.io.IOException;

/**
 * @author Bin
 */
class FragmentRandomAccessData implements RandomAccessData {
    private final RandomAccessData randomAccessData;
    private final long offset;
    private final long length;
    private long pos;

    public FragmentRandomAccessData(RandomAccessData randomAccessData, long offset, long length) throws IOException {
        this.randomAccessData = randomAccessData;
        this.offset = offset;
        this.length = length;
        long dataLength = randomAccessData.length();
        if (offset + length > dataLength) {
            throw new IOException(String.format("fragment.offset=%d, fragment.length=%d, data.length=%d", offset, length, dataLength));
        }
        seek(0);
    }

    @Override
    public void seek(long pos) throws IOException {
        randomAccessData.seek(pos + offset);
        this.pos = randomAccessData.position() - offset;
    }

    @Override
    public int read(byte[] data, int off, int len) throws IOException {
        long available = length - pos;
        if (len > available) {
            if (available <= 0) {
                return -1;
            }
            len = (int) available;
        }
        int readLen = randomAccessData.read(data, off, len);
        if (readLen > 0) {
            this.pos += readLen;
        }
        return readLen;
    }

    @Override
    public void write(byte[] data, int off, int len) throws IOException {
        throw new IOException("FragmentRandomAccessData is readonly");
    }

    @Override
    public long length() throws IOException {
        return length;
    }

    @Override
    public void setLength(long newLength) throws IOException {
        throw new IOException("FragmentRandomAccessData is readonly");
    }

    @Override
    public long position() throws IOException {
        return pos;
    }

    @Override
    public void sync() throws IOException {
        randomAccessData.sync();
    }

    @Override
    public String getName() {
        return randomAccessData.getName() + "-Fragment(" + offset + "," + length + ")";
    }

    @Override
    public RandomAccessData getAnotherInSameParent(String name) throws IOException {
        throw new IOException("Unsupported");
    }

    @Override
    public RandomAccessData newSameInstance() throws IOException {
        return new FragmentRandomAccessData(randomAccessData.newSameInstance(), offset, length);
    }

    @Override
    public void close() throws IOException {
        randomAccessData.close();
    }
}
