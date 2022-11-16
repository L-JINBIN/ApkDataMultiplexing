package bin.io;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * @author Bin
 */
class RandomAccessDataImpl implements RandomAccessData {
    private final RandomAccessFile randomAccessFile;
    private final File file;
    private final String mode;

    RandomAccessDataImpl(String path, String mode) throws FileNotFoundException {
        this(new File(path), mode);
    }

    RandomAccessDataImpl(File file, String mode) throws FileNotFoundException {
        this.file = file;
        this.mode = mode;
        this.randomAccessFile = new RandomAccessFile(file, mode);
    }

    @Override
    public void seek(long pos) throws IOException {
        randomAccessFile.seek(pos);
    }

    @Override
    public int read(byte[] data, int off, int len) throws IOException {
        return randomAccessFile.read(data, off, len);
    }

    @Override
    public void write(byte[] data, int off, int len) throws IOException {
        randomAccessFile.write(data, off, len);
    }

    @Override
    public long length() throws IOException {
        return randomAccessFile.length();
    }

    @Override
    public void setLength(long newLength) throws IOException {
        randomAccessFile.setLength(newLength);
    }

    @Override
    public long position() throws IOException {
        return randomAccessFile.getFilePointer();
    }

    @Override
    public void sync() throws IOException {
        randomAccessFile.getFD().sync();
    }

    @Override
    public String getName() {
        return file.getName();
    }

    @Override
    public RandomAccessData getAnotherInSameParent(String name) throws IOException {
        File another = new File(file.getParent(), name);
        return new RandomAccessDataImpl(another, mode);
    }

    @Override
    public RandomAccessData newSameInstance() throws IOException {
        return new RandomAccessDataImpl(file, mode);
    }

    @Override
    public void close() throws IOException {
        randomAccessFile.close();
    }
}
