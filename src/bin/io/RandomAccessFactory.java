package bin.io;

import java.io.File;
import java.io.IOException;

/**
 * @author Bin
 */
public class RandomAccessFactory {

    public static RandomAccessFile from(RandomAccessData randomAccessData) {
        return new BufferedRandomAccessFile(randomAccessData);
    }

    public static RandomAccessFile from(File file, String mode) throws IOException {
        return new BufferedRandomAccessFile(new RandomAccessDataImpl(file, mode));
    }

    public static RandomAccessFile from(String path, String mode) throws IOException {
        return new BufferedRandomAccessFile(new RandomAccessDataImpl(path, mode));
    }

}
