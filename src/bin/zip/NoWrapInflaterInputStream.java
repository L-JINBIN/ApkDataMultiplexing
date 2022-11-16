package bin.zip;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import java.util.zip.ZipException;

/**
 * @author Bin
 */
public class NoWrapInflaterInputStream extends InflaterInputStream {
    private final ZipEntry entry;

    public NoWrapInflaterInputStream(ZipEntry entry, InputStream in) {
        super(in, new Inflater(true));
        this.entry = entry;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        try {
            return super.read(b, off, len);
        } catch (ZipException e) {
            e.printStackTrace();
            throw new ZipException("Error: " + e.getMessage() + " (" + entry.getName() + ")");
        } catch (EOFException e) {
            return -1;
        }
    }

}
