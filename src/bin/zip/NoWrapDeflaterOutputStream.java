package bin.zip;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 * @author Bin
 */
public class NoWrapDeflaterOutputStream extends DeflaterOutputStream {

    public NoWrapDeflaterOutputStream(OutputStream os, int level) {
        super(os, new Deflater(level, true));
    }

    @Override
    public void close() throws IOException {
        super.close();
        def.end();
    }
}
