package bin.mt.apksign.data;

import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;

public class ChainedDataSource implements DataSource {
    private DataSource[] sources;
    private DataSource currentSource;
    private int currentIndex;
    private long size;
    private long pos;

    ChainedDataSource(DataSource... sources) {
        if (sources.length == 0)
            throw new IllegalArgumentException();
        this.sources = sources;
        this.currentIndex = 0;
        this.currentSource = sources[currentIndex];
        this.pos = 0;
        this.size = 0;
        for (DataSource source : sources) {
            size += source.size();
        }
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
    public void reset() throws IOException {
        this.currentIndex = 0;
        this.currentSource = sources[currentIndex];
        this.pos = 0;
        for (DataSource source : sources) {
            source.reset();
        }
    }

    @Override
    public void copyTo(OutputStream os, long length) throws IOException {
        if (length > remaining())
            throw new EOFException();
        while (length > 0) {
            long len = Math.min(length, currentSource.remaining());
            currentSource.copyTo(os, len);
            length -= len;
            pos += len;
            if (currentSource.remaining() == 0 && currentIndex < sources.length - 1) {
                currentSource = sources[++currentIndex];
            }
        }
    }

}
