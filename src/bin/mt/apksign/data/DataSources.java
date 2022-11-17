package bin.mt.apksign.data;

import bin.io.RandomAccessFile;

import java.io.IOException;

public class DataSources {

    public static DataSource fromFile(RandomAccessFile randomAccessFile, long start, long size) {
        return new FileDataSource(randomAccessFile, start, size);
    }

    public static DataSource fromData(byte[] data) {
        return fromData(data, 0, data.length);
    }

    public static DataSource fromData(byte[] data, int start, int size) {
        return new ByteArrayDataSource(data, start, size);
    }

    public static DataSource align(DataSource source, int align) {
        long size = source.size();
        int overCount = (int) (size % align);
        if (overCount == 0)
            return source;
        int fillCount = align - overCount;
        return link(source, fromData(new byte[fillCount]));
    }

    public static DataSource link(DataSource... sources) {
        return new ChainedDataSource(sources);
    }

    public static void reset(DataSource... sources) throws IOException {
        for (DataSource source : sources) {
            source.reset();
        }
    }

}
