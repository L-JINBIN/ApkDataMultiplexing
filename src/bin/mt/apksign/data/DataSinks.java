package bin.mt.apksign.data;

public class DataSinks {

    public static DataSink fromData(byte[] data) {
        return fromData(data, 0, data.length);
    }

    public static DataSink fromData(byte[] data, int position, int limit) {
        return new ByteArrayDataSink(data, position, limit);
    }

}
