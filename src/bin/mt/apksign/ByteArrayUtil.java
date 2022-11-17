package bin.mt.apksign;

class ByteArrayUtil {

    static void setInt(int value, byte[] data, int offset) {
        data[offset] = (byte) (value & 0xff);
        data[offset + 1] = (byte) ((value >> 8) & 0xff);
        data[offset + 2] = (byte) ((value >> 16) & 0xff);
        data[offset + 3] = (byte) ((value >> 24) & 0xff);
    }

    static void setUInt(long value, byte[] data, int offset) {
        data[offset] = (byte) (value & 0xff);
        data[offset + 1] = (byte) ((value >> 8) & 0xff);
        data[offset + 2] = (byte) ((value >> 16) & 0xff);
        data[offset + 3] = (byte) ((value >> 24) & 0xff);
    }

    static void setLong(long value, byte[] data, int offset) {
        data[offset] = (byte) (value & 0xff);
        data[offset + 1] = (byte) ((value >> 8) & 0xff);
        data[offset + 2] = (byte) ((value >> 16) & 0xff);
        data[offset + 3] = (byte) ((value >> 24) & 0xff);
        data[offset + 4] = (byte) ((value >> 32) & 0xff);
        data[offset + 5] = (byte) ((value >> 40) & 0xff);
        data[offset + 6] = (byte) ((value >> 48) & 0xff);
        data[offset + 7] = (byte) ((value >> 56) & 0xff);
    }

    static long readUInt(byte[] data, int offset) {
        long ch1 = data[offset] & 0xffL;
        long ch2 = data[offset + 1] & 0xffL;
        long ch3 = data[offset + 2] & 0xffL;
        long ch4 = data[offset + 3] & 0xffL;
        return (ch1) | (ch2 << 8) | (ch3 << 16) | (ch4 << 24);
    }

    static byte[] intToBytes(int value) {
        byte[] array = new byte[4];
        setInt(value, array, 0);
        return array;
    }

}
