package bin.zip;

import java.io.EOFException;
import java.io.IOException;
import java.util.Calendar;

/**
 * @author Bin
 */
public class ZipUtil {
    private static final Calendar CALENDAR = Calendar.getInstance();

    public static long dosToJavaTime(long dosTime) {
        synchronized (CALENDAR) {
            CALENDAR.set(Calendar.YEAR, (int) ((dosTime >> 25) & 0x7f) + 1980);
            CALENDAR.set(Calendar.MONTH, (int) ((dosTime >> 21) & 0x0f) - 1);
            CALENDAR.set(Calendar.DATE, (int) (dosTime >> 16) & 0x1f);
            CALENDAR.set(Calendar.HOUR_OF_DAY, (int) (dosTime >> 11) & 0x1f);
            CALENDAR.set(Calendar.MINUTE, (int) (dosTime >> 5) & 0x3f);
            CALENDAR.set(Calendar.SECOND, (int) (dosTime << 1) & 0x3e);
            return CALENDAR.getTime().getTime();
        }
    }

    public static long javaToDosTime(long time) {
        Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(time);
        int year = cal.get(Calendar.YEAR);
        if (year < 1980) {
            return (1 << 21) | (1 << 16);
        }
        return (year - 1980L) << 25 | (cal.get(Calendar.MONTH) + 1) << 21 |
                cal.get(Calendar.DATE) << 16 | cal.get(Calendar.HOUR_OF_DAY) << 11 | cal.get(Calendar.MINUTE) << 5 |
                cal.get(Calendar.SECOND) >> 1;
    }

    public static void writeByte(byte[] array, int pos, int value) throws IOException {
        if (pos + 1 > array.length) {
            throw new EOFException();
        }
        array[pos] = (byte) (value & 0xFF);
    }

    public static void writeShort(byte[] array, int pos, int value) throws IOException {
        if (pos + 2 > array.length) {
            throw new EOFException();
        }
        array[pos] = (byte) (value & 0xFF);
        array[pos + 1] = (byte) (value >>> 8 & 0xFF);
    }

    public static void writeLong(byte[] array, int pos, long value) throws IOException {
        if (pos + 8 > array.length) {
            throw new EOFException();
        }
        array[pos] = (byte) (value & 0xFF);
        array[pos + 1] = (byte) (value >>> 8 & 0xFF);
        array[pos + 2] = (byte) (value >>> 16 & 0xFF);
        array[pos + 3] = (byte) (value >>> 24 & 0xFF);
        array[pos + 4] = (byte) (value >>> 32 & 0xFF);
        array[pos + 5] = (byte) (value >>> 40 & 0xFF);
        array[pos + 6] = (byte) (value >>> 48 & 0xFF);
        array[pos + 7] = (byte) (value >>> 56 & 0xFF);
    }

    public static void writeBytes(byte[] array, int pos, byte[] value) throws IOException {
        if (pos + value.length > array.length) {
            throw new EOFException();
        }
        System.arraycopy(value, 0, array, pos, value.length);
    }

    public static int readUByte(byte[] b, int off) throws IOException {
        if (off + 1 > b.length) {
            throw new EOFException();
        }
        return (b[off] & 0xff);
    }

    public static int readUShort(byte[] b, int off) throws IOException {
        if (off + 2 > b.length) {
            throw new EOFException();
        }
        return (b[off + 1] & 0xFF) << 8 | b[off] & 0xFF;
    }

    public static int readInt(byte[] b, int off) throws IOException {
        if (off + 4 > b.length) {
            throw new EOFException();
        }
        return b[off + 3] << 24 | (b[off + 2] & 0xFF) << 16 | (b[off + 1] & 0xFF) << 8 | b[off] & 0xFF;
    }

    public static long readLong(byte[] b, int off) throws IOException {
        if (off + 8 > b.length) {
            throw new EOFException();
        }
        return (long) b[off + 7] << 56 | ((long) b[off + 6] & 0xFF) << 48
                | ((long) b[off + 5] & 0xFF) << 40 | ((long) b[off + 4] & 0xFF) << 32
                | ((long) b[off + 3] & 0xFF) << 24 | ((long) b[off + 2] & 0xFF) << 16
                | ((long) b[off + 1] & 0xFF) << 8 | (long) b[off] & 0xFF;
    }


}
