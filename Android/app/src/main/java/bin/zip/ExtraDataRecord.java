package bin.zip;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Bin
 */
class ExtraDataRecord {
    private static final Set<Integer> KNOWN_HEADER = new HashSet<>();

    static {
        // https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
        // 4.5.2 The current Header ID mappings defined by PKWARE are:
        KNOWN_HEADER.add(0x0001);
        KNOWN_HEADER.add(0x0007);
        KNOWN_HEADER.add(0x0008);
        KNOWN_HEADER.add(0x0009);
        KNOWN_HEADER.add(0x000a);
        KNOWN_HEADER.add(0x000c);
        KNOWN_HEADER.add(0x000d);
        KNOWN_HEADER.add(0x000e);
        KNOWN_HEADER.add(0x000f);
        KNOWN_HEADER.add(0x0014);
        KNOWN_HEADER.add(0x0015);
        KNOWN_HEADER.add(0x0016);
        KNOWN_HEADER.add(0x0017);
        KNOWN_HEADER.add(0x0018);
        KNOWN_HEADER.add(0x0019);
        KNOWN_HEADER.add(0x0020);
        KNOWN_HEADER.add(0x0021);
        KNOWN_HEADER.add(0x0022);
        KNOWN_HEADER.add(0x0023);
        KNOWN_HEADER.add(0x0065);
        KNOWN_HEADER.add(0x0066);
        KNOWN_HEADER.add(0x4690);
        KNOWN_HEADER.add(0x07c8);
        KNOWN_HEADER.add(0x2605);
        KNOWN_HEADER.add(0x2705);
        KNOWN_HEADER.add(0x2805);
        KNOWN_HEADER.add(0x334d);
        KNOWN_HEADER.add(0x4341);
        KNOWN_HEADER.add(0x4453);
        KNOWN_HEADER.add(0x4704);
        KNOWN_HEADER.add(0x470f);
        KNOWN_HEADER.add(0x4b46);
        KNOWN_HEADER.add(0x4c41);
        KNOWN_HEADER.add(0x4d49);
        KNOWN_HEADER.add(0x4f4c);
        KNOWN_HEADER.add(0x5356);
        KNOWN_HEADER.add(0x5455);
        KNOWN_HEADER.add(0x554e);
        KNOWN_HEADER.add(0x5855);
        KNOWN_HEADER.add(0x6375);
        KNOWN_HEADER.add(0x6542);
        KNOWN_HEADER.add(0x7075);
        KNOWN_HEADER.add(0x756e);
        KNOWN_HEADER.add(0x7855);
        KNOWN_HEADER.add(0xa11e);
        KNOWN_HEADER.add(0xa220);
        KNOWN_HEADER.add(0xfd4a);
        KNOWN_HEADER.add(0x9901);
        KNOWN_HEADER.add(0x9902);
    }

    private int header;
    private int sizeOfData;
    private byte[] data;

    /**
     * 去除无效数据
     */
    public static byte[] trim(byte[] extra) throws IOException {
        int offset = 0;
        while (extra.length - offset >= 4) {
            int header = ZipUtil.readUShort(extra, offset);
            int size = ZipUtil.readUShort(extra, offset + 2);
            if (!KNOWN_HEADER.contains(header) || offset + 4 + size > extra.length) {
                break;
            }
            offset += 4 + size;
        }
        return Arrays.copyOf(extra, offset);
    }

    public static byte[] set(byte[] extra, int header, byte[] data) throws IOException {
        extra = remove(extra, header);
        byte[] newExtra = new byte[4 + data.length + extra.length];
        ZipUtil.writeShort(newExtra, 0, header);
        ZipUtil.writeShort(newExtra, 2, data.length);
        System.arraycopy(data, 0, newExtra, 4, data.length);
        System.arraycopy(extra, 0, newExtra, 4 + data.length, extra.length);
        return newExtra;
    }

    public static byte[] remove(byte[] extra, int header) throws IOException {
        int offset = 0;
        while (extra.length - offset >= 4) {
            int h = ZipUtil.readUShort(extra, offset);
            int size = ZipUtil.readUShort(extra, offset + 2);
            offset += 4;
            if (size > extra.length - offset)
                return extra;
            if (h != header) {
                offset += size;
            } else {
                offset -= 4;
                size += 4;
                byte[] bytes = new byte[extra.length - size];
                System.arraycopy(extra, 0, bytes, 0, offset);
                System.arraycopy(extra, offset + size, bytes, offset, extra.length - size - offset);
                return bytes;
            }
        }
        return extra;
    }

    public static ExtraDataRecord find(byte[] extra, int header) throws IOException {
        int offset = 0;
        while (extra.length - offset >= 4) {
            int h = ZipUtil.readUShort(extra, offset);
            int size = ZipUtil.readUShort(extra, offset + 2);
            offset += 4;
            if (size > extra.length - offset)
                return null;
            if (h != header) {
                offset += size;
            } else {
                byte[] bytes = new byte[size];
                System.arraycopy(extra, offset, bytes, 0, size);
                ExtraDataRecord record = new ExtraDataRecord();
                record.setHeader(header);
                record.setSizeOfData(size);
                record.setData(bytes);
                return record;
            }
        }
        return null;
    }

    public static byte[] generateAESExtra(int aesKeyStrength, int method) throws IOException {
        int versionNumber = 2;  // 2
        String vendorID = "AE"; // 2
        // aesKeyStrength       // 1
        // method               // 2
        byte[] data = new byte[7];
        ZipUtil.writeShort(data, 0, versionNumber);
        ZipUtil.writeBytes(data, 2, vendorID.getBytes());
        ZipUtil.writeByte(data, 4, aesKeyStrength);
        ZipUtil.writeShort(data, 5, method);
        return data;
    }

    public int getHeader() {
        return header;
    }

    public void setHeader(int header) {
        this.header = header;
    }

    public int getSizeOfData() {
        return sizeOfData;
    }

    public void setSizeOfData(int sizeOfData) {
        this.sizeOfData = sizeOfData;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public int readUByte(int off) throws IOException {
        return ZipUtil.readUByte(data, off);
    }

    public int readUShort(int off) throws IOException {
        return ZipUtil.readUShort(data, off);
    }

    public int readInt(int off) throws IOException {
        return ZipUtil.readInt(data, off);
    }

    public long readLong(int off) throws IOException {
        return ZipUtil.readLong(data, off);
    }

}
