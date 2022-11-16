package bin.zip;

/**
 * @author Bin
 */
class CenterFileHeader implements Comparable<CenterFileHeader> {
    int generalPurposeFlag;
    int method;
    int time;
    int crc;
    long compressedSize;
    long size;
    String nameStr;
    byte[] name;
    byte[] extra;
    byte[] comment;
    int diskNumberStart;
    int internalAttributes;
    int externalAttributes;
    long headerOffset;
    long dataOffset;
    boolean isDirectory;
    boolean isUtf8;
    boolean sizeNeedZip64;
    boolean offsetNeedZip64;

    CenterFileHeader(String name) {
        this.nameStr = name;
        this.name = name.getBytes(ZipConstant.UTF_8);
        isUtf8 = true;
        extra = new byte[0];
        comment = new byte[0];
        time = (int) ZipUtil.javaToDosTime(System.currentTimeMillis());
        isDirectory = name.endsWith("/") || name.endsWith("\\");
        compressedSize = ZipEntry.UNKNOWN_SIZE;
        size = ZipEntry.UNKNOWN_SIZE;
    }

    CenterFileHeader(ZipEntry entry) {
        nameStr = entry.getName();
        name = entry.getName().getBytes(ZipConstant.UTF_8);
        isUtf8 = true;
        time = (int) ZipUtil.javaToDosTime(entry.getTime());
        method = entry.getMethod();
        crc = entry.getCrc();
        compressedSize = entry.getCompressedSize();
        size = entry.getSize();
        extra = entry.getExtra() == null ? new byte[0] : entry.getExtra();
        comment = entry.getCommentData() == null ? new byte[0] : entry.getCommentData();
        internalAttributes = entry.getInternalAttributes();
        externalAttributes = entry.getExternalAttributes();
        isDirectory = entry.isDirectory();
    }

    boolean needZip64() {
        return sizeNeedZip64 || offsetNeedZip64;
    }

    boolean isEncrypted() {
        return (generalPurposeFlag & 1) != 0;
    }

    int version() {
        if (needZip64()) {
            return 45;
        } else if (method == ZipConstant.METHOD_STORED && !isEncrypted()) {
            return 10;
        } else {
            return 20;
        }
    }

    @Override
    public int compareTo(CenterFileHeader o) {
        return nameStr.compareTo(o.nameStr);
    }
}
