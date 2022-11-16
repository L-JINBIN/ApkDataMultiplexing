package bin.zip;

import java.io.IOException;

import static bin.zip.ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE;
import static bin.zip.ZipConstant.ZIP64_EXTENDED_INFO_HEADER_ID;

/**
 * @author Bin
 */
public class ZipEntry {
    public static final long UNKNOWN_SIZE = -1;
    private int platform = ZipConstant.PLATFORM_FAT;
    private int generalPurposeFlag;
    private int method;
    private String name;
    private long time;
    private int crc;
    private long compressedSize = UNKNOWN_SIZE;
    private long size = UNKNOWN_SIZE;
    private int internalAttributes = 0;
    private int externalAttributes = 0;
    private long headerOffset;
    private long dataOffset;
    private byte[] extra;
    private byte[] commentData;

    ZipEntry() {
    }

    public ZipEntry(String name) {
        setName(name);
    }

    public int getPlatform() {
        return platform;
    }

    void setPlatform(int platform) {
        this.platform = platform;
    }

    public int getGeneralPurposeFlag() {
        return generalPurposeFlag;
    }

    void setGeneralPurposeFlag(int generalPurposeFlag) {
        this.generalPurposeFlag = generalPurposeFlag;
    }

    public int getMethod() {
        return method;
    }

    public void setMethod(int method) {
        this.method = method;
    }

    public long getTime() {
        return time;
    }

    public void setTime(long time) {
        this.time = time;
    }

    public int getCrc() {
        return crc;
    }

    void setCrc(int crc) {
        this.crc = crc;
    }

    public long getCompressedSize() {
        return compressedSize;
    }

    public void setCompressedSize(long compressedSize) {
        this.compressedSize = compressedSize;
    }

    public long getSize() {
        return size;
    }

    public void setSize(long size) {
        this.size = size;
    }

    public boolean isDirectory() {
        return getName().endsWith("/");
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        if (name == null)
            name = "";
        if (getPlatform() == ZipConstant.PLATFORM_FAT && !name.contains("/")) {
            name = name.replace('\\', '/');
        }
        this.name = name;
    }

    public byte[] getExtra() {
        return extra;
    }

    void setExtra(byte[] extra) {
        this.extra = extra;
    }

    public int getInternalAttributes() {
        return internalAttributes;
    }

    void setInternalAttributes(int internalAttributes) {
        this.internalAttributes = internalAttributes;
    }

    public int getExternalAttributes() {
        return externalAttributes;
    }

    void setExternalAttributes(int externalAttributes) {
        this.externalAttributes = externalAttributes;
    }

    public long getHeaderOffset() {
        return headerOffset;
    }

    void setHeaderOffset(long headerOffset) {
        this.headerOffset = headerOffset;
    }

    public long getDataOffset() {
        return dataOffset;
    }

    void setDataOffset(long dataOffset) {
        this.dataOffset = dataOffset;
    }

    boolean setupZip64WithCenterDirectoryExtra(byte[] extra) throws IOException {
        ExtraDataRecord record = ExtraDataRecord.find(extra, ZIP64_EXTENDED_INFO_HEADER_ID);
        if (record == null) {
            if (compressedSize == MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE ||
                    size == MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE ||
                    headerOffset == MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE) {
                throw new IOException("File contains no zip64 extended information: "
                        + "name=" + name + ", compressedSize=" + compressedSize + ", size="
                        + size + ", headerOffset=" + headerOffset);
            }
            return false;
        }
        int offset = 0;
        if (size == MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE) {
            size = record.readLong(offset);
            offset += 8;
        }
        if (compressedSize == MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE) {
            compressedSize = record.readLong(offset);
            offset += 8;
        }
        if (headerOffset == MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE) {
            headerOffset = record.readLong(offset);
        }
        return true;
    }

    void setNameData(byte[] nameData) {
        this.name = new String(nameData, ZipConstant.UTF_8);
    }

    void setCommentData(byte[] commentData) {
        this.commentData = commentData;
    }

    public byte[] getCommentData() {
        return commentData;
    }

}
