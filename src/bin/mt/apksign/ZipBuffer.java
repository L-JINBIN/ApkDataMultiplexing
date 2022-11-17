package bin.mt.apksign;

import bin.io.RandomAccessFile;

import java.io.EOFException;
import java.io.IOException;

class ZipBuffer {
    static final long APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L;
    static final long APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L;
    static final int EOCD_SIG = 0X06054B50;
    static final int MIN_EOCD_SIZE = 22;
    static final int MAX_EOCD_SIZE = MIN_EOCD_SIZE + 0xFFFF;
    static final int APK_SIG_BLOCK_MIN_SIZE = 32;

    private final long entriesDataSizeBytes;
    private final long centralDirectoryOffset;
    private final long centralDirectorySizeBytes;
    private final long eocdOffset;
    private final boolean hasApkSigBlock;
    private final RandomAccessFile file;

    ZipBuffer(RandomAccessFile file) throws IOException {
        this.file = file;
        boolean found = false;
        long length = length();
        long off = length - MIN_EOCD_SIZE;
        final long stopSearching =
                Math.max(0L, length - MAX_EOCD_SIZE);
        while (off >= stopSearching) {
            seek(off);
            if (readInt() == EOCD_SIG) {
                found = true;
                break;
            }
            off--;
        }
        if (!found) {
            throw new IOException("Archive is not a ZIP archive");
        }

        eocdOffset = off;
        // 没做zip64支持
        seek(off + 12);
        centralDirectorySizeBytes = readUInt();
        centralDirectoryOffset = readUInt();

        long entriesDataEnd = centralDirectoryOffset;
        boolean matchV2SigBlock = false;
        try {
            if (centralDirectoryOffset >= APK_SIG_BLOCK_MIN_SIZE) {
                seek(centralDirectoryOffset - 16);
                if (readLong() == APK_SIG_BLOCK_MAGIC_LO && readLong() == APK_SIG_BLOCK_MAGIC_HI) {
                    seek(centralDirectoryOffset - 24);
                    long size = readLong();
                    long sigStart = centralDirectoryOffset - size - 8;
                    seek(sigStart);
                    if (readLong() == size) {
                        matchV2SigBlock = true;
                        entriesDataEnd = sigStart;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        entriesDataSizeBytes = entriesDataEnd;
        hasApkSigBlock = matchV2SigBlock;
    }

    public long length() throws IOException {
        return file.length();
    }

    public void seek(long position) throws IOException {
        file.seek(position);
    }

    public long position() throws IOException {
        return file.getFilePointer();
    }

    public void skip(int length) throws IOException {
        if (length < 0)
            throw new IOException("Skip " + length);
        long pos = file.getFilePointer() + length;
        long len = file.length();
        if (pos > len)
            throw new EOFException();
        file.seek(pos);
    }

    public byte[] readBytes(int len) throws IOException {
        byte[] bytes = new byte[len];
        file.readFully(bytes);
        return bytes;
    }

    public int readInt() throws IOException {
        int ch1 = file.read();
        int ch2 = file.read();
        int ch3 = file.read();
        int ch4 = file.read();
        if ((ch1 | ch2 | ch3 | ch4) < 0)
            throw new EOFException();
        return (ch1) | (ch2 << 8) | (ch3 << 16) | (ch4 << 24);
    }

    public long readLong() throws IOException {
        long ch1 = file.read();
        long ch2 = file.read();
        long ch3 = file.read();
        long ch4 = file.read();
        long ch5 = file.read();
        long ch6 = file.read();
        long ch7 = file.read();
        long ch8 = file.read();
        if ((ch1 | ch2 | ch3 | ch4) < 0)
            throw new EOFException();
        return (ch1) | (ch2 << 8) | (ch3 << 16) | (ch4 << 24) | (ch5 << 32) | (ch6 << 40) | (ch7 << 48) | (ch8 << 56);

    }

    public long readUInt() throws IOException {
        return readInt() & 0xFFFFFFFFL;
    }

    public long getEntriesDataSizeBytes() {
        return entriesDataSizeBytes;
    }

    public long getCentralDirectoryOffset() {
        return centralDirectoryOffset;
    }

    public long getCentralDirectorySizeBytes() {
        return centralDirectorySizeBytes;
    }

    public long getEocdOffset() {
        return eocdOffset;
    }

    public boolean hasApkSigBlock() {
        return hasApkSigBlock;
    }

    public RandomAccessFile getFile() {
        return file;
    }
}
