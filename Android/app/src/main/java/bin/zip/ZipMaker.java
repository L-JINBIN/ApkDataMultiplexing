package bin.zip;

import static bin.zip.ZipConstant.CFH_SIG;
import static bin.zip.ZipConstant.EOCD_SIG;
import static bin.zip.ZipConstant.LFH_SIG;
import static bin.zip.ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE;
import static bin.zip.ZipConstant.SHORT;
import static bin.zip.ZipConstant.UFT8_NAMES_FLAG;
import static bin.zip.ZipConstant.WORD;
import static bin.zip.ZipConstant.ZIP64_EOCD_RECORD_EFFECTIVE_SIZE;
import static bin.zip.ZipConstant.ZIP64_EOCD_RECORD_SIGNATURE;
import static bin.zip.ZipConstant.ZIP64_EXTENDED_INFO_HEADER_ID;
import static bin.zip.ZipConstant.ZIP64_LOCATOR_SIGNATURE;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.zip.Deflater;

import bin.io.RandomAccessFactory;
import bin.io.RandomAccessFile;

/**
 * @author Bin
 */
public class ZipMaker implements Closeable {
    public static final int LEVEL_FASTEST = Deflater.BEST_SPEED;
    public static final int LEVEL_FASTER = 3;
    public static final int LEVEL_DEFAULT = Deflater.DEFAULT_COMPRESSION;
    public static final int LEVEL_BETTER = 7;
    public static final int LEVEL_BEST = Deflater.BEST_COMPRESSION;

    public static final int METHOD_DEFLATED = ZipConstant.METHOD_DEFLATED;
    public static final int METHOD_STORED = ZipConstant.METHOD_STORED;

    private final RandomAccessFile archive;

    private final ArrayList<CenterFileHeader> headers = new ArrayList<>();
    private final byte[] copyEntryBuffer = new byte[8 * 1024];
    private CenterFileHeader currentHeader;
    private int method = METHOD_DEFLATED;
    private int level = LEVEL_DEFAULT;
    private Charset encoding = ZipConstant.UTF_8;
    private String comment;
    private boolean needsZip64EocdRecord;
    private boolean forceZip64;
    private CrcOutputStream topOutput;
    private BridgeOutputStream bottomOutput;

    public ZipMaker(String path) throws IOException {
        this(new File(path));
    }

    public ZipMaker(File file) throws IOException {
        if (file.exists())
            //noinspection ResultOfMethodCallIgnored
            file.delete();
        this.archive = RandomAccessFactory.from(file, "rw");
    }

    private static boolean isAligned(long pos, int alignTo) {
        return (pos % alignTo) == 0;
    }

    private static int getAlignedPadding(long pos, int alignTo) {
        return (int) (alignTo - (pos % alignTo)) % alignTo;
    }

    public void setForceZip64(boolean forceZip64) {
        this.forceZip64 = forceZip64;
    }

    public void setEncoding(Charset encoding) {
        this.encoding = encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = Charset.forName(encoding);
    }

    public int getMethod() {
        return method;
    }

    public void setMethod(int method) {
        this.method = method;
    }

    public int getLevel() {
        return level;
    }

    public void setLevel(int level) {
        this.level = level;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public void putNextEntry(String name) throws IOException {
        putNextEntry(new CenterFileHeader(name));
    }

    public void putNextEntry(ZipEntry ze) throws IOException {
        putNextEntry(new CenterFileHeader(ze));
    }

    private void putNextEntry(CenterFileHeader header) throws IOException {
        if (currentHeader != null) {
            closeEntry();
        }
        header.headerOffset = _getFilePointer();
        headers.add(header);

        if (!header.isDirectory) {
            currentHeader = header;

            int generalPurposeFlag = 0;
            int method = this.method;

            bottomOutput = new BridgeOutputStream(archive);
            OutputStream os = bottomOutput;

            if (header.isUtf8)
                generalPurposeFlag |= UFT8_NAMES_FLAG;

            switch (this.method) {
                case METHOD_DEFLATED:
                    os = new NoWrapDeflaterOutputStream(os, level);
                    break;
                case METHOD_STORED:
                    break;
                default:
                    throw new IOException("Unsupported compression method " + method);
            }

            topOutput = new CrcOutputStream(os);

            header.generalPurposeFlag = generalPurposeFlag;
            header.method = method;
        } else {
            header.method = METHOD_STORED;
            if (header.isUtf8) {
                header.generalPurposeFlag = UFT8_NAMES_FLAG;
            }
        }

        writeHeader(header);
        header.dataOffset = _getFilePointer();
    }

    public void putNextRawEntry(ZipEntry ze) throws IOException {
        if (currentHeader != null)
            closeEntry();
        CenterFileHeader header = new CenterFileHeader(ze);
        if (header.isUtf8)
            header.generalPurposeFlag |= UFT8_NAMES_FLAG;
        header.headerOffset = _getFilePointer();
        headers.add(header);
        writeHeader(header);
        header.dataOffset = _getFilePointer();
    }

    public void writeRaw(byte[] data) throws IOException {
        writeRaw(data, 0, data.length);
    }

    public void writeRaw(byte[] data, int off, int len) throws IOException {
        archive.write(data, off, len);
    }

    public void copyZipEntry(ZipEntry ze, ZipFile zipFile) throws IOException {
        putNextRawEntry(ze);
        if (!ze.isDirectory()) {
            InputStream is = zipFile.getRawInputStream(ze);
            byte[] buffer = copyEntryBuffer;
            int len;
            while ((len = is.read(buffer)) != -1) {
                writeRaw(buffer, 0, len);
            }
        }
    }

    public HostEntryHolder putNextHostEntry(String name, ZipFile zipFile) throws IOException {
        if (name.endsWith("/") || name.endsWith("\\")) {
            throw new IOException("Invalid host entry name: " + name);
        }
        int savedMethod = method;
        method = METHOD_STORED;
        putNextEntry(name);
        currentHeader.isHost = true;
        method = savedMethod;
        return new HostEntryHolder(zipFile);
    }

    private void writeHeader(CenterFileHeader header) throws IOException {
        setupNeedZip64(header);

        _writeInt(LFH_SIG);
        _writeShort(header.version());
        _writeShort(header.generalPurposeFlag);
        _writeShort(header.method);
        _writeInt(header.time);
        _writeInt(header.crc);
        if (header.sizeNeedZip64) {
            _writeUInt(MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE);
            _writeUInt(MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE);
        } else {
            _writeUInt(header.compressedSize);
            _writeUInt(header.size);
        }
        _writeShort(header.name.length);

        byte[] extra;
        if (header.sizeNeedZip64) {
            byte[] data = new byte[2 * 8];
            ZipUtil.writeLong(data, 0, header.size);
            ZipUtil.writeLong(data, 8, header.compressedSize);
            extra = ExtraDataRecord.set(header.extra, ZIP64_EXTENDED_INFO_HEADER_ID, data);
        } else {
            extra = ExtraDataRecord.remove(header.extra, ZIP64_EXTENDED_INFO_HEADER_ID);
        }
        // zipAlign
        if (header.method == METHOD_STORED) {
            int alignment;
            if (header.isHost || new String(header.name, ZipConstant.UTF_8).endsWith(".so")) {
                // -p: memory page alignment for stored shared object files
                alignment = 4096;
            } else {
                alignment = 4;
            }
            long extraDataOffset = _getFilePointer() + 2 + header.name.length;
            extra = align(alignment, extra, extraDataOffset);
        }
        _writeShort(extra.length);
        _writeBytes(header.name);

        _writeBytes(extra);
    }

    private void setupNeedZip64(CenterFileHeader header) {
        if (forceZip64) {
            header.sizeNeedZip64 = true;
            header.offsetNeedZip64 = true;
        } else {
            // 只知道原体积但不知道压缩后体积时，若原体积大于0xf0000000L则采用zip64
            if (header.size >= 0xf0000000L && header.compressedSize == ZipEntry.UNKNOWN_SIZE) {
                header.sizeNeedZip64 = true;
            } else if (header.size >= MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE ||
                    header.compressedSize >= MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE) {
                header.sizeNeedZip64 = true;
            }
            if (header.headerOffset >= MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE)
                header.offsetNeedZip64 = true;
        }
        if (header.needZip64()) {
            needsZip64EocdRecord = true;
        }
        if (header.size == ZipEntry.UNKNOWN_SIZE) {
            header.size = 0;
        }
        if (header.compressedSize == ZipEntry.UNKNOWN_SIZE) {
            header.compressedSize = 0;
        }
    }

    public void write(int b) throws IOException {
        topOutput.write(b);
    }

    public void write(byte[] data) throws IOException {
        topOutput.write(data);
    }

    public void write(byte[] data, int off, int len) throws IOException {
        topOutput.write(data, off, len);
    }

    public void writeFully(InputStream is) throws IOException {
        int len;
        byte[] b = new byte[1024 * 4];
        while ((len = is.read(b)) > 0)
            write(b, 0, len);
    }

    public void closeEntry() throws IOException {
        if (currentHeader == null) {
            return;
        }
        topOutput.close();

        currentHeader.crc = topOutput.getCrc();
        currentHeader.compressedSize = bottomOutput.getCount();
        currentHeader.size = topOutput.getCount();

        long saved = _getFilePointer();
        _seek(currentHeader.headerOffset + WORD + SHORT + SHORT + SHORT + WORD);
        _writeInt(currentHeader.crc);
        if (currentHeader.sizeNeedZip64) {
            _writeUInt(MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE);
            _writeUInt(MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE);

            // skip nameLength + extraLength + nameData
            _skip(SHORT + SHORT + currentHeader.name.length);

            // skip zip64Extra(header + size)
            _skip(4);

            // update local extra
            _writeLong(currentHeader.size);
            _writeLong(currentHeader.compressedSize);
        } else {
            if (currentHeader.compressedSize >= MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE ||
                    currentHeader.size >= MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE) {
                throw new IOException("Zip entry size needs zip64: name=" + new String(currentHeader.name)
                        + ", compressedSize=" + currentHeader.compressedSize
                        + ", size=" + currentHeader.size
                );
            }
            _writeUInt(currentHeader.compressedSize);
            _writeUInt(currentHeader.size);
        }

        archive.seek(saved);

        topOutput = null;
        bottomOutput = null;
        currentHeader = null;
    }

    @Override
    public void close() throws IOException {
        if (archive.isClosed())
            return;
        if (currentHeader != null)
            closeEntry();
        long cdOffset = _getFilePointer();
        try {
            Collections.sort(headers);
        } catch (RuntimeException e) {
            throw new IOException(e);
        }
        for (CenterFileHeader header : headers) {
            writeCentralFileHeader(header);
        }
        long cdSize = _getFilePointer() - cdOffset;
        writeCentralDirectoryEnd(cdSize, cdOffset);
        archive.close();
    }

    private byte[] align(int alignment, byte[] extra, long extraDataOffset) throws IOException {
        if (isAligned(extraDataOffset + extra.length, alignment)) {
            return extra;
        }
        extra = ExtraDataRecord.trim(extra);
        int padding = getAlignedPadding(extraDataOffset + extra.length, alignment);
        return Arrays.copyOf(extra, extra.length + padding);
    }

    private void writeCentralFileHeader(CenterFileHeader header) throws IOException {
        boolean needZip64 = header.needZip64();
        byte[] extra;
        if (needZip64) {
            byte[] data = new byte[3 * 8];
            ZipUtil.writeLong(data, 0, header.size);
            ZipUtil.writeLong(data, 8, header.compressedSize);
            ZipUtil.writeLong(data, 16, header.headerOffset);
            extra = ExtraDataRecord.set(header.extra, ZIP64_EXTENDED_INFO_HEADER_ID, data);
        } else {
            extra = ExtraDataRecord.remove(header.extra, ZIP64_EXTENDED_INFO_HEADER_ID);
        }

        _writeInt(CFH_SIG);
        _writeShort(Math.max(20, header.version()));
        _writeShort(header.version());
        _writeShort(header.generalPurposeFlag);
        _writeShort(header.method);
        _writeInt(header.time);
        _writeInt(header.crc);
        if (needZip64) {
            _writeUInt(MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE);
            _writeUInt(MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE);
        } else {
            _writeUInt(header.compressedSize);
            _writeUInt(header.size);
        }
        _writeShort(header.name.length);
        _writeShort(extra.length);
        _writeShort(header.comment.length);
        _writeShort(header.diskNumberStart);
        _writeShort(header.internalAttributes);
        _writeInt(header.externalAttributes);
        if (needZip64) {
            _writeUInt(MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE);
        } else {
            _writeUInt(header.headerOffset);
        }
        _writeBytes(header.name);
        _writeBytes(extra);
        _writeBytes(header.comment);
    }

    private void writeCentralDirectoryEnd(long cdSize, long cdOffset) throws IOException {
        if (headers.size() >= 0xffff) {
            needsZip64EocdRecord = true;
        }
        if (needsZip64EocdRecord) {
            // Zip64 end of central directory record
            _writeInt(ZIP64_EOCD_RECORD_SIGNATURE);
            _writeLong(ZIP64_EOCD_RECORD_EFFECTIVE_SIZE + 4);
            _writeShort(20);
            _writeShort(20);
            _writeInt(0); // number of disk
            _writeInt(0); // number of disk with start of central dir.
            _writeLong(headers.size());
            _writeLong(headers.size());
            _writeLong(cdSize);
            _writeLong(cdOffset);

            // Zip64 end of central directory locator
            _writeInt(ZIP64_LOCATOR_SIGNATURE);
            _writeInt(0);
            _writeLong(cdSize + cdOffset);
            _writeInt(1);
        }
        byte[] comment = this.comment == null ? new byte[0] : this.comment.getBytes(encoding);
        _writeInt(EOCD_SIG);
        _writeShort(0);
        _writeShort(0);
        if (needsZip64EocdRecord) {
            _writeShort(0xFFFF);
            _writeShort(0xFFFF);
            _writeUInt(MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE);
            _writeUInt(MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE);
        } else {
            _writeShort(headers.size());
            _writeShort(headers.size());
            _writeUInt(cdSize);
            _writeUInt(cdOffset);
        }
        _writeShort(comment.length);
        _writeBytes(comment);
    }

    private void _seek(long position) throws IOException {
        archive.seek(position);
    }

    private long _getFilePointer() throws IOException {
        return archive.getFilePointer();
    }

    private void _skip(int n) throws IOException {
        archive.skipBytes(n);
    }

    private void _writeBytes(byte[] data) throws IOException {
        if (data.length > 0)
            archive.write(data);
    }

    private void _writeShort(int v) throws IOException {
        archive.write(v & 0xFF);
        archive.write((v >>> 8) & 0xFF);
    }

    private void _writeInt(int v) throws IOException {
        archive.write(v & 0xFF);
        archive.write((v >>> 8) & 0xFF);
        archive.write((v >>> 16) & 0xFF);
        archive.write((v >>> 24) & 0xFF);
    }

    private void _writeLong(long v) throws IOException {
        archive.write((int) (v & 0xFF));
        archive.write((int) ((v >>> 8) & 0xFF));
        archive.write((int) ((v >>> 16) & 0xFF));
        archive.write((int) ((v >>> 24) & 0xFF));
        archive.write((int) ((v >>> 32) & 0xFF));
        archive.write((int) ((v >>> 40) & 0xFF));
        archive.write((int) ((v >>> 48) & 0xFF));
        archive.write((int) ((v >>> 56) & 0xFF));
    }

    private void _writeUInt(long v) throws IOException {
        if (v < 0 || v > 0xffffffffL) {
            throw new IOException("Value out of unsigned int.");
        }
        archive.write((int) (v & 0xFF));
        archive.write((int) ((v >>> 8) & 0xFF));
        archive.write((int) ((v >>> 16) & 0xFF));
        archive.write((int) ((v >>> 24) & 0xFF));
    }

    public class HostEntryHolder {
        private final CenterFileHeader hostHeader;
        private final ZipFile zipFile;

        private HostEntryHolder(ZipFile zipFile) throws IOException {
            this.hostHeader = Objects.requireNonNull(currentHeader);
            this.zipFile = zipFile;
            try (RandomAccessFile archive = zipFile.getArchive().newSameInstance()) {
                writeFully(new BridgeInputStream(archive, 0, archive.length()));
                closeEntry();
            }
        }

        public long getHostEntryHeaderOffset() {
            return hostHeader.headerOffset;
        }

        /**
         * @return virtualEntry.headerOffset - hostHeader.headerOffset
         */
        public long putNextVirtualEntry(String name) throws IOException {
            ZipEntry innerEntry = zipFile.getEntryNonNull(name);
            CenterFileHeader header = new CenterFileHeader(innerEntry);
            setupNeedZip64(header);
            header.headerOffset = innerEntry.getHeaderOffset() + hostHeader.dataOffset;
            header.dataOffset = innerEntry.getDataOffset() + hostHeader.dataOffset;
            headers.add(header);
            return header.headerOffset - hostHeader.headerOffset;
        }
    }
}
