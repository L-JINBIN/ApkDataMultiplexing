package bin.zip;

import bin.io.RandomAccessFactory;
import bin.io.RandomAccessFile;

import java.io.*;
import java.util.*;

import static bin.zip.ZipConstant.*;

/**
 * @author Bin
 */
public class ZipFile implements Closeable {
    private final RandomAccessFile archive;
    private final Map<String, ZipEntry> entries = new LinkedHashMap<>();

    public ZipFile(File file) throws IOException {
        this(RandomAccessFactory.from(file, "r"));
    }

    public ZipFile(RandomAccessFile archive) throws IOException {
        this.archive = archive;
        readEntries();
    }

    public ZipEntry getEntry(String name) {
        return entries.get(name);
    }

    public ZipEntry getEntryNonNull(String name) throws IOException {
        ZipEntry entry = entries.get(name);
        if (entry == null) {
            throw new IOException("Entry not found: " + name);
        }
        return entry;
    }

    public ArrayList<ZipEntry> getEntries() {
        return new ArrayList<>(entries.values());
    }

    public int getEntrySize() {
        return entries.size();
    }

    private void readEntries() throws IOException {
        EocdRecord eocdRecord = readEocdRecord();
        if (eocdRecord == null) {
            throw new IOException("EOCD not found");
        }
        List<ZipEntry> list = new ArrayList<>();
        boolean zip64 = eocdRecord.zip64;
        _seek(eocdRecord.centralDirOffset);
        while (_readInt() == CFH_SIG) {
            ZipEntry ze = new ZipEntry();
            int versionMadeBy = _readUShort();
            ze.setPlatform((versionMadeBy >> 8) & 0xF);

            _readUShort(); // skip version info

            ze.setGeneralPurposeFlag(_readUShort());
            ze.setMethod(_readUShort());
            ze.setTime(ZipUtil.dosToJavaTime(_readUInt()));
            ze.setCrc(_readInt());

            ze.setCompressedSize(_readUInt());
            ze.setSize(_readUInt());

            int fileNameLen = _readUShort();
            int extraLen = _readUShort();
            int commentLen = _readUShort();

            _readUShort(); // disk number

            ze.setInternalAttributes(_readUShort());
            ze.setExternalAttributes(_readInt());

            ze.setHeaderOffset(_readUInt());

            ze.setNameData(_readBytes(fileNameLen));

            if (extraLen > 0) {
                if (zip64)
                    ze.setupZip64WithCenterDirectoryExtra(_readBytes(extraLen));
                else
                    _skip(extraLen);
            }

            if (commentLen > 0) {
                try {
                    byte[] comment = _readBytes(commentLen);
                    ze.setCommentData(comment);
                } catch (IOException ignored) {
                }
            }

            list.add(ze);
        }

        //noinspection Java8ListSort,ComparatorCombinators
        Collections.sort(list, (e1, e2) -> Long.compare(e1.getHeaderOffset(), e2.getHeaderOffset()));
        Set<String> ok = new HashSet<>(list.size());

        for (ZipEntry entry : list) {
            try {
                long offset = entry.getHeaderOffset();
                _seek(offset + LFH_OFFSET_FOR_FILENAME_LENGTH);
                int fileNameLen = _readUShort();
                int extraLen = _readUShort();
                _skip(fileNameLen);
                byte[] extra = _readBytes(extraLen);
                // 去除zip64Extra
                extra = ExtraDataRecord.remove(extra, ZIP64_EXTENDED_INFO_HEADER_ID);
                entry.setExtra(extra);
                entry.setDataOffset(offset + LFH_OFFSET_FOR_FILENAME_LENGTH
                        + SHORT + SHORT + fileNameLen + extraLen);
                ok.add(entry.getName());
            } catch (EOFException e) {
                e.printStackTrace();
            }
        }
        entries.clear();
        for (ZipEntry entry : list) {
            String key = entry.getName();
            if (ok.contains(key)) {
                entries.put(key, entry);
            }
        }
    }

    private EocdRecord readEocdRecord() throws IOException {
        boolean found = false;
        long length = _length();
        long off = length - MIN_EOCD_SIZE;
        final long stopSearching = Math.max(0L, length - MAX_EOCD_SIZE);
        while (off >= stopSearching) {
            _seek(off);
            if (_readInt() == EOCD_SIG) {
                found = true;
                break;
            }
            off--;
        }
        if (!found) {
            return null;
        }

        try {
            final long zip64EocdRecordOffset = parseZip64EocdRecordLocator(off);

            EocdRecord record = parseEocdRecord(off + 4, (zip64EocdRecordOffset != -1) /* isZip64 */);
            if (record.commentLength > 0) {
                try {
                    _readBytes(record.commentLength);
                } catch (IOException ignored) {
                    record = new EocdRecord(record.numEntries, record.centralDirOffset, 0, record.zip64);
                }
            }

            if (zip64EocdRecordOffset != -1) {
                record = parseZip64EocdRecord(zip64EocdRecordOffset, record.commentLength);
            }

            return record;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private long parseZip64EocdRecordLocator(long eocdOffset)
            throws IOException {
        // The spec stays curiously silent about whether a zip file with an EOCD record,
        // a zip64 locator and a zip64 eocd record is considered "empty". In our implementation,
        // we parse all records and read the counts from them instead of drawing any size or
        // layout based information.
        if (eocdOffset > ZIP64_LOCATOR_SIZE) {
            _seek(eocdOffset - ZIP64_LOCATOR_SIZE);
            if (_readInt() == ZIP64_LOCATOR_SIGNATURE) {
                final int diskWithCentralDir = _readInt();
                final long zip64EocdRecordOffset = _readLong();
                final int numDisks = _readInt();
                if (numDisks != 1 || diskWithCentralDir != 0) {
                    throw new IOException("Spanned archives not supported");
                }
                return zip64EocdRecordOffset;
            }
        }
        return -1;
    }

    private EocdRecord parseEocdRecord(long offset, boolean isZip64) throws IOException {
        _seek(offset);
        final long numEntries;
        final long centralDirOffset;
        if (isZip64) {
            numEntries = -1;
            centralDirOffset = -1;
            _skip(16);
        } else {
            _skip(4);
            numEntries = _readUShort();
            _skip(6);
            centralDirOffset = _readUInt();
        }
        final int commentLength = _readUShort();
        return new EocdRecord(numEntries, centralDirOffset, commentLength, false);
    }

    private EocdRecord parseZip64EocdRecord(long eocdRecordOffset, int commentLength) throws IOException {
        _seek(eocdRecordOffset);
        final int signature = _readInt();
        if (signature != ZIP64_EOCD_RECORD_SIGNATURE) {
            throw new IOException("Invalid zip64 eocd record offset, sig="
                    + Integer.toHexString(signature) + " offset=" + eocdRecordOffset);
        }
        _skip(12);
        int diskNumber = _readInt();
        int diskWithCentralDirStart = _readInt();
        long numEntries = _readLong();
        long totalNumEntries = _readLong();
        _readLong();
        long centralDirOffset = _readLong();
        if (numEntries != totalNumEntries || diskNumber != 0 || diskWithCentralDirStart != 0) {
            throw new IOException("Spanned archives not supported :" +
                    " numEntries=" + numEntries + ", totalNumEntries=" + totalNumEntries +
                    ", diskNumber=" + diskNumber + ", diskWithCentralDirStart=" +
                    diskWithCentralDirStart);
        }
        return new EocdRecord(numEntries, centralDirOffset, commentLength, true);
    }

    public InputStream getRawInputStream(ZipEntry ze) {
        return new BridgeInputStream(archive, ze.getDataOffset(), ze.getCompressedSize());
    }

    public InputStream getInputStream(ZipEntry ze) throws IOException {
        long start = ze.getDataOffset();
        int method = ze.getMethod();
        InputStream is = new BridgeInputStream(archive, start, method == METHOD_STORED ? ze.getSize() : ze.getCompressedSize());
        switch (method) {
            case METHOD_DEFLATED:
                is = new NoWrapInflaterInputStream(ze, is);
                break;
            case METHOD_STORED:
                break;
            default:
                throw new IOException("Unsupported compression method " + ze.getMethod() + " (" + ze.getName() + ")");
        }
        if (method != METHOD_STORED) {
            is = new BufferedInputStream(is, 64 * 1024);
        }
        return is;
    }

    public ZipFile openEntryAsZipFile(ZipEntry entry) throws IOException {
        if (entry.getMethod() != METHOD_STORED) {
            throw new IOException("Entry is not stored: " + entry.getName());
        }
        return new ZipFile(archive.newFragment(entry.getDataOffset(), entry.getCompressedSize()));
    }

    public RandomAccessFile getArchive() {
        return archive;
    }

    private long _length() throws IOException {
        return archive.length();
    }

    private void _seek(long position) throws IOException {
        archive.seek(position);
    }

    private void _skip(long length) throws IOException {
        if (length < 0)
            throw new IOException("Skip " + length);
        long pos = archive.getFilePointer() + length;
        long len = archive.length();
        if (pos > len)
            throw new EOFException();
        archive.seek(pos);
    }

    private byte[] _readBytes(int len) throws IOException {
        byte[] bytes = new byte[len];
        archive.readFully(bytes);
        return bytes;
    }

    private int _readInt() throws IOException {
        int ch1 = archive.read();
        int ch2 = archive.read();
        int ch3 = archive.read();
        int ch4 = archive.read();
        if ((ch1 | ch2 | ch3 | ch4) < 0)
            throw new EOFException();
        return (ch1) | (ch2 << 8) | (ch3 << 16) | (ch4 << 24);
    }

    private int _readUShort() throws IOException {
        int ch1 = archive.read();
        int ch2 = archive.read();
        if ((ch1 | ch2) < 0)
            throw new EOFException();
        return ch1 | (ch2 << 8);
    }

    private long _readUInt() throws IOException {
        int value = _readInt();
        return value & 0xFFFFFFFFL;
    }

    private long _readLong() throws IOException {
        return _readUInt() | (_readUInt() << 32);
    }

    private boolean closed = false;

    @Override
    public void close() throws IOException {
        if (closed)
            return;
        archive.close();
        closed = true;
    }

    private static class EocdRecord {
        final long numEntries;
        final long centralDirOffset;
        final int commentLength;
        final boolean zip64;

        EocdRecord(long numEntries, long centralDirOffset, int commentLength, boolean zip64) {
            this.numEntries = numEntries;
            this.centralDirOffset = centralDirOffset;
            this.commentLength = commentLength;
            this.zip64 = zip64;
        }
    }

}
