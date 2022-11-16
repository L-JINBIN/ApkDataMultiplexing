package bin.zip;

import java.nio.charset.Charset;

/**
 * @author Bin
 */
interface ZipConstant {
    @SuppressWarnings("CharsetObjectCanBeUsed")
    Charset UTF_8 = Charset.forName("UTF-8");
    int METHOD_STORED = 0;
    int METHOD_DEFLATED = 8;

    int PLATFORM_FAT = 0;

    int UFT8_NAMES_FLAG = 1 << 11;

    int EXTRA_HEADER_UNICODE_NAME = 0x7075;
    int EXTRA_HEADER_UNICODE_COMMENT = 0x6375;

    /**
     * local file header signature
     */
    int LFH_SIG = 0x04034B50;

    /**
     * local file data descriptor signature
     */
    int EXT_SIG = 0x08074b50;

    /**
     * End of central dir signature
     */
    int EOCD_SIG = 0x06054B50;

    /**
     * Central file header signature
     */
    int CFH_SIG = 0x02014B50;

    int BUFF_SIZE = 1024 * 4;

    int SHORT = 2;

    int WORD = 4;

    int MIN_EOCD_SIZE =
            /* end of central dir signature    */ WORD
            /* number of this disk             */ + SHORT
            /* number of the disk with the     */
            /* start of the central directory  */ + SHORT
            /* total number of entries in      */
            /* the central dir on this disk    */ + SHORT
            /* total number of entries in      */
            /* the central dir                 */ + SHORT
            /* size of the central directory   */ + WORD
            /* offset of start of central      */
            /* directory with respect to       */
            /* the starting disk number        */ + WORD
            /* zipfile comment length          */ + SHORT;

    int MAX_EOCD_SIZE = MIN_EOCD_SIZE
            /* maximum length of zipfile comment */ + 0xFFFF;

    int CFD_LOCATOR_OFFSET =
            /* end of central dir signature    */ WORD
            /* number of this disk             */ + SHORT
            /* number of the disk with the     */
            /* start of the central directory  */ + SHORT
            /* total number of entries in      */
            /* the central dir on this disk    */ + SHORT
            /* total number of entries in      */
            /* the central dir                 */ + SHORT
            /* size of the central directory   */ + WORD;

    int LFH_OFFSET_FOR_FILENAME_LENGTH =
            /* local file header signature     */ WORD
            /* version needed to extract       */ + SHORT
            /* general purpose bit flag        */ + SHORT
            /* compression method              */ + SHORT
            /* last mod file time              */ + SHORT
            /* last mod file date              */ + SHORT
            /* crc-32                          */ + WORD
            /* compressed size                 */ + WORD
            /* uncompressed size               */ + WORD;

    /**
     * The maximum supported entry / archive size for standard (non zip64) entries and archives.
     */
    long MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE = 0x00000000ffffffffL;

    /*
     * Size (in bytes) of the zip64 end of central directory locator. This will be located
     * immediately before the end of central directory record if a given zipfile is in the
     * zip64 format.
     */
    int ZIP64_LOCATOR_SIZE = 20;

    /**
     * The zip64 end of central directory locator signature (4 bytes wide).
     */
    int ZIP64_LOCATOR_SIGNATURE = 0x07064b50;

    /**
     * The zip64 end of central directory record singature (4 bytes wide).
     */
    int ZIP64_EOCD_RECORD_SIGNATURE = 0x06064b50;

    /**
     * The header ID of the zip64 extended info header. This value is used to identify
     * zip64 data in the "extra" field in the file headers.
     */
    short ZIP64_EXTENDED_INFO_HEADER_ID = 0x0001;

    /**
     * The "effective" size of the zip64 eocd record. This excludes the fields that
     * are proprietary, signature, or fields we aren't interested in. We include the
     * following (contiguous) fields in this calculation :
     * - disk number (4 bytes)
     * - disk with start of central directory (4 bytes)
     * - number of central directory entries on this disk (8 bytes)
     * - total number of central directory entries (8 bytes)
     * - size of the central directory (8 bytes)
     * - offset of the start of the central directory (8 bytes)
     */
    int ZIP64_EOCD_RECORD_EFFECTIVE_SIZE = 40;

}
