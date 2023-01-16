package bin.mt.apksign

import bin.io.RandomAccessFile
import java.io.EOFException
import java.io.IOException
import kotlin.math.max

internal class ZipBuffer(val file: RandomAccessFile) {
    val entriesDataSizeBytes: Long
    val centralDirectoryOffset: Long
    val centralDirectorySizeBytes: Long
    val eocdOffset: Long
    private val hasApkSigBlock: Boolean

    init {
        var found = false
        val length = length()
        var off = length - MIN_EOCD_SIZE
        val stopSearching = max(0L, length - MAX_EOCD_SIZE)
        while (off >= stopSearching) {
            seek(off)
            if (readInt() == EOCD_SIG) {
                found = true
                break
            }
            off--
        }
        if (!found) {
            throw IOException("Archive is not a ZIP archive")
        }
        eocdOffset = off
        // 没做zip64支持
        seek(off + 12)
        centralDirectorySizeBytes = readUInt()
        centralDirectoryOffset = readUInt()
        var entriesDataEnd = centralDirectoryOffset
        var matchV2SigBlock = false
        try {
            if (centralDirectoryOffset >= APK_SIG_BLOCK_MIN_SIZE) {
                seek(centralDirectoryOffset - 16)
                if (readLong() == APK_SIG_BLOCK_MAGIC_LO && readLong() == APK_SIG_BLOCK_MAGIC_HI) {
                    seek(centralDirectoryOffset - 24)
                    val size = readLong()
                    val sigStart = centralDirectoryOffset - size - 8
                    seek(sigStart)
                    if (readLong() == size) {
                        matchV2SigBlock = true
                        entriesDataEnd = sigStart
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        entriesDataSizeBytes = entriesDataEnd
        hasApkSigBlock = matchV2SigBlock
    }

    @Throws(IOException::class)
    fun length(): Long {
        return file.length()
    }

    @Throws(IOException::class)
    fun seek(position: Long) {
        file.seek(position)
    }

    @Throws(IOException::class)
    fun position(): Long {
        return file.filePointer
    }

    @Throws(IOException::class)
    fun skip(length: Int) {
        if (length < 0) throw IOException("Skip $length")
        val pos = file.filePointer + length
        val len = file.length()
        if (pos > len) throw EOFException()
        file.seek(pos)
    }

    @Throws(IOException::class)
    fun readBytes(len: Int): ByteArray {
        val bytes = ByteArray(len)
        file.readFully(bytes)
        return bytes
    }

    @Throws(IOException::class)
    fun readInt(): Int {
        val ch1 = file.read()
        val ch2 = file.read()
        val ch3 = file.read()
        val ch4 = file.read()
        if (ch1 or ch2 or ch3 or ch4 < 0) throw EOFException()
        return ch1 or (ch2 shl 8) or (ch3 shl 16) or (ch4 shl 24)
    }

    @Throws(IOException::class)
    fun readLong(): Long {
        val ch1 = file.read().toLong()
        val ch2 = file.read().toLong()
        val ch3 = file.read().toLong()
        val ch4 = file.read().toLong()
        val ch5 = file.read().toLong()
        val ch6 = file.read().toLong()
        val ch7 = file.read().toLong()
        val ch8 = file.read().toLong()
        if (ch1 or ch2 or ch3 or ch4 < 0) throw EOFException()
        return ch1 or (ch2 shl 8) or (ch3 shl 16) or (ch4 shl 24) or (ch5 shl 32) or (ch6 shl 40) or (ch7 shl 48) or (ch8 shl 56)
    }

    @Throws(IOException::class)
    fun readUInt(): Long {
        return readInt().toLong() and 0xFFFFFFFFL
    }

    fun hasApkSigBlock(): Boolean {
        return hasApkSigBlock
    }

    companion object {
        const val APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L
        const val APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L
        const val EOCD_SIG = 0X06054B50
        const val MIN_EOCD_SIZE = 22
        const val MAX_EOCD_SIZE = MIN_EOCD_SIZE + 0xFFFF
        const val APK_SIG_BLOCK_MIN_SIZE = 32
    }
}