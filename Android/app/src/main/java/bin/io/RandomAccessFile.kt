package bin.io

import java.io.Closeable
import java.io.EOFException
import java.io.IOException

/**
 * @author Bin
 */
interface RandomAccessFile : Closeable {
    @Throws(IOException::class)
    fun write(value: Int)

    @Throws(IOException::class)
    fun write(data: ByteArray)

    @Throws(IOException::class)
    fun write(data: ByteArray, off: Int, len: Int)

    @Throws(IOException::class)
    fun read(): Int

    @Throws(IOException::class)
    fun read(data: ByteArray): Int

    @Throws(IOException::class)
    fun read(data: ByteArray, off: Int, len: Int): Int

    @Throws(IOException::class)
    fun readFully(data: ByteArray)

    @Throws(IOException::class)
    fun readFully(data: ByteArray, off: Int, len: Int)

    @Throws(IOException::class)
    fun length(): Long

    @Throws(IOException::class)
    fun setLength(newLength: Long)

    @Throws(IOException::class)
    fun seek(pos: Long)

    @Throws(IOException::class)
    fun skipBytes(n: Int): Int

    @get:Throws(IOException::class)
    val filePointer: Long
    val name: String?

    @Throws(IOException::class)
    fun getAnotherInSameParent(name: String): RandomAccessFile

    @Throws(IOException::class)
    fun newSameInstance(): RandomAccessFile

    @Throws(IOException::class)
    fun newFragment(offset: Long, length: Long): RandomAccessFile

    @Throws(IOException::class)
    fun flush()
    val isClosed: Boolean

    @Throws(IOException::class)
    fun writeByte(b: Byte) {
        write(b.toInt())
    }

    @Throws(IOException::class)
    fun writeUShort(i: Int) {
        write(i and 0xFF)
        write(i ushr 8 and 0xFF)
    }

    @Throws(IOException::class)
    fun writeShort(i: Short) {
        writeUShort(i.toInt())
    }

    @Throws(IOException::class)
    fun writeChar(c: Char) {
        writeUShort(c.code)
    }

    @Throws(IOException::class)
    fun writeInt(i: Int) {
        write(i and 0xFF)
        write(i ushr 8 and 0xFF)
        write(i ushr 16 and 0xFF)
        write(i ushr 24 and 0xFF)
    }

    @Throws(IOException::class)
    fun writeLong(l: Long) {
        write((l and 0xFFL).toInt())
        write((l ushr 8 and 0xFFL).toInt())
        write((l ushr 16 and 0xFFL).toInt())
        write((l ushr 24 and 0xFFL).toInt())
        write((l ushr 32 and 0xFFL).toInt())
        write((l ushr 40 and 0xFFL).toInt())
        write((l ushr 48 and 0xFFL).toInt())
        write((l ushr 56 and 0xFFL).toInt())
    }

    @Throws(IOException::class)
    fun readByte(): Byte {
        val ret = read()
        if (ret == -1) {
            throw EOFException()
        }
        return ret.toByte()
    }

    @Throws(IOException::class)
    fun readUShort(): Int {
        return readByte().toInt() and 0xFF or (readByte().toInt() and 0xFF shl 8)
    }

    @Throws(IOException::class)
    fun readShort(): Short {
        return readUShort().toShort()
    }

    @Throws(IOException::class)
    fun readChar(): Char {
        return readUShort().toChar()
    }

    @Throws(IOException::class)
    fun readInt(): Int {
        return readByte().toInt() and 0xFF or (readByte().toInt() and 0xFF shl 8) or (readByte().toInt() and 0xFF shl 16) or (readByte().toInt() and 0xFF shl 24)
    }

    @Throws(IOException::class)
    fun readLong(): Long {
        return readByte().toLong() and 0xFFL or (readByte().toLong() and 0xFFL shl 8) or (readByte().toLong() and 0xFFL shl 16) or (readByte().toLong() and 0xFFL shl 24
                ) or (readByte().toLong() and 0xFFL shl 32) or (readByte().toLong() and 0xFFL shl 40) or (readByte().toLong() and 0xFFL shl 48) or (readByte().toLong() and 0xFFL shl 56)
    }
}