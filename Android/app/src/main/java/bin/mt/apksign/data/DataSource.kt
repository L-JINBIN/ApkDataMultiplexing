package bin.mt.apksign.data

import bin.io.RandomAccessFile
import bin.mt.apksign.data.DataSources.fromData
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.security.MessageDigest

interface DataSource {
    fun size(): Long
    fun pos(): Long
    fun remaining(): Long {
        return size() - pos()
    }

    @Throws(IOException::class)
    fun reset()

    @Throws(IOException::class)
    fun copyTo(os: OutputStream, length: Long)

    @Throws(IOException::class)
    fun copyTo(digest: MessageDigest, length: Long) {
        val os: OutputStream = object : OutputStream() {
            override fun write(b: Int) {
                digest.update(b.toByte())
            }

            override fun write(b: ByteArray, off: Int, len: Int) {
                digest.update(b, off, len)
            }
        }
        copyTo(os, length)
    }

    @Throws(IOException::class)
    fun copyTo(accessFile: RandomAccessFile, length: Long) {
        val os: OutputStream = object : OutputStream() {
            @Throws(IOException::class)
            override fun write(b: Int) {
                accessFile.write(b)
            }

            @Throws(IOException::class)
            override fun write(b: ByteArray, off: Int, len: Int) {
                accessFile.write(b, off, len)
            }
        }
        copyTo(os, length)
    }

    fun align(align: Int): DataSource {
        return DataSources.align(this, align)
    }

    @Throws(IOException::class)
    fun toMemory(): ByteArrayDataSource? {
        val remaining = remaining()
        if (remaining > Int.MAX_VALUE) {
            throw IOException("Data too large")
        }
        val baos = ByteArrayOutputStream(remaining.toInt())
        copyTo(baos, remaining)
        return fromData(baos.toByteArray()) as ByteArrayDataSource?
    }
}