package bin.io

import java.io.File
import java.io.IOException
import java.io.RandomAccessFile

/**
 * @author Bin
 */
internal class RandomAccessDataImpl(private val file: File, private val mode: String) :
    RandomAccessData {
    private val randomAccessFile: RandomAccessFile = RandomAccessFile(file, mode)

    constructor(path: String, mode: String) : this(File(path), mode)

    @Throws(IOException::class)
    override fun seek(pos: Long) {
        randomAccessFile.seek(pos)
    }

    @Throws(IOException::class)
    override fun read(data: ByteArray, off: Int, len: Int): Int {
        return randomAccessFile.read(data, off, len)
    }

    @Throws(IOException::class)
    override fun write(data: ByteArray, off: Int, len: Int) {
        randomAccessFile.write(data, off, len)
    }

    @Throws(IOException::class)
    override fun length(): Long {
        return randomAccessFile.length()
    }

    @Throws(IOException::class)
    override fun setLength(newLength: Long) {
        randomAccessFile.setLength(newLength)
    }

    @Throws(IOException::class)
    override fun position(): Long {
        return randomAccessFile.filePointer
    }

    @Throws(IOException::class)
    override fun sync() {
        randomAccessFile.fd.sync()
    }

    override val name: String
        get() = file.name

    @Throws(IOException::class)
    override fun getAnotherInSameParent(name: String): RandomAccessData {
        val another = File(file.parent, name)
        return RandomAccessDataImpl(another, mode)
    }

    @Throws(IOException::class)
    override fun newSameInstance(): RandomAccessData {
        return RandomAccessDataImpl(file, mode)
    }

    @Throws(IOException::class)
    override fun close() {
        randomAccessFile.close()
    }
}