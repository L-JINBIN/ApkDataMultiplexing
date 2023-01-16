package bin.io

import java.io.Closeable
import java.io.IOException

/**
 * @author Bin
 */
interface RandomAccessData : Closeable {
    @Throws(IOException::class)
    fun seek(pos: Long)

    @Throws(IOException::class)
    fun read(data: ByteArray, off: Int, len: Int): Int

    @Throws(IOException::class)
    fun write(data: ByteArray, off: Int, len: Int)

    @Throws(IOException::class)
    fun length(): Long

    @Throws(IOException::class)
    fun setLength(newLength: Long)

    @Throws(IOException::class)
    fun position(): Long

    @Throws(IOException::class)
    fun sync()
    val name: String

    @Throws(IOException::class)
    fun getAnotherInSameParent(name: String): RandomAccessData

    @Throws(IOException::class)
    fun newSameInstance(): RandomAccessData

    @Throws(IOException::class)
    fun newFragment(offset: Long, length: Long): RandomAccessData {
        return FragmentRandomAccessData(newSameInstance(), offset, length)
    }
}