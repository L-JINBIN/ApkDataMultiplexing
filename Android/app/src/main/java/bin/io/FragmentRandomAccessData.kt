package bin.io

import java.io.IOException

/**
 * @author Bin
 */
internal class FragmentRandomAccessData(
    private val randomAccessData: RandomAccessData,
    private val offset: Long,
    private val length: Long
) : RandomAccessData {
    private var pos: Long = 0

    init {
        val dataLength = randomAccessData.length()
        if (offset + length > dataLength) {
            throw IOException(
                String.format(
                    "fragment.offset=%d, fragment.length=%d, data.length=%d",
                    offset,
                    length,
                    dataLength
                )
            )
        }
        seek(0)
    }

    @Throws(IOException::class)
    override fun seek(pos: Long) {
        randomAccessData.seek(pos + offset)
        this.pos = randomAccessData.position() - offset
    }

    @Throws(IOException::class)
    override fun read(data: ByteArray, off: Int, len: Int): Int {
        var len = len
        val available = length - pos
        if (len > available) {
            if (available <= 0) {
                return -1
            }
            len = available.toInt()
        }
        val readLen = randomAccessData.read(data, off, len)
        if (readLen > 0) {
            pos += readLen.toLong()
        }
        return readLen
    }

    @Throws(IOException::class)
    override fun write(data: ByteArray, off: Int, len: Int) {
        throw IOException("FragmentRandomAccessData is readonly")
    }

    @Throws(IOException::class)
    override fun length(): Long {
        return length
    }

    @Throws(IOException::class)
    override fun setLength(newLength: Long) {
        throw IOException("FragmentRandomAccessData is readonly")
    }

    @Throws(IOException::class)
    override fun position(): Long {
        return pos
    }

    @Throws(IOException::class)
    override fun sync() {
        randomAccessData.sync()
    }

    override val name: String
        get() = randomAccessData.name + "-Fragment(" + offset + "," + length + ")"

    @Throws(IOException::class)
    override fun getAnotherInSameParent(name: String): RandomAccessData {
        throw IOException("Unsupported")
    }

    @Throws(IOException::class)
    override fun newSameInstance(): RandomAccessData {
        return FragmentRandomAccessData(randomAccessData.newSameInstance(), offset, length)
    }

    @Throws(IOException::class)
    override fun close() {
        randomAccessData.close()
    }
}