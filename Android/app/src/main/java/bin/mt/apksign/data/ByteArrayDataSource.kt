package bin.mt.apksign.data

import java.io.EOFException
import java.io.IOException
import java.io.OutputStream

class ByteArrayDataSource internal constructor(data: ByteArray, start: Int, size: Int) :
    DataSource {
    val buffer: ByteArray
    val start: Int
    private val size: Int
    private var pos: Int

    init {
        require(start + size <= data.size)
        buffer = data
        this.start = start
        this.size = size
        pos = 0
    }

    override fun size(): Long {
        return size.toLong()
    }

    override fun pos(): Long {
        return pos.toLong()
    }

    override fun reset() {
        pos = 0
    }

    @Throws(IOException::class)
    override fun copyTo(os: OutputStream, length: Long) {
        if (length > remaining()) throw EOFException()
        os.write(buffer, start + pos, length.toInt())
        pos += length.toInt()
    }
}