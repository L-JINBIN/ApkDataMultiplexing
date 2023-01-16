package bin.mt.apksign.data

import java.io.EOFException
import java.io.IOException

class ByteArrayDataSink internal constructor(
    private val data: ByteArray,
    private var pos: Int,
    private val limit: Int
) : DataSink {
    @Throws(IOException::class)
    override fun consume(buf: ByteArray, offset: Int, length: Int) {
        if (pos + length > limit) {
            throw EOFException()
        }
        System.arraycopy(buf, offset, data, pos, length)
        pos += length
    }
}