package bin.mt.apksign.data

import java.io.IOException

interface DataSink {
    @Throws(IOException::class)
    fun consume(buf: ByteArray, offset: Int, length: Int)
}