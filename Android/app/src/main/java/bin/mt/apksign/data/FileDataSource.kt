package bin.mt.apksign.data

import bin.io.RandomAccessFile
import java.io.EOFException
import java.io.IOException
import java.io.OutputStream
import kotlin.math.min

class FileDataSource internal constructor(
    private val randomAccessFile: RandomAccessFile,
    private val start: Long,
    private val size: Long
) : DataSource {
    private var pos: Long = 0
    override fun size(): Long {
        return size
    }

    override fun pos(): Long {
        return pos
    }

    override fun reset() {
        pos = 0
    }

    @Throws(IOException::class)
    override fun copyTo(os: OutputStream, length: Long) {
        var length = length
        if (length > remaining()) throw EOFException()
        val buf = ByteArray(4096)
        var readLen = 0
        randomAccessFile.seek(start + pos)
        while (length > 0 && randomAccessFile.read(buf, 0, min(length, buf.size.toLong()).toInt())
                .also { readLen = it } != -1
        ) {
            os.write(buf, 0, readLen)
            length -= readLen.toLong()
            pos += readLen.toLong()
        }
        check(length == 0L) { "Remaining length: $length" }
    }
}