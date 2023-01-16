package bin.mt.apksign.data

import java.io.EOFException
import java.io.IOException
import java.io.OutputStream
import kotlin.math.min

class ChainedDataSource internal constructor(vararg sources: DataSource) : DataSource {
    private val sources: Array<DataSource>
    private var currentSource: DataSource
    private var currentIndex: Int
    private var size: Long
    private var pos: Long

    init {
        require(sources.isNotEmpty())
        this.sources = sources as Array<DataSource>
        currentIndex = 0
        currentSource = sources[currentIndex]
        pos = 0
        size = 0
        for (source in sources) {
            size += source.size()
        }
    }

    override fun size(): Long {
        return size
    }

    override fun pos(): Long {
        return pos
    }

    @Throws(IOException::class)
    override fun reset() {
        currentIndex = 0
        currentSource = sources[currentIndex]
        pos = 0
        for (source in sources) {
            source.reset()
        }
    }

    @Throws(IOException::class)
    override fun copyTo(os: OutputStream, length: Long) {
        var length = length
        if (length > remaining()) throw EOFException()
        while (length > 0) {
            val len = min(length, currentSource.remaining())
            currentSource.copyTo(os, len)
            length -= len
            pos += len
            if (currentSource.remaining() == 0L && currentIndex < sources.size - 1) {
                currentSource = sources[++currentIndex]
            }
        }
    }
}