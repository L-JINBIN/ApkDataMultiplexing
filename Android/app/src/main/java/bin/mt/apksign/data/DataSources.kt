package bin.mt.apksign.data

import bin.io.RandomAccessFile
import java.io.IOException

object DataSources {
    fun fromFile(randomAccessFile: RandomAccessFile, start: Long, size: Long): DataSource {
        return FileDataSource(randomAccessFile, start, size)
    }

    @JvmOverloads
    fun fromData(data: ByteArray, start: Int = 0, size: Int = data.size): DataSource {
        return ByteArrayDataSource(data, start, size)
    }

    fun align(source: DataSource, align: Int): DataSource {
        val size = source.size()
        val overCount = (size % align).toInt()
        if (overCount == 0) return source
        val fillCount = align - overCount
        return link(source, fromData(ByteArray(fillCount)))
    }

    fun link(vararg sources: DataSource): DataSource {
        return ChainedDataSource(*sources)
    }

    @Throws(IOException::class)
    fun reset(vararg sources: DataSource) {
        for (source in sources) {
            source.reset()
        }
    }
}