package bin.io

import org.jetbrains.annotations.Contract
import java.io.File
import java.io.IOException

/**
 * @author Bin
 */
object RandomAccessFactory {
    @JvmStatic
    @Contract("_ -> new")
    fun from(randomAccessData: RandomAccessData): RandomAccessFile {
        return BufferedRandomAccessFile(randomAccessData)
    }

    @JvmStatic
    @Contract("_, _ -> new")
    @Throws(IOException::class)
    fun from(file: File, mode: String): RandomAccessFile {
        return BufferedRandomAccessFile(RandomAccessDataImpl(file, mode))
    }

    @JvmStatic
    @Contract("_, _ -> new")
    @Throws(IOException::class)
    fun from(path: String, mode: String): RandomAccessFile {
        return BufferedRandomAccessFile(RandomAccessDataImpl(path, mode))
    }
}