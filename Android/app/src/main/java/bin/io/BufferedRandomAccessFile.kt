package bin.io

import java.io.EOFException
import java.io.IOException
import java.util.*
import kotlin.math.max
import kotlin.math.min

/**
 * A `BufferedRandomAccessFile` is like a
 * `RandomAccessFile`, but it uses a private buffer so that most
 * operations do not require a disk access.
 *
 *
 *
 *
 * Note: The operations on this class are unmonitored. Also, the correct
 * functioning of the `RandomAccessFile` methods that are not
 * overridden here relies on the implementation of those methods in the
 * superclass.
 * Author : Avinash Lakshman ( alakshman@facebook.com) & Prashant Malik ( pmalik@facebook.com )
 */
class BufferedRandomAccessFile internal constructor(private val randomAccessData: RandomAccessData) :
    RandomAccessFile {
    private var dirty_ = false // true iff unflushed bytes exist
    override var isClosed = false // true iff the file is closed
        private set
    override var filePointer: Long = 0 // current position in file
        private set
    private var lo_: Long = 0
    private var hi_: Long = 0 // bounds on characters in "buff"
    private lateinit var buff_: ByteArray // local buffer
    private var maxHi_: Long = 0 // this.lo + this.buff.length
    private var hitEOF_ = false // buffer contains last file block?
    private var diskPos_: Long = 0 // disk position
    private var randomAccessDataLength: Long = -1

    /**
     * Open a new `BufferedRandomAccessFile` on `file`
     * in mode `mode`, which should be "r" for reading only, or
     * "rw" for reading and writing.
     */
    init {
        init()
    }

    private fun init() {
        isClosed = false
        dirty_ = isClosed
        hi_ = 0
        filePointer = hi_
        lo_ = filePointer
        buff_ = ByteArray(BuffSz_)
        maxHi_ = BuffSz_.toLong()
        hitEOF_ = false
        diskPos_ = 0L
    }

    @Throws(IOException::class)
    override fun write(value: Int) {
        if (filePointer >= hi_) {
            if (hitEOF_ && hi_ < maxHi_) {
                // at EOF -- bump "hi"
                hi_++
            } else {
                // slow path -- write current buffer; read next one
                seek(filePointer)
                if (filePointer == hi_) {
                    // appending to EOF -- bump "hi"
                    hi_++
                }
            }
        }
        buff_[(filePointer - lo_).toInt()] = value.toByte()
        filePointer++
        dirty_ = true
    }

    @Throws(IOException::class)
    override fun write(data: ByteArray) {
        this.write(data, 0, data.size)
    }

    @Throws(IOException::class)
    override fun write(data: ByteArray, off: Int, len: Int) {
        var off = off
        var len = len
        while (len > 0) {
            val n = writeAtMost(data, off, len)
            off += n
            len -= n
            dirty_ = true
        }
    }

    @Throws(IOException::class)
    override fun read(): Int {
        if (filePointer >= hi_) {
            // test for EOF
            // if (this.hi < this.maxHi) return -1;
            if (hitEOF_) return -1

            // slow path -- read another buffer
            seek(filePointer)
            if (filePointer == hi_) return -1
        }
        val res = buff_[(filePointer - lo_).toInt()]
        filePointer++
        return res.toInt() and 0xFF // convert byte -> int
    }

    @Throws(IOException::class)
    override fun read(data: ByteArray): Int {
        return read(data, 0, data.size)
    }

    @Throws(IOException::class)
    override fun read(b: ByteArray, off: Int, len: Int): Int {
        var len = len
        if (filePointer >= hi_) {
            // test for EOF
            // if (this.hi < this.maxHi) return -1;
            if (hitEOF_) return -1

            // slow path -- read another buffer
            seek(filePointer)
            if (filePointer == hi_) return -1
        }
        len = min(len, (hi_ - filePointer).toInt())
        val buffOff = (filePointer - lo_).toInt()
        System.arraycopy(buff_, buffOff, b, off, len)
        filePointer += len.toLong()
        return len
    }

    @Throws(IOException::class)
    override fun readFully(data: ByteArray) {
        readFully(data, 0, data.size)
    }

    @Throws(IOException::class)
    override fun readFully(data: ByteArray, off: Int, len: Int) {
        var n = 0
        do {
            val count = read(data, off + n, len - n)
            if (count < 0) throw EOFException()
            n += count
        } while (n < len)
    }

    @Throws(IOException::class)
    override fun length(): Long {
        return max(filePointer, getRandomAccessDataLength())
    }

    @Throws(IOException::class)
    private fun getRandomAccessDataLength(): Long {
        if (randomAccessDataLength == -1L) {
            randomAccessDataLength = randomAccessData.length()
        }
        return randomAccessDataLength
    }

    @Throws(IOException::class)
    override fun setLength(newLength: Long) {
        flushBuffer()
        randomAccessData.setLength(newLength)
        randomAccessDataLength = newLength
        if (filePointer > newLength) {
            filePointer = newLength
        }
        if (diskPos_ > newLength) {
            randomAccessData.seek(newLength)
            diskPos_ = newLength
        }

        // 为了fillBuffer
        hi_ = 0
        lo_ = hi_
        seek(filePointer)
    }

    /*
     * This method positions <code>this.curr</code> at position <code>pos</code>.
     * If <code>pos</code> does not fall in the current buffer, it flushes the
     * current buffer and loads the correct one.<p>
     *
     * On exit from this routine <code>this.curr == this.hi</code> iff <code>pos</code>
     * is at or past the end-of-file, which can only happen if the file was
     * opened in read-only mode.
     */
    @Throws(IOException::class)
    override fun seek(pos: Long) {
        if (pos >= hi_ || pos < lo_) {
            // seeking outside of current buffer -- flush and read
            flushBuffer()
            lo_ =
                pos and BuffMask_ // start at BuffSz boundary
            maxHi_ = lo_ + buff_.size.toLong()
            if (diskPos_ != lo_) {
                randomAccessData.seek(lo_)
                diskPos_ = lo_
            }
            val n = fillBuffer()
            hi_ = lo_ + n.toLong()
        } else {
            // seeking inside current buffer -- no read required
            if (pos < filePointer) {
                // if seeking backwards, we must flush to maintain V4
                flushBuffer()
            }
        }
        filePointer = pos
    }

    @Throws(IOException::class)
    override fun skipBytes(n: Int): Int {
        var newpos: Long
        if (n <= 0) {
            return 0
        }
        val pos: Long = filePointer
        val len: Long = length()
        newpos = pos + n
        if (newpos > len) {
            newpos = len
        }
        seek(newpos)

        /* return the actual number of bytes skipped */return (newpos - pos).toInt()
    }

    override val name: String
        get() = randomAccessData.name

    @Throws(IOException::class)
    override fun getAnotherInSameParent(name: String): RandomAccessFile {
        return BufferedRandomAccessFile(randomAccessData.getAnotherInSameParent(name))
    }

    @Throws(IOException::class)
    override fun newSameInstance(): RandomAccessFile {
        return BufferedRandomAccessFile(randomAccessData.newSameInstance())
    }

    @Throws(IOException::class)
    override fun newFragment(offset: Long, length: Long): RandomAccessFile {
        return BufferedRandomAccessFile(randomAccessData.newFragment(offset, length))
    }

    @Throws(IOException::class)
    override fun flush() {
        flushBuffer()
    }

    @Throws(IOException::class)
    override fun close() {
        flush()
        isClosed = true
        randomAccessData.close()
    }

    /* Flush any dirty bytes in the buffer to disk. */
    @Throws(IOException::class)
    private fun flushBuffer() {
        if (dirty_) {
            if (diskPos_ != lo_) randomAccessData.seek(lo_)
            val len = (filePointer - lo_).toInt()
            randomAccessData.write(buff_, 0, len)
            diskPos_ = filePointer
            dirty_ = false
            if (randomAccessDataLength != -1L && diskPos_ > randomAccessDataLength) {
                randomAccessDataLength = -1
            }
        }
    }

    /*
     * Read at most "this.buff.length" bytes into "this.buff", returning the
     * number of bytes read. If the return result is less than
     * "this.buff.length", then EOF was read.
     */
    @Throws(IOException::class)
    private fun fillBuffer(): Int {
        var cnt = 0
        var rem = buff_.size
        while (rem > 0) {
            val n = randomAccessData.read(buff_, cnt, rem)
            if (n < 0) break
            cnt += n
            rem -= n
        }
        if ((cnt < buff_.size).also { hitEOF_ = it }) {
            // make sure buffer that wasn't read is initialized with -1
            Arrays.fill(buff_, cnt, buff_.size, 0xff.toByte())
        }
        diskPos_ += cnt.toLong()
        return cnt
    }

    /*
     * Write at most "len" bytes to "b" starting at position "off", and return
     * the number of bytes written.
     */
    @Throws(IOException::class)
    private fun writeAtMost(b: ByteArray, off: Int, len: Int): Int {
        var len = len
        if (filePointer >= hi_) {
            if (hitEOF_ && hi_ < maxHi_) {
                // at EOF -- bump "hi"
                hi_ = maxHi_
            } else {
                // slow path -- write current buffer; read next one
                seek(filePointer)
                if (filePointer == hi_) {
                    // appending to EOF -- bump "hi"
                    hi_ = maxHi_
                }
            }
        }
        len = min(len, (hi_ - filePointer).toInt())
        val buffOff = (filePointer - lo_).toInt()
        System.arraycopy(b, off, buff_, buffOff, len)
        filePointer += len.toLong()
        return len
    }

    companion object {
        private const val LogBuffSz_ = 17 // 128K buffer
        private const val BuffSz_ = 1 shl LogBuffSz_
        private const val BuffMask_ = -BuffSz_.toLong()
    }
}