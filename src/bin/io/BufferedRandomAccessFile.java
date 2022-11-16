package bin.io;

import java.io.EOFException;
import java.io.IOException;
import java.util.Arrays;

/**
 * A <code>BufferedRandomAccessFile</code> is like a
 * <code>RandomAccessFile</code>, but it uses a private buffer so that most
 * operations do not require a disk access.
 * <p>
 * <p>
 * Note: The operations on this class are unmonitored. Also, the correct
 * functioning of the <code>RandomAccessFile</code> methods that are not
 * overridden here relies on the implementation of those methods in the
 * superclass.
 * Author : Avinash Lakshman ( alakshman@facebook.com) & Prashant Malik ( pmalik@facebook.com )
 */

public final class BufferedRandomAccessFile implements RandomAccessFile {
    private static final int LogBuffSz_ = 17; // 128K buffer
    private static final int BuffSz_ = (1 << LogBuffSz_);
    private static final long BuffMask_ = -((long) BuffSz_);

    private boolean dirty_; // true iff unflushed bytes exist
    private boolean closed_; // true iff the file is closed
    private long curr_; // current position in file
    private long lo_, hi_; // bounds on characters in "buff"
    private byte[] buff_; // local buffer
    private long maxHi_; // this.lo + this.buff.length
    private boolean hitEOF_; // buffer contains last file block?
    private long diskPos_; // disk position
    private RandomAccessData randomAccessData;
    private long randomAccessDataLength = -1;

    /**
     * Open a new <code>BufferedRandomAccessFile</code> on <code>file</code>
     * in mode <code>mode</code>, which should be "r" for reading only, or
     * "rw" for reading and writing.
     */
    BufferedRandomAccessFile(RandomAccessData randomAccessData) {
        this.randomAccessData = randomAccessData;
        this.init();
    }

    private void init() {
        this.dirty_ = this.closed_ = false;
        this.lo_ = this.curr_ = this.hi_ = 0;
        this.buff_ = new byte[BuffSz_];
        this.maxHi_ = (long) BuffSz_;
        this.hitEOF_ = false;
        this.diskPos_ = 0L;
    }

    @Override
    public void write(int value) throws IOException {
        if (this.curr_ >= this.hi_) {
            if (this.hitEOF_ && this.hi_ < this.maxHi_) {
                // at EOF -- bump "hi"
                this.hi_++;
            } else {
                // slow path -- write current buffer; read next one
                this.seek(this.curr_);
                if (this.curr_ == this.hi_) {
                    // appending to EOF -- bump "hi"
                    this.hi_++;
                }
            }
        }
        this.buff_[(int) (this.curr_ - this.lo_)] = (byte) value;
        this.curr_++;
        this.dirty_ = true;
    }

    @Override
    public void write(byte[] data) throws IOException {
        this.write(data, 0, data.length);
    }

    @Override
    public void write(byte[] data, int off, int len) throws IOException {
        while (len > 0) {
            int n = this.writeAtMost(data, off, len);
            off += n;
            len -= n;
            this.dirty_ = true;
        }
    }

    @Override
    public int read() throws IOException {
        if (this.curr_ >= this.hi_) {
            // test for EOF
            // if (this.hi < this.maxHi) return -1;
            if (this.hitEOF_)
                return -1;

            // slow path -- read another buffer
            this.seek(this.curr_);
            if (this.curr_ == this.hi_)
                return -1;
        }
        byte res = this.buff_[(int) (this.curr_ - this.lo_)];
        this.curr_++;
        return ((int) res) & 0xFF; // convert byte -> int
    }

    @Override
    public int read(byte[] data) throws IOException {
        return read(data, 0, data.length);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (this.curr_ >= this.hi_) {
            // test for EOF
            // if (this.hi < this.maxHi) return -1;
            if (this.hitEOF_)
                return -1;

            // slow path -- read another buffer
            this.seek(this.curr_);
            if (this.curr_ == this.hi_)
                return -1;
        }
        len = Math.min(len, (int) (this.hi_ - this.curr_));
        int buffOff = (int) (this.curr_ - this.lo_);
        System.arraycopy(this.buff_, buffOff, b, off, len);
        this.curr_ += len;
        return len;
    }

    @Override
    public void readFully(byte[] data) throws IOException {
        readFully(data, 0, data.length);
    }

    @Override
    public void readFully(byte[] data, int off, int len) throws IOException {
        int n = 0;
        do {
            int count = read(data, off + n, len - n);
            if (count < 0)
                throw new EOFException();
            n += count;
        } while (n < len);
    }

    @Override
    public long length() throws IOException {
        return Math.max(this.curr_, getRandomAccessDataLength());
    }

    private long getRandomAccessDataLength() throws IOException {
        if (randomAccessDataLength == -1) {
            randomAccessDataLength = randomAccessData.length();
        }
        return randomAccessDataLength;
    }

    @Override
    public void setLength(long newLength) throws IOException {
        flushBuffer();
        randomAccessData.setLength(newLength);
        randomAccessDataLength = newLength;
        if (this.curr_ > newLength) {
            this.curr_ = newLength;
        }
        if (this.diskPos_ > newLength) {
            randomAccessData.seek(newLength);
            this.diskPos_ = newLength;
        }

        // 为了fillBuffer
        this.lo_ = this.hi_ = 0;
        seek(this.curr_);
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
    @Override
    public void seek(long pos) throws IOException {
        if (pos >= this.hi_ || pos < this.lo_) {
            // seeking outside of current buffer -- flush and read
            this.flushBuffer();
            this.lo_ = pos & BuffMask_; // start at BuffSz boundary
            this.maxHi_ = this.lo_ + (long) this.buff_.length;
            if (this.diskPos_ != this.lo_) {
                randomAccessData.seek(this.lo_);
                this.diskPos_ = this.lo_;
            }
            int n = this.fillBuffer();
            this.hi_ = this.lo_ + (long) n;
        } else {
            // seeking inside current buffer -- no read required
            if (pos < this.curr_) {
                // if seeking backwards, we must flush to maintain V4
                this.flushBuffer();
            }
        }
        this.curr_ = pos;
    }

    @Override
    public int skipBytes(int n) throws IOException {
        long pos;
        long len;
        long newpos;

        if (n <= 0) {
            return 0;
        }
        pos = getFilePointer();
        len = length();
        newpos = pos + n;
        if (newpos > len) {
            newpos = len;
        }
        seek(newpos);

        /* return the actual number of bytes skipped */
        return (int) (newpos - pos);
    }

    @Override
    public long getFilePointer() {
        return this.curr_;
    }

    @Override
    public String getName() {
        return randomAccessData.getName();
    }

    @Override
    public RandomAccessFile getAnotherInSameParent(String name) throws IOException {
        return new BufferedRandomAccessFile(randomAccessData.getAnotherInSameParent(name));
    }

    @Override
    public RandomAccessFile newSameInstance() throws IOException {
        return new BufferedRandomAccessFile(randomAccessData.newSameInstance());
    }

    @Override
    public RandomAccessFile newFragment(long offset, long length) throws IOException {
        return new BufferedRandomAccessFile(randomAccessData.newFragment(offset, length));
    }

    @Override
    public void flush() throws IOException {
        this.flushBuffer();
    }

    @Override
    public void close() throws IOException {
        this.flush();
        this.closed_ = true;
        randomAccessData.close();
    }

    @Override
    public boolean isClosed() {
        return closed_;
    }

    /* Flush any dirty bytes in the buffer to disk. */
    private void flushBuffer() throws IOException {
        if (this.dirty_) {
            if (this.diskPos_ != this.lo_)
                randomAccessData.seek(this.lo_);
            int len = (int) (this.curr_ - this.lo_);
            randomAccessData.write(this.buff_, 0, len);
            this.diskPos_ = this.curr_;
            this.dirty_ = false;
            if (randomAccessDataLength != -1 && this.diskPos_ > randomAccessDataLength) {
                randomAccessDataLength = -1;
            }
        }
    }

    /*
     * Read at most "this.buff.length" bytes into "this.buff", returning the
     * number of bytes read. If the return result is less than
     * "this.buff.length", then EOF was read.
     */
    private int fillBuffer() throws IOException {
        int cnt = 0;
        int rem = this.buff_.length;
        while (rem > 0) {
            int n = randomAccessData.read(this.buff_, cnt, rem);
            if (n < 0)
                break;
            cnt += n;
            rem -= n;
        }
        if (this.hitEOF_ = (cnt < this.buff_.length)) {
            // make sure buffer that wasn't read is initialized with -1
            Arrays.fill(this.buff_, cnt, this.buff_.length, (byte) 0xff);
        }
        this.diskPos_ += cnt;
        return cnt;
    }

    /*
     * Write at most "len" bytes to "b" starting at position "off", and return
     * the number of bytes written.
     */
    private int writeAtMost(byte[] b, int off, int len) throws IOException {
        if (this.curr_ >= this.hi_) {
            if (this.hitEOF_ && this.hi_ < this.maxHi_) {
                // at EOF -- bump "hi"
                this.hi_ = this.maxHi_;
            } else {
                // slow path -- write current buffer; read next one
                this.seek(this.curr_);
                if (this.curr_ == this.hi_) {
                    // appending to EOF -- bump "hi"
                    this.hi_ = this.maxHi_;
                }
            }
        }
        len = Math.min(len, (int) (this.hi_ - this.curr_));
        int buffOff = (int) (this.curr_ - this.lo_);
        System.arraycopy(b, off, this.buff_, buffOff, len);
        this.curr_ += len;
        return len;
    }

}