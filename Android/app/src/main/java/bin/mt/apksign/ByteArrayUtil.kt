package bin.mt.apksign

internal object ByteArrayUtil {
    fun setInt(value: Int, data: ByteArray, offset: Int) {
        data[offset] = (value and 0xff).toByte()
        data[offset + 1] = (value shr 8 and 0xff).toByte()
        data[offset + 2] = (value shr 16 and 0xff).toByte()
        data[offset + 3] = (value shr 24 and 0xff).toByte()
    }

    fun setUInt(value: Long, data: ByteArray, offset: Int) {
        data[offset] = (value and 0xffL).toByte()
        data[offset + 1] = (value shr 8 and 0xffL).toByte()
        data[offset + 2] = (value shr 16 and 0xffL).toByte()
        data[offset + 3] = (value shr 24 and 0xffL).toByte()
    }

    fun setLong(value: Long, data: ByteArray, offset: Int) {
        data[offset] = (value and 0xffL).toByte()
        data[offset + 1] = (value shr 8 and 0xffL).toByte()
        data[offset + 2] = (value shr 16 and 0xffL).toByte()
        data[offset + 3] = (value shr 24 and 0xffL).toByte()
        data[offset + 4] = (value shr 32 and 0xffL).toByte()
        data[offset + 5] = (value shr 40 and 0xffL).toByte()
        data[offset + 6] = (value shr 48 and 0xffL).toByte()
        data[offset + 7] = (value shr 56 and 0xffL).toByte()
    }

    fun readUInt(data: ByteArray, offset: Int): Long {
        val ch1 = data[offset].toLong() and 0xffL
        val ch2 = data[offset + 1].toLong() and 0xffL
        val ch3 = data[offset + 2].toLong() and 0xffL
        val ch4 = data[offset + 3].toLong() and 0xffL
        return ch1 or (ch2 shl 8) or (ch3 shl 16) or (ch4 shl 24)
    }

    fun intToBytes(value: Int): ByteArray {
        val array = ByteArray(4)
        setInt(value, array, 0)
        return array
    }
}