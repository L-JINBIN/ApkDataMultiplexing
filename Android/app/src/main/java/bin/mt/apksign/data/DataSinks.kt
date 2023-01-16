package bin.mt.apksign.data

object DataSinks {
    @JvmOverloads
    fun fromData(data: ByteArray, position: Int = 0, limit: Int = data.size): DataSink {
        return ByteArrayDataSink(data, position, limit)
    }
}