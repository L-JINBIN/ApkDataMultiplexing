package com.mcal.apkdatamultiplexing.utils

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

object FileHelper {
    @Throws(IOException::class)
    fun copyFile(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(1024)
        var length: Int = input.read(buffer)
        while ((length) > 0) {
            output.write(buffer, 0, length)
            length = input.read(buffer)
        }
        input.close()
        output.flush()
        output.close()
    }
}