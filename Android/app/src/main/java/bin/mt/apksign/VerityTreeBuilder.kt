/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package bin.mt.apksign

import bin.mt.apksign.data.DataSink
import bin.mt.apksign.data.DataSinks
import bin.mt.apksign.data.DataSource
import bin.mt.apksign.data.DataSources
import java.io.IOException
import java.security.MessageDigest

/**
 * VerityTreeBuilder is used to generate the root hash of verity tree built from the input file.
 * The root hash can be used on device for on-access verification.  The tree itself is reproducible
 * on device, and is not shipped with the APK.
 */
internal class VerityTreeBuilder(
    /**
     * Optional salt to apply before each digestion.
     */
    private val mSalt: ByteArray?
) {
    private val mMd: MessageDigest = MessageDigest.getInstance(JCA_ALGORITHM)

    /**
     * Returns the root hash of the APK verity tree built from ZIP blocks.
     *
     *
     * Specifically, APK verity tree is built from the APK, but as if the APK Signing Block (which
     * must be page aligned) and the "Central Directory offset" field in End of Central Directory
     * are skipped.
     */
    @Throws(IOException::class)
    fun generateVerityTreeRootHash(
        beforeApkSigningBlock: DataSource, centralDir: DataSource,
        eocd: DataSource
    ): ByteArray {
        check(beforeApkSigningBlock.size() % CHUNK_SIZE == 0L) {
            ("APK Signing Block size not a multiple of " + CHUNK_SIZE
                    + ": " + beforeApkSigningBlock.size())
        }
        return generateVerityTreeRootHash(DataSources.link(beforeApkSigningBlock, centralDir, eocd))
    }

    /**
     * Returns the root hash of the verity tree built from the data source.
     *
     *
     * The tree is built bottom up. The bottom level has 256-bit digest for each 4 KB block in the
     * input file.  If the total size is larger than 4 KB, take this level as input and repeat the
     * same procedure, until the level is within 4 KB.  If salt is given, it will apply to each
     * digestion before the actual data.
     *
     *
     * The returned root hash is calculated from the last level of 4 KB chunk, similarly with salt.
     *
     *
     * The tree is currently stored only in memory and is never written out.  Nevertheless, it is
     * the actual verity tree format on disk, and is supposed to be re-generated on device.
     *
     *
     * This is package-private for testing purpose.
     */
    @Throws(IOException::class)
    private fun generateVerityTreeRootHash(fileSource: DataSource): ByteArray {
        val digestSize = mMd.digestLength

        // Calculate the summed area table of level size. In other word, this is the offset
        // table of each level, plus the next non-existing level.
        val levelOffset = calculateLevelOffset(fileSource.size(), digestSize)
        val verityBuffer = ByteArray(levelOffset[levelOffset.size - 1])

        // Generate the hash tree bottom-up.
        for (i in levelOffset.size - 2 downTo 0) {
            val middleBufferSink =
                DataSinks.fromData(verityBuffer, levelOffset[i], levelOffset[i + 1])
            val src: DataSource = if (i == levelOffset.size - 2) {
                fileSource
            } else {
                val start = levelOffset[i + 1]
                val end = levelOffset[i + 2]
                DataSources.fromData(verityBuffer, start, end - start)
            }
            digestDataByChunks(src, middleBufferSink)

            // If the output is not full chunk, pad with 0s.
            val totalOutput = divideRoundup(src.size()) * digestSize
            val incomplete = (totalOutput % CHUNK_SIZE).toInt()
            if (incomplete > 0) {
                val padding = ByteArray(CHUNK_SIZE - incomplete)
                middleBufferSink.consume(padding, 0, padding.size)
            }
        }

        // Finally, calculate the root hash from the top level (only page).
        return saltedDigest(verityBuffer)
    }

    /**
     * Digest data source by chunks then feeds them to the sink one by one.  If the last unit is
     * less than the chunk size and padding is desired, feed with extra padding 0 to fill up the
     * chunk before digesting.
     */
    @Throws(IOException::class)
    private fun digestDataByChunks(dataSource: DataSource, dataSink: DataSink) {
        var dataSource = dataSource
        dataSource = dataSource.align(CHUNK_SIZE)
        val size = dataSource.size()
        var offset: Long = 0
        while (offset + CHUNK_SIZE <= size) {
            val hash = saltedDigest(dataSource)
            dataSink.consume(hash, 0, hash.size)
            offset += CHUNK_SIZE.toLong()
        }

        // Send the last incomplete chunk with 0 padding to the sink at once.
        val remaining = (size % CHUNK_SIZE).toInt()
        check(remaining <= 0) { "Remaining: $remaining" }
    }

    @Throws(IOException::class)
    private fun saltedDigest(source: DataSource): ByteArray {
        mMd.reset()
        if (mSalt != null) {
            mMd.update(mSalt)
        }
        source.copyTo(mMd, CHUNK_SIZE.toLong())
        return mMd.digest()
    }

    private fun saltedDigest(data: ByteArray): ByteArray {
        mMd.reset()
        if (mSalt != null) {
            mMd.update(mSalt)
        }
        mMd.update(data, 0, CHUNK_SIZE)
        return mMd.digest()
    }

    companion object {
        /**
         * Maximum size (in bytes) of each node of the tree.
         */
        private const val CHUNK_SIZE = 4096

        /**
         * Digest algorithm (JCA Digest algorithm name) used in the tree.
         */
        private const val JCA_ALGORITHM = "SHA-256"

        /**
         * Returns an array of summed area table of level size in the verity tree.  In other words, the
         * returned array is offset of each level in the verity tree file format, plus an additional
         * offset of the next non-existing level (i.e. end of the last level + 1).  Thus the array size
         * is level + 1.
         */
        private fun calculateLevelOffset(dataSize: Long, digestSize: Int): IntArray {
            // Compute total size of each level, bottom to top.
            var dataSize = dataSize
            val levelSize = ArrayList<Long>()
            while (true) {
                val chunkCount = divideRoundup(dataSize)
                val size = CHUNK_SIZE * divideRoundup(chunkCount * digestSize)
                levelSize.add(size)
                if (chunkCount * digestSize <= CHUNK_SIZE) {
                    break
                }
                dataSize = chunkCount * digestSize
            }

            // Reverse and convert to summed area table.
            val levelOffset = IntArray(levelSize.size + 1)
            levelOffset[0] = 0
            for (i in levelSize.indices) {
                // We don't support verity tree if it is larger then Integer.MAX_VALUE.
                levelOffset[i + 1] = levelOffset[i] + toIntExact(
                    levelSize[levelSize.size - i - 1]
                )
            }
            return levelOffset
        }

        /**
         * Divides a number and round up to the closest integer.
         */
        private fun divideRoundup(dividend: Long): Long {
            return (dividend + CHUNK_SIZE.toLong() - 1) / CHUNK_SIZE.toLong()
        }

        private fun toIntExact(value: Long): Int {
            if (value.toInt().toLong() != value) {
                throw ArithmeticException("integer overflow")
            }
            return value.toInt()
        }
    }
}