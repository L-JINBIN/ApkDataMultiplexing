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

package bin.mt.apksign;

import bin.mt.apksign.data.DataSink;
import bin.mt.apksign.data.DataSinks;
import bin.mt.apksign.data.DataSource;
import bin.mt.apksign.data.DataSources;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

/**
 * VerityTreeBuilder is used to generate the root hash of verity tree built from the input file.
 * The root hash can be used on device for on-access verification.  The tree itself is reproducible
 * on device, and is not shipped with the APK.
 */
class VerityTreeBuilder {

    /**
     * Maximum size (in bytes) of each node of the tree.
     */
    private final static int CHUNK_SIZE = 4096;

    /**
     * Digest algorithm (JCA Digest algorithm name) used in the tree.
     */
    private final static String JCA_ALGORITHM = "SHA-256";

    /**
     * Optional salt to apply before each digestion.
     */
    private final byte[] mSalt;

    private final MessageDigest mMd;

    VerityTreeBuilder(byte[] salt) throws NoSuchAlgorithmException {
        mSalt = salt;
        mMd = MessageDigest.getInstance(JCA_ALGORITHM);
    }

    /**
     * Returns the root hash of the APK verity tree built from ZIP blocks.
     * <p>
     * Specifically, APK verity tree is built from the APK, but as if the APK Signing Block (which
     * must be page aligned) and the "Central Directory offset" field in End of Central Directory
     * are skipped.
     */
    byte[] generateVerityTreeRootHash(DataSource beforeApkSigningBlock, DataSource centralDir,
                                      DataSource eocd) throws IOException {
        if (beforeApkSigningBlock.size() % CHUNK_SIZE != 0) {
            throw new IllegalStateException("APK Signing Block size not a multiple of " + CHUNK_SIZE
                    + ": " + beforeApkSigningBlock.size());
        }

        return generateVerityTreeRootHash(DataSources.link(beforeApkSigningBlock, centralDir, eocd));
    }

    /**
     * Returns the root hash of the verity tree built from the data source.
     * <p>
     * The tree is built bottom up. The bottom level has 256-bit digest for each 4 KB block in the
     * input file.  If the total size is larger than 4 KB, take this level as input and repeat the
     * same procedure, until the level is within 4 KB.  If salt is given, it will apply to each
     * digestion before the actual data.
     * <p>
     * The returned root hash is calculated from the last level of 4 KB chunk, similarly with salt.
     * <p>
     * The tree is currently stored only in memory and is never written out.  Nevertheless, it is
     * the actual verity tree format on disk, and is supposed to be re-generated on device.
     * <p>
     * This is package-private for testing purpose.
     */
    private byte[] generateVerityTreeRootHash(DataSource fileSource) throws IOException {
        int digestSize = mMd.getDigestLength();

        // Calculate the summed area table of level size. In other word, this is the offset
        // table of each level, plus the next non-existing level.
        int[] levelOffset = calculateLevelOffset(fileSource.size(), digestSize);


        byte[] verityBuffer = new byte[levelOffset[levelOffset.length - 1]];

        // Generate the hash tree bottom-up.
        for (int i = levelOffset.length - 2; i >= 0; i--) {
            DataSink middleBufferSink = DataSinks.fromData(verityBuffer, levelOffset[i], levelOffset[i + 1]);
            DataSource src;
            if (i == levelOffset.length - 2) {
                src = fileSource;
            } else {
                int start = levelOffset[i + 1];
                int end = levelOffset[i + 2];
                src = DataSources.fromData(verityBuffer, start, end - start);
            }
            digestDataByChunks(src, middleBufferSink);

            // If the output is not full chunk, pad with 0s.
            long totalOutput = divideRoundup(src.size()) * digestSize;
            int incomplete = (int) (totalOutput % CHUNK_SIZE);
            if (incomplete > 0) {
                byte[] padding = new byte[CHUNK_SIZE - incomplete];
                middleBufferSink.consume(padding, 0, padding.length);
            }
        }

        // Finally, calculate the root hash from the top level (only page).
        return saltedDigest(verityBuffer);
    }

    /**
     * Returns an array of summed area table of level size in the verity tree.  In other words, the
     * returned array is offset of each level in the verity tree file format, plus an additional
     * offset of the next non-existing level (i.e. end of the last level + 1).  Thus the array size
     * is level + 1.
     */
    private static int[] calculateLevelOffset(long dataSize, int digestSize) {
        // Compute total size of each level, bottom to top.
        ArrayList<Long> levelSize = new ArrayList<>();
        while (true) {
            long chunkCount = divideRoundup(dataSize);
            long size = CHUNK_SIZE * divideRoundup(chunkCount * digestSize);
            levelSize.add(size);
            if (chunkCount * digestSize <= CHUNK_SIZE) {
                break;
            }
            dataSize = chunkCount * digestSize;
        }

        // Reverse and convert to summed area table.
        int[] levelOffset = new int[levelSize.size() + 1];
        levelOffset[0] = 0;
        for (int i = 0; i < levelSize.size(); i++) {
            // We don't support verity tree if it is larger then Integer.MAX_VALUE.
            levelOffset[i + 1] = levelOffset[i] + toIntExact(
                    levelSize.get(levelSize.size() - i - 1));
        }
        return levelOffset;
    }

    /**
     * Digest data source by chunks then feeds them to the sink one by one.  If the last unit is
     * less than the chunk size and padding is desired, feed with extra padding 0 to fill up the
     * chunk before digesting.
     */
    private void digestDataByChunks(DataSource dataSource, DataSink dataSink) throws IOException {
        dataSource = dataSource.align(CHUNK_SIZE);
        long size = dataSource.size();
        long offset = 0;
        for (; offset + CHUNK_SIZE <= size; offset += CHUNK_SIZE) {
            byte[] hash = saltedDigest(dataSource);
            dataSink.consume(hash, 0, hash.length);
        }

        // Send the last incomplete chunk with 0 padding to the sink at once.
        int remaining = (int) (size % CHUNK_SIZE);
        if (remaining > 0) {
            throw new IllegalStateException("Remaining: " + remaining);
        }
    }

    private byte[] saltedDigest(DataSource source) throws IOException {
        mMd.reset();
        if (mSalt != null) {
            mMd.update(mSalt);
        }
        source.copyTo(mMd, VerityTreeBuilder.CHUNK_SIZE);
        return mMd.digest();
    }

    private byte[] saltedDigest(byte[] data) {
        mMd.reset();
        if (mSalt != null) {
            mMd.update(mSalt);
        }
        mMd.update(data, 0, VerityTreeBuilder.CHUNK_SIZE);
        return mMd.digest();
    }

    /**
     * Divides a number and round up to the closest integer.
     */
    private static long divideRoundup(long dividend) {
        return (dividend + (long) VerityTreeBuilder.CHUNK_SIZE - 1) / (long) VerityTreeBuilder.CHUNK_SIZE;
    }

    private static int toIntExact(long value) {
        if ((int) value != value) {
            throw new ArithmeticException("integer overflow");
        }
        return (int) value;
    }
}
