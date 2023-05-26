package bin.zip;

import bin.mt.apksign.V2V3SchemeSigner;
import bin.mt.apksign.key.JksSignatureKey;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.text.DecimalFormat;
import java.util.*;

public class DataMultiplexing {

    public static void main(String[] args) throws Exception {
        File input = new File("test.apk");
        File output = new File("output.apk");
        optimize(input, output, "assets/base.apk", true);
        V2V3SchemeSigner.sign(output, new JksSignatureKey("test.jks", "123456", "123456", "123456"), true, true);
        System.out.println("Check " + isZipFileContentEquals(input, output));
    }

    /**
     * @param input         输入文件
     * @param output        输出文件
     * @param hostEntryName 原包路径，如 assets/base.apk
     * @param printDetails  是否打印优化详情
     */
    public static void optimize(String input, String output, String hostEntryName, boolean printDetails) throws IOException {
        optimize(new File(input), new File(output), hostEntryName, printDetails);
    }

    /**
     * @param input         输入文件
     * @param output        输出文件
     * @param hostEntryName 原包路径，如 assets/base.apk
     * @param printDetails  是否打印优化详情
     */
    public static void optimize(File input, File output, String hostEntryName, boolean printDetails) throws IOException {
        try (ZipFile zipFile = new ZipFile(input)) {
            ZipEntry hostEntry = zipFile.getEntryNonNull(hostEntryName);
            Set<String> children = new TreeSet<>();
            // 返回的innerZipFile已经close了，但内部的entries还在
            ZipFile innerZipFile = collectChildren(zipFile, hostEntry, children);
            if (innerZipFile == null) {
                throw new IOException("No multiplexable data found");
            }
            List<ZipEntry> otherZipEntry = new ArrayList<>();
            for (ZipEntry entry : zipFile.getEntries()) {
                if (entry != hostEntry && !children.contains(entry.getName())) {
                    otherZipEntry.add(entry);
                }
            }
            try (ZipMaker zipMaker = new ZipMaker(output)) {
                ZipMaker.HostEntryHolder holder = zipMaker.putNextHostEntry(hostEntry.getName(), innerZipFile);
                String format = "%0" + Math.min(Long.toHexString(hostEntry.getSize()).length(), 9) + "x";
                if (printDetails) {
                    System.out.println(hostEntry.getName() + " >> offset=0x" + Long.toHexString(holder.getHostEntryHeaderOffset()));
                }
                for (String name : children) {
                    long offset = holder.putNextVirtualEntry(name);
                    if (printDetails) {
                        System.out.println("  +0x" + String.format(format, offset) + "  " + name);
                    }
                }
                for (ZipEntry entry : otherZipEntry) {
                    zipMaker.copyZipEntry(entry, zipFile);
                }
            }
        }
        long inputLen = input.length();
        long outputLen = output.length();
        System.out.printf("Data multiplexing optimize: %s (%s) -> %s (%s)  [%.2f%%]\n", input.getName(), formatFileSize(inputLen), output.getName(), formatFileSize(outputLen), (outputLen - inputLen) * 100f / inputLen);
    }

    /**
     * 判断两个ZIP文件内容是否完全相同
     */
    public static boolean isZipFileContentEquals(File file1, File file2) throws IOException {
        try (ZipFile zipFile1 = new ZipFile(file1); ZipFile zipFile2 = new ZipFile(file2)) {
            if (zipFile1.getEntrySize() != zipFile2.getEntrySize()) {
                return false;
            }
            for (ZipEntry entry1 : zipFile1.getEntries()) {
                ZipEntry entry2 = zipFile2.getEntry(entry1.getName());
                if (entry2 == null) {
                    return false;
                }
                if (entry1.isDirectory() && entry2.isDirectory()) {
                    continue;
                }
                if (entry1.getMethod() != entry2.getMethod()) {
                    return false;
                }
                if (entry1.getCrc() != entry2.getCrc()) {
                    return false;
                }
                if (entry1.getSize() != entry2.getSize()) {
                    return false;
                }
                if (!Arrays.equals(entry1.getCommentData(), entry2.getCommentData())) {
                    return false;
                }
                if (!isInputStreamContentEquals(zipFile1.getInputStream(entry1), zipFile2.getInputStream(entry2))) {
                    return false;
                }
            }
            return true;
        }
    }

    private static ZipFile collectChildren(ZipFile outer, ZipEntry hostEntry, Set<String> children) throws IOException {
        try (ZipFile inner = openEntryAsZipFile(outer, hostEntry)) {
            for (ZipEntry outerEntry : outer.getEntries()) {
                if (outerEntry == hostEntry || outerEntry.isDirectory()) {
                    continue;
                }
                ZipEntry innerEntry = inner.getEntry(outerEntry.getName());
                if (innerEntry == null) {
                    continue;
                }
                if (outerEntry.getMethod() != innerEntry.getMethod()) {
                    continue;
                }
                if (outerEntry.getCrc() != innerEntry.getCrc()) {
                    continue;
                }
                if (outerEntry.getSize() != innerEntry.getSize()) {
                    continue;
                }
                if (!Arrays.equals(outerEntry.getCommentData(), innerEntry.getCommentData())) {
                    continue;
                }
                // 必须4k对齐
                if (innerEntry.getMethod() == ZipMaker.METHOD_STORED && innerEntry.getDataOffset() % 4 != 0) {
                    String name = innerEntry.getName();
                    if (name.equals("resources.arsc") || name.endsWith(".so")) {
                        continue;
                    }
                }
                boolean equals = outerEntry.getCompressedSize() == innerEntry.getCompressedSize() &&
                        isInputStreamContentEquals(inner.getRawInputStream(innerEntry), outer.getRawInputStream(outerEntry)) ||
                        isInputStreamContentEquals(inner.getInputStream(innerEntry), outer.getInputStream(outerEntry));
                if (equals) {
                    children.add(innerEntry.getName());
                }
            }
            return children.isEmpty() ? null : inner;
        }
    }

    private static ZipFile openEntryAsZipFile(ZipFile zipFile, ZipEntry hostEntry) throws IOException {
        if (hostEntry.getMethod() == ZipMaker.METHOD_STORED) {
            return zipFile.openEntryAsZipFile(hostEntry);
        } else {
            throw new IOException("Entry must be packaged with the stored method: " + hostEntry.getName());
        }
    }

    private static boolean isInputStreamContentEquals(InputStream input1, InputStream input2) throws IOException {
        if (input1 == input2) {
            return true;
        }
        if (!(input1 instanceof BufferedInputStream)) {
            input1 = new BufferedInputStream(input1);
        }
        if (!(input2 instanceof BufferedInputStream)) {
            input2 = new BufferedInputStream(input2);
        }

        int ch = input1.read();
        while (-1 != ch) {
            final int ch2 = input2.read();
            if (ch != ch2) {
                return false;
            }
            ch = input1.read();
        }

        final int ch2 = input2.read();
        return ch2 == -1;
    }

    private static final DecimalFormat df = new DecimalFormat("#.00");

    private static String formatFileSize(long fileSize) {
        if (fileSize < 1024)
            return fileSize + "B";
        else if (fileSize < 1024 * 1024)
            return df.format((double) fileSize / 1024) + "KB";
        else if (fileSize < 1024 * 1024 * 1024)
            return df.format((double) fileSize / 1048576) + "MB";
        else
            return df.format((double) fileSize / 1073741824) + "GB";
    }

}
