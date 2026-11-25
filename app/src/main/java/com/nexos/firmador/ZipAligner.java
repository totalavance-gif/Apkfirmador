package com.nexos.firmador;

import java.io.FilterOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * Prepara un APK para firmar: elimina firmas anteriores (v1) y, si se pide,
 * realinea las entradas sin comprimir como hace {@code zipalign}
 * (4 bytes general, 16 KB para .so nativas como exige Android 15).
 *
 * <p>El bloque de firma v2/v3 anterior se descarta solo: vive fuera de las
 * entradas ZIP y no se copia. La clase es Java puro (sin Android) para poder
 * probarla en JVM de escritorio.
 */
public final class ZipAligner {

    /** Registro de progreso. */
    public interface Logger {
        void log(String s);
    }

    private ZipAligner() {
    }

    /**
     * Copia {@code inApk} a {@code outApk} sin firmas previas y con alineación opcional.
     *
     * @param align true para alinear entradas STORED (equivale a zipalign -f 4)
     */
    public static void prepare(File inApk, File outApk, boolean align, Logger logger) throws IOException {
        List<? extends ZipEntry> entries;
        String zipComment;
        try (ZipFile zin = new ZipFile(inApk)) {
            zipComment = zin.getComment();
            entries = Collections.list(zin.entries());
            List<ZipEntry> copy = new ArrayList<ZipEntry>(entries.size());
            for (ZipEntry e : entries) {
                copy.add(e);
            }
            entries = copy;

            int stripped = 0;
            int aligned = 0;
            byte[] buf = new byte[65536];
            try (FileOutputStream fout = new FileOutputStream(outApk);
                 CountingOutputStream cout = new CountingOutputStream(fout);
                 ZipOutputStream zout = new ZipOutputStream(cout)) {
                for (ZipEntry e : entries) {
                    String name = e.getName();
                    if (isOldSignatureFile(name)) {
                        stripped++;
                        continue;
                    }
                    if (e.isDirectory() || name.endsWith("/")) {
                        ZipEntry dir = new ZipEntry(name);
                        copyTime(e, dir);
                        dir.setMethod(ZipEntry.STORED);
                        dir.setSize(0);
                        dir.setCompressedSize(0);
                        dir.setCrc(0);
                        zout.putNextEntry(dir);
                        zout.closeEntry();
                        continue;
                    }
                    if (e.getMethod() == ZipEntry.STORED) {
                        // Dos pasadas en streaming: 1) tamaño+CRC, 2) copia. Sin cargar en RAM.
                        long size = 0;
                        CRC32 crc = new CRC32();
                        InputStream in1 = zin.getInputStream(e);
                        try {
                            int n;
                            while ((n = in1.read(buf)) != -1) {
                                size += n;
                                crc.update(buf, 0, n);
                            }
                        } finally {
                            in1.close();
                        }
                        ZipEntry ne = new ZipEntry(name);
                        copyTime(e, ne);
                        ne.setComment(e.getComment());
                        ne.setMethod(ZipEntry.STORED);
                        ne.setSize(size);
                        ne.setCompressedSize(size);
                        ne.setCrc(crc.getValue());

                        byte[] origExtra = e.getExtra();
                        if (origExtra == null) {
                            origExtra = new byte[0];
                        }
                        if (align) {
                            int alignment = name.endsWith(".so") ? 16384 : 4;
                            int nameLen = name.getBytes(StandardCharsets.UTF_8).length;
                            int headerLen = 30 + nameLen;
                            int pad = 0;
                            while (pad < alignment
                                    && (cout.getCount() + headerLen + origExtra.length + pad) % alignment != 0) {
                                pad++;
                            }
                            if (origExtra.length + pad <= 65535) {
                                if (pad > 0) {
                                    aligned++;
                                }
                                byte[] extra = new byte[origExtra.length + pad];
                                System.arraycopy(origExtra, 0, extra, 0, origExtra.length);
                                ne.setExtra(extra);
                            } else {
                                ne.setExtra(origExtra);
                            }
                        } else {
                            ne.setExtra(origExtra);
                        }
                        zout.putNextEntry(ne);
                        InputStream in2 = zin.getInputStream(e);
                        try {
                            int n;
                            while ((n = in2.read(buf)) != -1) {
                                zout.write(buf, 0, n);
                            }
                        } finally {
                            in2.close();
                        }
                        zout.closeEntry();
                    } else {
                        ZipEntry ne = new ZipEntry(name);
                        copyTime(e, ne);
                        ne.setComment(e.getComment());
                        ne.setMethod(ZipEntry.DEFLATED);
                        ne.setExtra(e.getExtra());
                        zout.putNextEntry(ne);
                        InputStream in = zin.getInputStream(e);
                        try {
                            int n;
                            while ((n = in.read(buf)) != -1) {
                                zout.write(buf, 0, n);
                            }
                        } finally {
                            in.close();
                        }
                        zout.closeEntry();
                    }
                }
                if (zipComment != null) {
                    zout.setComment(zipComment);
                }
            }
            if (logger != null) {
                logger.log("Entradas copiadas, firmas viejas eliminadas: " + stripped
                        + ", entradas alineadas: " + aligned);
            }
        }
    }

    /** true si es un fichero de firma v1 (JAR) que hay que descartar al refirmar. */
    static boolean isOldSignatureFile(String name) {
        String upper = name.toUpperCase(Locale.US);
        if (!upper.startsWith("META-INF/")) {
            return false;
        }
        String rest = upper.substring("META-INF/".length());
        if (rest.contains("/")) {
            return false;
        }
        return rest.equals("MANIFEST.MF")
                || rest.endsWith(".SF")
                || rest.endsWith(".RSA")
                || rest.endsWith(".DSA")
                || rest.endsWith(".EC")
                || rest.startsWith("SIG-");
    }

    private static void copyTime(ZipEntry from, ZipEntry to) {
        long t = from.getTime();
        if (t != -1) {
            to.setTime(t);
        }
    }

    /** Cuenta los bytes escritos para calcular el desplazamiento de cada entrada. */
    private static final class CountingOutputStream extends FilterOutputStream {
        private long count;

        CountingOutputStream(OutputStream out) {
            super(out);
        }

        long getCount() {
            return count;
        }

        @Override
        public void write(int b) throws IOException {
            out.write(b);
            count++;
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            out.write(b, off, len);
            count += len;
        }
    }

    /** Recorre las cabeceras locales y devuelve [desplazamiento, tamaño] de cada STORED (para pruebas). */
    static List<long[]> storedDataOffsets(File apk) throws IOException {
        List<long[]> result = new ArrayList<long[]>();
        InputStream bin = new java.io.BufferedInputStream(new FileInputStream(apk));
        try {
            byte[] header = new byte[30];
            long pos = 0;
            while (true) {
                readFully(bin, header, 0, 30);
                pos += 30;
                if (u32(header, 0) != 0x04034b50L) {
                    break; // Fin de entradas locales (bloque de firma o directorio central).
                }
                int method = u16(header, 8);
                int nameLen = u16(header, 26);
                int extraLen = u16(header, 28);
                skipFully(bin, nameLen + extraLen);
                pos += nameLen + extraLen;
                long compSize = u32(header, 18);
                if (method == 0) {
                    result.add(new long[]{pos, compSize});
                }
                skipFully(bin, compSize);
                pos += compSize;
            }
        } finally {
            bin.close();
        }
        return result;
    }

    private static int u16(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    private static long u32(byte[] b, int off) {
        return (b[off] & 0xFFL) | ((b[off + 1] & 0xFFL) << 8)
                | ((b[off + 2] & 0xFFL) << 16) | ((b[off + 3] & 0xFFL) << 24);
    }

    private static void readFully(InputStream in, byte[] b, int off, int len) throws IOException {
        while (len > 0) {
            int n = in.read(b, off, len);
            if (n == -1) {
                throw new IOException("ZIP truncado");
            }
            off += n;
            len -= n;
        }
    }

    private static void skipFully(InputStream in, long n) throws IOException {
        while (n > 0) {
            long skipped = in.skip(n);
            if (skipped <= 0) {
                if (in.read() == -1) {
                    throw new IOException("ZIP truncado");
                }
                n--;
            } else {
                n -= skipped;
            }
        }
    }
}
