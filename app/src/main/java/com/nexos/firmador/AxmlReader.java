package com.nexos.firmador;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Lee lo esencial de un AndroidManifest.xml binario (AXML): paquete, versión,
 * minSdk/targetSdk y debuggable. Java puro (sin Android).
 */
public final class AxmlReader {

    private AxmlReader() {
    }

    /** Datos extraídos del manifiesto (null = no presente). */
    public static final class ManifestInfo {
        public String packageName;
        public String versionCode;
        public String versionName;
        public Integer minSdk;
        public Integer targetSdk;
        public Boolean debuggable;
    }

    /** Lee el manifiesto dentro de un APK. */
    public static ManifestInfo parseApk(File apk) throws IOException {
        ZipFile zip = new ZipFile(apk);
        try {
            ZipEntry manifest = zip.getEntry("AndroidManifest.xml");
            if (manifest == null) {
                throw new IOException("El ZIP no tiene AndroidManifest.xml");
            }
            InputStream in = zip.getInputStream(manifest);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try {
                byte[] buf = new byte[32768];
                int n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                }
            } finally {
                in.close();
            }
            return parse(out.toByteArray());
        } finally {
            zip.close();
        }
    }

    /** Interpreta bytes AXML. */
    public static ManifestInfo parse(byte[] axml) throws IOException {
        Reader r = new Reader(axml);
        int type = r.u16();
        r.u16(); // headerSize
        r.u32(); // size
        if (type != 0x0003) {
            throw new IOException("No es un XML binario (tipo " + type + ")");
        }
        List<String> pool = null;
        ManifestInfo info = new ManifestInfo();
        List<String> stack = new ArrayList<String>();
        while (r.remaining() >= 8) {
            int chunk = r.u16();
            int headerSize = r.u16();
            long size = r.u32();
            if (size < 8 || size > r.remaining() + 8) {
                throw new IOException("Trozo AXML corrupto");
            }
            int bodyEnd = r.pos + (int) size - 8;
            if (chunk == 0x0001) {
                pool = readPool(r, headerSize, bodyEnd);
            } else if (chunk == 0x0102 && pool != null) {
                readElement(r, pool, stack, info, bodyEnd);
            } else if (chunk == 0x0103 && pool != null) {
                r.skip(8); // line, comment
                r.u32(); // ns
                r.u32(); // name
                if (!stack.isEmpty()) {
                    stack.remove(stack.size() - 1);
                }
            }
            r.pos = bodyEnd;
        }
        if (pool == null) {
            throw new IOException("AXML sin tabla de textos");
        }
        return info;
    }

    private static List<String> readPool(Reader r, int headerSize, int bodyEnd) throws IOException {
        long stringCount = r.u32();
        r.u32(); // styleCount
        long flags = r.u32();
        long stringsStart = r.u32();
        r.u32(); // stylesStart
        boolean utf8 = (flags & 0x100) != 0;
        if (stringCount > 100000) {
            throw new IOException("Tabla de textos absurda: " + stringCount);
        }
        int chunkStart = r.pos - headerSize;
        int[] offsets = new int[(int) stringCount];
        for (int i = 0; i < offsets.length; i++) {
            offsets[i] = (int) r.u32();
        }
        List<String> pool = new ArrayList<String>(offsets.length);
        int dataStart = (int) (chunkStart + stringsStart);
        for (int off : offsets) {
            pool.add(readPoolString(r.data, dataStart + off, utf8, bodyEnd));
        }
        return pool;
    }

    private static String readPoolString(byte[] data, int pos, boolean utf8, int limit)
            throws IOException {
        if (pos < 0 || pos >= limit) {
            throw new IOException("Texto fuera de rango");
        }
        if (utf8) {
            int[] p = new int[]{pos};
            readVarLen(data, p, limit); // longitud UTF-16 (se ignora)
            int bytes = readVarLen(data, p, limit);
            if (p[0] + bytes > limit) {
                throw new IOException("Texto UTF-8 truncado");
            }
            return new String(data, p[0], bytes, StandardCharsets.UTF_8);
        }
        // En UTF-16 la longitud es u16 fija (4 bytes si supera 0x7FFF).
        if (pos + 2 > limit) {
            throw new IOException("Longitud truncada");
        }
        int chars = (data[pos] & 0xFF) | ((data[pos + 1] & 0xFF) << 8);
        pos += 2;
        if ((chars & 0x8000) != 0) {
            if (pos + 2 > limit) {
                throw new IOException("Longitud truncada");
            }
            int extra = (data[pos] & 0xFF) | ((data[pos + 1] & 0xFF) << 8);
            pos += 2;
            chars = ((chars & 0x7FFF) << 16) | extra;
        }
        if (chars < 0 || pos + chars * 2 > limit) {
            throw new IOException("Texto UTF-16 truncado");
        }
        return new String(data, pos, chars * 2, StandardCharsets.UTF_16LE);
    }

    private static int readVarLen(byte[] data, int[] pos, int limit) throws IOException {
        if (pos[0] >= limit) {
            throw new IOException("Longitud truncada");
        }
        int first = data[pos[0]++] & 0xFF;
        if ((first & 0x80) != 0) {
            if (pos[0] >= limit) {
                throw new IOException("Longitud truncada");
            }
            int second = data[pos[0]++] & 0xFF;
            return ((first & 0x7F) << 8) | second;
        }
        return first;
    }

    private static void readElement(Reader r, List<String> pool, List<String> stack,
                                    ManifestInfo info, int bodyEnd) throws IOException {
        r.skip(8); // line, comment
        r.u32(); // ns del elemento
        String name = poolString(pool, (int) r.u32());
        int attrStart = r.u16();
        int attrSize = r.u16();
        int attrCount = r.u16();
        r.skip(6); // idIndex, classIndex, styleIndex
        if (attrCount < 0 || attrCount > 500 || attrSize < 20) {
            throw new IOException("Atributos corruptos");
        }
        // attrStart se mide desde el inicio del elemento extendido; ya consumimos 20.
        int attrsPos = r.pos - 20 + attrStart;
        stack.add(name == null ? "?" : name);
        String parent = stack.size() >= 2 ? stack.get(stack.size() - 2) : "";
        for (int i = 0; i < attrCount; i++) {
            int p = attrsPos + i * attrSize;
            if (p + 20 > bodyEnd) {
                throw new IOException("Atributo truncado");
            }
            long ns = u32At(r.data, p);
            String attrName = poolString(pool, (int) u32At(r.data, p + 4));
            long raw = u32At(r.data, p + 8);
            int valType = r.data[p + 15] & 0xFF;
            long valData = u32At(r.data, p + 16);
            if (attrName != null) {
                collect(info, name, parent, ns, attrName, valType, valData, raw, pool);
            }
        }
    }

    private static void collect(ManifestInfo info, String element, String parent, long ns,
                                String attr, int valType, long valData, long raw,
                                List<String> pool) {
        boolean androidNs = ns == 0xFFFFFFFFL || isAndroidNs(pool, (int) ns);
        if ("manifest".equals(element) && parent.isEmpty()) {
            if ("package".equals(attr)) {
                info.packageName = stringValue(pool, valType, valData, raw);
            } else if ("versionCode".equals(attr) && androidNs) {
                info.versionCode = intOrString(pool, valType, valData, raw);
            } else if ("versionName".equals(attr) && androidNs) {
                info.versionName = stringValue(pool, valType, valData, raw);
            }
        } else if ("uses-sdk".equals(element)) {
            if ("minSdkVersion".equals(attr)) {
                info.minSdk = intValue(pool, valType, valData, raw);
            } else if ("targetSdkVersion".equals(attr)) {
                info.targetSdk = intValue(pool, valType, valData, raw);
            }
        } else if ("application".equals(element) && "debuggable".equals(attr) && androidNs) {
            if (valType == 0x12) {
                info.debuggable = valData != 0;
            } else {
                String s = stringValue(pool, valType, valData, raw);
                if (s != null) {
                    info.debuggable = Boolean.parseBoolean(s);
                }
            }
        }
    }

    private static boolean isAndroidNs(List<String> pool, int index) {
        String uri = poolString(pool, index);
        return "http://schemas.android.com/apk/res/android".equals(uri);
    }

    private static String stringValue(List<String> pool, int type, long data, long raw) {
        if (type == 0x03) {
            return poolString(pool, (int) data);
        }
        if (raw != 0xFFFFFFFFL) {
            return poolString(pool, (int) raw);
        }
        if (type == 0x10 || type == 0x11) {
            return String.valueOf((int) data);
        }
        return null;
    }

    private static String intOrString(List<String> pool, int type, long data, long raw) {
        if (type == 0x10 || type == 0x11) {
            return String.valueOf((int) data);
        }
        return stringValue(pool, type, data, raw);
    }

    private static Integer intValue(List<String> pool, int type, long data, long raw) {
        if (type == 0x10 || type == 0x11) {
            return (int) data;
        }
        String s = stringValue(pool, type, data, raw);
        if (s == null) {
            return null;
        }
        try {
            // "UpsideDownCake" y otros nombres no numéricos se ignoran.
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String poolString(List<String> pool, int index) {
        if (index < 0 || index >= pool.size()) {
            return null;
        }
        return pool.get(index);
    }

    private static long u32At(byte[] data, int pos) {
        return (data[pos] & 0xFFL) | ((data[pos + 1] & 0xFFL) << 8)
                | ((data[pos + 2] & 0xFFL) << 16) | ((data[pos + 3] & 0xFFL) << 24);
    }

    /** Lector little-endian con control de límites. */
    private static final class Reader {
        final byte[] data;
        int pos;

        Reader(byte[] data) {
            this.data = data;
        }

        int remaining() {
            return data.length - pos;
        }

        int u16() throws IOException {
            if (remaining() < 2) {
                throw new IOException("AXML truncado");
            }
            int v = (data[pos] & 0xFF) | ((data[pos + 1] & 0xFF) << 8);
            pos += 2;
            return v;
        }

        long u32() throws IOException {
            if (remaining() < 4) {
                throw new IOException("AXML truncado");
            }
            long v = u32At(data, pos);
            pos += 4;
            return v;
        }

        void skip(int n) throws IOException {
            if (remaining() < n) {
                throw new IOException("AXML truncado");
            }
            pos += n;
        }
    }
}
