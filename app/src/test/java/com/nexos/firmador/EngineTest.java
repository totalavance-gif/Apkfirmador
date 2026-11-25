package com.nexos.firmador;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import javax.crypto.SecretKey;

/**
 * Pruebas del motor en JVM (sin Android). Las ejecuta CI en cada push.
 */
public class EngineTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void aliasValidation() {
        KeyStoreManager.validateAlias("clave1");
        KeyStoreManager.validateAlias("a-b_c9");
        for (String bad : new String[]{"", "mala clave", "-x", "áé", "a/b"}) {
            try {
                KeyStoreManager.validateAlias(bad);
                fail("debió rechazar: " + bad);
            } catch (IllegalArgumentException expected) {
            }
        }
    }

    @Test
    public void keygenRsa() throws Exception {
        KeyStoreManager keys = new KeyStoreManager(new File(tmp.getRoot(), "k"));
        keys.generate("rsa1", 2048, 25);
        assertEquals(Collections.singletonList("rsa1"), keys.listAliases());
        KeyStoreManager.KeyInfo info = keys.loadInfo("rsa1");
        assertEquals("RSA", info.algorithm);
        assertEquals(2048, info.keySize);
        assertEquals(95, info.fingerprintSha256.length());
        assertNotNull(keys.load("rsa1").privateKey);
    }

    @Test
    public void keygenEc() throws Exception {
        KeyStoreManager keys = new KeyStoreManager(new File(tmp.getRoot(), "k"));
        keys.generateEc("ecc", "secp256r1", 10);
        KeyStoreManager.KeyInfo info = keys.loadInfo("ecc");
        assertEquals("EC", info.algorithm);
        assertEquals(256, info.keySize);
    }

    @Test
    public void masterRoundTrip() throws Exception {
        MasterKeyManager m = new MasterKeyManager(new File(tmp.getRoot(), "k"));
        assertFalse(m.isConfigured());
        SecretKey session = m.setup("secreta".toCharArray());
        assertTrue(m.isConfigured());
        byte[] enc = MasterKeyManager.encryptWith(session, "hola".getBytes("UTF-8"));
        assertEquals("hola", new String(MasterKeyManager.decryptWith(session, enc), "UTF-8"));
        try {
            m.unlock("otra".toCharArray());
            fail("debió rechazar contraseña mala");
        } catch (SecurityException expected) {
        }
        SecretKey session2 = m.unlock("secreta".toCharArray());
        assertNotNull(session2);
    }

    @Test
    public void keyEncryptionFlow() throws Exception {
        KeyStoreManager keys = new KeyStoreManager(new File(tmp.getRoot(), "k"));
        keys.generate("c1", 2048, 5);
        String fp = keys.loadInfo("c1").fingerprintSha256;
        keys.setSessionKey(keys.getMaster().setup("maestra".toCharArray()));
        assertEquals(1, keys.encryptPlaintextKeys());
        keys.setSessionKey(null);
        assertTrue(keys.isLocked());
        try {
            keys.load("c1");
            fail("debió exigir desbloqueo");
        } catch (IllegalStateException expected) {
        }
        keys.setSessionKey(keys.getMaster().unlock("maestra".toCharArray()));
        assertEquals(fp, keys.loadInfo("c1").fingerprintSha256);
        assertEquals(1, keys.decryptAllKeys());
        keys.getMaster().remove("maestra".toCharArray());
        keys.setSessionKey(null);
        assertFalse(keys.isLocked());
    }

    @Test
    public void jksRoundTrip() throws Exception {
        KeyStoreManager keys = new KeyStoreManager(new File(tmp.getRoot(), "k"));
        keys.generate("j", 2048, 5);
        String fp = keys.loadInfo("j").fingerprintSha256;
        File jks = new File(tmp.getRoot(), "c.jks");
        keys.exportJks("j", jks, "secreto12");
        String alias = keys.importKeyStore(jks, "secreto12", "", null);
        assertEquals(fp, keys.loadInfo(alias).fingerprintSha256);
    }

    @Test
    public void zipAlignAndStrip() throws Exception {
        File in = new File(tmp.getRoot(), "in.apk");
        ZipOutputStream zout = new ZipOutputStream(new FileOutputStream(in));
        stored(zout, "AndroidManifest.xml", "<m/>".getBytes("UTF-8"));
        stored(zout, "x", new byte[]{1});
        stored(zout, "lib/arm64-v8a/a.so", new byte[64]);
        stored(zout, "META-INF/MANIFEST.MF", "v".getBytes("UTF-8"));
        stored(zout, "META-INF/C.SF", "v".getBytes("UTF-8"));
        stored(zout, "META-INF/C.RSA", "v".getBytes("UTF-8"));
        stored(zout, "META-INF/keep.txt", "ok".getBytes("UTF-8"));
        ZipEntry def = new ZipEntry("res/a.xml");
        zout.putNextEntry(def);
        zout.write(new byte[100]);
        zout.closeEntry();
        zout.close();

        File out = new File(tmp.getRoot(), "out.apk");
        ZipAligner.prepare(in, out, true, null);
        for (long[] o : ZipAligner.storedDataOffsets(out)) {
            assertEquals(0, o[0] % 4);
        }
        ZipFile zf = new ZipFile(out);
        assertNull(zf.getEntry("META-INF/C.SF"));
        assertNull(zf.getEntry("META-INF/C.RSA"));
        assertNull(zf.getEntry("META-INF/MANIFEST.MF"));
        assertNotNull(zf.getEntry("META-INF/keep.txt"));
        zf.close();
    }

    @Test
    public void signDummySmoke() throws Exception {
        KeyStoreManager keys = new KeyStoreManager(new File(tmp.getRoot(), "k"));
        keys.generate("s", 2048, 5);
        File in = new File(tmp.getRoot(), "in.apk");
        ZipOutputStream zout = new ZipOutputStream(new FileOutputStream(in));
        stored(zout, "AndroidManifest.xml", "<m/>".getBytes("UTF-8"));
        stored(zout, "classes.dex", new byte[32]);
        zout.close();
        File base = new File(tmp.getRoot(), "base.apk");
        ZipAligner.prepare(in, base, true, null);
        File signed = new File(tmp.getRoot(), "signed.apk");
        // Sin verificar: el manifiesto ficticio no es binario.
        ApkSignHelper.sign(base, signed, keys.load("s"), true, true, true, 24, null);
        assertTrue(signed.length() > base.length());
    }

    @Test
    public void axmlParsesGenerated() throws Exception {
        byte[] axml = AxmlFixture.build();
        AxmlReader.ManifestInfo mi = AxmlReader.parse(axml);
        assertEquals("com.example.t", mi.packageName);
        assertEquals("7", mi.versionCode);
        assertEquals("1.2", mi.versionName);
        assertEquals(Integer.valueOf(24), mi.minSdk);
        assertEquals(Integer.valueOf(34), mi.targetSdk);
        assertEquals(Boolean.TRUE, mi.debuggable);
    }

    @Test
    public void axmlRejectsGarbage() {
        try {
            AxmlReader.parse(new byte[]{1, 2, 3, 4, 5, 6, 7, 8});
            fail("debió rechazar");
        } catch (Exception expected) {
        }
    }

    @Test
    public void profilesRoundTrip() throws Exception {
        ProfileManager pm = new ProfileManager(new File(tmp.getRoot(), "p"));
        ProfileManager.Profile p = new ProfileManager.Profile("rel");
        p.keyAlias = "k1";
        p.v3 = false;
        p.minSdk = 26;
        p.pattern = "{nombre}-R.apk";
        pm.save(p);
        pm.setDefault("rel");
        ProfileManager.Profile back = pm.load("rel");
        assertEquals("k1", back.keyAlias);
        assertFalse(back.v3);
        assertEquals(26, back.minSdk);
        assertEquals("rel", pm.getDefault());
        assertEquals("app-R.apk", ProfileManager.applyPattern(back.pattern, "app.apk"));
        assertTrue(ProfileManager.applyPattern(null, null).endsWith(".apk"));
        pm.delete("rel");
        assertTrue(pm.list().isEmpty());
    }

    @Test
    public void historyOrder() throws Exception {
        HistoryLog h = new HistoryLog(new File(tmp.getRoot(), "h"));
        h.add("a.apk", "k", "v2", 1, 2, "OK");
        h.add("b.apk", "k", "v2", 1, 2, "OK");
        List<String> last = h.readLast(5);
        assertEquals(2, last.size());
        assertTrue(last.get(0).contains("b.apk"));
    }

    private static void stored(ZipOutputStream zout, String name, byte[] data) throws Exception {
        CRC32 crc = new CRC32();
        crc.update(data);
        ZipEntry e = new ZipEntry(name);
        e.setMethod(ZipEntry.STORED);
        e.setSize(data.length);
        e.setCompressedSize(data.length);
        e.setCrc(crc.getValue());
        zout.putNextEntry(e);
        zout.write(data);
        zout.closeEntry();
    }

    /** Genera un AXML mínimo válido (pool UTF-16) para probar el lector. */
    static final class AxmlFixture {
        // Índices del pool.
        static final int S_MANIFEST = 0;
        static final int S_USES_SDK = 1;
        static final int S_PACKAGE = 2;
        static final int S_VERSION_CODE = 3;
        static final int S_VERSION_NAME = 4;
        static final int S_MIN_SDK = 5;
        static final int S_TARGET_SDK = 6;
        static final int S_APPLICATION = 7;
        static final int S_DEBUGGABLE = 8;
        static final int S_ANDROID_URI = 9;
        static final int S_ANDROID = 10;
        static final int S_PKG_VALUE = 11;
        static final int S_VNAME_VALUE = 12;

        static byte[] build() throws Exception {
            String[] strings = {"manifest", "uses-sdk", "package", "versionCode",
                    "versionName", "minSdkVersion", "targetSdkVersion", "application",
                    "debuggable", "http://schemas.android.com/apk/res/android",
                    "android", "com.example.t", "1.2"};
            ByteArrayOutputStream file = new ByteArrayOutputStream();
            // Cabecera del fichero (tipo 0x0003).
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            body.write(poolChunk(strings), 0, poolChunk(strings).length);
            body.write(namespaceChunk(true), 0, namespaceChunk(true).length);
            body.write(elementChunk(S_MANIFEST, new int[][]{
                    attr(-1, S_PACKAGE, strVal(S_PKG_VALUE)),
                    attr(S_ANDROID_URI, S_VERSION_CODE, intVal(7)),
                    attr(S_ANDROID_URI, S_VERSION_NAME, strVal(S_VNAME_VALUE)),
            }), 0, elementChunk(S_MANIFEST, new int[][]{
                    attr(-1, S_PACKAGE, strVal(S_PKG_VALUE)),
                    attr(S_ANDROID_URI, S_VERSION_CODE, intVal(7)),
                    attr(S_ANDROID_URI, S_VERSION_NAME, strVal(S_VNAME_VALUE)),
            }).length);
            body.write(elementChunk(S_USES_SDK, new int[][]{
                    attr(S_ANDROID_URI, S_MIN_SDK, intVal(24)),
                    attr(S_ANDROID_URI, S_TARGET_SDK, intVal(34)),
            }), 0, elementChunk(S_USES_SDK, new int[][]{
                    attr(S_ANDROID_URI, S_MIN_SDK, intVal(24)),
                    attr(S_ANDROID_URI, S_TARGET_SDK, intVal(34)),
            }).length);
            body.write(endChunk(S_USES_SDK), 0, endChunk(S_USES_SDK).length);
            body.write(elementChunk(S_APPLICATION, new int[][]{
                    attr(S_ANDROID_URI, S_DEBUGGABLE, boolVal(true)),
            }), 0, elementChunk(S_APPLICATION, new int[][]{
                    attr(S_ANDROID_URI, S_DEBUGGABLE, boolVal(true)),
            }).length);
            body.write(endChunk(S_APPLICATION), 0, endChunk(S_APPLICATION).length);
            body.write(endChunk(S_MANIFEST), 0, endChunk(S_MANIFEST).length);
            body.write(namespaceChunk(false), 0, namespaceChunk(false).length);
            byte[] bodyBytes = body.toByteArray();
            write16(file, 0x0003);
            write16(file, 8);
            write32(file, 8 + bodyBytes.length);
            file.write(bodyBytes);
            return file.toByteArray();
        }

        static int[] attr(int ns, int name, int[] typed) {
            return new int[]{ns, name, typed[0], typed[1], typed[2]};
        }

        static int[] strVal(int poolIndex) {
            return new int[]{poolIndex, 0x03, poolIndex};
        }

        static int[] intVal(int v) {
            return new int[]{-1, 0x10, v};
        }

        static int[] boolVal(boolean v) {
            return new int[]{-1, 0x12, v ? 1 : 0};
        }

        static byte[] poolChunk(String[] strings) throws Exception {
            ByteArrayOutputStream data = new ByteArrayOutputStream();
            int[] offsets = new int[strings.length];
            int pos = 0;
            for (int i = 0; i < strings.length; i++) {
                offsets[i] = pos;
                byte[] chars = strings[i].getBytes(StandardCharsets.UTF_16LE);
                write16(data, chars.length / 2);
                data.write(chars);
                write16(data, 0);
                pos += 2 + chars.length + 2;
            }
            byte[] dataBytes = data.toByteArray();
            int stringsStart = 28 + 4 * strings.length;
            ByteArrayOutputStream chunk = new ByteArrayOutputStream();
            write16(chunk, 0x0001);
            write16(chunk, 28);
            write32(chunk, stringsStart + dataBytes.length);
            write32(chunk, strings.length);
            write32(chunk, 0);
            write32(chunk, 0); // UTF-16
            write32(chunk, stringsStart);
            write32(chunk, 0);
            for (int off : offsets) {
                write32(chunk, off);
            }
            chunk.write(dataBytes);
            return chunk.toByteArray();
        }

        static byte[] namespaceChunk(boolean start) {
            ByteArrayOutputStream c = new ByteArrayOutputStream();
            write16(c, start ? 0x0100 : 0x0101);
            write16(c, 16);
            write32(c, 24);
            write32(c, 0);
            write32(c, 0xFFFFFFFF);
            write32(c, S_ANDROID);
            write32(c, S_ANDROID_URI);
            return c.toByteArray();
        }

        static byte[] elementChunk(int name, int[][] attrs) {
            ByteArrayOutputStream c = new ByteArrayOutputStream();
            write16(c, 0x0102);
            write16(c, 16);
            write32(c, 8 + 8 + 20 + 20 * attrs.length);
            write32(c, 0);
            write32(c, 0xFFFFFFFF);
            write32(c, 0xFFFFFFFF);
            write32(c, name);
            write16(c, 20);
            write16(c, 20);
            write16(c, attrs.length);
            write16(c, 0xFFFF);
            write16(c, 0xFFFF);
            write16(c, 0xFFFF);
            for (int[] a : attrs) {
                write32(c, a[0]); // ns
                write32(c, a[1]); // name
                write32(c, a[2]); // raw
                write16(c, 8); // value size
                c.write(0); // res0
                c.write(a[3]); // type
                write32(c, a[4]); // data
            }
            return c.toByteArray();
        }

        static byte[] endChunk(int name) {
            ByteArrayOutputStream c = new ByteArrayOutputStream();
            write16(c, 0x0103);
            write16(c, 16);
            write32(c, 24);
            write32(c, 0);
            write32(c, 0xFFFFFFFF);
            write32(c, 0xFFFFFFFF);
            write32(c, name);
            return c.toByteArray();
        }

        static void write16(ByteArrayOutputStream out, int v) {
            out.write(v & 0xFF);
            out.write((v >> 8) & 0xFF);
        }

        static void write32(ByteArrayOutputStream out, long v) {
            out.write((int) (v & 0xFF));
            out.write((int) ((v >> 8) & 0xFF));
            out.write((int) ((v >> 16) & 0xFF));
            out.write((int) ((v >> 24) & 0xFF));
        }
    }
}
