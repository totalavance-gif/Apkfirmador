package com.nexos.firmador;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Crea y guarda claves de firma RSA con certificado autofirmado X.509.
 *
 * <p>Cada clave vive como ficheros privados de la app, sin contraseñas que recordar:
 * {@code <alias>/private.pk8} (clave PKCS#8), {@code <alias>/cert-0.der} y
 * {@code <alias>/meta.properties}. También importa claves existentes desde
 * almacenes PKCS#12 (.p12/.pfx) o JKS (.jks/.keystore).
 *
 * <p>Java puro (sin Android) salvo por el directorio que se le entrega.
 */
public final class KeyStoreManager {

    /** Proveedor BC propio, sin registrarlo globalmente (Android ya trae otro "BC"). */
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    private static final List<String> IMPORT_TYPES = Arrays.asList("PKCS12", "JKS");

    private final File keysDir;
    private final MasterKeyManager master;
    private SecretKey sessionKey;

    public KeyStoreManager(File keysDir) throws IOException {
        this.keysDir = keysDir;
        if (!keysDir.isDirectory() && !keysDir.mkdirs()) {
            throw new IOException("No se pudo crear " + keysDir);
        }
        this.master = new MasterKeyManager(keysDir);
    }

    public MasterKeyManager getMaster() {
        return master;
    }

    /** Clave de sesión tras desbloquear (null = bloqueado o sin maestra). */
    public void setSessionKey(SecretKey key) {
        this.sessionKey = key;
    }

    /** true si hay maestra configurada pero no se ha desbloqueado. */
    public boolean isLocked() {
        return master.isConfigured() && sessionKey == null;
    }

    private void requireUnlocked() {
        if (isLocked()) {
            throw new IllegalStateException("Desbloquea la contraseña maestra primero");
        }
    }

    /** Clave lista para firmar: privada + cadena de certificados. */
    public static final class SigningKey {
        public final PrivateKey privateKey;
        public final List<X509Certificate> certificates;

        SigningKey(PrivateKey privateKey, List<X509Certificate> certificates) {
            this.privateKey = privateKey;
            this.certificates = certificates;
        }
    }

    /** Datos visibles de una clave guardada. */
    public static final class KeyInfo {
        public final String alias;
        public final String algorithm;
        public final int keySize;
        public final Date notBefore;
        public final Date notAfter;
        public final String fingerprintSha256;

        KeyInfo(String alias, String algorithm, int keySize,
                Date notBefore, Date notAfter, String fingerprintSha256) {
            this.alias = alias;
            this.algorithm = algorithm;
            this.keySize = keySize;
            this.notBefore = notBefore;
            this.notAfter = notAfter;
            this.fingerprintSha256 = fingerprintSha256;
        }
    }

    /** Nombres de clave permitidos: letras, dígitos, guion y subrayado. */
    public static void validateAlias(String alias) {
        if (alias == null || !alias.matches("[A-Za-z0-9][A-Za-z0-9_-]{0,63}")) {
            throw new IllegalArgumentException(
                    "Nombre de clave inválido (usa letras, dígitos, - y _): " + alias);
        }
    }

    /** Genera una clave RSA nueva con certificado autofirmado válido {@code validityYears} años. */
    public void generate(String alias, int keySize, int validityYears) throws Exception {
        if (keySize != 2048 && keySize != 3072 && keySize != 4096) {
            throw new IllegalArgumentException("Tamaño de clave no soportado: " + keySize);
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", PROVIDER);
        kpg.initialize(keySize, new SecureRandom());
        generateInternal(alias, kpg.generateKeyPair(), "SHA256withRSA",
                validityYears, "RSA", keySize);
    }

    /** Genera una clave EC (ECDSA) nueva: curva {@code secp256r1} o {@code secp384r1}. */
    public void generateEc(String alias, String curve, int validityYears) throws Exception {
        if (!"secp256r1".equals(curve) && !"secp384r1".equals(curve)) {
            throw new IllegalArgumentException("Curva no soportada: " + curve);
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", PROVIDER);
        kpg.initialize(new ECGenParameterSpec(curve), new SecureRandom());
        String sigAlg = "secp384r1".equals(curve) ? "SHA384withECDSA" : "SHA256withECDSA";
        int bits = "secp384r1".equals(curve) ? 384 : 256;
        generateInternal(alias, kpg.generateKeyPair(), sigAlg, validityYears, "EC", bits);
    }

    private void generateInternal(String alias, KeyPair pair, String sigAlg,
                                  int validityYears, String algorithm, int keySize) throws Exception {
        requireUnlocked();
        validateAlias(alias);
        if (validityYears < 1 || validityYears > 100) {
            throw new IllegalArgumentException("Validez fuera de rango (1-100 años): " + validityYears);
        }
        File dir = dirFor(alias);
        if (dir.isDirectory()) {
            throw new IllegalArgumentException("Ya existe una clave llamada " + alias);
        }

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 3600_000L);
        Date notAfter = new Date(now + validityYears * 365L * 24L * 3600_000L);
        BigInteger serial = new BigInteger(64, new SecureRandom());
        X500Name dn = new X500Name("CN=" + escapeDn(alias) + ",OU=Firmador APK,O=Nexos");
        SubjectPublicKeyInfo pubKey =
                SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                dn, serial, notBefore, notAfter, dn, pubKey);
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(pair.getPublic()));
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider(PROVIDER).build(pair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(PROVIDER).getCertificate(holder);
        cert.verify(pair.getPublic());

        List<X509Certificate> chain = Collections.singletonList(cert);
        saveKey(alias, pair.getPrivate(), chain, algorithm, keySize);
    }

    /**
     * Importa una clave desde un almacén PKCS#12 o JKS. Si {@code wantedAlias} es null o no es
     * una entrada de clave, usa la primera entrada de clave que encuentre. Devuelve el alias guardado.
     */
    public String importKeyStore(File file, String storePassword, String keyPassword,
                                 String wantedAlias) throws Exception {
        Exception lastError = null;
        for (String type : IMPORT_TYPES) {
            try {
                return importWithType(file, type, storePassword, keyPassword, wantedAlias);
            } catch (Exception e) {
                lastError = e;
            }
        }
        throw new IOException("No se pudo leer el almacén (probé PKCS#12 y JKS): "
                + (lastError == null ? file.getName() : lastError.getMessage()), lastError);
    }

    private String importWithType(File file, String type, String storePassword,
                                  String keyPassword, String wantedAlias) throws Exception {
        KeyStore ks = KeyStore.getInstance(type);
        InputStream in = new FileInputStream(file);
        try {
            ks.load(in, storePassword == null ? null : storePassword.toCharArray());
        } finally {
            in.close();
        }
        String entryAlias = null;
        if (wantedAlias != null && ks.isKeyEntry(wantedAlias)) {
            entryAlias = wantedAlias;
        } else {
            List<String> aliases = Collections.list(ks.aliases());
            for (String a : aliases) {
                if (ks.isKeyEntry(a)) {
                    entryAlias = a;
                    break;
                }
            }
        }
        if (entryAlias == null) {
            throw new IOException("El almacén " + type + " no contiene claves privadas");
        }
        char[] keyPass = (keyPassword == null || keyPassword.isEmpty()
                ? storePassword : keyPassword).toCharArray();
        java.security.Key key = ks.getKey(entryAlias, keyPass);
        if (!(key instanceof PrivateKey)) {
            throw new IOException("La entrada " + entryAlias + " no es una clave privada");
        }
        Certificate[] chain = ks.getCertificateChain(entryAlias);
        if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate)) {
            throw new IOException("La entrada " + entryAlias + " no tiene certificado X.509");
        }
        List<X509Certificate> certs = new ArrayList<X509Certificate>(chain.length);
        for (Certificate c : chain) {
            certs.add((X509Certificate) c);
        }
        String alias = uniqueAlias(sanitizeAlias(wantedAlias != null ? wantedAlias : entryAlias));
        String algorithm = ((PrivateKey) key).getAlgorithm();
        saveKey(alias, (PrivateKey) key, certs, algorithm, guessKeySize((PrivateKey) key));
        return alias;
    }

    /** Exporta una clave a un almacén PKCS#12 (.p12) protegido con contraseña. */
    public void exportPkcs12(String alias, File out, String password) throws Exception {
        SigningKey key = load(alias);
        if (password == null || password.length() < 4) {
            throw new IllegalArgumentException("La contraseña debe tener 4 caracteres mínimo");
        }
        char[] pass = password.toCharArray();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(alias, key.privateKey, pass,
                key.certificates.toArray(new Certificate[key.certificates.size()]));
        OutputStream o = new FileOutputStream(out);
        try {
            ks.store(o, pass);
        } finally {
            o.close();
        }
    }

    /** Lista los alias guardados, ordenados. */
    public List<String> listAliases() {
        String[] names = keysDir.list();
        List<String> result = new ArrayList<String>();
        if (names != null) {
            for (String n : names) {
                if (new File(new File(keysDir, n), "private.pk8").isFile()) {
                    result.add(n);
                }
            }
        }
        Collections.sort(result);
        return result;
    }

    public boolean exists(String alias) {
        return new File(dirFor(alias), "private.pk8").isFile();
    }

    /** Carga una clave para firmar (descifra si está protegida). */
    public SigningKey load(String alias) throws Exception {
        requireUnlocked();
        validateAlias(alias);
        File dir = dirFor(alias);
        Properties meta = readMeta(dir);
        byte[] pkcs8 = readFully(new File(dir, "private.pk8"));
        if ("true".equals(meta.getProperty("encrypted"))) {
            if (sessionKey == null) {
                throw new IllegalStateException("Clave cifrada: desbloquea primero");
            }
            pkcs8 = MasterKeyManager.decryptWith(sessionKey, pkcs8);
        }
        byte[] certDer = readFully(new File(dir, "cert-0.der"));
        String algorithm = meta.getProperty("algorithm", "RSA");

        KeyFactory kf = KeyFactory.getInstance(algorithm);
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream cin = new java.io.ByteArrayInputStream(certDer);
        X509Certificate cert;
        try {
            cert = (X509Certificate) cf.generateCertificate(cin);
        } finally {
            cin.close();
        }
        return new SigningKey(privateKey, Collections.singletonList(cert));
    }

    /** Datos visibles de una clave guardada. */
    public KeyInfo loadInfo(String alias) throws Exception {
        SigningKey key = load(alias);
        Properties meta = readMeta(dirFor(alias));
        int keySize = Integer.parseInt(meta.getProperty("keySize", "0"));
        X509Certificate cert = key.certificates.get(0);
        return new KeyInfo(alias, key.privateKey.getAlgorithm(), keySize,
                cert.getNotBefore(), cert.getNotAfter(), fingerprintSha256(cert));
    }

    /** Borra una clave guardada. */
    public void delete(String alias) throws IOException {
        validateAlias(alias);
        File dir = dirFor(alias);
        File[] files = dir.listFiles();
        if (files != null) {
            for (File f : files) {
                if (!f.delete()) {
                    throw new IOException("No se pudo borrar " + f);
                }
            }
        }
        if (dir.isDirectory() && !dir.delete()) {
            throw new IOException("No se pudo borrar " + dir);
        }
    }

    /** Huella SHA-256 del certificado en formato AA:BB:.... */
    public static String fingerprintSha256(X509Certificate cert) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(cert.getEncoded());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < digest.length; i++) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(String.format(Locale.US, "%02X", digest[i]));
        }
        return sb.toString();
    }

    /** Cifra con la sesión actual las claves que aún están en claro. Devuelve cuántas. */
    public int encryptPlaintextKeys() throws Exception {
        requireUnlocked();
        if (sessionKey == null) {
            throw new IllegalStateException("Sin sesión de maestra");
        }
        int done = 0;
        for (String alias : listAliases()) {
            File dir = dirFor(alias);
            Properties meta = readMeta(dir);
            if (!"true".equals(meta.getProperty("encrypted"))) {
                byte[] plain = readFully(new File(dir, "private.pk8"));
                writeFully(new File(dir, "private.pk8"),
                        MasterKeyManager.encryptWith(sessionKey, plain));
                Arrays.fill(plain, (byte) 0);
                meta.setProperty("encrypted", "true");
                writeMeta(dir, meta);
                done++;
            }
        }
        return done;
    }

    /** Deja en claro las claves cifradas (para quitar la maestra). Devuelve cuántas. */
    public int decryptAllKeys() throws Exception {
        if (sessionKey == null) {
            throw new IllegalStateException("Sin sesión de maestra");
        }
        int done = 0;
        for (String alias : listAliases()) {
            File dir = dirFor(alias);
            Properties meta = readMeta(dir);
            if ("true".equals(meta.getProperty("encrypted"))) {
                byte[] enc = readFully(new File(dir, "private.pk8"));
                writeFully(new File(dir, "private.pk8"),
                        MasterKeyManager.decryptWith(sessionKey, enc));
                meta.setProperty("encrypted", "false");
                writeMeta(dir, meta);
                done++;
            }
        }
        return done;
    }

    private void saveKey(String alias, PrivateKey privateKey, List<X509Certificate> chain,
                         String algorithm, int keySize) throws IOException {
        requireUnlocked();
        File dir = dirFor(alias);
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("No se pudo crear " + dir);
        }
        byte[] priv = privateKey.getEncoded();
        boolean encrypted = false;
        if (sessionKey != null) {
            try {
                priv = MasterKeyManager.encryptWith(sessionKey, priv);
                encrypted = true;
            } catch (Exception e) {
                throw new IOException("No se pudo cifrar la clave: " + e.getMessage(), e);
            }
        }
        writeFully(new File(dir, "private.pk8"), priv);
        try {
            writeFully(new File(dir, "cert-0.der"), chain.get(0).getEncoded());
        } catch (Exception e) {
            throw new IOException("No se pudo guardar el certificado: " + e.getMessage(), e);
        }
        Properties meta = new Properties();
        meta.setProperty("alias", alias);
        meta.setProperty("algorithm", algorithm);
        meta.setProperty("keySize", String.valueOf(keySize));
        meta.setProperty("encrypted", String.valueOf(encrypted));
        meta.setProperty("created", String.valueOf(System.currentTimeMillis()));
        writeMeta(dir, meta);
    }

    /** Exporta una clave a un almacén JKS clásico (sirve en Android Studio/apksigner). */
    public void exportJks(String alias, File out, String password) throws Exception {
        SigningKey key = load(alias);
        if (password == null || password.length() < 6) {
            throw new IllegalArgumentException("JKS exige 6 caracteres mínimo");
        }
        char[] pass = password.toCharArray();
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry(alias, key.privateKey, pass,
                key.certificates.toArray(new Certificate[key.certificates.size()]));
        OutputStream o = new FileOutputStream(out);
        try {
            ks.store(o, pass);
        } finally {
            o.close();
        }
    }

    private void writeMeta(File dir, Properties meta) throws IOException {
        OutputStream out = new FileOutputStream(new File(dir, "meta.properties"));
        try {
            meta.store(out, "Firmador APK");
        } finally {
            out.close();
        }
    }

    private Properties readMeta(File dir) throws IOException {
        Properties meta = new Properties();
        File f = new File(dir, "meta.properties");
        if (f.isFile()) {
            InputStream in = new FileInputStream(f);
            try {
                meta.load(in);
            } finally {
                in.close();
            }
        }
        return meta;
    }

    private File dirFor(String alias) {
        return new File(keysDir, alias);
    }

    private String uniqueAlias(String base) {
        if (!exists(base)) {
            return base;
        }
        for (int i = 2; i < 1000; i++) {
            String candidate = base + "-" + i;
            if (!exists(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("No hay nombre libre para " + base);
    }

    static String sanitizeAlias(String raw) {
        String clean = raw.toLowerCase(Locale.US).replaceAll("[^a-z0-9_-]", "_");
        clean = clean.replaceAll("^[^a-z0-9]+", "");
        if (clean.isEmpty()) {
            clean = "clave";
        }
        if (clean.length() > 48) {
            clean = clean.substring(0, 48);
        }
        return clean;
    }

    private static int guessKeySize(PrivateKey key) {
        // Solo informativo: módulo si es RSA, campo si es EC.
        try {
            java.security.interfaces.RSAKey rsa = (java.security.interfaces.RSAKey) key;
            return rsa.getModulus().bitLength();
        } catch (ClassCastException e) {
            // Sigue a EC.
        }
        try {
            java.security.interfaces.ECKey ec = (java.security.interfaces.ECKey) key;
            return ec.getParams().getCurve().getField().getFieldSize();
        } catch (ClassCastException e) {
            return 0;
        }
    }

    private static String escapeDn(String alias) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < alias.length(); i++) {
            char c = alias.charAt(i);
            if (c == ',' || c == '+' || c == '"' || c == '\\'
                    || c == '<' || c == '>' || c == ';') {
                sb.append('\\');
            }
            sb.append(c);
        }
        return sb.toString();
    }

    private static byte[] readFully(File f) throws IOException {
        long len = f.length();
        if (len > 16 * 1024 * 1024) {
            throw new IOException("Fichero demasiado grande: " + f);
        }
        InputStream in = new FileInputStream(f);
        try {
            byte[] buf = new byte[(int) len];
            int off = 0;
            while (off < buf.length) {
                int n = in.read(buf, off, buf.length - off);
                if (n == -1) {
                    break;
                }
                off += n;
            }
            if (off != buf.length) {
                throw new IOException("Lectura incompleta de " + f);
            }
            return buf;
        } finally {
            in.close();
        }
    }

    private static void writeFully(File f, byte[] data) throws IOException {
        OutputStream out = new FileOutputStream(f);
        try {
            out.write(data);
        } finally {
            out.close();
        }
    }
}
