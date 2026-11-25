package com.nexos.firmador;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Contraseña maestra: cifra las claves privadas en reposo (AES-256-GCM con clave
 * derivada por PBKDF2). La clave vive solo en memoria mientras la app está desbloqueada.
 * Java puro (sin Android).
 */
public final class MasterKeyManager {

    private static final int SALT_LEN = 16;
    private static final int NONCE_LEN = 12;
    private static final int GCM_BITS = 128;
    private static final int PBKDF2_ITERS = 120000;
    private static final byte[] MAGIC = "NexosFirmador1".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    private final File keysDir;

    public MasterKeyManager(File keysDir) {
        this.keysDir = keysDir;
    }

    /** true si hay contraseña maestra configurada. */
    public boolean isConfigured() {
        return saltFile().isFile() && checkFile().isFile();
    }

    /** Crea la contraseña maestra. Falla si ya existe (usar {@link #change}). */
    public SecretKey setup(char[] password) throws Exception {
        if (!keysDir.isDirectory() && !keysDir.mkdirs()) {
            throw new IOException("No se pudo crear " + keysDir);
        }
        if (isConfigured()) {
            throw new IllegalStateException("Ya hay contraseña maestra");
        }
        checkPassword(password);
        byte[] salt = random(SALT_LEN);
        writeFully(saltFile(), salt);
        SecretKey key = derive(password, salt);
        writeFully(checkFile(), encryptWith(key, MAGIC));
        return key;
    }

    /** Deriva la clave y comprueba la contraseña. Lanza si es incorrecta. */
    public SecretKey unlock(char[] password) throws Exception {
        if (!isConfigured()) {
            throw new IllegalStateException("No hay contraseña maestra");
        }
        SecretKey key = derive(password, readFully(saltFile()));
        byte[] magic;
        try {
            magic = decryptWith(key, readFully(checkFile()));
        } catch (Exception e) {
            throw new SecurityException("Contraseña incorrecta");
        }
        if (!Arrays.equals(magic, MAGIC)) {
            throw new SecurityException("Contraseña incorrecta");
        }
        return key;
    }

    /**
     * Cambia la contraseña re-cifrando solo el testigo. El llamador debe
     * descifrar las claves con la sesión vieja antes y cifrarlas con la nueva
     * después (ver KeyStoreManager.encryptPlaintextKeys/decryptAllKeys).
     */
    public SecretKey change(char[] oldPassword, char[] newPassword) throws Exception {
        SecretKey oldKey = unlock(oldPassword);
        checkPassword(newPassword);
        byte[] salt = random(SALT_LEN);
        writeFully(saltFile(), salt);
        SecretKey newKey = derive(newPassword, salt);
        writeFully(checkFile(), encryptWith(newKey, MAGIC));
        Arrays.fill(salt, (byte) 0);
        return newKey;
    }

    /** Quita la protección (el llamador debe dejar las claves en claro antes). */
    public void remove(char[] password) throws Exception {
        unlock(password);
        if (!saltFile().delete() || !checkFile().delete()) {
            throw new IOException("No se pudo quitar la protección");
        }
    }

    /** Cifra bytes con la clave de sesión (nonce aleatorio incluido). */
    public static byte[] encryptWith(SecretKey key, byte[] plain) throws Exception {
        byte[] nonce = random(NONCE_LEN);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_BITS, nonce));
        byte[] cipherText = cipher.doFinal(plain);
        byte[] out = new byte[NONCE_LEN + cipherText.length];
        System.arraycopy(nonce, 0, out, 0, NONCE_LEN);
        System.arraycopy(cipherText, 0, out, NONCE_LEN, cipherText.length);
        return out;
    }

    /** Descifra bytes cifrados con {@link #encryptWith}. */
    public static byte[] decryptWith(SecretKey key, byte[] encrypted) throws Exception {
        if (encrypted.length < NONCE_LEN + 1) {
            throw new SecurityException("Datos cifrados inválidos");
        }
        byte[] nonce = Arrays.copyOfRange(encrypted, 0, NONCE_LEN);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_BITS, nonce));
        return cipher.doFinal(encrypted, NONCE_LEN, encrypted.length - NONCE_LEN);
    }

    private static SecretKey derive(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERS, 256);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] raw = factory.generateSecret(spec).getEncoded();
            SecretKey key = new SecretKeySpec(raw, "AES");
            Arrays.fill(raw, (byte) 0);
            return key;
        } finally {
            spec.clearPassword();
        }
    }

    private static void checkPassword(char[] password) {
        if (password == null || password.length < 4) {
            throw new IllegalArgumentException("La contraseña debe tener 4 caracteres mínimo");
        }
    }

    private File saltFile() {
        return new File(keysDir, "master.salt");
    }

    private File checkFile() {
        return new File(keysDir, "master.check");
    }

    private static byte[] random(int len) {
        byte[] b = new byte[len];
        new SecureRandom().nextBytes(b);
        return b;
    }

    static byte[] readFully(File f) throws IOException {
        long len = f.length();
        if (len > 1024 * 1024) {
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

    static void writeFully(File f, byte[] data) throws IOException {
        OutputStream out = new FileOutputStream(f);
        try {
            out.write(data);
        } finally {
            out.close();
        }
    }
}
