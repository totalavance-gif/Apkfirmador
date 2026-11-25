package com.nexos.firmador;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Firma APK con los esquemas v1/v2/v3 y verifica el resultado.
 * Usa la librería apksig (la misma que {@code apksigner} de las build-tools).
 * Java puro (sin Android).
 */
public final class ApkSignHelper {

    /** Registro de progreso. */
    public interface Logger {
        void log(String s);
    }

    private ApkSignHelper() {
    }

    /**
     * Firma {@code inputApk} en {@code outputApk} con la clave dada.
     * Las firmas anteriores se reemplazan (no se conservan otros firmantes).
     */
    public static void sign(File inputApk, File outputApk, KeyStoreManager.SigningKey key,
                            boolean v1, boolean v2, boolean v3, int minSdk,
                            Logger logger) throws Exception {
        if (!v1 && !v2 && !v3) {
            throw new IllegalArgumentException("Activa al menos un esquema de firma");
        }
        if (inputApk.getCanonicalPath().equals(outputApk.getCanonicalPath())) {
            throw new IllegalArgumentException("Entrada y salida deben ser ficheros distintos");
        }
        List<ApkSigner.SignerConfig> signers = new ArrayList<ApkSigner.SignerConfig>(1);
        signers.add(new ApkSigner.SignerConfig.Builder(
                "firmador", key.privateKey, key.certificates).build());
        ApkSigner.Builder builder = new ApkSigner.Builder(signers)
                .setInputApk(inputApk)
                .setOutputApk(outputApk)
                .setV1SigningEnabled(v1)
                .setV2SigningEnabled(v2)
                .setV3SigningEnabled(v3)
                .setMinSdkVersion(minSdk)
                .setOtherSignersSignaturesPreserved(false);
        if (logger != null) {
            logger.log("Firmando (v1=" + v1 + " v2=" + v2 + " v3=" + v3 + ")…");
        }
        builder.build().sign();
        if (logger != null) {
            logger.log("Firma escrita: " + outputApk.length() + " bytes.");
        }
    }

    /** Verifica un APK firmado y resume con qué esquemas valida. */
    public static VerifyReport verify(File apk) throws Exception {
        ApkVerifier.Result result = new ApkVerifier.Builder(apk).build().verify();
        boolean v1 = result.isVerifiedUsingV1Scheme();
        boolean v2 = result.isVerifiedUsingV2Scheme();
        boolean v3 = result.isVerifiedUsingV3Scheme();
        List<String> errors = new ArrayList<String>();
        for (ApkVerifier.IssueWithParams issue : result.getErrors()) {
            errors.add(issue.toString());
        }
        return new VerifyReport(result.isVerified(), v1, v2, v3, errors);
    }

    /** Resultado legible de {@link #verify(File)}. */
    public static final class VerifyReport {
        public final boolean verified;
        public final boolean v1;
        public final boolean v2;
        public final boolean v3;
        public final List<String> errors;

        VerifyReport(boolean verified, boolean v1, boolean v2, boolean v3, List<String> errors) {
            this.verified = verified;
            this.v1 = v1;
            this.v2 = v2;
            this.v3 = v3;
            this.errors = errors;
        }

        /** Resumen de una línea (más errores si los hay). */
        public String describe() {
            StringBuilder sb = new StringBuilder();
            sb.append(verified ? "Verificación OK" : "Verificación FALLIDA");
            sb.append(" [v1=").append(v1 ? "sí" : "no")
                    .append(" v2=").append(v2 ? "sí" : "no")
                    .append(" v3=").append(v3 ? "sí" : "no").append(']');
            for (String e : errors) {
                sb.append('\n').append(" - ").append(e);
            }
            return sb.toString();
        }
    }
}
