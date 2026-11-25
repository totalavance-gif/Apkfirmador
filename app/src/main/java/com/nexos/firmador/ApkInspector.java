package com.nexos.firmador;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Inspecciona un APK sin modificarlo: datos del manifiesto, esquemas de firma
 * y certificados firmantes. Nunca lanza: los fallos quedan en el informe.
 * Java puro (sin Android).
 */
public final class ApkInspector {

    private ApkInspector() {
    }

    /** Informe de inspección. */
    public static final class Report {
        public AxmlReader.ManifestInfo manifest;
        public String manifestError;
        public boolean verified;
        public boolean v1;
        public boolean v2;
        public boolean v3;
        public final List<String> signerSubjects = new ArrayList<String>();
        public final List<String> signerFingerprints = new ArrayList<String>();
        public final List<String> verifyErrors = new ArrayList<String>();

        /** true si al menos se pudo leer el manifiesto o alguna firma. */
        public boolean hasData() {
            return manifest != null || verified || !signerFingerprints.isEmpty();
        }

        /** Resumen en varias líneas para mostrar al usuario. */
        public String describe() {
            StringBuilder sb = new StringBuilder();
            if (manifest != null) {
                sb.append("Paquete: ").append(orUnknown(manifest.packageName)).append('\n');
                sb.append("Versión: ").append(orUnknown(manifest.versionName));
                if (manifest.versionCode != null) {
                    sb.append(" (").append(manifest.versionCode).append(')');
                }
                sb.append('\n');
                sb.append("SDK: mín ").append(orUnknown(manifest.minSdk))
                        .append(" / objetivo ").append(orUnknown(manifest.targetSdk)).append('\n');
                sb.append("Debuggable: ").append(manifest.debuggable == null
                        ? "no" : manifest.debuggable ? "SÍ" : "no").append('\n');
            } else if (manifestError != null) {
                sb.append("Manifiesto: ").append(manifestError).append('\n');
            }
            sb.append(verified ? "Firma VÁLIDA" : "Firma NO válida o ausente");
            sb.append(" [v1=").append(v1 ? "sí" : "no")
                    .append(" v2=").append(v2 ? "sí" : "no")
                    .append(" v3=").append(v3 ? "sí" : "no").append(']');
            for (int i = 0; i < signerFingerprints.size(); i++) {
                sb.append("\nFirmante ").append(i + 1).append(": ")
                        .append(signerSubjects.size() > i ? signerSubjects.get(i) : "?")
                        .append("\n  SHA-256: ").append(signerFingerprints.get(i));
            }
            for (String e : verifyErrors) {
                sb.append('\n').append(" - ").append(e);
            }
            return sb.toString();
        }

        private static String orUnknown(Object o) {
            return o == null ? "?" : o.toString();
        }
    }

    /** Inspecciona un APK. No lanza excepciones. */
    public static Report inspect(File apk) {
        Report report = new Report();
        try {
            report.manifest = AxmlReader.parseApk(apk);
        } catch (Exception e) {
            report.manifestError = e.getMessage();
        }
        try {
            ApkSignHelper.VerifyReport verify = ApkSignHelper.verify(apk);
            report.verified = verify.verified;
            report.v1 = verify.v1;
            report.v2 = verify.v2;
            report.v3 = verify.v3;
            report.verifyErrors.addAll(verify.errors);
            for (X509Certificate cert : signerCerts(apk)) {
                try {
                    report.signerSubjects.add(cert.getSubjectX500Principal().getName());
                    report.signerFingerprints.add(KeyStoreManager.fingerprintSha256(cert));
                } catch (Exception ignored) {
                    // Certificado ilegible: se omite.
                }
            }
        } catch (Exception e) {
            report.verifyErrors.add(String.valueOf(e.getMessage()));
        }
        return report;
    }

    private static List<X509Certificate> signerCerts(File apk) {
        try {
            com.android.apksig.ApkVerifier.Result result =
                    new com.android.apksig.ApkVerifier.Builder(apk).build().verify();
            List<X509Certificate> certs = result.getSignerCertificates();
            return certs == null ? new ArrayList<X509Certificate>() : certs;
        } catch (Exception e) {
            return new ArrayList<X509Certificate>();
        }
    }
}
