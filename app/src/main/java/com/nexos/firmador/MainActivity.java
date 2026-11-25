package com.nexos.firmador;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ContentResolver;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TextView;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Firmador de APK 100% offline: elige un APK, elige (o genera) una clave y firma con
 * esquemas v1/v2/v3. Alinear ZIP y verificación posterior incluidos.
 */
public class MainActivity extends Activity {

    private static final int REQ_PICK_APK = 1;
    private static final int REQ_CREATE_SIGNED = 2;
    private static final int REQ_PICK_KEYSTORE = 3;
    private static final int REQ_EXPORT_P12 = 4;

    private TextView tvInput;
    private Spinner spinnerKeys;
    private TextView tvKeyInfo;
    private CheckBox cbV1;
    private CheckBox cbV2;
    private CheckBox cbV3;
    private CheckBox cbAlign;
    private EditText etMinSdk;
    private Button btnSign;
    private ProgressBar progressBar;
    private TextView tvStatus;
    private TextView tvLog;

    private KeyStoreManager keys;
    private File keysDir;
    private Uri inputUri;
    private String inputName;
    private Uri pendingKeystoreUri;
    private String pendingKeystoreName;
    private volatile boolean working;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tvInput = findViewById(R.id.tvInput);
        spinnerKeys = findViewById(R.id.spinnerKeys);
        tvKeyInfo = findViewById(R.id.tvKeyInfo);
        cbV1 = findViewById(R.id.cbV1);
        cbV2 = findViewById(R.id.cbV2);
        cbV3 = findViewById(R.id.cbV3);
        cbAlign = findViewById(R.id.cbAlign);
        etMinSdk = findViewById(R.id.etMinSdk);
        btnSign = findViewById(R.id.btnSign);
        progressBar = findViewById(R.id.progressBar);
        tvStatus = findViewById(R.id.tvStatus);
        tvLog = findViewById(R.id.tvLog);

        try {
            keysDir = new File(getFilesDir(), "keys");
            keys = new KeyStoreManager(keysDir);
        } catch (Exception e) {
            log("ERROR al abrir las claves: " + e.getMessage());
        }

        findViewById(R.id.btnPickApk).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                pickFile(REQ_PICK_APK, "*/*");
            }
        });
        findViewById(R.id.btnGenKey).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showGenerateDialog();
            }
        });
        findViewById(R.id.btnImportKey).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                pickFile(REQ_PICK_KEYSTORE, "*/*");
            }
        });
        findViewById(R.id.btnDelKey).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                deleteSelectedKey();
            }
        });
        findViewById(R.id.btnExportKey).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startExportFlow();
            }
        });
        btnSign.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startSignFlow();
            }
        });
        spinnerKeys.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                showSelectedKeyInfo();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
                tvKeyInfo.setText("Sin claves.");
            }
        });

        refreshKeyList();
        log("Firmador listo. Todo se hace en el teléfono, sin internet.");
    }

    // ---------- Selección de ficheros ----------

    private void pickFile(int request, String mime) {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType(mime);
        startActivityForResult(i, request);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            return;
        }
        Uri uri = data.getData();
        if (requestCode == REQ_PICK_APK) {
            inputUri = uri;
            inputName = displayName(uri);
            tvInput.setText(inputName);
            log("Entrada: " + inputName);
        } else if (requestCode == REQ_CREATE_SIGNED) {
            signToOutput(uri);
        } else if (requestCode == REQ_PICK_KEYSTORE) {
            pendingKeystoreUri = uri;
            pendingKeystoreName = displayName(uri);
            showImportDialog();
        } else if (requestCode == REQ_EXPORT_P12) {
            showExportDialog(uri);
        }
    }

    private String displayName(Uri uri) {
        ContentResolver cr = getContentResolver();
        Cursor c = cr.query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null);
        try {
            if (c != null && c.moveToFirst()) {
                return c.getString(0);
            }
        } finally {
            if (c != null) {
                c.close();
            }
        }
        return uri.getLastPathSegment();
    }

    // ---------- Claves ----------

    private void refreshKeyList() {
        List<String> aliases = new ArrayList<String>();
        if (keys != null) {
            aliases = keys.listAliases();
        }
        ArrayAdapter<String> adapter = new ArrayAdapter<String>(
                this, android.R.layout.simple_spinner_item, aliases);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerKeys.setAdapter(adapter);
        showSelectedKeyInfo();
    }

    private String selectedAlias() {
        Object o = spinnerKeys.getSelectedItem();
        return o == null ? null : o.toString();
    }

    private void showSelectedKeyInfo() {
        String alias = selectedAlias();
        if (alias == null || keys == null) {
            tvKeyInfo.setText("Sin claves. Genera una o importa tu .jks/.p12.");
            return;
        }
        try {
            KeyStoreManager.KeyInfo info = keys.loadInfo(alias);
            SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
            tvKeyInfo.setText(info.algorithm + "-" + info.keySize
                    + " válida " + fmt.format(info.notBefore) + " → " + fmt.format(info.notAfter)
                    + "\nSHA-256: " + info.fingerprintSha256);
        } catch (Exception e) {
            tvKeyInfo.setText("No se pudo leer la clave: " + e.getMessage());
        }
    }

    private void showGenerateDialog() {
        if (keys == null || working) {
            return;
        }
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);

        final EditText etAlias = new EditText(this);
        etAlias.setHint("Nombre (ej. clave1)");
        etAlias.setSingleLine(true);
        layout.addView(etAlias);

        final EditText etYears = new EditText(this);
        etYears.setHint("Validez en años (ej. 25)");
        etYears.setText("25");
        etYears.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        layout.addView(etYears);

        final Spinner spSize = new Spinner(this);
        ArrayAdapter<Integer> sizeAdapter = new ArrayAdapter<Integer>(
                this, android.R.layout.simple_spinner_item,
                new Integer[]{2048, 3072, 4096});
        sizeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spSize.setAdapter(sizeAdapter);
        layout.addView(spSize);

        new AlertDialog.Builder(this)
                .setTitle("Generar clave")
                .setView(layout)
                .setPositiveButton("Generar", new android.content.DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(android.content.DialogInterface d, int w) {
                        String alias = etAlias.getText().toString().trim();
                        int years;
                        try {
                            years = Integer.parseInt(etYears.getText().toString().trim());
                        } catch (NumberFormatException e) {
                            years = -1;
                        }
                        int size = (Integer) spSize.getSelectedItem();
                        generateKey(alias, size, years);
                    }
                })
                .setNegativeButton("Cancelar", null)
                .show();
    }

    private void generateKey(final String alias, final int size, final int years) {
        setWorking(true, "Generando clave…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    keys.generate(alias, size, years);
                    uiLog("Clave '" + alias + "' generada (RSA-" + size + ", " + years + " años).");
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            refreshKeyList();
                            selectAlias(alias);
                            setWorking(false, "Clave generada.");
                        }
                    });
                } catch (final Exception e) {
                    uiLog("ERROR al generar: " + e.getMessage());
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            setWorking(false, "Error: " + e.getMessage());
                        }
                    });
                }
            }
        }).start();
    }

    private void selectAlias(String alias) {
        ArrayAdapter<?> adapter = (ArrayAdapter<?>) spinnerKeys.getAdapter();
        for (int i = 0; i < adapter.getCount(); i++) {
            if (alias.equals(adapter.getItem(i))) {
                spinnerKeys.setSelection(i);
                break;
            }
        }
    }

    private void deleteSelectedKey() {
        final String alias = selectedAlias();
        if (alias == null || keys == null || working) {
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Borrar clave")
                .setMessage("¿Borrar '" + alias + "'? Los APK firmados con ella no se podrán actualizar con otra clave.")
                .setPositiveButton("Borrar", new android.content.DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(android.content.DialogInterface d, int w) {
                        try {
                            keys.delete(alias);
                            log("Clave '" + alias + "' borrada.");
                        } catch (Exception e) {
                            log("ERROR al borrar: " + e.getMessage());
                        }
                        refreshKeyList();
                    }
                })
                .setNegativeButton("Cancelar", null)
                .show();
    }

    private void showImportDialog() {
        if (keys == null || working || pendingKeystoreUri == null) {
            return;
        }
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);

        TextView tv = new TextView(this);
        tv.setText("Importar desde " + pendingKeystoreName + " (.p12/.pfx/.jks)");
        layout.addView(tv);

        final EditText etStore = new EditText(this);
        etStore.setHint("Contraseña del almacén");
        etStore.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        layout.addView(etStore);

        final EditText etKey = new EditText(this);
        etKey.setHint("Contraseña de la clave (vacío = misma)");
        etKey.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        layout.addView(etKey);

        final EditText etAlias = new EditText(this);
        etAlias.setHint("Alias dentro del almacén (vacío = primero)");
        etAlias.setSingleLine(true);
        layout.addView(etAlias);

        new AlertDialog.Builder(this)
                .setTitle("Importar clave")
                .setView(layout)
                .setPositiveButton("Importar", new android.content.DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(android.content.DialogInterface d, int w) {
                        importKeystore(
                                etStore.getText().toString(),
                                etKey.getText().toString(),
                                etAlias.getText().toString().trim());
                    }
                })
                .setNegativeButton("Cancelar", null)
                .show();
    }

    private void importKeystore(final String storePass, final String keyPass, final String wanted) {
        setWorking(true, "Importando…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    File tmp = new File(getCacheDir(), "import.keystore");
                    copyUriToFile(pendingKeystoreUri, tmp);
                    final String alias = keys.importKeyStore(tmp, storePass, keyPass,
                            wanted.isEmpty() ? null : wanted);
                    tmp.delete();
                    uiLog("Clave importada como '" + alias + "'.");
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            refreshKeyList();
                            selectAlias(alias);
                            setWorking(false, "Clave importada.");
                        }
                    });
                } catch (final Exception e) {
                    uiLog("ERROR al importar: " + e.getMessage());
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            setWorking(false, "Error: " + e.getMessage());
                        }
                    });
                }
            }
        }).start();
    }

    private void startExportFlow() {
        String alias = selectedAlias();
        if (alias == null || keys == null || working) {
            return;
        }
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("application/x-pkcs12");
        i.putExtra(Intent.EXTRA_TITLE, alias + ".p12");
        startActivityForResult(i, REQ_EXPORT_P12);
    }

    private void showExportDialog(final Uri dest) {
        final String alias = selectedAlias();
        if (alias == null) {
            return;
        }
        final EditText etPass = new EditText(this);
        etPass.setHint("Contraseña del .p12 (mínimo 4)");
        etPass.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        etPass.setPadding(pad, pad, pad, pad);
        new AlertDialog.Builder(this)
                .setTitle("Exportar '" + alias + "'")
                .setMessage("Guarda este .p12: sin la clave no podrás actualizar tus APK firmados.")
                .setView(etPass)
                .setPositiveButton("Exportar", new android.content.DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(android.content.DialogInterface d, int w) {
                        exportKey(alias, dest, etPass.getText().toString());
                    }
                })
                .setNegativeButton("Cancelar", null)
                .show();
    }

    private void exportKey(final String alias, final Uri dest, final String password) {
        setWorking(true, "Exportando…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    File tmp = new File(getCacheDir(), "export.p12");
                    keys.exportPkcs12(alias, tmp, password);
                    copyFileToUri(tmp, dest);
                    tmp.delete();
                    uiLog("Clave '" + alias + "' exportada. Guárdala bien.");
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            setWorking(false, "Clave exportada.");
                        }
                    });
                } catch (final Exception e) {
                    uiLog("ERROR al exportar: " + e.getMessage());
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            setWorking(false, "Error: " + e.getMessage());
                        }
                    });
                }
            }
        }).start();
    }

    // ---------- Firma ----------

    private void startSignFlow() {
        if (working) {
            return;
        }
        if (inputUri == null) {
            tvStatus.setText("Elige primero el APK de entrada.");
            return;
        }
        if (selectedAlias() == null) {
            tvStatus.setText("Genera o importa una clave primero.");
            return;
        }
        if (!cbV1.isChecked() && !cbV2.isChecked() && !cbV3.isChecked()) {
            tvStatus.setText("Activa al menos un esquema de firma (v1/v2/v3).");
            return;
        }
        String outName = inputName == null ? "app-firmado.apk"
                : inputName.replaceAll("(?i)\\.apk$", "") + "-firmado.apk";
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("application/vnd.android.package-archive");
        i.putExtra(Intent.EXTRA_TITLE, outName);
        startActivityForResult(i, REQ_CREATE_SIGNED);
    }

    private void signToOutput(final Uri outputUri) {
        final String alias = selectedAlias();
        final boolean v1 = cbV1.isChecked();
        final boolean v2 = cbV2.isChecked();
        final boolean v3 = cbV3.isChecked();
        final boolean align = cbAlign.isChecked();
        int minSdk;
        try {
            minSdk = Integer.parseInt(etMinSdk.getText().toString().trim());
        } catch (NumberFormatException e) {
            minSdk = 24;
        }
        final int minSdkVersion = Math.max(1, minSdk);
        setWorking(true, "Firmando…");
        log("Firmando con '" + alias + "' (v1=" + v1 + " v2=" + v2 + " v3=" + v3
                + " alinear=" + align + " minSdk=" + minSdkVersion + ")…");
        if (!v2 && !v3) {
            log("AVISO: sin v2 ni v3, Android 11+ rechaza APK con targetSdk 30 o más.");
        }

        new Thread(new Runnable() {
            @Override
            public void run() {
                File workDir = new File(getCacheDir(), "firmar");
                workDir.mkdirs();
                final File aligned = new File(workDir, "alineado.apk");
                final File signed = new File(workDir, "firmado.apk");
                try {
                    KeyStoreManager.SigningKey key = keys.load(alias);
                    final long[] total = new long[1];
                    copyUriToFile(inputUri, aligned);
                    total[0] = aligned.length();
                    uiLog("Entrada copiada (" + total[0] + " bytes).");
                    final File toSign;
                    if (align) {
                        File stripped = new File(workDir, "base.apk");
                        if (!aligned.renameTo(stripped)) {
                            copyFile(aligned, stripped);
                        }
                        ZipAligner.prepare(stripped, aligned, true, new ZipAligner.Logger() {
                            @Override
                            public void log(String s) {
                                uiLog(s);
                            }
                        });
                        toSign = aligned;
                    } else {
                        File stripped = new File(workDir, "base.apk");
                        if (!aligned.renameTo(stripped)) {
                            copyFile(aligned, stripped);
                        }
                        // Sin alinear igual hay que quitar firmas viejas para refirmar limpio.
                        ZipAligner.prepare(stripped, aligned, false, null);
                        toSign = aligned;
                    }
                    ApkSignHelper.sign(toSign, signed, key, v1, v2, v3, minSdkVersion,
                            new ApkSignHelper.Logger() {
                                @Override
                                public void log(String s) {
                                    uiLog(s);
                                }
                            });
                    ApkSignHelper.VerifyReport report = ApkSignHelper.verify(signed);
                    uiLog(report.describe());
                    if (!report.verified) {
                        throw new Exception("La verificación falló:\n" + report.describe());
                    }
                    copyFileToUri(signed, outputUri);
                    uiLog("Guardado (" + signed.length() + " bytes). Listo para instalar.");
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            setWorking(false, "Firmado y verificado correctamente.");
                        }
                    });
                } catch (final Exception e) {
                    uiLog("ERROR al firmar: " + e.getMessage());
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            setWorking(false, "Error: " + e.getMessage());
                        }
                    });
                } finally {
                    aligned.delete();
                    signed.delete();
                    new File(workDir, "base.apk").delete();
                }
            }
        }).start();
    }

    // ---------- Utilidades ----------

    private void setWorking(boolean w, String status) {
        working = w;
        progressBar.setVisibility(w ? View.VISIBLE : View.GONE);
        btnSign.setEnabled(!w);
        tvStatus.setText(status);
    }

    private void log(String s) {
        tvLog.append(s + "\n");
    }

    private void uiLog(final String s) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                log(s);
            }
        });
    }

    private void copyUriToFile(Uri uri, File out) throws Exception {
        InputStream in = getContentResolver().openInputStream(uri);
        if (in == null) {
            throw new Exception("No se pudo abrir " + uri);
        }
        try {
            copyStream(in, new java.io.FileOutputStream(out));
        } finally {
            in.close();
        }
    }

    private void copyFileToUri(File in, Uri uri) throws Exception {
        OutputStream out = getContentResolver().openOutputStream(uri);
        if (out == null) {
            throw new Exception("No se pudo escribir en el destino elegido.");
        }
        try {
            copyStream(new java.io.FileInputStream(in), out);
        } finally {
            out.close();
        }
    }

    private static void copyFile(File in, File out) throws Exception {
        copyStream(new java.io.FileInputStream(in), new java.io.FileOutputStream(out));
    }

    private static void copyStream(InputStream in, OutputStream out) throws Exception {
        byte[] buf = new byte[65536];
        try {
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            out.flush();
        } finally {
            try {
                in.close();
            } catch (Exception ignored) {
            }
            try {
                out.close();
            } catch (Exception ignored) {
            }
        }
    }
}
