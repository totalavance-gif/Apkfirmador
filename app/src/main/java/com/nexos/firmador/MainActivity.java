package com.nexos.firmador;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ContentResolver;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.view.View;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.crypto.SecretKey;

/**
 * Firmador de APK 100% offline: claves propias (RSA/EC, cifradas si se quiere),
 * firma v1/v2/v3, lote, perfiles, inspector e intents para otras apps.
 */
public class MainActivity extends Activity {

    /** Firma automática desde otras apps/Termux (ver README). */
    public static final String ACTION_SIGN = "com.nexos.firmador.SIGN";

    private static final int REQ_PICK_APK = 1;
    private static final int REQ_CREATE_SIGNED = 2;
    private static final int REQ_PICK_KEYSTORE = 3;
    private static final int REQ_EXPORT_KEY = 4;
    private static final int REQ_OPEN_TREE = 5;
    private static final int REQ_CREATE_CER = 6;
    private static final int REQ_CREATE_LOG = 7;

    private static final String PREFS = "firmador";

    private TextView tvInput;
    private Spinner spinnerKeys;
    private TextView tvKeyInfo;
    private TextView tvSecurity;
    private Spinner spinnerProfiles;
    private CheckBox cbV1;
    private CheckBox cbV2;
    private CheckBox cbV3;
    private CheckBox cbAlign;
    private CheckBox cbAlignOnly;
    private CheckBox cbAutoSdk;
    private EditText etMinSdk;
    private EditText etPattern;
    private Button btnSign;
    private ProgressBar progressBar;
    private TextView tvStatus;
    private TextView tvLog;

    private KeyStoreManager keys;
    private ProfileManager profiles;
    private HistoryLog history;
    private SharedPreferences prefs;
    private final List<Uri> inputUris = new ArrayList<Uri>();
    private final List<String> inputNames = new ArrayList<String>();
    private Uri pendingKeystoreUri;
    private String pendingKeystoreName;
    private String pendingExportFormat = ".p12";
    private volatile boolean working;
    private boolean profileApplying;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.activity_main);

        tvInput = findViewById(R.id.tvInput);
        spinnerKeys = findViewById(R.id.spinnerKeys);
        tvKeyInfo = findViewById(R.id.tvKeyInfo);
        tvSecurity = findViewById(R.id.tvSecurity);
        spinnerProfiles = findViewById(R.id.spinnerProfiles);
        cbV1 = findViewById(R.id.cbV1);
        cbV2 = findViewById(R.id.cbV2);
        cbV3 = findViewById(R.id.cbV3);
        cbAlign = findViewById(R.id.cbAlign);
        cbAlignOnly = findViewById(R.id.cbAlignOnly);
        cbAutoSdk = findViewById(R.id.cbAutoSdk);
        etMinSdk = findViewById(R.id.etMinSdk);
        etPattern = findViewById(R.id.etPattern);
        btnSign = findViewById(R.id.btnSign);
        progressBar = findViewById(R.id.progressBar);
        tvStatus = findViewById(R.id.tvStatus);
        tvLog = findViewById(R.id.tvLog);

        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        try {
            keys = new KeyStoreManager(new File(getFilesDir(), "keys"));
            profiles = new ProfileManager(new File(getFilesDir(), "profiles"));
            history = new HistoryLog(new File(getFilesDir(), "history"));
        } catch (Exception e) {
            log("ERROR al abrir datos: " + e.getMessage());
        }

        findViewById(R.id.btnPickApk).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                pickApks();
            }
        });
        findViewById(R.id.btnInspect).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                inspectFirstInput();
            }
        });
        findViewById(R.id.btnCert).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startCertFlow();
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
                pickFile(REQ_PICK_KEYSTORE);
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
        findViewById(R.id.btnSecurity).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showSecurityDialog();
            }
        });
        findViewById(R.id.btnProfileSave).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showSaveProfileDialog();
            }
        });
        findViewById(R.id.btnProfileDel).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                deleteSelectedProfile();
            }
        });
        findViewById(R.id.btnHistory).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showHistoryDialog();
            }
        });
        findViewById(R.id.btnExportLog).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startLogFlow();
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
        spinnerProfiles.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (!profileApplying && position > 0) {
                    applyProfile(parent.getItemAtPosition(position).toString());
                }
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        });
        cbAutoSdk.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                etMinSdk.setEnabled(!isChecked);
            }
        });

        refreshKeyList();
        refreshProfileList();
        restoreLastKey();
        updateSecurityLabel();
        log("Firmador listo. Todo se hace en el teléfono, sin internet.");

        if (hasPin()) {
            showPinUnlock();
        } else {
            afterPinGate(savedInstanceState);
        }
    }

    private void afterPinGate(Bundle savedInstanceState) {
        handleIntent(getIntent());
        if (keys != null && keys.isLocked() && savedInstanceState == null) {
            showMasterUnlock(true);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    // ---------- Intents entrantes ----------

    private void handleIntent(Intent intent) {
        if (intent == null || intent.getAction() == null) {
            return;
        }
        String action = intent.getAction();
        if (Intent.ACTION_VIEW.equals(action) && intent.getData() != null) {
            setSingleInput(intent.getData());
            applyDefaultProfile();
        } else if (Intent.ACTION_SEND.equals(action)) {
            Uri uri = intent.getParcelableExtra(Intent.EXTRA_STREAM);
            if (uri != null) {
                setSingleInput(uri);
                applyDefaultProfile();
            }
        } else if (Intent.ACTION_SEND_MULTIPLE.equals(action)) {
            ArrayList<Uri> uris = intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM);
            if (uris != null && !uris.isEmpty()) {
                setInputs(uris);
                applyDefaultProfile();
            }
        } else if (ACTION_SIGN.equals(action)) {
            runSignIntent(intent);
        }
    }

    // ---------- PIN de apertura ----------

    private boolean hasPin() {
        return prefs.contains("pin_hash");
    }

    private void showPinUnlock() {
        final EditText et = passwordField("PIN");
        new AlertDialog.Builder(this)
                .setTitle("Firmador bloqueado")
                .setView(pad(et))
                .setCancelable(false)
                .setPositiveButton("Abrir", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
                        if (checkPin(et.getText().toString())) {
                            afterPinGate(null);
                        } else {
                            toast("PIN incorrecto");
                            showPinUnlock();
                        }
                    }
                })
                .setNegativeButton("Salir", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
                        finish();
                    }
                })
                .show();
    }

    private boolean checkPin(String pin) {
        try {
            String saltHex = prefs.getString("pin_salt", "");
            String want = prefs.getString("pin_hash", "");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(hexToBytes(saltHex));
            md.update(pin.getBytes("UTF-8"));
            return toHex(md.digest()).equals(want);
        } catch (Exception e) {
            return false;
        }
    }

    private void setPin(String pin) {
        try {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            md.update(pin.getBytes("UTF-8"));
            prefs.edit().putString("pin_salt", toHex(salt))
                    .putString("pin_hash", toHex(md.digest())).apply();
        } catch (Exception e) {
            toast("No se pudo guardar el PIN");
        }
    }

    // ---------- Selección de ficheros ----------

    private void pickApks() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
                | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(i, REQ_PICK_APK);
    }

    private void pickFile(int request) {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        startActivityForResult(i, request);
    }

    private void pickTree(int request) {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
                | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(i, request);
    }

    private void createDocument(int request, String mime, String name) {
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType(mime);
        i.putExtra(Intent.EXTRA_TITLE, name);
        startActivityForResult(i, request);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null) {
            return;
        }
        if (requestCode == REQ_PICK_APK) {
            List<Uri> uris = new ArrayList<Uri>();
            if (data.getData() != null) {
                uris.add(data.getData());
            }
            ClipData clip = data.getClipData();
            if (clip != null) {
                for (int i = 0; i < clip.getItemCount(); i++) {
                    uris.add(clip.getItemAt(i).getUri());
                }
            }
            takePersistable(data);
            setInputs(uris);
        } else if (requestCode == REQ_CREATE_SIGNED && data.getData() != null) {
            takePersistable(data);
            signSingleToOutput(data.getData());
        } else if (requestCode == REQ_PICK_KEYSTORE && data.getData() != null) {
            pendingKeystoreUri = data.getData();
            pendingKeystoreName = displayName(pendingKeystoreUri);
            showImportDialog();
        } else if (requestCode == REQ_EXPORT_KEY && data.getData() != null) {
            showExportDialog(data.getData());
        } else if (requestCode == REQ_OPEN_TREE && data.getData() != null) {
            takePersistable(data);
            signBatchToTree(data.getData());
        } else if (requestCode == REQ_CREATE_CER && data.getData() != null) {
            extractCertTo(data.getData());
        } else if (requestCode == REQ_CREATE_LOG && data.getData() != null) {
            saveLogTo(data.getData());
        }
    }

    private void takePersistable(Intent data) {
        try {
            int flags = data.getFlags()
                    & (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            if (data.getData() != null) {
                getContentResolver().takePersistableUriPermission(data.getData(), flags);
            }
            ClipData clip = data.getClipData();
            if (clip != null) {
                for (int i = 0; i < clip.getItemCount(); i++) {
                    getContentResolver().takePersistableUriPermission(
                            clip.getItemAt(i).getUri(), flags);
                }
            }
        } catch (Exception ignored) {
            // No todos los proveedores lo permiten; se sigue sin persistir.
        }
    }

    private void setSingleInput(Uri uri) {
        List<Uri> uris = new ArrayList<Uri>(1);
        uris.add(uri);
        setInputs(uris);
    }

    private void setInputs(List<Uri> uris) {
        inputUris.clear();
        inputNames.clear();
        for (Uri u : uris) {
            if (u == null) {
                continue;
            }
            inputUris.add(u);
            inputNames.add(displayName(u));
        }
        if (inputUris.isEmpty()) {
            tvInput.setText("Ningún APK elegido");
        } else if (inputUris.size() == 1) {
            tvInput.setText(inputNames.get(0));
            log("Entrada: " + inputNames.get(0));
        } else {
            tvInput.setText(inputUris.size() + " APK en lote");
            log("Lote con " + inputUris.size() + " APK.");
        }
    }

    private String displayName(Uri uri) {
        ContentResolver cr = getContentResolver();
        Cursor c = null;
        try {
            c = cr.query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null);
            if (c != null && c.moveToFirst()) {
                return c.getString(0);
            }
        } catch (Exception ignored) {
        } finally {
            if (c != null) {
                c.close();
            }
        }
        String last = uri.getLastPathSegment();
        return last == null ? uri.toString() : last;
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

    private void selectAlias(String alias) {
        ArrayAdapter<?> adapter = (ArrayAdapter<?>) spinnerKeys.getAdapter();
        for (int i = 0; i < adapter.getCount(); i++) {
            if (alias.equals(adapter.getItem(i))) {
                spinnerKeys.setSelection(i);
                break;
            }
        }
    }

    private void restoreLastKey() {
        String last = prefs.getString("last_key", null);
        if (last != null) {
            selectAlias(last);
        }
    }

    private void showSelectedKeyInfo() {
        String alias = selectedAlias();
        if (alias == null || keys == null) {
            tvKeyInfo.setText("Sin claves. Genera una o importa tu .jks/.p12.");
            return;
        }
        prefs.edit().putString("last_key", alias).apply();
        if (keys.isLocked()) {
            tvKeyInfo.setText("Claves bloqueadas (contraseña maestra).");
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
        if (keys.isLocked()) {
            toast("Desbloquea la maestra primero");
            showMasterUnlock(true);
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

        final Spinner spAlg = new Spinner(this);
        ArrayAdapter<String> algAdapter = new ArrayAdapter<String>(
                this, android.R.layout.simple_spinner_item,
                new String[]{"RSA-2048", "RSA-3072", "RSA-4096", "EC-P256", "EC-P384"});
        algAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spAlg.setAdapter(algAdapter);
        layout.addView(spAlg);

        new AlertDialog.Builder(this)
                .setTitle("Generar clave")
                .setView(layout)
                .setPositiveButton("Generar", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
                        String alias = etAlias.getText().toString().trim();
                        int years;
                        try {
                            years = Integer.parseInt(etYears.getText().toString().trim());
                        } catch (NumberFormatException e) {
                            years = -1;
                        }
                        generateKey(alias, spAlg.getSelectedItem().toString(), years);
                    }
                })
                .setNegativeButton("Cancelar", null)
                .show();
    }

    private void generateKey(final String alias, final String alg, final int years) {
        setWorking(true, "Generando clave…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    String what;
                    if (alg.startsWith("EC-")) {
                        String curve = "EC-P384".equals(alg) ? "secp384r1" : "secp256r1";
                        keys.generateEc(alias, curve, years);
                        what = "EC " + curve;
                    } else {
                        int size = Integer.parseInt(alg.substring(4));
                        keys.generate(alias, size, years);
                        what = "RSA-" + size;
                    }
                    uiLog("Clave '" + alias + "' generada (" + what + ", " + years + " años).");
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

    private void deleteSelectedKey() {
        final String alias = selectedAlias();
        if (alias == null || keys == null || working) {
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Borrar clave")
                .setMessage("¿Borrar '" + alias + "'? Los APK firmados con ella no se podrán actualizar con otra clave.")
                .setPositiveButton("Borrar", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
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
        if (keys.isLocked()) {
            toast("Desbloquea la maestra primero");
            showMasterUnlock(true);
            return;
        }
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);

        TextView tv = new TextView(this);
        tv.setText("Importar desde " + pendingKeystoreName + " (.p12/.pfx/.jks)");
        layout.addView(tv);

        final EditText etStore = passwordField("Contraseña del almacén");
        layout.addView(etStore);
        final EditText etKey = passwordField("Contraseña de la clave (vacío = misma)");
        layout.addView(etKey);
        final EditText etAlias = new EditText(this);
        etAlias.setHint("Alias dentro del almacén (vacío = primero)");
        etAlias.setSingleLine(true);
        layout.addView(etAlias);

        new AlertDialog.Builder(this)
                .setTitle("Importar clave")
                .setView(layout)
                .setPositiveButton("Importar", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
                        importKeystore(etStore.getText().toString(),
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

    // ---------- Exportar clave ----------

    private void startExportFlow() {
        String alias = selectedAlias();
        if (alias == null || keys == null || working) {
            return;
        }
        if (keys.isLocked()) {
            toast("Desbloquea la maestra primero");
            showMasterUnlock(true);
            return;
        }
        createDocument(REQ_EXPORT_KEY, "application/x-pkcs12", alias + ".p12");
    }

    private void showExportDialog(final Uri dest) {
        final String alias = selectedAlias();
        if (alias == null) {
            return;
        }
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);

        final Spinner spFmt = new Spinner(this);
        ArrayAdapter<String> fmtAdapter = new ArrayAdapter<String>(
                this, android.R.layout.simple_spinner_item,
                new String[]{".p12 (recomendado)", ".jks (Android Studio)"});
        fmtAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spFmt.setAdapter(fmtAdapter);
        layout.addView(spFmt);

        final EditText etPass = passwordField("Contraseña (mínimo 4, 6 para .jks)");
        layout.addView(etPass);

        new AlertDialog.Builder(this)
                .setTitle("Exportar '" + alias + "'")
                .setMessage("Guarda este fichero: sin la clave no podrás actualizar tus APK firmados.")
                .setView(layout)
                .setPositiveButton("Exportar", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
                        boolean jks = spFmt.getSelectedItemPosition() == 1;
                        exportKey(alias, dest, etPass.getText().toString(), jks);
                    }
                })
                .setNegativeButton("Cancelar", null)
                .show();
    }

    private void exportKey(final String alias, final Uri dest, final String password,
                           final boolean jks) {
        setWorking(true, "Exportando…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    File tmp = new File(getCacheDir(), jks ? "export.jks" : "export.p12");
                    if (jks) {
                        keys.exportJks(alias, tmp, password);
                    } else {
                        keys.exportPkcs12(alias, tmp, password);
                    }
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

    // ---------- Seguridad: maestra y PIN ----------

    private void updateSecurityLabel() {
        if (keys == null) {
            tvSecurity.setText("Sin protección.");
            return;
        }
        String master = keys.getMaster().isConfigured()
                ? (keys.isLocked() ? "maestra: BLOQUEADA" : "maestra: desbloqueada")
                : "maestra: no";
        String pin = hasPin() ? "PIN: sí" : "PIN: no";
        tvSecurity.setText(master + " · " + pin);
    }

    private void showSecurityDialog() {
        if (keys == null || working) {
            return;
        }
        final List<String> items = new ArrayList<String>();
        boolean hasMaster = keys.getMaster().isConfigured();
        boolean locked = keys.isLocked();
        if (!hasMaster) {
            items.add("Fijar contraseña maestra");
        } else if (locked) {
            items.add("Desbloquear maestra");
        } else {
            items.add("Cambiar contraseña maestra");
            items.add("Quitar contraseña maestra");
            items.add("Bloquear ahora");
        }
        items.add(hasPin() ? "Quitar PIN" : "Fijar PIN");
        new AlertDialog.Builder(this)
                .setTitle("Seguridad")
                .setItems(items.toArray(new String[0]), new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int which) {
                        String item = items.get(which);
                        if (item.startsWith("Fijar contraseña")) {
                            showMasterSetup();
                        } else if (item.startsWith("Desbloquear")) {
                            showMasterUnlock(false);
                        } else if (item.startsWith("Cambiar")) {
                            showMasterChange();
                        } else if (item.startsWith("Quitar contraseña")) {
                            showMasterRemove();
                        } else if (item.startsWith("Bloquear")) {
                            keys.setSessionKey(null);
                            refreshKeyList();
                            updateSecurityLabel();
                            log("Claves bloqueadas.");
                        } else if (item.startsWith("Fijar PIN")) {
                            showPinSetup();
                        } else {
                            prefs.edit().remove("pin_hash").remove("pin_salt").apply();
                            updateSecurityLabel();
                            log("PIN quitado.");
                        }
                    }
                })
                .show();
    }

    private void showMasterSetup() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);
        final EditText et1 = passwordField("Nueva contraseña (mínimo 4)");
        final EditText et2 = passwordField("Repite la contraseña");
        layout.addView(et1);
        layout.addView(et2);
        new AlertDialog.Builder(this)
                .setTitle("Contraseña maestra")
                .setMessage("Cifra las claves guardadas. Si la pierdes, no hay forma de recuperarlas.")
                .setView(layout)
                .setPositiveButton("Fijar", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
                        String a = et1.getText().toString();
                        String b = et2.getText().toString();
                        if (!a.equals(b)) {
                            toast("No coinciden");
                            return;
                        }
                        masterSetup(a);
                    }
                })
                .setNegativeButton("Cancelar", null)
                .show();
    }

    private void masterSetup(final String password) {
        setWorking(true, "Cifrando claves…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    SecretKey session = keys.getMaster().setup(password.toCharArray());
                    keys.setSessionKey(session);
                    final int n = keys.encryptPlaintextKeys();
                    uiLog("Maestra fijada. Claves cifradas: " + n + ".");
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            refreshKeyList();
                            updateSecurityLabel();
                            setWorking(false, "Protección activada.");
                        }
                    });
                } catch (final Exception e) {
                    uiLog("ERROR: " + e.getMessage());
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

    private void showMasterUnlock(boolean cancelable) {
        final EditText et = passwordField("Contraseña maestra");
        AlertDialog.Builder b = new AlertDialog.Builder(this)
                .setTitle("Desbloquear claves")
                .setView(pad(et))
                .setPositiveButton("Abrir", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
                        masterUnlock(et.getText().toString());
                    }
                });
        if (cancelable) {
            b.setNegativeButton("Luego", null);
        } else {
            b.setNegativeButton("Cancelar", null);
        }
        b.show();
    }

    private void masterUnlock(final String password) {
        setWorking(true, "Desbloqueando…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    keys.setSessionKey(keys.getMaster().unlock(password.toCharArray()));
                    uiLog("Claves desbloqueadas.");
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            refreshKeyList();
                            updateSecurityLabel();
                            setWorking(false, "Desbloqueado.");
                        }
                    });
                } catch (final Exception e) {
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            setWorking(false, "Error: " + e.getMessage());
                            toast(String.valueOf(e.getMessage()));
                        }
                    });
                }
            }
        }).start();
    }

    private void showMasterChange() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);
        final EditText etOld = passwordField("Contraseña actual");
        final EditText etNew = passwordField("Nueva contraseña");
        layout.addView(etOld);
        layout.addView(etNew);
        new AlertDialog.Builder(this)
                .setTitle("Cambiar maestra")
                .setView(layout)
                .setPositiveButton("Cambiar", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
                        masterChange(etOld.getText().toString(), etNew.getText().toString());
                    }
                })
                .setNegativeButton("Cancelar", null)
                .show();
    }

    private void masterChange(final String oldPass, final String newPass) {
        setWorking(true, "Cambiando maestra…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    keys.decryptAllKeys();
                    SecretKey session = keys.getMaster().change(
                            oldPass.toCharArray(), newPass.toCharArray());
                    keys.setSessionKey(session);
                    final int n = keys.encryptPlaintextKeys();
                    uiLog("Maestra cambiada. Claves re-cifradas: " + n + ".");
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            updateSecurityLabel();
                            setWorking(false, "Maestra cambiada.");
                        }
                    });
                } catch (final Exception e) {
                    uiLog("ERROR: " + e.getMessage());
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

    private void showMasterRemove() {
        final EditText et = passwordField("Contraseña actual");
        new AlertDialog.Builder(this)
                .setTitle("Quitar maestra")
                .setMessage("Las claves quedarán sin cifrar.")
                .setView(pad(et))
                .setPositiveButton("Quitar", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
                        masterRemove(et.getText().toString());
                    }
                })
                .setNegativeButton("Cancelar", null)
                .show();
    }

    private void masterRemove(final String password) {
        setWorking(true, "Quitando protección…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    keys.decryptAllKeys();
                    keys.getMaster().remove(password.toCharArray());
                    keys.setSessionKey(null);
                    uiLog("Protección quitada.");
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            updateSecurityLabel();
                            setWorking(false, "Sin protección.");
                        }
                    });
                } catch (final Exception e) {
                    uiLog("ERROR: " + e.getMessage());
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

    private void showPinSetup() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);
        final EditText et1 = passwordField("Nuevo PIN (mínimo 4)");
        et1.setInputType(android.text.InputType.TYPE_CLASS_NUMBER
                | android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        final EditText et2 = passwordField("Repite el PIN");
        et2.setInputType(android.text.InputType.TYPE_CLASS_NUMBER
                | android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        layout.addView(et1);
        layout.addView(et2);
        new AlertDialog.Builder(this)
                .setTitle("PIN de apertura")
                .setView(layout)
                .setPositiveButton("Fijar", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
                        String a = et1.getText().toString();
                        if (a.length() < 4 || !a.equals(et2.getText().toString())) {
                            toast("PIN inválido (4+ cifras, iguales)");
                            return;
                        }
                        setPin(a);
                        updateSecurityLabel();
                        log("PIN fijado.");
                    }
                })
                .setNegativeButton("Cancelar", null)
                .show();
    }

    // ---------- Perfiles ----------

    private void refreshProfileList() {
        List<String> names = new ArrayList<String>();
        names.add("(manual)");
        if (profiles != null) {
            try {
                names.addAll(profiles.list());
            } catch (Exception e) {
                log("ERROR perfiles: " + e.getMessage());
            }
        }
        profileApplying = true;
        ArrayAdapter<String> adapter = new ArrayAdapter<String>(
                this, android.R.layout.simple_spinner_item, names);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerProfiles.setAdapter(adapter);
        profileApplying = false;
    }

    private String selectedProfile() {
        Object o = spinnerProfiles.getSelectedItem();
        if (o == null || "(manual)".equals(o.toString())) {
            return null;
        }
        return o.toString();
    }

    private void applyDefaultProfile() {
        if (profiles == null) {
            return;
        }
        try {
            String def = profiles.getDefault();
            if (def != null && profiles.load(def) != null) {
                applyProfile(def);
                log("Perfil '" + def + "' aplicado.");
            }
        } catch (Exception e) {
            log("ERROR perfil: " + e.getMessage());
        }
    }

    private void applyProfile(String name) {
        try {
            ProfileManager.Profile p = profiles.load(name);
            if (p == null) {
                return;
            }
            profileApplying = true;
            selectAlias(p.keyAlias);
            cbV1.setChecked(p.v1);
            cbV2.setChecked(p.v2);
            cbV3.setChecked(p.v3);
            cbAlign.setChecked(p.align);
            cbAutoSdk.setChecked(p.autoSdk);
            etMinSdk.setText(String.valueOf(p.minSdk));
            etMinSdk.setEnabled(!p.autoSdk);
            etPattern.setText(p.pattern);
            ArrayAdapter<?> adapter = (ArrayAdapter<?>) spinnerProfiles.getAdapter();
            for (int i = 0; i < adapter.getCount(); i++) {
                if (name.equals(adapter.getItem(i))) {
                    spinnerProfiles.setSelection(i);
                    break;
                }
            }
            profileApplying = false;
        } catch (Exception e) {
            profileApplying = false;
            toast("No se pudo aplicar el perfil");
        }
    }

    private void showSaveProfileDialog() {
        if (profiles == null || working) {
            return;
        }
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);
        final EditText etName = new EditText(this);
        etName.setHint("Nombre del perfil");
        etName.setSingleLine(true);
        String sel = selectedProfile();
        if (sel != null) {
            etName.setText(sel);
        }
        layout.addView(etName);
        final CheckBox cbDef = new CheckBox(this);
        cbDef.setText("Usar por defecto (intents entrantes)");
        layout.addView(cbDef);
        new AlertDialog.Builder(this)
                .setTitle("Guardar perfil")
                .setMessage("Guarda clave, esquemas y opciones actuales.")
                .setView(layout)
                .setPositiveButton("Guardar", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
                        saveProfile(etName.getText().toString().trim(), cbDef.isChecked());
                    }
                })
                .setNegativeButton("Cancelar", null)
                .show();
    }

    private void saveProfile(String name, boolean asDefault) {
        try {
            ProfileManager.Profile p = new ProfileManager.Profile(name);
            String alias = selectedAlias();
            p.keyAlias = alias == null ? "" : alias;
            p.v1 = cbV1.isChecked();
            p.v2 = cbV2.isChecked();
            p.v3 = cbV3.isChecked();
            p.align = cbAlign.isChecked();
            p.autoSdk = cbAutoSdk.isChecked();
            try {
                p.minSdk = Integer.parseInt(etMinSdk.getText().toString().trim());
            } catch (NumberFormatException e) {
                p.minSdk = 24;
            }
            p.pattern = etPattern.getText().toString();
            profiles.save(p);
            if (asDefault) {
                profiles.setDefault(name);
            }
            refreshProfileList();
            profileApplying = true;
            ArrayAdapter<?> adapter = (ArrayAdapter<?>) spinnerProfiles.getAdapter();
            for (int i = 0; i < adapter.getCount(); i++) {
                if (name.equals(adapter.getItem(i))) {
                    spinnerProfiles.setSelection(i);
                    break;
                }
            }
            profileApplying = false;
            log("Perfil '" + name + "' guardado.");
        } catch (Exception e) {
            toast("Error: " + e.getMessage());
        }
    }

    private void deleteSelectedProfile() {
        final String name = selectedProfile();
        if (name == null || profiles == null || working) {
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Borrar perfil")
                .setMessage("¿Borrar '" + name + "'?")
                .setPositiveButton("Borrar", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
                        try {
                            profiles.delete(name);
                            refreshProfileList();
                            log("Perfil '" + name + "' borrado.");
                        } catch (Exception e) {
                            toast("Error: " + e.getMessage());
                        }
                    }
                })
                .setNegativeButton("Cancelar", null)
                .show();
    }

    // ---------- Inspector y certificado ----------

    private void inspectFirstInput() {
        if (working || inputUris.isEmpty()) {
            if (inputUris.isEmpty()) {
                toast("Elige un APK primero");
            }
            return;
        }
        setWorking(true, "Inspeccionando…");
        final Uri uri = inputUris.get(0);
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    File tmp = new File(getCacheDir(), "inspect.apk");
                    copyUriToFile(uri, tmp);
                    final ApkInspector.Report report = ApkInspector.inspect(tmp);
                    tmp.delete();
                    final String text = report.describe();
                    uiLog(text);
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            setWorking(false, report.hasData() ? "Inspección lista." : "No se pudo leer.");
                            showTextDialog("Inspección", text);
                        }
                    });
                } catch (final Exception e) {
                    uiLog("ERROR al inspeccionar: " + e.getMessage());
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

    private void startCertFlow() {
        if (working || inputUris.isEmpty()) {
            if (inputUris.isEmpty()) {
                toast("Elige un APK firmado primero");
            }
            return;
        }
        String base = inputNames.get(0).replaceAll("(?i)\\.apk$", "");
        createDocument(REQ_CREATE_CER, "application/x-x509-ca-cert", base + ".cer");
    }

    private void extractCertTo(final Uri dest) {
        setWorking(true, "Extrayendo certificado…");
        final Uri uri = inputUris.get(0);
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    File tmp = new File(getCacheDir(), "certsrc.apk");
                    copyUriToFile(uri, tmp);
                    java.security.cert.X509Certificate cert = ApkSignHelper.firstSignerCert(tmp);
                    tmp.delete();
                    if (cert == null) {
                        throw new Exception("El APK no tiene firmantes.");
                    }
                    File out = new File(getCacheDir(), "firmante.cer");
                    OutputStream o = new java.io.FileOutputStream(out);
                    try {
                        o.write(cert.getEncoded());
                    } finally {
                        o.close();
                    }
                    copyFileToUri(out, dest);
                    out.delete();
                    uiLog("Certificado extraído: " + cert.getSubjectX500Principal().getName());
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            setWorking(false, "Certificado extraído.");
                        }
                    });
                } catch (final Exception e) {
                    uiLog("ERROR: " + e.getMessage());
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

    /** Opciones resueltas para un trabajo de firma. */
    private static final class SignOptions {
        String alias;
        boolean v1 = true;
        boolean v2 = true;
        boolean v3 = true;
        boolean align = true;
        boolean alignOnly;
        boolean autoSdk = true;
        int minSdk = 24;
    }

    private SignOptions optionsFromUi() {
        SignOptions o = new SignOptions();
        o.alias = selectedAlias();
        o.v1 = cbV1.isChecked();
        o.v2 = cbV2.isChecked();
        o.v3 = cbV3.isChecked();
        o.align = cbAlign.isChecked();
        o.alignOnly = cbAlignOnly.isChecked();
        o.autoSdk = cbAutoSdk.isChecked();
        try {
            o.minSdk = Integer.parseInt(etMinSdk.getText().toString().trim());
        } catch (NumberFormatException e) {
            o.minSdk = 24;
        }
        o.minSdk = Math.max(1, o.minSdk);
        return o;
    }

    private void startSignFlow() {
        if (working) {
            return;
        }
        if (inputUris.isEmpty()) {
            tvStatus.setText("Elige primero el APK de entrada.");
            return;
        }
        SignOptions o = optionsFromUi();
        if (!o.alignOnly) {
            if (o.alias == null) {
                tvStatus.setText("Genera o importa una clave primero.");
                return;
            }
            if (keys.isLocked()) {
                toast("Desbloquea la maestra primero");
                showMasterUnlock(true);
                return;
            }
            if (!o.v1 && !o.v2 && !o.v3) {
                tvStatus.setText("Activa al menos un esquema de firma (v1/v2/v3).");
                return;
            }
        }
        if (inputUris.size() == 1) {
            String outName = ProfileManager.applyPattern(
                    etPattern.getText().toString(), inputNames.get(0));
            createDocument(REQ_CREATE_SIGNED, "application/vnd.android.package-archive", outName);
        } else {
            toast("Elige la carpeta de salida para el lote");
            pickTree(REQ_OPEN_TREE);
        }
    }

    private void signSingleToOutput(final Uri outputUri) {
        final SignOptions o = optionsFromUi();
        setWorking(true, "Firmando…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    String result = runSignJob(inputUris.get(0), inputNames.get(0), outputUri, o);
                    uiLog(result);
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            setWorking(false, "Terminado. Ver registro.");
                        }
                    });
                } catch (final Exception e) {
                    uiLog("ERROR: " + e.getMessage());
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

    private void signBatchToTree(final Uri treeUri) {
        final SignOptions o = optionsFromUi();
        final List<Uri> uris = new ArrayList<Uri>(inputUris);
        final List<String> names = new ArrayList<String>(inputNames);
        final String pattern = etPattern.getText().toString();
        setWorking(true, "Firmando lote…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                int ok = 0;
                for (int i = 0; i < uris.size(); i++) {
                    final int n = i + 1;
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            tvStatus.setText("Archivo " + n + "/" + uris.size() + "…");
                        }
                    });
                    try {
                        String outName = ProfileManager.applyPattern(pattern, names.get(i));
                        Uri out = DocumentsContract.createDocument(getContentResolver(),
                                treeUri, "application/vnd.android.package-archive", outName);
                        if (out == null) {
                            throw new Exception("No se pudo crear " + outName);
                        }
                        uiLog(runSignJob(uris.get(i), names.get(i), out, o));
                        ok++;
                    } catch (Exception e) {
                        uiLog("ERROR con " + names.get(i) + ": " + e.getMessage());
                    }
                }
                final int done = ok;
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        setWorking(false, "Lote: " + done + "/" + uris.size() + " correctos.");
                    }
                });
            }
        }).start();
    }

    /**
     * Firma (o solo alinea) un APK de entrada a salida. Devuelve el resumen.
     * Llamar siempre en hilo de fondo.
     */
    private String runSignJob(Uri inUri, String inName, Uri outUri, SignOptions o)
            throws Exception {
        File workDir = new File(getCacheDir(), "firmar");
        workDir.mkdirs();
        File input = new File(workDir, "entrada.apk");
        File base = new File(workDir, "base.apk");
        File out = new File(workDir, "salida.apk");
        try {
            copyUriToFile(inUri, input);
            long inBytes = input.length();
            long free = getCacheDir().getFreeSpace();
            if (free < inBytes * 3 + 50 * 1024 * 1024) {
                throw new Exception("Poco espacio en caché (libres " + free / 1048576
                        + " MB para " + inBytes / 1048576 + " MB).");
            }
            int minSdk = o.minSdk;
            if (o.autoSdk && !o.alignOnly) {
                try {
                    AxmlReader.ManifestInfo mi = AxmlReader.parseApk(input);
                    if (mi.minSdk != null) {
                        minSdk = mi.minSdk;
                        uiLog("minSdk detectado: " + minSdk
                                + (mi.targetSdk != null ? " (target " + mi.targetSdk + ")" : ""));
                    }
                } catch (Exception e) {
                    uiLog("minSdk no legible, uso " + minSdk + ".");
                }
            }
            if (!o.alignOnly && !o.v2 && !o.v3) {
                uiLog("AVISO: sin v2 ni v3, Android 11+ rechaza APK con targetSdk 30 o más.");
            }
            final String prefix = "[" + inName + "] ";
            if (o.align) {
                ZipAligner.prepare(input, base, true, new ZipAligner.Logger() {
                    @Override
                    public void log(String s) {
                        uiLog(prefix + s);
                    }
                });
            } else {
                // Sin alinear igual hay que quitar firmas viejas para refirmar limpio.
                ZipAligner.prepare(input, base, false, null);
            }
            String schemes;
            if (o.alignOnly) {
                copyFile(base, out);
                schemes = "align";
            } else {
                KeyStoreManager.SigningKey key = keys.load(o.alias);
                schemes = (o.v1 ? "v1" : "") + (o.v2 ? "+v2" : "") + (o.v3 ? "+v3" : "");
                schemes = schemes.startsWith("+") ? schemes.substring(1) : schemes;
                uiLog(prefix + "Firmando con '" + o.alias + "' (" + schemes
                        + " minSdk=" + minSdk + ")…");
                ApkSignHelper.sign(base, out, key, o.v1, o.v2, o.v3, minSdk, null);
                ApkSignHelper.VerifyReport report = ApkSignHelper.verify(out);
                uiLog(prefix + report.describe());
                if (!report.verified) {
                    throw new Exception("La verificación falló:\n" + report.describe());
                }
            }
            copyFileToUri(out, outUri);
            long outBytes = out.length();
            history.add(inName, o.alignOnly ? "-" : o.alias, schemes, inBytes, outBytes, "OK");
            return prefix + "OK (" + inBytes + " → " + outBytes + " bytes).";
        } finally {
            input.delete();
            base.delete();
            out.delete();
        }
    }

    // ---------- Firma por intent (Termux/otras apps) ----------

    private void runSignIntent(Intent intent) {
        if (hasPin()) {
            toast("Quita el PIN para firma automática");
            finish();
            return;
        }
        if (working) {
            finish();
            return;
        }
        String inStr = intent.getStringExtra("input");
        String outStr = intent.getStringExtra("output");
        if (inStr == null || outStr == null) {
            toast("SIGN necesita extras input y output");
            finish();
            return;
        }
        final Uri inUri;
        final Uri outUri;
        try {
            inUri = Uri.parse(inStr);
            outUri = Uri.parse(outStr);
        } catch (Exception e) {
            toast("URIs inválidas");
            finish();
            return;
        }
        final SignOptions o = new SignOptions();
        String profile = intent.getStringExtra("profile");
        try {
            if (profile != null && profiles.load(profile) != null) {
                ProfileManager.Profile p = profiles.load(profile);
                o.alias = p.keyAlias;
                o.v1 = p.v1;
                o.v2 = p.v2;
                o.v3 = p.v3;
                o.align = p.align;
                o.autoSdk = p.autoSdk;
                o.minSdk = p.minSdk;
            }
        } catch (Exception e) {
            toast("Perfil inválido");
            finish();
            return;
        }
        if (intent.hasExtra("key")) {
            o.alias = intent.getStringExtra("key");
        }
        if (intent.hasExtra("v1")) {
            o.v1 = intent.getBooleanExtra("v1", o.v1);
        }
        if (intent.hasExtra("v2")) {
            o.v2 = intent.getBooleanExtra("v2", o.v2);
        }
        if (intent.hasExtra("v3")) {
            o.v3 = intent.getBooleanExtra("v3", o.v3);
        }
        if (intent.hasExtra("align")) {
            o.align = intent.getBooleanExtra("align", o.align);
        }
        if (intent.hasExtra("minSdk")) {
            o.minSdk = intent.getIntExtra("minSdk", o.minSdk);
            o.autoSdk = false;
        }
        final boolean finishAfter = intent.getBooleanExtra("finish", true);
        if (o.alias == null || keys.isLocked() || (!o.v1 && !o.v2 && !o.v3)) {
            toast("Firma automática no disponible (clave/PIN/maestra)");
            if (finishAfter) {
                finish();
            }
            return;
        }
        setWorking(true, "Firmando por intent…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    final String result = runSignJob(inUri, displayName(inUri), outUri, o);
                    uiLog(result);
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            toast("Firmado OK");
                            if (finishAfter) {
                                finish();
                            } else {
                                setWorking(false, "Firmado por intent.");
                            }
                        }
                    });
                } catch (final Exception e) {
                    uiLog("ERROR intent: " + e.getMessage());
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            toast("Error: " + e.getMessage());
                            if (finishAfter) {
                                finish();
                            } else {
                                setWorking(false, "Error: " + e.getMessage());
                            }
                        }
                    });
                }
            }
        }).start();
    }

    // ---------- Historial ----------

    private void showHistoryDialog() {
        if (history == null) {
            return;
        }
        try {
            List<String> lines = history.readLast(100);
            StringBuilder sb = new StringBuilder();
            if (lines.isEmpty()) {
                sb.append("Sin firmados todavía.");
            }
            for (String l : lines) {
                sb.append(l).append("\n");
            }
            TextView tv = new TextView(this);
            tv.setText(sb.toString());
            tv.setTextSize(12);
            tv.setTypeface(android.graphics.Typeface.MONOSPACE);
            int pad = (int) (16 * getResources().getDisplayMetrics().density);
            tv.setPadding(pad, pad, pad, pad);
            ScrollView scroll = new ScrollView(this);
            scroll.addView(tv);
            new AlertDialog.Builder(this)
                    .setTitle("Historial")
                    .setView(scroll)
                    .setPositiveButton("Cerrar", null)
                    .setNeutralButton("Borrar", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface d, int w) {
                            history.clear();
                            log("Historial borrado.");
                        }
                    })
                    .show();
        } catch (Exception e) {
            toast("No se pudo leer el historial");
        }
    }

    // ---------- Registro ----------

    private void startLogFlow() {
        createDocument(REQ_CREATE_LOG, "text/plain", "firmador-log.txt");
    }

    private void saveLogTo(Uri dest) {
        try {
            OutputStream out = getContentResolver().openOutputStream(dest);
            if (out == null) {
                throw new Exception("No se pudo escribir.");
            }
            try {
                out.write(tvLog.getText().toString().getBytes("UTF-8"));
                out.flush();
            } finally {
                out.close();
            }
            log("Registro guardado.");
        } catch (Exception e) {
            toast("Error: " + e.getMessage());
        }
    }

    private void showTextDialog(String title, String text) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextSize(13);
        tv.setTypeface(android.graphics.Typeface.MONOSPACE);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        tv.setPadding(pad, pad, pad, pad);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(tv);
        new AlertDialog.Builder(this)
                .setTitle(title)
                .setView(scroll)
                .setPositiveButton("Cerrar", null)
                .show();
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

    private void toast(final String s) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, s, Toast.LENGTH_LONG).show();
            }
        });
    }

    private EditText passwordField(String hint) {
        EditText et = new EditText(this);
        et.setHint(hint);
        et.setSingleLine(true);
        et.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        return et;
    }

    private LinearLayout pad(View v) {
        LinearLayout layout = new LinearLayout(this);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);
        layout.addView(v);
        return layout;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format(Locale.US, "%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
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
