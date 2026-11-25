package com.nexos.firmador;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Historial de firmados (últimos 100) en un fichero de texto. Java puro.
 */
public final class HistoryLog {

    private static final int MAX_LINES = 100;

    private final File file;

    public HistoryLog(File dir) throws IOException {
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("No se pudo crear " + dir);
        }
        this.file = new File(dir, "history.log");
    }

    /** Añade una línea: fecha | apk | clave | esquemas | entrada→salida bytes | resultado. */
    public synchronized void add(String apkName, String keyAlias, String schemes,
                                 long inBytes, long outBytes, String result) throws IOException {
        String stamp = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(new Date());
        String line = stamp + " | " + clean(apkName) + " | " + clean(keyAlias) + " | " + schemes
                + " | " + inBytes + "→" + outBytes + " | " + clean(result);
        List<String> lines = readAll();
        lines.add(line);
        while (lines.size() > MAX_LINES) {
            lines.remove(0);
        }
        Writer w = new OutputStreamWriter(new FileOutputStream(file, false), StandardCharsets.UTF_8);
        try {
            for (String l : lines) {
                w.write(l);
                w.write('\n');
            }
        } finally {
            w.close();
        }
    }

    /** Últimas {@code n} líneas (la más reciente primero). */
    public synchronized List<String> readLast(int n) throws IOException {
        List<String> lines = readAll();
        List<String> out = new ArrayList<String>();
        for (int i = lines.size() - 1; i >= 0 && out.size() < n; i--) {
            out.add(lines.get(i));
        }
        return out;
    }

    public synchronized void clear() {
        file.delete();
    }

    private List<String> readAll() throws IOException {
        List<String> lines = new ArrayList<String>();
        if (!file.isFile()) {
            return lines;
        }
        BufferedReader r = new BufferedReader(new InputStreamReader(
                new FileInputStream(file), StandardCharsets.UTF_8));
        try {
            String line;
            while ((line = r.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    lines.add(line);
                }
            }
        } finally {
            r.close();
        }
        return lines;
    }

    private static String clean(String s) {
        return s == null ? "-" : s.replace('\n', ' ').replace('|', '/');
    }
}
