package com.nexos.firmador;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

/**
 * Perfiles de firma: combinan clave + esquemas + opciones con un nombre,
 * para firmar con un toque o desde otras apps. Se guardan en un fichero
 * properties. Java puro (sin Android).
 */
public final class ProfileManager {

    /** Un perfil de firma. */
    public static final class Profile {
        public String name;
        public String keyAlias = "";
        public boolean v1 = true;
        public boolean v2 = true;
        public boolean v3 = true;
        public boolean align = true;
        public boolean autoSdk = true;
        public int minSdk = 24;
        public String pattern = "{nombre}-firmado.apk";

        public Profile(String name) {
            this.name = name;
        }
    }

    private final File file;

    public ProfileManager(File dir) throws IOException {
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("No se pudo crear " + dir);
        }
        this.file = new File(dir, "profiles.properties");
    }

    public static void validateName(String name) {
        if (name == null || !name.matches("[A-Za-z0-9][A-Za-z0-9 _.-]{0,39}")) {
            throw new IllegalArgumentException("Nombre de perfil inválido: " + name);
        }
    }

    public void save(Profile p) throws IOException {
        validateName(p.name);
        Properties props = loadAll();
        String k = "profile." + p.name + ".";
        props.setProperty(k + "key", p.keyAlias);
        props.setProperty(k + "v1", String.valueOf(p.v1));
        props.setProperty(k + "v2", String.valueOf(p.v2));
        props.setProperty(k + "v3", String.valueOf(p.v3));
        props.setProperty(k + "align", String.valueOf(p.align));
        props.setProperty(k + "autoSdk", String.valueOf(p.autoSdk));
        props.setProperty(k + "minSdk", String.valueOf(p.minSdk));
        props.setProperty(k + "pattern", p.pattern);
        storeAll(props);
    }

    public Profile load(String name) throws IOException {
        validateName(name);
        Properties props = loadAll();
        String k = "profile." + name + ".";
        if (props.getProperty(k + "key") == null) {
            return null;
        }
        Profile p = new Profile(name);
        p.keyAlias = props.getProperty(k + "key", "");
        p.v1 = Boolean.parseBoolean(props.getProperty(k + "v1", "true"));
        p.v2 = Boolean.parseBoolean(props.getProperty(k + "v2", "true"));
        p.v3 = Boolean.parseBoolean(props.getProperty(k + "v3", "true"));
        p.align = Boolean.parseBoolean(props.getProperty(k + "align", "true"));
        p.autoSdk = Boolean.parseBoolean(props.getProperty(k + "autoSdk", "true"));
        try {
            p.minSdk = Integer.parseInt(props.getProperty(k + "minSdk", "24"));
        } catch (NumberFormatException e) {
            p.minSdk = 24;
        }
        p.pattern = props.getProperty(k + "pattern", "{nombre}-firmado.apk");
        return p;
    }

    public void delete(String name) throws IOException {
        validateName(name);
        Properties props = loadAll();
        String k = "profile." + name + ".";
        for (String suffix : new String[]{"key", "v1", "v2", "v3", "align",
                "autoSdk", "minSdk", "pattern"}) {
            props.remove(k + suffix);
        }
        if (name.equals(props.getProperty("default"))) {
            props.remove("default");
        }
        storeAll(props);
    }

    public List<String> list() throws IOException {
        Properties props = loadAll();
        List<String> names = new ArrayList<String>();
        for (String key : props.stringPropertyNames()) {
            if (key.startsWith("profile.") && key.endsWith(".key")) {
                names.add(key.substring("profile.".length(), key.length() - ".key".length()));
            }
        }
        Collections.sort(names);
        return names;
    }

    public void setDefault(String name) throws IOException {
        Properties props = loadAll();
        if (name == null) {
            props.remove("default");
        } else {
            validateName(name);
            props.setProperty("default", name);
        }
        storeAll(props);
    }

    public String getDefault() throws IOException {
        return loadAll().getProperty("default");
    }

    /** Aplica {nombre} al patrón de salida. */
    public static String applyPattern(String pattern, String inputName) {
        String base = inputName == null ? "app" : inputName.replaceAll("(?i)\\.apk$", "");
        String p = pattern == null || pattern.trim().isEmpty() ? "{nombre}-firmado.apk" : pattern;
        String out = p.replace("{nombre}", base).replace("{name}", base);
        if (!out.toLowerCase().endsWith(".apk")) {
            out += ".apk";
        }
        return out.replaceAll("[\\\\/:*?\"<>|]", "_");
    }

    private Properties loadAll() throws IOException {
        Properties props = new Properties();
        if (file.isFile()) {
            InputStream in = new FileInputStream(file);
            try {
                props.load(in);
            } finally {
                in.close();
            }
        }
        return props;
    }

    private void storeAll(Properties props) throws IOException {
        OutputStream out = new FileOutputStream(file);
        try {
            props.store(out, "Firmador APK: perfiles");
        } finally {
            out.close();
        }
    }
}
