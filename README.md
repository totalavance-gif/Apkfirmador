# Firmador APK

App Android que firma APK en el propio teléfono, sin internet y sin nada externo:
genera sus claves, alinea el ZIP, firma con esquemas v1/v2/v3 y verifica el resultado.

- Paquete: `com.nexos.firmador` · minSdk 24 · Java 17 · AGP 8.5.2
- Sin permisos: usa el selector de archivos del sistema.

## Funciones

- Generar claves RSA (2048/3072/4096) con certificado autofirmado, guardadas en la app.
- Importar claves existentes desde `.p12`/`.pfx`/`.jks`/`.keystore`.
- Exportar claves a `.p12` con contraseña (copia de seguridad).
- Firmar cualquier APK con v1, v2 y v3 (reemplaza firmas anteriores).
- Alinear ZIP tipo `zipalign` (4 bytes general, 16 KB para `.so`).
- Verificación posterior con informe de esquemas.

## Compilar

Igual que la plantilla: no compila en este entorno (build-tools x86_64), compila en CI.

1. Crea el repo en GitHub y sube este proyecto a `main`.
2. Actions construye el debug y publica el artefacto `firmador-debug`.
3. Descarga el APK e instálalo.

```sh
git init -b main
git add -A
git commit -m "Firmador APK inicial"
git remote add origin git@github.com:totalavance-gif/ApkFirmador.git
git push -u origin main
```

## Uso

1. Elige el APK de entrada.
2. Genera una clave (o importa tu `.jks`/`.p12`).
3. Deja v1+v2+v3 activos y pulsa Firmar; elige dónde guardar el `-firmado.apk`.

## Aviso importante

Guarda una copia del `.p12` de cada clave (botón Exportar). Si pierdes la clave,
no podrás publicar actualizaciones de los APK firmados con ella: Android exige la
misma firma para actualizar.

## Código

- `app/src/main/java/com/nexos/firmador/MainActivity.java` — interfaz.
- `app/src/main/java/com/nexos/firmador/KeyStoreManager.java` — claves (BouncyCastle).
- `app/src/main/java/com/nexos/firmador/ApkSignHelper.java` — firma y verificación (apksig).
- `app/src/main/java/com/nexos/firmador/ZipAligner.java` — limpieza de firmas viejas + alineado.

Motor verificado en JVM con un APK real de 12 MB: generar → alinear → firmar v1+v2+v3 →
verificar, más refirmado, importación PKCS#12 y round-trip de exportar/importar.
