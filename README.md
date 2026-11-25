# Firmador APK

App Android que firma APK en el propio teléfono, sin internet y sin nada externo.
Genera sus claves, alinea el ZIP, firma con esquemas v1/v2/v3 y verifica el resultado.

- Paquete: `com.nexos.firmador` · minSdk 24 · Java 17 · AGP 8.5.2
- Sin permisos: usa el selector de archivos del sistema.

## Funciones

Claves:

- Generar claves RSA (2048/3072/4096) y EC (P-256/P-384) con certificado autofirmado.
- Contraseña maestra opcional: cifra las claves en reposo (AES-256-GCM + PBKDF2).
- PIN de apertura opcional + pantalla segura (sin capturas).
- Importar desde `.p12`/`.pfx`/`.jks`/`.keystore`; exportar a `.p12` o `.jks`
  (el `.jks` sirve en Android Studio y `apksigner`).

Firma:

- Esquemas v1/v2/v3, reemplaza firmas anteriores; minSdk auto-detectado del APK.
- Un APK o lote completo a una carpeta; solo-alinear sin firmar.
- Alineado tipo `zipalign` (4 bytes general, 16 KB para `.so`).
- Verificación posterior con informe de esquemas + comprobación de espacio.
- Inspector: paquete, versión, SDK, esquemas, firmantes y huellas de cualquier APK.
- Extraer el certificado firmante a `.cer`.

Flujos:

- Perfiles (clave + esquemas + opciones) con perfil por defecto.
- Recibe APK desde Compartir / Abrir con (uno o varios).
- Firma automática por intent `com.nexos.firmador.SIGN` (ver abajo).
- Historial de firmados, registro exportable, nombre de salida configurable.

## Compilar

No compila en ARM local (build-tools x86_64): compila en CI.

- Cada push a `main`: tests unitarios + debug, artefacto `firmador-debug`.
- Cada tag `v*`: además publica el APK en Releases (enlace directo).
- Con secretos configurados (abajo), el tag también publica `app-release.apk`
  firmado con tu clave.

## Firmar releases con tu clave

En GitHub → Settings → Secrets and variables → Actions, añade:

- `FIRMADOR_KEYSTORE_B64`: tu `.jks` en base64 de una línea:
  `base64 -w0 nexos-release.jks`
- `FIRMADOR_STORE_PASS`: contraseña del almacén.
- `FIRMADOR_KEY_ALIAS`: alias de la clave.
- `FIRMADOR_KEY_PASS`: contraseña de la clave.

El siguiente tag `v*` publicará el APK firmado con esa clave (permite actualizar
sin desinstalar).

## Firma automática por intent

Acción `com.nexos.firmador.SIGN` (requiere quitar el PIN; funciona mejor sin
maestra o desbloqueada). Extras:

- `input`, `output`: URIs `content://` (el llamante cede lectura/escritura).
- `profile`: nombre del perfil (opcional), `key`: alias (opcional).
- `v1`, `v2`, `v3`, `align`: booleanos (opcional); `minSdk`: entero (opcional).
- `finish`: cerrar al terminar (por defecto true).

Ejemplo con `adb` (las URIs deben existir y ser legibles):

```sh
adb shell am start -a com.nexos.firmador.SIGN \
  --es input "content://..." --es output "content://..." \
  --es profile "release" --ez finish true
```

Desde Termux lo práctico es `termux-share archivo.apk` y elegir Firmador APK.

## Aviso importante

Guarda una copia exportada de cada clave. Si pierdes la clave, no podrás
publicar actualizaciones de los APK firmados con ella: Android exige la misma
firma para actualizar.

## Código

- `MainActivity.java` — interfaz y flujos.
- `KeyStoreManager.java` + `MasterKeyManager.java` — claves y cifrado (BouncyCastle).
- `ApkSignHelper.java` — firma y verificación (apksig).
- `ZipAligner.java` — limpieza de firmas viejas + alineado.
- `AxmlReader.java` + `ApkInspector.java` — manifiesto binario e inspección.
- `ProfileManager.java` + `HistoryLog.java` — perfiles e historial.
- `src/test/.../EngineTest.java` — 12 pruebas unitarias (CI + JVM local).
