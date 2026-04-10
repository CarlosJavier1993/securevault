# 🔐 SecureVault

**Sistema de cifrado e integridad para texto y archivos pequeños**  
Implementación académica de AES-256-CBC + HMAC-SHA256 en Python

---

## 📌 Descripción

SecureVault es una aplicación de línea de comandos que protege información mediante dos mecanismos combinados:

- **Confidencialidad** — cifrado simétrico AES-256 en modo CBC.
- **Integridad** — huella digital HMAC-SHA256 que detecta cualquier alteración.
- **Derivación de clave segura** — PBKDF2-HMAC-SHA256 con salt aleatorio y 200.000 iteraciones.

El proyecto fue desarrollado como trabajo académico para el curso de Seguridad Informática, siguiendo buenas prácticas criptográficas (patrón Encrypt-then-MAC, comparación en tiempo constante, IV aleatorio por operación).

---

## 🏗️ Estructura del repositorio

```
securevault/
│
├── main.py                    # Punto de entrada — interfaz CLI
├── requirements.txt           # Dependencias Python
├── .gitignore
│
├── src/
│   ├── key_manager.py         # Derivación de clave (PBKDF2-HMAC-SHA256)
│   ├── cipher.py              # Cifrado/descifrado (AES-256-CBC)
│   ├── integrity.py           # Huella digital (HMAC-SHA256)
│   └── file_handler.py        # Lectura/escritura de archivos
│
├── tests/
│   └── test_securevault.py    # Suite de 18 pruebas unitarias
│
└── examples/
    └── mensaje_prueba.txt     # Archivo de texto de ejemplo
```

---

## ⚙️ Requisitos

- Python 3.10 o superior
- pip

---

## 🚀 Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/tu_usuario/securevault.git
cd securevault

# 2. (Opcional) Crear entorno virtual
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Instalar dependencias
pip install -r requirements.txt
```

---

## 💻 Uso

### Modo demostración (recomendado para la primera ejecución)

Ejecuta los tres casos de prueba fundamentales de forma automática:

```bash
python main.py demo
```

**Salida esperada:**

```
════════════════════════════════════════════════════════════
  SecureVault — Demostración de funcionalidad
════════════════════════════════════════════════════════════

CASO 1 — Cifrado y descifrado correcto
────────────────────────────────────────────────────────────
  Mensaje original : Este mensaje contiene información confidencial.
  Passphrase       : clave_secreta_academica

  Paquete cifrado  : raBmc1zF+Y1kO7C5jHCk62/b0D1pJIqAmy87RfCWtm5...  [Base64]

  Mensaje descifrado: Este mensaje contiene información confidencial.
  Verificación     : ✅ EXITOSO

CASO 2 — Integridad verificada correctamente
────────────────────────────────────────────────────────────
  El HMAC del paquete coincide con el recalculado.
  Estado: ✅ INTEGRIDAD CONFIRMADA

CASO 3 — Detección de alteración del paquete cifrado
────────────────────────────────────────────────────────────
  Posición alterada : 80
  Carácter original : 'P'
  Carácter falso    : 'A'

  Excepción capturada:
  ⚠️  INTEGRIDAD COMPROMETIDA: el contenido fue alterado o
      la passphrase es incorrecta. No se procederá al descifrado.

  Estado: ✅ ALTERACIÓN DETECTADA CORRECTAMENTE
```

---

### Cifrar un archivo `.txt`

```bash
python main.py cifrar --entrada examples/mensaje_prueba.txt --salida salida/mensaje.enc --clave "mi_passphrase_segura"
```

**Salida esperada:**
```
✅ Archivo cifrado guardado en: 'salida/mensaje.enc'
```

El archivo `.enc` contiene el paquete en Base64 con el siguiente layout interno:

```
┌──────────┬──────────┬──────────────┬──────────────────┐
│  salt    │   IV     │  HMAC-SHA256 │   ciphertext     │
│ 16 bytes │ 16 bytes │   32 bytes   │   N bytes        │
└──────────┴──────────┴──────────────┴──────────────────┘
            Todo codificado en Base64
```

---

### Descifrar un archivo `.enc`

```bash
python main.py descifrar --entrada salida/mensaje.enc --salida salida/mensaje_recuperado.txt --clave "mi_passphrase_segura"

```

**Salida esperada:**
```
✅ Archivo descifrado guardado en: 'salida/mensaje_recuperado.txt'
```

---

### Ejemplo de detección de alteración

Si el archivo `.enc` es modificado (por un atacante o por error), el sistema lo detecta antes de intentar descifrar:

```
❌ Error: ⚠️  INTEGRIDAD COMPROMETIDA: el contenido fue alterado o
   la passphrase es incorrecta. No se procederá al descifrado.
```

---

## 🧪 Ejecutar pruebas unitarias

```bash
python -m pytest tests/ -v
```

**Resultado esperado:**

```
============================= test session starts ==============================
collected 18 items

tests/test_securevault.py::TestCifradoDescifrado::test_cifrado_produce_base64          PASSED
tests/test_securevault.py::TestCifradoDescifrado::test_descifrado_con_clave_incorrecta_falla PASSED
tests/test_securevault.py::TestCifradoDescifrado::test_descifrado_correcto              PASSED
tests/test_securevault.py::TestCifradoDescifrado::test_mensaje_con_caracteres_especiales PASSED
tests/test_securevault.py::TestCifradoDescifrado::test_mensaje_largo                   PASSED
tests/test_securevault.py::TestCifradoDescifrado::test_mismo_mensaje_produce_paquetes_distintos PASSED
tests/test_securevault.py::TestIntegridadHMAC::test_deteccion_de_alteracion_en_ciphertext PASSED
tests/test_securevault.py::TestIntegridadHMAC::test_deteccion_de_alteracion_en_iv      PASSED
tests/test_securevault.py::TestIntegridadHMAC::test_hmac_directo_alterado               PASSED
tests/test_securevault.py::TestIntegridadHMAC::test_hmac_directo_correcto              PASSED
tests/test_securevault.py::TestIntegridadHMAC::test_integridad_correcta_no_lanza_excepcion PASSED
tests/test_securevault.py::TestValidacionEntradas::test_cifrar_passphrase_muy_corta    PASSED
tests/test_securevault.py::TestValidacionEntradas::test_cifrar_passphrase_vacia        PASSED
tests/test_securevault.py::TestValidacionEntradas::test_cifrar_texto_vacio             PASSED
tests/test_securevault.py::TestValidacionEntradas::test_derivar_clave_passphrase_no_string PASSED
tests/test_securevault.py::TestValidacionEntradas::test_descifrar_paquete_malformado   PASSED
tests/test_securevault.py::TestValidacionEntradas::test_descifrar_paquete_muy_corto    PASSED
tests/test_securevault.py::TestValidacionEntradas::test_hmac_con_datos_vacios          PASSED

============================== 18 passed in 1.28s ==============================
```

---

## 🔑 Decisiones de diseño

| Componente | Elección | Justificación |
|---|---|---|
| Cifrado | AES-256-CBC | Estándar NIST, didáctico, con IV aleatorio |
| Integridad | HMAC-SHA256 | Combina hash + clave; protege autenticidad |
| Derivación | PBKDF2 (200k iter) | Resiste ataques de fuerza bruta y diccionario |
| Patrón | Encrypt-then-MAC | El más seguro de los tres patrones posibles |
| Verificación | `hmac.compare_digest` | Resistente a timing attacks |
| Empaquetado | Bytes fijos + Base64 | Simple, sin dependencias extra |

---

## ⚠️ Limitaciones

- Solo procesa texto UTF-8 y archivos `.txt` de hasta 1 MB.
- No incluye gestión de claves (el usuario debe recordar su passphrase).
- No implementa cifrado asimétrico ni infraestructura PKI.
- Diseñado con fines académicos; no reemplaza soluciones de producción como GPG o age.

---

## 📚 Referencias

- NIST. (2001). *FIPS 197: Advanced Encryption Standard (AES)*. https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
- NIST. (2001). *SP 800-38A: Recommendation for Block Cipher Modes of Operation*. https://csrc.nist.gov/publications/detail/sp/800-38a/final
- Krawczyk, H., Bellare, M., & Canetti, R. (1997). *RFC 2104: HMAC: Keyed-Hashing for Message Authentication*. https://www.rfc-editor.org/rfc/rfc2104
- NIST. (2010). *SP 800-132: Recommendation for Password-Based Key Derivation*. https://csrc.nist.gov/publications/detail/sp/800-132/final
- Python Software Foundation. (2024). *hashlib — Secure hashes and message digests*. https://docs.python.org/3/library/hashlib.html
- Python Cryptographic Authority. (2024). *cryptography — Cryptographic recipes and primitives*. https://cryptography.io/en/latest/

---

## 👥 Autores

Desarrollado como proyecto académico para el curso de **Seguridad Informática** por:
* Carlos Javier Ramos Corredor
* Willian Ferney Lozada Garcia

---

## 📄 Licencia

MIT License — libre para uso académico y educativo.
