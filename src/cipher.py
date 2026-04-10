"""
cipher.py
---------
Módulo de cifrado y descifrado usando AES-256-CBC.

AES (Advanced Encryption Standard) es el algoritmo de cifrado simétrico
más utilizado en el mundo. Aquí se implementa con:
  - Clave de 256 bits (más segura que 128 bits).
  - Modo CBC (Cipher Block Chaining): cada bloque cifrado depende del anterior,
    lo que hace que bloques idénticos produzcan ciphertext diferente.
  - IV (Initialization Vector) aleatorio: garantiza que el mismo texto cifrado
    dos veces produzca resultados distintos.
  - Padding PKCS7: rellena el último bloque hasta completar 16 bytes.

Patrón de seguridad: Encrypt-then-MAC.
  1. Se cifra el texto → ciphertext.
  2. Se calcula HMAC sobre (IV + ciphertext).
  El HMAC se verifica ANTES de descifrar (nunca después).

Referencia: NIST FIPS 197 (AES), NIST SP 800-38A (modos de operación).

Dependencia: `cryptography` (pip install cryptography)
"""

import os
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from key_manager import derivar_clave
from integrity import generar_hmac, verificar_hmac


# ──────────────────────────────────────────────
# Constantes
# ──────────────────────────────────────────────
BLOCK_SIZE  = 128   # AES opera en bloques de 128 bits (16 bytes)
IV_SIZE     = 16    # IV = tamaño de un bloque AES
SALT_SIZE   = 16    # Salt para PBKDF2
HMAC_SIZE   = 32    # SHA-256 produce 32 bytes

# Layout fijo del paquete cifrado:
#   [0  : 16] → salt       (16 bytes)
#   [16 : 32] → iv         (16 bytes)
#   [32 : 64] → hmac_tag   (32 bytes)
#   [64 :   ] → ciphertext (variable)
SALT_START  = 0
SALT_END    = 16
IV_START    = 16
IV_END      = 32
HMAC_START  = 32
HMAC_END    = 64
CT_START    = 64


# ─────────────────────────────────────────────────────────────────────────────
# CIFRADO
# ─────────────────────────────────────────────────────────────────────────────

def cifrar(texto_plano: str, passphrase: str) -> str:
    """
    Cifra un texto plano con AES-256-CBC y protege su integridad con HMAC-SHA256.

    Flujo interno:
        1. Deriva clave de 256 bits con PBKDF2 + salt aleatorio.
        2. Genera IV aleatorio de 16 bytes.
        3. Aplica padding PKCS7 al texto (múltiplo de 16 bytes).
        4. Cifra con AES-256-CBC.
        5. Calcula HMAC-SHA256 sobre (IV + ciphertext).
        6. Empaqueta: salt + iv + hmac + ciphertext → Base64.

    Args:
        texto_plano: Texto UTF-8 a cifrar.
        passphrase:  Contraseña del usuario.

    Returns:
        String en Base64 con el paquete completo (salt+iv+hmac+ciphertext).

    Raises:
        ValueError: Si alguna entrada es inválida.
    """
    # ── Validaciones ───────────────────────────────────────────────────────
    _validar_texto(texto_plano, "texto_plano")
    _validar_passphrase(passphrase)

    # ── Paso 1: Derivar clave ──────────────────────────────────────────────
    clave, salt = derivar_clave(passphrase)

    # ── Paso 2: Generar IV aleatorio ───────────────────────────────────────
    iv = os.urandom(IV_SIZE)

    # ── Paso 3: Padding PKCS7 ─────────────────────────────────────────────
    # AES-CBC requiere que el mensaje sea múltiplo de 16 bytes.
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    datos_con_padding = padder.update(texto_plano.encode("utf-8")) + padder.finalize()

    # ── Paso 4: Cifrar con AES-256-CBC ─────────────────────────────────────
    cifrador = Cipher(
        algorithms.AES(clave),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = cifrador.update(datos_con_padding) + cifrador.finalize()

    # ── Paso 5: HMAC sobre IV + ciphertext ────────────────────────────────
    # Patrón Encrypt-then-MAC: el HMAC cubre el material cifrado completo.
    hmac_tag = generar_hmac(clave, iv + ciphertext)

    # ── Paso 6: Empaquetar y codificar en Base64 ──────────────────────────
    paquete = salt + iv + hmac_tag + ciphertext
    return base64.b64encode(paquete).decode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# DESCIFRADO
# ─────────────────────────────────────────────────────────────────────────────

def descifrar(paquete_b64: str, passphrase: str) -> str:
    """
    Verifica la integridad y descifra un paquete producido por cifrar().

    Flujo interno:
        1. Decodifica Base64 y desempaqueta componentes por posición fija.
        2. Rederiva la clave usando el salt guardado en el paquete.
        3. Verifica HMAC ANTES de descifrar (Encrypt-then-MAC).
        4. Descifra con AES-256-CBC.
        5. Elimina el padding PKCS7.

    Args:
        paquete_b64: String Base64 producido por cifrar().
        passphrase:  La misma contraseña usada al cifrar.

    Returns:
        Texto plano original como str UTF-8.

    Raises:
        ValueError: Si el HMAC no coincide (dato alterado o clave incorrecta).
        ValueError: Si el paquete es demasiado corto o está malformado.
    """
    # ── Validaciones ───────────────────────────────────────────────────────
    _validar_texto(paquete_b64, "paquete_b64")
    _validar_passphrase(passphrase)

    # ── Paso 1: Decodificar Base64 y desempaquetar ────────────────────────
    try:
        paquete = base64.b64decode(paquete_b64.encode("utf-8"))
    except Exception:
        raise ValueError("El paquete no es Base64 válido.")

    min_size = SALT_SIZE + IV_SIZE + HMAC_SIZE + BLOCK_SIZE // 8
    if len(paquete) < min_size:
        raise ValueError(
            f"Paquete demasiado corto ({len(paquete)} bytes). "
            f"Mínimo esperado: {min_size} bytes."
        )

    salt       = paquete[SALT_START : SALT_END]
    iv         = paquete[IV_START   : IV_END]
    hmac_tag   = paquete[HMAC_START : HMAC_END]
    ciphertext = paquete[CT_START   :]

    # ── Paso 2: Rederivación de clave ─────────────────────────────────────
    # Usamos el salt guardado en el paquete para reproducir exactamente
    # la misma clave que se usó al cifrar.
    clave, _ = derivar_clave(passphrase, salt=salt)

    # ── Paso 3: Verificar integridad ANTES de descifrar ───────────────────
    # Si el HMAC no coincide se lanza ValueError y el descifrado NO ocurre.
    # Esto previene padding oracle attacks.
    verificar_hmac(clave, iv + ciphertext, hmac_tag)

    # ── Paso 4: Descifrar con AES-256-CBC ──────────────────────────────────
    descifrador = Cipher(
        algorithms.AES(clave),
        modes.CBC(iv),
        backend=default_backend()
    ).decryptor()
    datos_con_padding = descifrador.update(ciphertext) + descifrador.finalize()

    # ── Paso 5: Eliminar padding PKCS7 ────────────────────────────────────
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    texto_bytes = unpadder.update(datos_con_padding) + unpadder.finalize()

    return texto_bytes.decode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers de validación (privados)
# ─────────────────────────────────────────────────────────────────────────────

def _validar_texto(valor: str, nombre: str) -> None:
    """Valida que un argumento sea str no vacío."""
    if not isinstance(valor, str):
        raise ValueError(f"'{nombre}' debe ser una cadena de texto (str).")
    if not valor.strip():
        raise ValueError(f"'{nombre}' no puede estar vacío.")


def _validar_passphrase(passphrase: str) -> None:
    """Valida que la passphrase sea str y tenga al menos 4 caracteres."""
    if not isinstance(passphrase, str):
        raise ValueError("La passphrase debe ser una cadena de texto (str).")
    if len(passphrase.strip()) < 4:
        raise ValueError("La passphrase debe tener al menos 4 caracteres.")
