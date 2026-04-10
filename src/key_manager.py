"""
key_manager.py
--------------
Módulo responsable de la derivación segura de claves criptográficas.

Usa PBKDF2-HMAC-SHA256 para convertir una passphrase legible por humanos
en una clave de 256 bits apta para AES-256. El salt aleatorio evita que
dos usuarios con la misma passphrase obtengan la misma clave derivada.

Referencia: NIST SP 800-132 (derivación de claves con contraseñas).
"""

import os
import hashlib


# ──────────────────────────────────────────────
# Constantes
# ──────────────────────────────────────────────
SALT_SIZE       = 16        # 128 bits — tamaño del salt aleatorio
KEY_SIZE        = 32        # 256 bits — longitud de clave para AES-256
PBKDF2_ITERS    = 200_000   # Iteraciones recomendadas por NIST (2023)
PBKDF2_HASH     = "sha256"  # Algoritmo hash interno de PBKDF2


def derivar_clave(passphrase: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Deriva una clave criptográfica de 256 bits a partir de una passphrase.

    Si no se provee salt (modo cifrado), se genera uno aleatorio nuevo.
    Si se provee salt (modo descifrado), se reproduce exactamente la misma clave.

    Args:
        passphrase: Contraseña/frase elegida por el usuario.
        salt:       Salt previo (solo en descifrado). None para generar uno nuevo.

    Returns:
        Tupla (clave_bytes, salt_bytes):
            - clave_bytes : 32 bytes listos para AES-256.
            - salt_bytes  : 16 bytes del salt utilizado (guardar junto al cifrado).

    Raises:
        ValueError: Si la passphrase está vacía o no es una cadena de texto.
    """
    # ── Validación de entrada ──────────────────────────────────────────────
    if not isinstance(passphrase, str):
        raise ValueError("La passphrase debe ser una cadena de texto (str).")
    if not passphrase.strip():
        raise ValueError("La passphrase no puede estar vacía.")

    # ── Generación de salt ────────────────────────────────────────────────
    # En modo cifrado generamos un salt fresco; en descifrado reutilizamos el guardado.
    if salt is None:
        salt = os.urandom(SALT_SIZE)

    # ── Derivación PBKDF2 ──────────────────────────────────────────────────
    # hashlib.pbkdf2_hmac es la implementación estándar de Python.
    # Las 200.000 iteraciones hacen que un ataque de fuerza bruta sea muy costoso.
    clave = hashlib.pbkdf2_hmac(
        hash_name   = PBKDF2_HASH,
        password    = passphrase.encode("utf-8"),
        salt        = salt,
        iterations  = PBKDF2_ITERS,
        dklen       = KEY_SIZE,
    )

    return clave, salt
