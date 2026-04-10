"""
integrity.py
------------
Módulo de verificación de integridad mediante HMAC-SHA256.

HMAC (Hash-based Message Authentication Code) combina una clave secreta
con SHA-256 para producir una "huella digital" que solo quien posea la
clave puede generar o verificar. Esto protege contra:
  - Alteración accidental del ciphertext.
  - Modificación maliciosa (tampering).
  - Ataques de extensión de longitud (length extension attacks).

El patrón utilizado es Encrypt-then-MAC: el HMAC se calcula SOBRE el
ciphertext (no sobre el texto plano), garantizando integridad end-to-end.

Referencia: RFC 2104 — HMAC: Keyed-Hashing for Message Authentication.
"""

import hmac
import hashlib


# ──────────────────────────────────────────────
# Constantes
# ──────────────────────────────────────────────
HMAC_HASH   = "sha256"  # Algoritmo subyacente
HMAC_SIZE   = 32        # SHA-256 produce 32 bytes (256 bits)


def generar_hmac(clave: bytes, datos: bytes) -> bytes:
    """
    Calcula el HMAC-SHA256 de los datos usando la clave dada.

    Debe llamarse con (IV + ciphertext) como `datos` para cubrir
    la totalidad del material cifrado.

    Args:
        clave: Clave derivada de 32 bytes (salida de key_manager.derivar_clave).
        datos: Bytes sobre los cuales calcular el HMAC (iv + ciphertext).

    Returns:
        Tag HMAC de 32 bytes.

    Raises:
        TypeError:  Si los argumentos no son bytes.
        ValueError: Si la clave o los datos están vacíos.
    """
    # ── Validaciones ───────────────────────────────────────────────────────
    if not isinstance(clave, bytes) or not isinstance(datos, bytes):
        raise TypeError("Tanto 'clave' como 'datos' deben ser de tipo bytes.")
    if len(clave) == 0:
        raise ValueError("La clave no puede estar vacía.")
    if len(datos) == 0:
        raise ValueError("Los datos no pueden estar vacíos.")

    # ── Cálculo HMAC ───────────────────────────────────────────────────────
    tag = hmac.new(clave, datos, digestmod=HMAC_HASH).digest()
    return tag


def verificar_hmac(clave: bytes, datos: bytes, tag_recibido: bytes) -> None:
    """
    Verifica que el tag HMAC recibido corresponde a los datos y la clave.

    Usa hmac.compare_digest para comparación en tiempo constante, lo que
    previene ataques de temporización (timing attacks): un atacante no puede
    deducir cuántos bytes coinciden midiendo el tiempo de la comparación.

    Args:
        clave:        Clave derivada de 32 bytes.
        datos:        Bytes que se verifican (iv + ciphertext).
        tag_recibido: Tag HMAC de 32 bytes extraído del paquete cifrado.

    Returns:
        None si la verificación es exitosa.

    Raises:
        ValueError: Si el HMAC no coincide (integridad comprometida).
        TypeError:  Si los argumentos no son bytes.
    """
    # ── Validaciones ───────────────────────────────────────────────────────
    if not isinstance(clave, bytes) or not isinstance(datos, bytes) or not isinstance(tag_recibido, bytes):
        raise TypeError("Todos los argumentos deben ser de tipo bytes.")

    # ── Recálculo y comparación segura ────────────────────────────────────
    tag_calculado = generar_hmac(clave, datos)

    # compare_digest: tiempo constante, resistente a timing attacks
    if not hmac.compare_digest(tag_calculado, tag_recibido):
        raise ValueError(
            "⚠️  INTEGRIDAD COMPROMETIDA: el contenido fue alterado o "
            "la passphrase es incorrecta. No se procederá al descifrado."
        )
