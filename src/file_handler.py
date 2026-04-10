"""
file_handler.py
---------------
Módulo para lectura y escritura de archivos de texto y paquetes cifrados.

Centraliza el manejo de I/O para que cipher.py permanezca puro (sin efectos
de disco). Admite:
  - Archivos .txt  → lectura como texto UTF-8.
  - Archivos .enc  → lectura/escritura del paquete cifrado en Base64.

Limitación explícita: archivos de hasta 1 MB (suficiente para uso académico).
"""

import os
from pathlib import Path


# ──────────────────────────────────────────────
# Constantes
# ──────────────────────────────────────────────
MAX_FILE_SIZE   = 1 * 1024 * 1024   # 1 MB
ALLOWED_READ    = {".txt"}          # Extensiones permitidas para leer como texto
ALLOWED_WRITE   = {".enc", ".txt"}  # Extensiones permitidas para escribir


def leer_archivo_texto(ruta: str) -> str:
    """
    Lee un archivo de texto y devuelve su contenido como str UTF-8.

    Args:
        ruta: Ruta al archivo .txt.

    Returns:
        Contenido del archivo como cadena de texto.

    Raises:
        FileNotFoundError: Si el archivo no existe.
        ValueError:        Si la extensión no es .txt, el archivo está vacío
                           o supera el tamaño máximo.
        UnicodeDecodeError: Si el archivo no es UTF-8 válido.
    """
    ruta_obj = Path(ruta)

    # ── Validaciones ───────────────────────────────────────────────────────
    if not ruta_obj.exists():
        raise FileNotFoundError(f"Archivo no encontrado: '{ruta}'")
    if ruta_obj.suffix.lower() not in ALLOWED_READ:
        raise ValueError(
            f"Extensión no permitida '{ruta_obj.suffix}'. "
            f"Solo se aceptan: {ALLOWED_READ}"
        )
    tamaño = ruta_obj.stat().st_size
    if tamaño == 0:
        raise ValueError(f"El archivo '{ruta}' está vacío.")
    if tamaño > MAX_FILE_SIZE:
        raise ValueError(
            f"El archivo supera el límite de {MAX_FILE_SIZE // 1024} KB "
            f"({tamaño} bytes)."
        )

    # ── Lectura ────────────────────────────────────────────────────────────
    contenido = ruta_obj.read_text(encoding="utf-8")
    return contenido


def escribir_archivo(ruta: str, contenido: str) -> None:
    """
    Escribe contenido de texto en un archivo.

    Crea los directorios intermedios si no existen.
    No sobreescribe archivos existentes sin advertencia (lanza ValueError).

    Args:
        ruta:      Ruta destino. Extensión debe ser .enc o .txt.
        contenido: Texto a escribir.

    Raises:
        ValueError: Si la extensión no está permitida o el archivo ya existe.
    """
    ruta_obj = Path(ruta)

    # ── Validaciones ───────────────────────────────────────────────────────
    if ruta_obj.suffix.lower() not in ALLOWED_WRITE:
        raise ValueError(
            f"Extensión no permitida '{ruta_obj.suffix}'. "
            f"Solo se permiten: {ALLOWED_WRITE}"
        )
    if ruta_obj.exists():
        raise ValueError(
            f"El archivo '{ruta}' ya existe. "
            "Elimínalo manualmente para evitar sobreescrituras accidentales."
        )

    # ── Escritura ──────────────────────────────────────────────────────────
    ruta_obj.parent.mkdir(parents=True, exist_ok=True)
    ruta_obj.write_text(contenido, encoding="utf-8")


def leer_paquete_cifrado(ruta: str) -> str:
    """
    Lee un archivo .enc y devuelve su contenido (paquete Base64) como str.

    Args:
        ruta: Ruta al archivo .enc generado por SecureVault.

    Returns:
        Contenido del archivo como cadena (Base64).

    Raises:
        FileNotFoundError: Si el archivo no existe.
        ValueError:        Si la extensión no es .enc.
    """
    ruta_obj = Path(ruta)

    if not ruta_obj.exists():
        raise FileNotFoundError(f"Archivo cifrado no encontrado: '{ruta}'")
    if ruta_obj.suffix.lower() != ".enc":
        raise ValueError(f"Se esperaba un archivo .enc, se recibió '{ruta_obj.suffix}'.")

    return ruta_obj.read_text(encoding="utf-8").strip()
