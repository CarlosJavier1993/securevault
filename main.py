"""
main.py
-------
SecureVault — Interfaz de línea de comandos (CLI).

Punto de entrada principal del proyecto. Integra todos los módulos:
  - key_manager  → derivación de clave
  - cipher       → cifrado / descifrado AES-256-CBC
  - integrity    → verificación HMAC-SHA256
  - file_handler → lectura / escritura de archivos

Uso:
    python main.py cifrar   --entrada msg.txt   --salida msg.enc  --clave "miClave123"
    python main.py descifrar --entrada msg.enc  --salida msg_dec.txt --clave "miClave123"
    python main.py demo

Modo 'demo' ejecuta los tres casos de prueba sin argumentos adicionales.
"""

import sys
import argparse
from pathlib import Path

# ── Importaciones locales ──────────────────────────────────────────────────
# Añadimos src/ al path para que los módulos se encuentren correctamente.
sys.path.insert(0, str(Path(__file__).parent / "src"))

from cipher       import cifrar, descifrar
from file_handler import leer_archivo_texto, escribir_archivo, leer_paquete_cifrado


# ─────────────────────────────────────────────────────────────────────────────
# Modo DEMO — tres casos de prueba integrados
# ─────────────────────────────────────────────────────────────────────────────

def modo_demo() -> None:
    """
    Ejecuta los tres casos de prueba fundamentales del proyecto:
      1. Cifrado y descifrado correcto.
      2. Verificación de integridad exitosa.
      3. Detección de alteración (hash no coincide).
    """
    separador = "─" * 60

    print(f"\n{'═'*60}")
    print("  SecureVault — Demostración de funcionalidad")
    print(f"{'═'*60}\n")

    passphrase  = "clave_secreta_academica"
    mensaje     = "Este mensaje contiene información confidencial."

    # ─────────────────────────────────────────────────────────────────
    # CASO 1: Cifrado y descifrado correcto
    # ─────────────────────────────────────────────────────────────────
    print("CASO 1 — Cifrado y descifrado correcto")
    print(separador)
    print(f"  Mensaje original : {mensaje}")
    print(f"  Passphrase       : {passphrase}")

    paquete = cifrar(mensaje, passphrase)
    print(f"\n  Paquete cifrado  : {paquete[:60]}...  [Base64 truncado]")

    recuperado = descifrar(paquete, passphrase)
    print(f"\n  Mensaje descifrado: {recuperado}")

    estado = "✅ EXITOSO" if recuperado == mensaje else "❌ FALLIDO"
    print(f"  Verificación     : {estado}\n")

    # ─────────────────────────────────────────────────────────────────
    # CASO 2: Verificación de integridad exitosa
    # ─────────────────────────────────────────────────────────────────
    print("CASO 2 — Integridad verificada correctamente")
    print(separador)

    # Al descifrar con la clave correcta el HMAC coincide automáticamente.
    # Si llegamos aquí sin excepción, la integridad fue verificada.
    try:
        descifrar(paquete, passphrase)
        print("  El HMAC del paquete coincide con el recalculado.")
        print("  Estado: ✅ INTEGRIDAD CONFIRMADA\n")
    except ValueError as e:
        print(f"  Estado: ❌ ERROR INESPERADO — {e}\n")

    # ─────────────────────────────────────────────────────────────────
    # CASO 3: Detección de alteración
    # ─────────────────────────────────────────────────────────────────
    print("CASO 3 — Detección de alteración del paquete cifrado")
    print(separador)

    # Simulamos que un atacante modifica un byte del paquete Base64.
    # Reemplazamos el carácter en la posición 80 por otro diferente.
    paquete_lista = list(paquete)
    pos = 80
    original_char = paquete_lista[pos]
    # Elegimos un carácter distinto al actual (rotación simple)
    paquete_lista[pos] = "A" if original_char != "A" else "B"
    paquete_alterado = "".join(paquete_lista)

    print(f"  Posición alterada : {pos}")
    print(f"  Carácter original : '{original_char}'")
    print(f"  Carácter falso    : '{paquete_lista[pos]}'")

    try:
        descifrar(paquete_alterado, passphrase)
        print("  Estado: ❌ ERROR — No detectó la alteración (no debería llegar aquí)")
    except ValueError as e:
        print(f"\n  Excepción capturada:\n  {e}")
        print("\n  Estado: ✅ ALTERACIÓN DETECTADA CORRECTAMENTE\n")

    print(f"{'═'*60}")
    print("  Demostración completada.\n")


# ─────────────────────────────────────────────────────────────────────────────
# Modo ARCHIVO — cifrar / descifrar desde disco
# ─────────────────────────────────────────────────────────────────────────────

def cmd_cifrar(entrada: str, salida: str, passphrase: str) -> None:
    """Lee un .txt, lo cifra y guarda el paquete como .enc."""
    texto = leer_archivo_texto(entrada)
    paquete = cifrar(texto, passphrase)
    escribir_archivo(salida, paquete)
    print(f"✅ Archivo cifrado guardado en: '{salida}'")


def cmd_descifrar(entrada: str, salida: str, passphrase: str) -> None:
    """Lee un .enc, verifica integridad, descifra y guarda el .txt."""
    paquete = leer_paquete_cifrado(entrada)
    texto   = descifrar(paquete, passphrase)
    escribir_archivo(salida, texto)
    print(f"✅ Archivo descifrado guardado en: '{salida}'")


# ─────────────────────────────────────────────────────────────────────────────
# Parser de argumentos
# ─────────────────────────────────────────────────────────────────────────────

def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securevault",
        description="SecureVault — Cifrado AES-256-CBC + Integridad HMAC-SHA256",
    )
    subparsers = parser.add_subparsers(dest="comando", required=True)

    # Sub-comando: demo
    subparsers.add_parser("demo", help="Ejecuta los 3 casos de prueba integrados.")

    # Sub-comando: cifrar
    p_cifrar = subparsers.add_parser("cifrar", help="Cifra un archivo .txt.")
    p_cifrar.add_argument("--entrada",  required=True, help="Archivo .txt a cifrar.")
    p_cifrar.add_argument("--salida",   required=True, help="Archivo .enc de salida.")
    p_cifrar.add_argument("--clave",    required=True, help="Passphrase de cifrado.")

    # Sub-comando: descifrar
    p_desc = subparsers.add_parser("descifrar", help="Descifra un archivo .enc.")
    p_desc.add_argument("--entrada",  required=True, help="Archivo .enc a descifrar.")
    p_desc.add_argument("--salida",   required=True, help="Archivo .txt de salida.")
    p_desc.add_argument("--clave",    required=True, help="Passphrase de descifrado.")

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# Punto de entrada
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = construir_parser()
    args   = parser.parse_args()

    try:
        if args.comando == "demo":
            modo_demo()
        elif args.comando == "cifrar":
            cmd_cifrar(args.entrada, args.salida, args.clave)
        elif args.comando == "descifrar":
            cmd_descifrar(args.entrada, args.salida, args.clave)
    except (ValueError, FileNotFoundError) as e:
        print(f"\n❌ Error: {e}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
