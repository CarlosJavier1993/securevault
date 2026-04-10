"""
test_securevault.py
-------------------
Suite de pruebas unitarias para SecureVault.

Cubre los tres escenarios fundamentales del proyecto:
  1. Cifrado y descifrado correcto (caso normal).
  2. Detección de alteración del paquete (caso de error).
  3. Validación de entradas inválidas (robustez).

Ejecutar con:
    cd securevault
    python -m pytest tests/ -v
    (o)
    python tests/test_securevault.py
"""

import sys
import base64
import unittest
from pathlib import Path

# Agregar src/ al path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cipher    import cifrar, descifrar
from integrity import generar_hmac, verificar_hmac
from key_manager import derivar_clave


class TestCifradoDescifrado(unittest.TestCase):
    """Pruebas del flujo principal: cifrar → descifrar."""

    def setUp(self):
        self.mensaje    = "Hola, este es un mensaje confidencial de prueba."
        self.passphrase = "passphrase_de_prueba_123"

    def test_descifrado_correcto(self):
        """El texto descifrado debe ser idéntico al original."""
        paquete     = cifrar(self.mensaje, self.passphrase)
        recuperado  = descifrar(paquete, self.passphrase)
        self.assertEqual(recuperado, self.mensaje)

    def test_cifrado_produce_base64(self):
        """El paquete cifrado debe ser Base64 válido."""
        paquete = cifrar(self.mensaje, self.passphrase)
        # No debe lanzar excepción al decodificar
        decodificado = base64.b64decode(paquete.encode("utf-8"))
        self.assertIsInstance(decodificado, bytes)

    def test_mismo_mensaje_produce_paquetes_distintos(self):
        """
        Dos cifrados del mismo mensaje deben producir paquetes distintos
        (gracias al salt e IV aleatorios).
        """
        paquete1 = cifrar(self.mensaje, self.passphrase)
        paquete2 = cifrar(self.mensaje, self.passphrase)
        self.assertNotEqual(paquete1, paquete2)

    def test_descifrado_con_clave_incorrecta_falla(self):
        """Descifrar con una passphrase incorrecta debe lanzar ValueError."""
        paquete = cifrar(self.mensaje, self.passphrase)
        with self.assertRaises(ValueError):
            descifrar(paquete, "clave_totalmente_incorrecta")

    def test_mensaje_con_caracteres_especiales(self):
        """Debe funcionar con caracteres UTF-8 no ASCII."""
        mensaje_utf8 = "¡Hola! Ñoño. 日本語テスト 🔐"
        paquete    = cifrar(mensaje_utf8, self.passphrase)
        recuperado = descifrar(paquete, self.passphrase)
        self.assertEqual(recuperado, mensaje_utf8)

    def test_mensaje_largo(self):
        """Debe funcionar con un mensaje de varios kilobytes."""
        mensaje_largo = "A" * 10_000
        paquete    = cifrar(mensaje_largo, self.passphrase)
        recuperado = descifrar(paquete, self.passphrase)
        self.assertEqual(recuperado, mensaje_largo)


class TestIntegridadHMAC(unittest.TestCase):
    """Pruebas del mecanismo de verificación de integridad."""

    def setUp(self):
        self.mensaje    = "Mensaje para verificar integridad."
        self.passphrase = "clave_integridad"

    def test_integridad_correcta_no_lanza_excepcion(self):
        """Si el paquete no fue alterado, descifrar no debe lanzar excepción."""
        paquete = cifrar(self.mensaje, self.passphrase)
        # No debe lanzar ValueError
        resultado = descifrar(paquete, self.passphrase)
        self.assertEqual(resultado, self.mensaje)

    def test_deteccion_de_alteracion_en_ciphertext(self):
        """
        Modificar un byte del ciphertext debe hacer que el HMAC no coincida
        y provocar un ValueError con el mensaje de integridad comprometida.
        """
        paquete = cifrar(self.mensaje, self.passphrase)

        # Decodificamos, alteramos un byte del ciphertext (posición 70+)
        raw = bytearray(base64.b64decode(paquete.encode("utf-8")))
        raw[70] ^= 0xFF  # XOR con 0xFF invierte todos los bits de ese byte

        paquete_alterado = base64.b64encode(bytes(raw)).decode("utf-8")

        with self.assertRaises(ValueError) as ctx:
            descifrar(paquete_alterado, self.passphrase)

        self.assertIn("INTEGRIDAD COMPROMETIDA", str(ctx.exception))

    def test_deteccion_de_alteracion_en_iv(self):
        """Modificar el IV (bytes 16-32) también debe ser detectado."""
        paquete = cifrar(self.mensaje, self.passphrase)

        raw = bytearray(base64.b64decode(paquete.encode("utf-8")))
        raw[16] ^= 0x01   # Altera el primer byte del IV

        paquete_alterado = base64.b64encode(bytes(raw)).decode("utf-8")

        with self.assertRaises(ValueError):
            descifrar(paquete_alterado, self.passphrase)

    def test_hmac_directo_correcto(self):
        """generar_hmac + verificar_hmac deben funcionar sin error cuando los datos son correctos."""
        clave, _ = derivar_clave("clave_test")
        datos    = b"datos de prueba"
        tag      = generar_hmac(clave, datos)
        # No debe lanzar excepción
        verificar_hmac(clave, datos, tag)

    def test_hmac_directo_alterado(self):
        """verificar_hmac debe lanzar ValueError si los datos cambian."""
        clave, _ = derivar_clave("clave_test")
        datos    = b"datos de prueba"
        tag      = generar_hmac(clave, datos)
        datos_alterados = b"datos de prueba!"  # Un carácter adicional
        with self.assertRaises(ValueError):
            verificar_hmac(clave, datos_alterados, tag)


class TestValidacionEntradas(unittest.TestCase):
    """Pruebas de robustez: entradas inválidas deben lanzar excepciones claras."""

    def test_cifrar_texto_vacio(self):
        with self.assertRaises(ValueError):
            cifrar("", "clave_valida")

    def test_cifrar_passphrase_vacia(self):
        with self.assertRaises(ValueError):
            cifrar("mensaje válido", "")

    def test_cifrar_passphrase_muy_corta(self):
        with self.assertRaises(ValueError):
            cifrar("mensaje válido", "ab")

    def test_descifrar_paquete_malformado(self):
        with self.assertRaises(ValueError):
            descifrar("esto_no_es_base64_valido!!!!", "clave_valida")

    def test_descifrar_paquete_muy_corto(self):
        # Un paquete Base64 válido pero demasiado corto
        corto = base64.b64encode(b"solamente10bytes").decode("utf-8")
        with self.assertRaises(ValueError):
            descifrar(corto, "clave_valida")

    def test_derivar_clave_passphrase_no_string(self):
        with self.assertRaises(ValueError):
            derivar_clave(12345)  # type: ignore

    def test_hmac_con_datos_vacios(self):
        clave, _ = derivar_clave("clave_test")
        with self.assertRaises(ValueError):
            generar_hmac(clave, b"")


if __name__ == "__main__":
    unittest.main(verbosity=2)
