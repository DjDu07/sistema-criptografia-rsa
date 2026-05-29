# Sistema Criptográfico RSA y Firmas Digitales

Este repositorio contiene una implementación completa y didáctica de un **Sistema de Criptografía Asimétrica RSA** con soporte para **Firmas Digitales (SHA-256)**, desarrollado en Python con una interfaz gráfica intuitiva.

## Características Técnicas
- **Generación Segura de Claves:** Implementación manual del algoritmo de Euclides extendido para el inverso modular y del test de primalidad probabilístico de Miller-Rabin para manejar primos grandes (512 y 1024 bits).
- **Cifrado y Descifrado Asimétrico:** Operaciones eficientes mediante exponenciación modular para la protección de mensajes de texto expandidos (letras, números y símbolos).
- **Firmas Digitales:** Autenticación e integridad de mensajes mediante hashing criptográfico SHA-256 firmado con la clave privada del emisor.
- **Interfaz Gráfica de Escritorio:** GUI interactiva construida con Tkinter estructurada en módulos independientes para Emisor, Receptor y Firma Digital.

## Requisitos e Instalación
El proyecto utiliza la librería estándar de Python por lo que no requiere dependencias externas complejas. Solo necesitas asegurar el entorno gráfico:
```bash
python main.py
```
