"""
Sistema RSA - Versión LIMPIA
Interfaz gráfica completa + RSA real + Sin claves originales
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import os
import random
import math
import hashlib
from datetime import datetime

# Mapeo de caracteres EXPANDIDO
char_to_num = {
    'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4, 'F': 5, 'G': 6, 'H': 7, 'I': 8, 'J': 9,
    'K': 10, 'L': 11, 'M': 12, 'N': 13, 'O': 14, 'P': 15, 'Q': 16, 'R': 17, 'S': 18, 'T': 19,
    'U': 20, 'V': 21, 'W': 22, 'X': 23, 'Y': 24, 'Z': 25,
    ' ': 26, '.': 27, ',': 28, '!': 29, '?': 30, ':': 31, ';': 32, '-': 33, '(': 34, ')': 35,
    '0': 36, '1': 37, '2': 38, '3': 39, '4': 40, '5': 41, '6': 42, '7': 43, '8': 44, '9': 45,
    '@': 46, '#': 47, '$': 48, '%': 49, '&': 50, '*': 51, '+': 52, '=': 53, '[': 54, ']': 55,
    '{': 56, '}': 57, '|': 58, '\\': 59, '/': 60, '<': 61, '>': 62, '^': 63, '_': 64, '~': 65
}

num_to_char = {v: k for k, v in char_to_num.items()}

class RSACryptography:
    """Clase para manejar todas las operaciones criptográficas RSA"""
    
    def __init__(self):
        self.n = None
        self.e = None
        self.d = None
        self.p = None
        self.q = None
        self.phi = None
        self.key_size = 512
        self.ultimo_cifrado = None
    
    def es_primo_miller_rabin(self, n, k=10):
        """Test de primalidad de Miller-Rabin"""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        r = 0
        d = n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
                
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    def generar_primo_grande(self, bits):
        """Genera un número primo aleatorio de 'bits' bits"""
        print(f"🔍 Generando primo de {bits} bits...")
        intentos = 0
        
        while True:
            intentos += 1
            candidato = random.getrandbits(bits)
            candidato |= (1 << bits - 1) | 1
            
            if self.es_primo_miller_rabin(candidato, k=15):
                print(f"✅ Primo encontrado en {intentos} intentos")
                return candidato
            
            if intentos % 100 == 0:
                print(f"⏳ Llevamos {intentos} intentos...")
    
    def algoritmo_euclides_extendido(self, a, b):
        """Algoritmo extendido de Euclides"""
        if a == 0:
            return b, 0, 1
        
        gcd, x1, y1 = self.algoritmo_euclides_extendido(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    
    def calcular_inverso_modular(self, e, phi):
        """Calcula el inverso modular de e módulo phi"""
        gcd, x, _ = self.algoritmo_euclides_extendido(e, phi)
        
        if gcd != 1:
            raise ValueError(f"❌ No existe inverso modular")
        
        d = (x % phi + phi) % phi
        return d
    
    def generar_claves_rsa(self, bits=512):
        """Genera un par de claves RSA matemáticamente correcto"""
        print("🔐 INICIANDO GENERACIÓN DE CLAVES RSA")
        
        self.key_size = bits
        
        print("📍 Paso 1: Generando primer primo...")
        self.p = self.generar_primo_grande(bits // 2)
        
        print("📍 Paso 2: Generando segundo primo...")
        self.q = self.generar_primo_grande(bits // 2)
        
        while self.q == self.p:
            print("⚠️ Los primos son iguales, generando nuevo q...")
            self.q = self.generar_primo_grande(bits // 2)
        
        self.n = self.p * self.q
        print(f"📍 Paso 3: n = p × q = {self.n}")
        
        self.phi = (self.p - 1) * (self.q - 1)
        print(f"📍 Paso 4: φ(n) = {self.phi}")
        
        self.e = 65537
        while math.gcd(self.e, self.phi) != 1:
            self.e += 2
            if self.e >= self.phi:
                self.e = 3
        
        print(f"📍 Paso 5: e = {self.e}")
        
        self.d = self.calcular_inverso_modular(self.e, self.phi)
        print(f"📍 Paso 6: d = {self.d}")
        
        verificacion = (self.e * self.d) % self.phi
        print(f"📍 Verificación: {verificacion}")
        
        if verificacion != 1:
            raise ValueError("❌ Error crítico en generación de claves RSA")
        
        info_claves = {
            'n': self.n, 'e': self.e, 'd': self.d,
            'p': self.p, 'q': self.q, 'phi': self.phi,
            'bits': self.n.bit_length(),
            'timestamp': datetime.now().isoformat()
        }
        
        print("✅ CLAVES RSA GENERADAS EXITOSAMENTE")
        return info_claves
    
    def modular_pow(self, base, exp, mod):
        """Exponenciación modular eficiente"""
        result = 1
        base = base % mod
        while exp > 0:
            if exp % 2 == 1:
                result = (result * base) % mod
            exp = exp // 2
            base = (base * base) % mod
        return result
    
    def encrypt_message(self, message):
        """Cifra un mensaje usando RSA"""
        if not (self.n and self.e):
            raise ValueError("❌ Claves RSA no generadas")
        
        encrypted = []
        ignorados = []
        
        for char in message.upper():
            if char in char_to_num:
                num = char_to_num[char]
                if num < self.n:
                    c = self.modular_pow(num, self.e, self.n)
                    encrypted.append(c)
                else:
                    ignorados.append(char)
            else:
                ignorados.append(char)
        
        # Guardar para exportar
        self.ultimo_cifrado = {
            'mensaje_original': message,
            'numeros_cifrados': encrypted,
            'claves_usadas': {'n': self.n, 'e': self.e},
            'timestamp': datetime.now().isoformat()
        }
        
        info = {
            'mensaje_original': message,
            'mensaje_procesado': ''.join([c for c in message.upper() if c in char_to_num and char_to_num[c] < self.n]),
            'numeros_cifrados': encrypted,
            'caracteres_ignorados': ignorados
        }
        
        return encrypted, ignorados, info
    
    def decrypt_message(self, encrypted):
        """Descifra un mensaje usando RSA"""
        if not (self.n and self.d):
            raise ValueError("❌ Claves RSA no generadas")
        
        decrypted = ''
        for c in encrypted:
            num = self.modular_pow(c, self.d, self.n)
            decrypted += num_to_char.get(num, '?')
        
        info = {
            'numeros_cifrados': encrypted,
            'mensaje_descifrado': decrypted
        }
        
        return decrypted, info
    
    def firmar_mensaje(self, mensaje):
        """Crea una firma digital del mensaje"""
        if not (self.n and self.d):
            raise ValueError("❌ Claves RSA no generadas")
        
        hash_obj = hashlib.sha256(mensaje.encode('utf-8'))
        hash_hex = hash_obj.hexdigest()
        hash_int = int(hash_hex, 16)
        
        if hash_int >= self.n:
            hash_int = hash_int % self.n
        
        firma = self.modular_pow(hash_int, self.d, self.n)
        
        info = {
            'mensaje': mensaje,
            'hash_sha256': hash_hex,
            'hash_numerico': hash_int,
            'firma': firma,
            'timestamp': datetime.now().isoformat()
        }
        
        return firma, hash_hex, info
    
    def verificar_firma(self, mensaje, firma):
        """Verifica una firma digital"""
        if not (self.n and self.e):
            raise ValueError("❌ Claves RSA no generadas")
        
        hash_obj = hashlib.sha256(mensaje.encode('utf-8'))
        hash_hex = hash_obj.hexdigest()
        hash_int = int(hash_hex, 16)
        
        if hash_int >= self.n:
            hash_int = hash_int % self.n
        
        hash_verificado = self.modular_pow(firma, self.e, self.n)
        es_valida = hash_int == hash_verificado
        
        info = {
            'mensaje': mensaje,
            'firma': firma,
            'hash_original': hash_int,
            'hash_verificado': hash_verificado,
            'es_valida': es_valida
        }
        
        return es_valida, info
    
    def guardar_claves(self):
        """Guarda las claves en archivos"""
        if not all([self.n, self.e, self.d]):
            return False
        
        try:
            with open("clave_publica.txt", "w") as f:
                f.write(f"{self.n} {self.e}")
            
            with open("clave_privada.txt", "w") as f:
                f.write(f"{self.n} {self.d}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error guardando claves: {e}")
            return False
    
    def cargar_claves(self):
        """Carga claves desde archivos"""
        try:
            if os.path.exists("clave_publica.txt") and os.path.exists("clave_privada.txt"):
                with open("clave_publica.txt", "r") as f:
                    n_pub, e = map(int, f.read().split())
                
                with open("clave_privada.txt", "r") as f:
                    n_priv, d = map(int, f.read().split())
                
                if n_pub == n_priv:
                    self.n = n_pub
                    self.e = e
                    self.d = d
                    return True
            
            return False
            
        except Exception as e:
            print(f"❌ Error cargando claves: {e}")
            return False

class RSAApp:
    """Interfaz gráfica para el sistema RSA"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema RSA - Matemática Computacional")
        self.root.geometry("950x750")
        
        self.rsa = RSACryptography()
        self.setup_ui()
        
        if self.rsa.cargar_claves():
            self.actualizar_info_claves()
        else:
            self.mostrar_info_sin_claves()
    
    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.root, bg="#2c3e50", height=100)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        
        titulo = tk.Label(header_frame, text="🔐 Sistema RSA", 
                         font=("Arial", 16, "bold"), fg="white", bg="#2c3e50")
        titulo.pack(pady=8)
        
        info_frame = tk.Frame(header_frame, bg="#2c3e50")
        info_frame.pack(fill="x", padx=20)
        
        self.info_claves_label = tk.Label(info_frame, text="Sin claves cargadas", 
                                         font=("Courier", 9), fg="#ecf0f1", bg="#2c3e50")
        self.info_claves_label.pack(side="left")
        
        btn_generar = tk.Button(info_frame, text="🔑 GENERAR CLAVES", 
                               command=self.generar_claves_dialog,
                               bg="#e74c3c", fg="white", font=("Arial", 10, "bold"))
        btn_generar.pack(side="right")
        
        # Notebook
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Pestañas
        self.frame_emisor = ttk.Frame(notebook)
        notebook.add(self.frame_emisor, text="📤 EMISOR")
        self.setup_emisor()
        
        self.frame_receptor = ttk.Frame(notebook)
        notebook.add(self.frame_receptor, text="📥 RECEPTOR")
        self.setup_receptor()
        
        self.frame_firma = ttk.Frame(notebook)
        notebook.add(self.frame_firma, text="✍️ FIRMA DIGITAL")
        self.setup_firma()
    
    def setup_emisor(self):
        main_frame = tk.Frame(self.frame_emisor)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Entrada
        entrada_frame = ttk.LabelFrame(main_frame, text="✏️ Mensaje", padding="10")
        entrada_frame.pack(fill="both", expand=True, pady=(0,10))
        
        self.text_mensaje = scrolledtext.ScrolledText(entrada_frame, height=6, width=70, 
                                                     font=("Consolas", 11), wrap=tk.WORD)
        self.text_mensaje.pack(fill="both", expand=True)
        self.text_mensaje.insert(1.0, "Escribe aquí tu mensaje...")
        
        # Info
        info_label = tk.Label(entrada_frame, 
                             text="📝 Soporta: A-Z, 0-9, espacios y símbolos comunes", 
                             font=("Arial", 9), fg="gray")
        info_label.pack(pady=5)
        
        # Botones PRINCIPALES
        botones_frame = tk.Frame(entrada_frame)
        botones_frame.pack(pady=10)
        
        btn_cifrar = tk.Button(botones_frame, text="🔒 CIFRAR", 
                              command=self.cifrar_mensaje, 
                              bg="#27ae60", fg="white", font=("Arial", 12, "bold"))
        btn_cifrar.pack(side="left", padx=5)
        
        btn_exportar = tk.Button(botones_frame, text="📤 EXPORTAR", 
                                command=self.exportar_mensaje_cifrado,
                                bg="#f39c12", fg="white", font=("Arial", 12, "bold"))
        btn_exportar.pack(side="left", padx=5)
        
        # Botones AUXILIARES
        botones_aux_frame = tk.Frame(entrada_frame)
        botones_aux_frame.pack(pady=5)
        
        btn_cargar = tk.Button(botones_aux_frame, text="📁 CARGAR ARCHIVO", 
                              command=self.cargar_archivo_para_cifrar,
                              bg="#3498db", fg="white", font=("Arial", 10))
        btn_cargar.pack(side="left", padx=5)
        
        btn_limpiar = tk.Button(botones_aux_frame, text="🗑️ LIMPIAR", 
                               command=self.limpiar_emisor,
                               bg="#e74c3c", fg="white", font=("Arial", 10))
        btn_limpiar.pack(side="left", padx=5)
        
        # Resultado
        resultado_frame = ttk.LabelFrame(main_frame, text="🔐 Resultado", padding="10")
        resultado_frame.pack(fill="both", expand=True)
        
        self.text_cifrado = scrolledtext.ScrolledText(resultado_frame, height=12, width=70,
                                                     font=("Consolas", 10), wrap=tk.WORD)
        self.text_cifrado.pack(fill="both", expand=True)
    
    def setup_receptor(self):
        main_frame = tk.Frame(self.frame_receptor)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Acciones
        acciones_frame = ttk.LabelFrame(main_frame, text="🔓 Descifrar", padding="15")
        acciones_frame.pack(fill="x", pady=(0,10))
        
        desc_label = tk.Label(acciones_frame, 
                             text="Descifra mensajes automáticamente o carga archivos",
                             font=("Arial", 10), fg="gray")
        desc_label.pack(pady=(0,10))
        
        botones_frame = tk.Frame(acciones_frame)
        botones_frame.pack()
        
        btn_descifrar = tk.Button(botones_frame, text="🔓 DESCIFRAR AUTOMÁTICO", 
                                 command=self.descifrar_mensaje_automatico,
                                 bg="#8e44ad", fg="white", font=("Arial", 11, "bold"))
        btn_descifrar.pack(side="left", padx=5)
        
        btn_cargar = tk.Button(botones_frame, text="📂 CARGAR ARCHIVO", 
                              command=self.cargar_y_descifrar_archivo,
                              bg="#f39c12", fg="white", font=("Arial", 11))
        btn_cargar.pack(side="left", padx=5)
        
        # Resultado
        resultado_frame = ttk.LabelFrame(main_frame, text="✅ Resultado", padding="10")
        resultado_frame.pack(fill="both", expand=True)
        
        self.text_descifrado = scrolledtext.ScrolledText(resultado_frame, height=15, width=70,
                                                        font=("Consolas", 11), wrap=tk.WORD)
        self.text_descifrado.pack(fill="both", expand=True)
    
    def setup_firma(self):
        main_frame = tk.Frame(self.frame_firma)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Firma
        firma_frame = ttk.LabelFrame(main_frame, text="✍️ Firma Digital", padding="10")
        firma_frame.pack(fill="x", pady=(0,10))
        
        tk.Label(firma_frame, text="Mensaje a firmar:", font=("Arial", 10)).pack(anchor="w")
        self.text_firma_mensaje = scrolledtext.ScrolledText(firma_frame, height=4, width=70)
        self.text_firma_mensaje.pack(fill="x", pady=(0,10))
        
        botones_frame = tk.Frame(firma_frame)
        botones_frame.pack()
        
        btn_firmar = tk.Button(botones_frame, text="✍️ FIRMAR", 
                              command=self.firmar_mensaje,
                              bg="#9b59b6", fg="white", font=("Arial", 11, "bold"))
        btn_firmar.pack(side="left", padx=5)
        
        btn_verificar = tk.Button(botones_frame, text="🔍 VERIFICAR", 
                                 command=self.verificar_firma,
                                 bg="#34495e", fg="white", font=("Arial", 11))
        btn_verificar.pack(side="left", padx=5)
        
        # Resultado
        resultado_frame = ttk.LabelFrame(main_frame, text="📋 Resultado", padding="10")
        resultado_frame.pack(fill="both", expand=True)
        
        self.text_resultado_firma = scrolledtext.ScrolledText(resultado_frame, height=15, width=70,
                                                             font=("Consolas", 10), wrap=tk.WORD)
        self.text_resultado_firma.pack(fill="both", expand=True)
    
    def actualizar_info_claves(self):
        if self.rsa.n and self.rsa.e and self.rsa.d:
            info = f"🔑 Claves cargadas - n: {self.rsa.n.bit_length()} bits"
        else:
            info = "❌ Sin claves"
        self.info_claves_label.config(text=info)
    
    def mostrar_info_sin_claves(self):
        self.info_claves_label.config(text="❌ Sin claves - Genera nuevas")
    
    def generar_claves_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("🔑 Generar Claves")
        dialog.geometry("400x200")
        dialog.grab_set()
        
        main_frame = tk.Frame(dialog, padx=20, pady=20)
        main_frame.pack(fill="both", expand=True)
        
        tk.Label(main_frame, text="🔑 Generar Claves RSA", 
                font=("Arial", 14, "bold")).pack(pady=(0,20))
        
        key_size_var = tk.StringVar(value="512")
        
        tk.Radiobutton(main_frame, text="512 bits (Rápido)", 
                      variable=key_size_var, value="512").pack(anchor="w")
        tk.Radiobutton(main_frame, text="1024 bits (Moderado)", 
                      variable=key_size_var, value="1024").pack(anchor="w")
        
        def generar():
            try:
                bits = int(key_size_var.get())
                info = self.rsa.generar_claves_rsa(bits)
                
                if self.rsa.guardar_claves():
                    self.actualizar_info_claves()
                    messagebox.showinfo("✅ Éxito", f"Claves de {bits} bits generadas")
                    dialog.destroy()
                    
            except Exception as e:
                messagebox.showerror("❌ Error", f"Error: {str(e)}")
        
        botones_frame = tk.Frame(main_frame)
        botones_frame.pack(pady=20)
        
        btn_generar = tk.Button(botones_frame, text="🔑 GENERAR", 
                               command=generar, bg="#27ae60", fg="white")
        btn_generar.pack(side="left", padx=5)
        
        btn_cancelar = tk.Button(botones_frame, text="❌ CANCELAR", 
                                command=dialog.destroy, bg="#e74c3c", fg="white")
        btn_cancelar.pack(side="left", padx=5)
    
    def cifrar_mensaje(self):
        if not (self.rsa.n and self.rsa.e):
            messagebox.showerror("❌ Error", "Genera claves primero")
            return
        
        mensaje = self.text_mensaje.get(1.0, tk.END).strip()
        if not mensaje or mensaje == "Escribe aquí tu mensaje...":
            messagebox.showwarning("⚠️ Advertencia", "Ingresa un mensaje")
            return
        
        try:
            cifrado, ignorados, info = self.rsa.encrypt_message(mensaje)
            
            resultado = f"🔐 CIFRADO COMPLETADO\n\n"
            resultado += f"📝 Original: {mensaje}\n\n"
            resultado += f"🔢 Cifrado: {cifrado}\n\n"
            resultado += f"📄 Para archivo: {' '.join(map(str, cifrado))}\n\n"
            resultado += f"🔑 Claves: n={self.rsa.n}, e={self.rsa.e}\n\n"
            
            if ignorados:
                resultado += f"⚠️ Ignorados: {ignorados}\n\n"
            
            # Verificar
            descifrado, _ = self.rsa.decrypt_message(cifrado)
            resultado += f"✅ Verificación: {descifrado}"
            
            self.text_cifrado.delete(1.0, tk.END)
            self.text_cifrado.insert(1.0, resultado)
            
            # Guardar automáticamente
            with open("mensaje_encriptado.txt", "w") as f:
                f.write(" ".join(map(str, cifrado)))
            
            messagebox.showinfo("✅ Éxito", "Mensaje cifrado y guardado")
            
        except Exception as e:
            messagebox.showerror("❌ Error", f"Error: {str(e)}")
    
    def exportar_mensaje_cifrado(self):
        if not self.rsa.ultimo_cifrado:
            messagebox.showwarning("⚠️ Advertencia", "Cifra un mensaje primero")
            return
        
        try:
            archivo = filedialog.asksaveasfilename(
                title="Exportar mensaje cifrado",
                defaultextension=".txt",
                filetypes=[
                    ("Archivo de texto", "*.txt"),
                    ("Archivo cifrado", "*.enc"), 
                    ("Todos los archivos", "*.*")
                ],
                initialfile="mi_mensaje_cifrado.txt"
            )
            
            if archivo:
                cifrado = self.rsa.ultimo_cifrado
                
                contenido = f"""# ARCHIVO RSA CIFRADO
# Generado: {cifrado['timestamp']}
# Sistema: RSA - Matemática Computacional
# 
# INFORMACIÓN DE CIFRADO:
# - Mensaje original: "{cifrado['mensaje_original']}"
# - Clave pública (n): {cifrado['claves_usadas']['n']}
# - Exponente público (e): {cifrado['claves_usadas']['e']}
# - Longitud: {len(cifrado['numeros_cifrados'])} números
#
# DATOS CIFRADOS (una línea):
{' '.join(map(str, cifrado['numeros_cifrados']))}
"""
                
                with open(archivo, "w", encoding="utf-8") as f:
                    f.write(contenido)
                
                messagebox.showinfo("📤 Exportado", 
                    f"Mensaje cifrado exportado a:\n{archivo}")
                
        except Exception as e:
            messagebox.showerror("❌ Error", f"Error exportando: {str(e)}")
    
    def cargar_archivo_para_cifrar(self):
        archivo = filedialog.askopenfilename(
            title="Seleccionar archivo",
            filetypes=[
                ("Archivos de texto", "*.txt"),
                ("Todos los archivos", "*.*")
            ]
        )
        
        if archivo:
            try:
                with open(archivo, "r", encoding="utf-8") as f:
                    contenido = f.read()
                
                self.text_mensaje.delete(1.0, tk.END)
                self.text_mensaje.insert(1.0, contenido)
                
                messagebox.showinfo("📁 Éxito", f"Archivo cargado: {archivo}")
                
            except Exception as e:
                messagebox.showerror("❌ Error", f"Error: {str(e)}")
    
    def descifrar_mensaje_automatico(self):
        if not (self.rsa.n and self.rsa.d):
            messagebox.showerror("❌ Error", "Genera claves primero")
            return
        
        try:
            if not os.path.exists("mensaje_encriptado.txt"):
                messagebox.showerror("❌ Error", "No existe mensaje_encriptado.txt")
                return
            
            with open("mensaje_encriptado.txt", "r") as f:
                contenido = f.read().strip()
                numeros_str = []
                for linea in contenido.split('\n'):
                    if not linea.startswith('#') and linea.strip():
                        numeros_str.extend(linea.split())
                
                encrypted_numbers = [int(x) for x in numeros_str if x.isdigit()]
            
            if not encrypted_numbers:
                messagebox.showerror("❌ Error", "No se encontraron números válidos")
                return
            
            descifrado, info = self.rsa.decrypt_message(encrypted_numbers)
            
            resultado = f"🔓 DESCIFRADO COMPLETADO\n\n"
            resultado += f"🔢 Números: {encrypted_numbers}\n\n"
            resultado += f"✅ Mensaje: '{descifrado}'\n\n"
            resultado += f"🔑 Claves usadas: n={self.rsa.n} ({self.rsa.n.bit_length()} bits)"
            
            self.text_descifrado.delete(1.0, tk.END)
            self.text_descifrado.insert(1.0, resultado)
            
            with open("mensaje_desencriptado.txt", "w") as f:
                f.write(descifrado)
            
            messagebox.showinfo("✅ Éxito", f"Descifrado: '{descifrado}'")
            
        except Exception as e:
            messagebox.showerror("❌ Error", f"Error: {str(e)}")
    
    def cargar_y_descifrar_archivo(self):
        if not (self.rsa.n and self.rsa.d):
            messagebox.showerror("❌ Error", "Genera claves primero")
            return
        
        archivo = filedialog.askopenfilename(
            title="Seleccionar archivo para descifrar",
            filetypes=[
                ("Archivos de texto", "*.txt"),
                ("Archivos cifrados", "*.enc"),
                ("Todos los archivos", "*.*")
            ]
        )
        
        if archivo:
            try:
                with open(archivo, "r", encoding="utf-8") as f:
                    contenido = f.read().strip()
                
                numeros_str = []
                for linea in contenido.split('\n'):
                    if not linea.startswith('#') and linea.strip():
                        numeros_str.extend(linea.split())
                
                encrypted_numbers = [int(x) for x in numeros_str if x.isdigit()]
                
                if not encrypted_numbers:
                    messagebox.showerror("❌ Error", "No se encontraron números válidos")
                    return
                
                descifrado, _ = self.rsa.decrypt_message(encrypted_numbers)
                
                resultado = f"🔓 ARCHIVO DESCIFRADO\n\n"
                resultado += f"📂 Archivo: {os.path.basename(archivo)}\n\n"
                resultado += f"🔢 Números: {encrypted_numbers}\n\n"
                resultado += f"✅ Mensaje: '{descifrado}'\n\n"
                resultado += f"🔑 Claves: n={self.rsa.n}"
                
                self.text_descifrado.delete(1.0, tk.END)
                self.text_descifrado.insert(1.0, resultado)
                
                messagebox.showinfo("✅ Éxito", f"Archivo descifrado:\n'{descifrado}'")
                
            except Exception as e:
                messagebox.showerror("❌ Error", f"Error procesando archivo: {str(e)}")
    
    def firmar_mensaje(self):
        if not (self.rsa.n and self.rsa.d):
            messagebox.showerror("❌ Error", "Genera claves primero")
            return
        
        mensaje = self.text_firma_mensaje.get(1.0, tk.END).strip()
        if not mensaje:
            messagebox.showwarning("⚠️ Advertencia", "Ingresa mensaje a firmar")
            return
        
        try:
            firma, hash_hex, info = self.rsa.firmar_mensaje(mensaje)
            
            resultado = f"✍️ FIRMA CREADA\n\n"
            resultado += f"📝 Mensaje: '{mensaje}'\n\n"
            resultado += f"🔐 Hash SHA-256: {hash_hex}\n\n"
            resultado += f"✍️ Firma digital: {firma}\n\n"
            resultado += f"🔑 Claves usadas: n={self.rsa.n}, d={self.rsa.d}"
            
            self.text_resultado_firma.delete(1.0, tk.END)
            self.text_resultado_firma.insert(1.0, resultado)
            
            messagebox.showinfo("✅ Éxito", f"Firma creada: {firma}")
            
        except Exception as e:
            messagebox.showerror("❌ Error", f"Error: {str(e)}")
    
    def verificar_firma(self):
        if not (self.rsa.n and self.rsa.e):
            messagebox.showerror("❌ Error", "Genera claves primero")
            return
        
        mensaje = simpledialog.askstring("Mensaje", "Mensaje original:")
        if not mensaje:
            return
        
        try:
            firma_str = simpledialog.askstring("Firma", "Firma digital:")
            if not firma_str:
                return
            
            firma = int(firma_str)
            es_valida, info = self.rsa.verificar_firma(mensaje, firma)
            
            resultado = f"🔍 VERIFICACIÓN DE FIRMA\n\n"
            resultado += f"📝 Mensaje: '{mensaje}'\n\n"
            resultado += f"✍️ Firma: {firma}\n\n"
            resultado += f"🔐 Hash calculado: {info['hash_original']}\n\n"
            resultado += f"🔓 Hash de la firma: {info['hash_verificado']}\n\n"
            resultado += f"✅ Resultado: {'VÁLIDA ✓' if es_valida else 'INVÁLIDA ✗'}\n\n"
            resultado += f"🔑 Claves usadas: n={self.rsa.n}, e={self.rsa.e}"
            
            self.text_resultado_firma.delete(1.0, tk.END)
            self.text_resultado_firma.insert(1.0, resultado)
            
            if es_valida:
                messagebox.showinfo("✅ Válida", "La firma es VÁLIDA")
            else:
                messagebox.showerror("❌ Inválida", "La firma es INVÁLIDA")
                
        except Exception as e:
            messagebox.showerror("❌ Error", f"Error: {str(e)}")
    
    def limpiar_emisor(self):
        self.text_mensaje.delete(1.0, tk.END)
        self.text_mensaje.insert(1.0, "Escribe aquí tu mensaje...")
        self.text_cifrado.delete(1.0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()