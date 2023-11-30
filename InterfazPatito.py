#IMPORTACION DE BIBLIOTECAS Y FUNCIONES
import heapq
import string
import secrets
import tkinter as tk
from tkinter import messagebox 
from collections import Counter
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# *****CREAR ALGORITMO DE HUFFMAN*****
class NodoHuffman:
    def __init__(self, caracter=None, frecuencia=None):
        self.caracter = caracter
        self.frecuencia = frecuencia
        self.izquierda = None
        self.derecha = None

    def __lt__(self, otro):
        return self.frecuencia < otro.frecuencia
def construir_arbol_huffman(frecuencias):
    cola_prioridad = [NodoHuffman(caracter=car, frecuencia=freq) for car, freq in frecuencias.items()]
    heapq.heapify(cola_prioridad)

    while len(cola_prioridad) > 1:
        nodo_izq = heapq.heappop(cola_prioridad)
        nodo_der = heapq.heappop(cola_prioridad)

        nuevo_nodo = NodoHuffman(frecuencia=nodo_izq.frecuencia + nodo_der.frecuencia)
        nuevo_nodo.izquierda, nuevo_nodo.derecha = nodo_izq, nodo_der

        heapq.heappush(cola_prioridad, nuevo_nodo)

    return cola_prioridad[0]
def generar_tabla_de_compresion(arbol_huffman, codigo='', tabla=None):
    if tabla is None:
        tabla = {}
    if arbol_huffman is not None:
        if arbol_huffman.caracter is not None:
            tabla[arbol_huffman.caracter] = codigo
        generar_tabla_de_compresion(arbol_huffman.izquierda, codigo + '0', tabla)
        generar_tabla_de_compresion(arbol_huffman.derecha, codigo + '1', tabla)
    return tabla
# *****COMPRIMIR*****
def comprimir_texto():
    #Declarar las variables globales
    global mensaje_comprimido, tabla_compresion, btn_encriptar

    texto = str(entradaTexto.get())
    
    if not texto:
        messagebox.showerror("Error", "Debes de ingresar un mensaje primero")
        return

    frecuencias = Counter(texto)
    arbol_huffman = construir_arbol_huffman(frecuencias)
    tabla_compresion = generar_tabla_de_compresion(arbol_huffman)
    
    mensaje_comprimido = ''.join(tabla_compresion[caracter] for caracter in texto)
    
    messagebox.showinfo("\nTabla compresion: ", tabla_compresion)
    messagebox.showinfo("Mensaje comprimido: ", mensaje_comprimido)
    

    btn_comprimir['state'] = tk.DISABLED
    btn_encriptar['state'] = tk.NORMAL

    return tabla_compresion, mensaje_comprimido
# *****DESCOMPRIMIR*****
def descomprimir_texto():
    global tabla_compresion, mensaje_comprimido

    tabla_invertida = {codigo: caracter for caracter, codigo in tabla_compresion.items()}
    mensaje_descomprimido = ""
    codigo_actual = ""
    for bit in mensaje_comprimido:
        codigo_actual += bit
        if codigo_actual in tabla_invertida:
            caracter = tabla_invertida[codigo_actual]
            mensaje_descomprimido += caracter
            codigo_actual = ""

    return mensaje_descomprimido
# *****GENERACION DE CLAVES*****
def generar_claves():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    # Serializar las claves en formato PEM para guardarlas o intercambiarlas
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem
# *****ENCRIPTACION*****
def encriptar():
    global mensaje_comprimido, clave_privada, clave_publica, ciphertext

    if mensaje_comprimido is None:
        messagebox.showwarning("ADVERTENCIA", "PRIMERO SE DEBE COMPRIMIR EL MENSAJE")
        return
    clave_privada, clave_publica = generar_claves()
    public_key = serialization.load_pem_public_key(clave_publica, backend=default_backend())
    ciphertext = public_key.encrypt(
        mensaje_comprimido.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    entradaTexto.delete(0, tk.END)
    entradaTexto.insert(0, '')
    btn_encriptar["state"] = tk.DISABLED
    btn_enviar["state"] = tk.NORMAL

    messagebox.showinfo("Mensaje Encriptado: ", ciphertext)

    return ciphertext
# *****DESENCRIPTACION*****
def desencriptar():
    global ciphertext
    global clave_privada
    private_key = serialization.load_pem_private_key(clave_privada, password=None, backend=default_backend())
    mensaje = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return mensaje.decode()
# *****REINICIAR PROGRAMA*****
def reiniciar_programa():
    btn_comprimir['state'] = tk.NORMAL
    btn_encriptar['state'] = tk.NORMAL
    btn_enviar["state"] = tk.DISABLED
# *****ENVIAR MENSAJE*****
def enviar_mensaje():
    global ciphertext, codigoR

    alphabet = string.ascii_letters + string.digits
    codigoR = ''.join(secrets.choice(alphabet) for i in range (2))

    messagebox.showinfo("Se envio el mensaje", codigoR)

    reiniciar_programa()
    return codigoR, ciphertext
# *****RECIBIR MENSAJE*****
def recibir_mensaje():
    global codigoR, ciphertext
    codigoEntrada = str(entradaCodigo.get())

    if codigoEntrada is None:
        messagebox.showwarning("Advertencia", "Debes ingresar un codigo para recibir un mensaje")
        return

    if codigoEntrada == codigoR:
        ciphertext = desencriptar()
        ciphertext = descomprimir_texto()
        messagebox.showinfo("Mensaje Recibido", ciphertext)
        entradaCodigo.delete(0, tk.END)
        entradaCodigo.insert(0, '')
        return ciphertext
    else:
        messagebox.showerror("ERROR", "El codigo ingresado no es correcto")
        return 
    
# *****INICIALIZACION DE LAS VARIABLES GLOBALES*****
mensaje_comprimido = None
tabla_compresion = None

# *****CODIGO PARA EL EJECUTABLE*****
root = tk.Tk()
root.geometry("200x300")
root.title("Scrum Proyect")

etiquetaPrograma = tk.Label(root, text="PATITO'S MESSAGES")
etiqueta0 = tk.Label(root, text="MANDAR UN MENSAJE")
etiqueta1 = tk.Label(root, text="Ingresa tu mensaje")
entradaTexto = tk.Entry(root)
btn_comprimir = tk.Button(root, text="Comprimir", command=comprimir_texto)
btn_encriptar = tk.Button(root, text="Encriptar", command=encriptar)
btn_enviar = tk.Button(root, text="Enviar", command=enviar_mensaje, state=tk.DISABLED)
etiqueta2 = tk.Label(root, text="")
etiqueta3 = tk.Label(root, text="RECIBE UN MENSAJE")
etiqueta4 = tk.Label(root, text="Ingresa el codigo")
entradaCodigo = tk.Entry(root)
btn_recibir = tk.Button(root, text="Recibir", command=recibir_mensaje)

# Usar el método grid para organizar los widgets
etiquetaPrograma.pack()
etiqueta0.pack()
etiqueta1.pack()
entradaTexto.pack()
btn_comprimir.pack() 
btn_encriptar.pack()
btn_enviar.pack()
etiqueta2.pack()
etiqueta3.pack()
etiqueta4.pack()
entradaCodigo.pack()
btn_recibir.pack()


root.mainloop()
