#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, argparse
from time import time
import numpy as np
import base64
import hashlib
parser = argparse.ArgumentParser()
# Opciones algoritmos.
parser.add_argument("-tg", help="Algoritmo de transposicion por grupos", action="store_true")
parser.add_argument("-spol", help="Algoritmo de sustitucion monoalfabetica Polybios ", action="store_true")
parser.add_argument("-splay", help="Algoritmo de sustitucion monoalfabetica Playfair", action="store_true")
parser.add_argument("-vroz", help="Cifrado polialfabetico de vigenère rozier ", action="store_true")
parser.add_argument("-hill", help="Cifrado de sustitucion poligrafica (matrices de hill)", action="store_true")
parser.add_argument("-a", help="Despliega ayuda del algoritmo en particular", action="store_true")
parser.add_argument("-c", help="opcion para cifrar", action="store_true")
parser.add_argument("-d", help="opcion para descifrar", action="store_true")
parser.add_argument("-b64", help="opcion para codificar", action="store_true")
parser.add_argument("-alpha1", help="Si esta activada, el texto se cifra con numeros", action="store_true")
parser.add_argument("-texto", type=str, help="nombre del archivo del texto a cifrar o descifrar", default=os.getcwd(), required=False)
parser.add_argument("-txtclave", type=str, help="nombre del archivo que contiene la clave", default=os.getcwd(), required=False)
args=parser.parse_args()

if (args.tg == True and args.a == True) or (args.tg == True and args.c == False and args.d == False):


	print("""
        --------------------------------UNIVERSIDAD DEL CAUCA------------------------------------
        ---------------------------Algoritmos Transposicion por grupos---------------------------
        |                                                                         		|
	|                							  		|
        |    Sintaxis: ./menu.py -tg <opcion> -texto <ArchivoEntrada> -txtclave <ArchivoClave>  |
        |                                                                         		|
        |      <opcion> : -c para cifrar el archivo <ArchivoEntrada>               		|
	|		  -d para descifrar el archivo <ArchivoEntrada>            		|
        |									  		|
        |      <ArchivoEntrada>: nombre del archivo de entrada                     		|
        |							                  		|
	|      <ArchivoClave>  : nombre del archivo que contiene la clave          		|
     	|									  		|
	|      si <opcion> es -c, el archivo de salida es <ArchivoEntrada>	  		|
	|		       , que cambia a la extension .cif	 		  		|
	|									  		|
 	|      si <opcion> es -d, el archivo de salida es <ArchivoEntrada> 	  		|
	|		       , que cambia a la extension .dec			  		|
	|									  		|
	|  El archivo que contiene la clave debe contener los digitos normal      		|
	|  sin espacios.							  		|
        |   											|
  	|  Al ser un algoritmo de difusiòn la codificaciòn base64 no es necesaria, ya que el	|
	|  mensaje se reorganiza en todo el criptograma sin la necesidad de un alfabeto.	|	
	|  											|
	|									  		|
	|  Ejemplos:								  		|
	|									  		|
	|  Cifrar:       ./menu.py -tg -c -texto quijote.txt -txtclave clavegrupo.txt		|
        |  Descifrar:    ./menu.py -tg -d -texto quijote.cif -txtclave clavegrupo.txt    	|
	|  									  		|
	|  Elaborado por: Esteban Arteaga      estebanben@unicauca.edu.co	  		|
	|		  German Moran         germanmoran@unicauca.edu.co	  		|
	|---------------------------------------------------------------------------------------|
        """)

if args.spol == True and args.a == True or args.spol == True and args.c == False and args.d == False:


	print("""
        --------------------------------UNIVERSIDAD DEL CAUCA--------------------------------------------
        --------------------Algoritmo de sustitucion monoalfabetica Polybios-----------------------------
        |                                                                         		        |
	|                							  		        |
        |     Sintaxis : ./menu.py -spol <opcion> -texto <ArchivoEntrada> -txtclave <ArchivoClave> 	|
        |                                                                         			|
        |     <opcion> : -c para cifrar el archivo <ArchivoEntrada>               			|
	|		 -d para descifrar el archivo <ArchivoEntrada>            			|
        |									  			|
        |     <ArchivoEntrada>: nombre del archivo de entrada                     			|
     	|									  			|
	|     si <opcion> es -c, el archivo de salida es <ArchivoEntrada>	  			|
	|		       , que cambia a la extension .cif				  		|
	|									  			|
 	|     si <opcion> es -d, el archivo de salida es <ArchivoEntrada> 	  			|
	|		       , que cambia a la extension .dec						|
	|												|
	|     si alpha1 esta activada, el archivo de entrada se cifra con numeros, caso contrario,	|
	|     el archivo de entrada se cifra con letras.	  					|
	|												|
	|     Si se desea codificar el mensaje a base 64 antes de realizar el cifrado, se agrega	|
	|     la bandera -b64										|									  			|
	|									  			|
	|  Ejemplos:								  			|
	|									  			|
	|  Cifrar (numeros):              ./menu.py -spol -c -texto quijote.txt -alpha1			|
	|  Cifrar (letras):               ./menu.py -spol -c -texto quijote.txt				|
	|  Cifrar base64 (numeros):       ./menu.py -spol -c -texto quijote.txt -alpha1	-b64		|
	|  Cifrar base64 (letras):        ./menu.py -spol -c -texto quijote.txt	-b64			|
        |  Descifrar:                     ./menu.py -spol -d -texto quijote.cif   			|
        |  Descifrar base64:              ./menu.py -spol -d -texto quijote.cif -b64			|
	|  									  			|
	|  Elaborado por: Esteban Arteaga      estebanben@unicauca.edu.co	  			|
	|		  German Moran         germanmoran@unicauca.edu.co	  			|
	|-----------------------------------------------------------------------------------------------|
        """)

if args.splay == True and args.a == True or args.splay == True and args.c == False and args.d == False:


	print("""
        --------------------------------UNIVERSIDAD DEL CAUCA--------------------------------------------
        --------------------Algoritmo de sustitucion monoalfabetica Playfair ----------------------------
        |                                                                         		        |
	|                							  		        |
        |     Sintaxis: ./menu.py -splay <opcion> -texto <ArchivoEntrada> -txtclave <ArchivoClave> 	|
        |                                                                         			|
        |     <opcion> : -c para cifrar el archivo <ArchivoEntrada>               			|
	|		 -d para descifrar el archivo <ArchivoEntrada>            			|
        |									  			|
        |     <ArchivoEntrada>: nombre del archivo de entrada                     			|
	|     <ArchivoClave>  : nombre del archivo que contiene la clave          			|
     	|									  			|
	|     si <opcion> es -c, el archivo de salida es <ArchivoEntrada>	  			|
	|		       , que cambia a la extension .cif				  		|
	|									  			|
 	|     si <opcion> es -d, el archivo de salida es <ArchivoEntrada> 	  			|
	|		       , que cambia a la extension .dec						|
	|												|
	|												|
	|									  			|
	|     El archivo que contiene la clave debe contener las letras normal      			|
	|     sin espacios.										|
	|												|
	|     Si se desea codificar el mensaje a base 64 antes de realizar el cifrado, se agrega	|
	|     la bandera -b64										|						  			|
	|									  			|
	|  Ejemplos:								  			|
	|									  			|
	|  Cifrar:            ./menu.py -splay -c -texto quijote.txt -txtclave clavePlay.txt		|
	|  Cifrar base64:     ./menu.py -splay -c -texto quijote.txt -txtclave clavePlay.txt -b64	|
        |  Descifrar:         ./menu.py -splay -d -texto quijote.cif -txtclave clavePlay.txt 	    	|
        |  Descifrar base64:  ./menu.py -splay -d -texto quijote.cif -txtclave clavePlay.txt -b64  	|
	|  									  			|
	|  Elaborado por: Esteban Arteaga      estebanben@unicauca.edu.co	  			|
	|		  German Moran         germanmoran@unicauca.edu.co	  			|
	|-----------------------------------------------------------------------------------------------|
        """)


if args.vroz == True and args.a == True or args.vroz == True and args.c == False and args.d == False:


	print("""
        ------------------------------------UNIVERSIDAD DEL CAUCA----------------------------------------
        ------------------------------Cifrado polialfabetico de vigenère rozier--------------------------
        |                                                                         			|
	|                							  			|
        |     Sintaxis: ./menu.py -vroz <opcion> -texto <ArchivoEntrada> -txtclave <ArchivoClave>	|
        |                                                                         			|
        |     <opcion> : -c para cifrar el archivo <ArchivoEntrada>               			|
	|		 -d para descifrar el archivo <ArchivoEntrada>            			|
        |									  			|
        |      <ArchivoEntrada>: nombre del archivo de entrada                     			|
        |							                  			|
	|      <ArchivoClave>  :nombre del archivo que contiene la clave          			|
     	|									  			|
	|      si <opcion> es -c, el archivo de salida es <ArchivoEntrada>	  			|
	|		       , que cambia a la extension .cif				  		|
	|									  			|
 	|      si <opcion> es -d, el archivo de salida es <ArchivoEntrada> 	  			|
	|		       ,  que cambia a la extension .dec		  			|
	|									  			|
	|   El archivo que contiene la clave debe contener las letras normal      			|
	|   sin espacios										|
	|												|
	|   Si se desea codificar el mensaje a base 64 antes de realizar el cifrado, se agrega		|
	|   la bandera -b64										|								|
	|									  			|
	|  Ejemplos:								  			|
	|									  			|
	|  Cifrar:             ./menu.py -vroz -c -texto quijote.txt -txtclave claveRozier.txt		|
	|  Cifrar base64:      ./menu.py -vroz -c -texto quijote.txt -txtclave claveRozier.txt -b64	|
        |  Descifrar:          ./menu.py -vroz -d -texto quijote.cif -txtclave claveRozier.txt   	|
        |  Descifrar base64 :  ./menu.py -vroz -d -texto quijote.cif -txtclave claveRozier.txt -b64	|
	|  									  			|
	|  Elaborado por: Esteban Arteaga      estebanben@unicauca.edu.co	  			|
	|		  German Moran         germanmoran@unicauca.edu.co	  			|
	|-----------------------------------------------------------------------------------------------|
        """)


if (args.hill == True and args.a == True) or (args.hill == True and args.c == False and args.d == False):

	print("""
        ------------------------------------UNIVERSIDAD DEL CAUCA---------------------------------------
        ----------------------Cifrado de sustitucion poligrafica (matrices de hill)---------------------
        |                                                                         			|
	|                							  			|
        |     Sintaxis: ./menu.py -hill <opcion> -texto <ArchivoEntrada> -txtclave <ArchivoClave>	|
        |                                                                         			|
        |     <opcion> : -c para cifrar el archivo <ArchivoEntrada>               			|
	|		 -d para descifrar el archivo <ArchivoEntrada>            			|
        |									  			|
        |      <ArchivoEntrada>: nombre del archivo de entrada                     			|
        |							                  			|
	|      <ArchivoClave>  :nombre del archivo que contiene la clave          			|
     	|									  			|
	|      si <opcion> es -c, el archivo de salida es <ArchivoEntrada>	  			|
	|		       , que cambia a la extension .cif				  		|
	|									  			|
 	|      si <opcion> es -d, el archivo de salida es <ArchivoEntrada> 	  			|
	|		       , que cambia a la extension .dec				  		|
	|									  			|
	|  El archivo que contiene la clave debe contener la matriz clave en numeros enteros,   	|
	|  definida en forma matricial, es decir:							|
	|												|
	|				8  6 9  5							|
	|				6  9 5  10							|
	|				5  8 4  9							|
	|				10 6 11 4							|
	|												|
	|  Nota: La matriz clave debe ser invertible para poder ejecutar el algoritmo de hill.		|
	|												|
	|  Si se desea codificar el mensaje a base 64 antes de realizar el cifrado, se agrega		|
	|  la bandera -b64										|	
	|												|								  		|
	|  Ejemplos:								  			|
	|									  			|
	|  Cifrar:               ./menu.py -hill -c -texto quijote.txt -txtclave claveHill.dat		|
	|  Cifrar base64:        ./menu.py -hill -c -texto quijote.txt -txtclave claveHill.dat -b64	|
        |  Descifrar:            ./menu.py -hill -d -texto quijote.cif -txtclave claveHill.dat  	|
        |  Descifrar base64:     ./menu.py -hill -d -texto quijote.cif -txtclave claveHill.dat -b64	|
	|  									  			|
	|  Elaborado por: Esteban Arteaga      estebanben@unicauca.edu.co	  			|
	|		  German Moran         germanmoran@unicauca.edu.co	  			|
	|----------------------------------------------------------------------------------------------	|
        """)

#Cifrado transposiciòn por grupos

if args.tg == True and args.c == True:


	tiempo_inicial = time()         # Funciòn de tiempo original.

	mensaje=open(args.texto,'r',encoding="ISO-8859-1") # leer archivo que contiene el texto plano
	mensaje=mensaje.read()

	# Calculo del hash

	filename = '/root/Criptografia/' + args.texto
	hasher = hashlib.md5()
	with open(filename,"rb") as open_file:
		content = open_file.read()
		hasher.update(content)
	print ("Hash = ", hasher.hexdigest())

	
	# Leo el archivo que contiene la clave	

	clave=open(args.txtclave,'r') # leer archivo que contiene la clave
	clave=clave.read()
	clave=int(clave)
	clave=str(clave)


	long_msg = len(mensaje)   # Obtengo la longitud del mensaje
	long_key = len(clave)	  # Obtengo la longitud de la clave

	grupo = ""                # Defino los grupos de mensajes
	comp = ""		  # varible con el # de x para completar el mensaje
	cad_grupos = []		  # Defino una cadena de grupos de mensajes
	cont = 0				  # variable para dividir el mensaje
	msg_cifra = ""

	# Completo los mensajes incompletos con X

	resto = long_msg%long_key			 # residuo de letras que no completan el grupo exacto
	for n in range (resto, long_key):
		comp = comp  + "x"		 # Complemento para rellenar el grupo incompleto
	mensaje = mensaje + comp

	# Divido el mensaje el poligramas, dependiendo de la longitud de la clave.

	for letras in mensaje:			# Reviso cada una de las letras en el mensaje
		grupo += mensaje[cont]		# Conformo el tamaño de los grupos
		cont = cont + 1
		if cont%long_key == 0:		 #Ciclo para dividir el mensaje en grupos iguales
			cad_grupos.append(grupo) # Arreglo para guardar cada uno de los grupos del mensaje
			grupo = ""


	# Función para cifrar

	long_msg = len(mensaje)

	for n in range (0, int(long_msg/long_key)): # ciclo para recorrer el mensaje de acuerdo a los poligramas del tamaño de la clave.
		for x in range (0, long_key):	    # Ciclo para reorganizar los caracteres de acuerdo a la clave (teoria trans grupos).
			msg_cifra = msg_cifra + cad_grupos[n][int(clave[x])-1]

	salida = args.texto
	punto = salida.index(".")
	salida = salida[0:punto] + ".cif"
	cripto = open(salida, "w", encoding="ISO-8859-1")
	cripto.write(msg_cifra)

	
	#print (msg_cifra)
	#print (long_msg)
	#print (len(msg_cifra))
	tiempo_final = time()			# funcion de calculo de tiempo final
	tiempo_total = tiempo_final - tiempo_inicial   #Calculo el tiempo total de ejecucion
	print ("tiempo_total: ", tiempo_total)


# Descifrar transposicion por grupos

if args.tg == True and args.d == True:


	tiempo_inicial = time()         # Funciòn de tiempo original.

	cripto=open(args.texto,'r', encoding="ISO-8859-1") # leer archivo que contiene el criptograma
	cripto=cripto.read()

	clave=open(args.txtclave,'r')	# leer archivo que contiene la clave
	clave=clave.read()

	clave=int(clave)
	clave=str(clave)

	# Convierto la clave de cifrado en una clave de descifrado

	clave_desci = ""
	for i in range (1, len(clave)+1):
			for n in clave:
				if n == str(i):
					clave_desci = clave_desci + str(clave.index(n)+1)



	long_cripto = len(cripto)   # Obtengo la longitud del criptograma
	long_key = len(clave)
	grupo = ""                # Defino los grupos del criptograma
	comp = ""
	cad_grupos = []		  # Defino una cadena de grupos del criptograma
	cont = 0				  # variable para dividir el criptograma
	msg_decifra = ""

	for letras in cripto:			# Reviso cada una de las letras en el criptograma
		grupo += cripto[cont]		# Conformo el tamaño de los grupos
		cont = cont + 1
		if cont%long_key == 0:		 #Ciclo para dividir el criptograma en grupos iguales
			cad_grupos.append(grupo) # Arreglo para guardar cada uno de los grupos del criptograma
			grupo = ""
	resto = long_cripto%long_key			 # residuo de letras que no completan el grupo exacto

	# Función para descifrar

	for n in range (0, int(long_cripto/long_key)):  # ciclo para recorrer el mensaje de acuerdo a la division poligramas del tamaño de la clave.
		for x in range (0, long_key):	        # Ciclo para reorganizar los caracteres de acuerdo a la clave (teoria trans grupos).
			if cad_grupos[n][int(clave_desci[x])-1] == "x": # condicional para remover las x agregadas en el tx
				msg_decifra = msg_decifra		
			else:
				msg_decifra = msg_decifra + cad_grupos[n][int(clave_desci[x])-1]

	salida = args.texto 
	punto = salida.index(".")
	salida = salida[0:punto] + ".dec"
	cripto = open(salida, "w", encoding="ISO-8859-1")
	cripto.write(msg_decifra)

	
	# Calculo del hash

	filename = '/root/Criptografia/' + salida
	hasher = hashlib.md5()
	with open(filename,"rb") as open_file:
		content = open_file.read()
		hasher.update(content)
	print ("Hash = ", hasher.hexdigest())

	#print(msg_decifra)
	#print(long_cripto)
	tiempo_final = time()			# funcion de calculo de tiempo final
	tiempo_total = tiempo_final - tiempo_inicial   #Calculo el tiempo total de ejecucion
	print ("tiempo_total: ", tiempo_total)

#Cifrado polybios

if args.spol == True and args.c == True:

	tiempo_inicial = time()         # Funciòn de tiempo original.

	mensaje=open(args.texto,'r',encoding="ISO-8859-1") # leer archivo que contiene el mensaje
	mensaje=mensaje.read()

	cifrar = ""		       # funcion para guardar el texto cifrado

	# Cifrado con codificacion base 64

	if args.b64 == True:

		alfabetot="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=@@@@@@@"

		n = 0
		pos_inicial = -1               # Variable para guardar las posiciones de Ñ y J
		espacios = []                  # cadena donde se guarda todas las posiciones
		lista = ""		       # Variable para guardar la lista de todas las posiciones de Ñ y J separadas por un cero

		pos_inicial1 = -1               # Variable para guardar las posiciones de Ñ y J
		espacios1 = []                  # cadena donde se guarda todas las posiciones
		lista1 = ""		       # Variable para guardar la lista de todas las posiciones de Ñ y J separadas por un cero


		tabla = [[0]*8 for filas in range(9)]  # Defino el tamaño de la tabla y la relleno con ceros



		for f in range(9):					 # Bucle para cambiar las filas de la tabla de cifrado 
			for c in range(8):			     # Bucle para cambiar las columnas de la tabla de cifrado
				tabla[f][c] = alfabetot[n]	 # Relleno la tabla de cifrado con cada una de las letras del alfabeto
				n += 1


		# Codifico el mensaje a Base64

		conversion = mensaje.encode("utf-8")
		
		encoded = base64.b64encode(conversion)
		
		Mcodificado = encoded.decode("utf-8")		  


		# Cifro el mensaje

		for palabra in Mcodificado:						# Ciclo para recorrer las palabras del mensaje modificado
			for filas in range(0,9):				# Ciclo para recorrer las filas de la tabla de cifrado 
				if palabra in tabla[filas]:			# Condicional para ubicar la fila de la letra a cifrar
					fila = str(filas + 1)			# 1 variable de cifrado
					columna = str((tabla[filas].index(palabra) + 1))	# 2 variable de cifrado
					cifrar += fila + columna

		# Concateno las posiciones de las J y Ñ con el mensaje cifrado


		# Calculo del hash

		filename = '/root/Criptografia/' + args.texto
		hasher = hashlib.md5()
		with open(filename,"rb") as open_file:
			content = open_file.read()
			hasher.update(content)
		print ("Hash = ", hasher.hexdigest())

	# Cifrado normal

	if args.b64 == False:

		alfabetot="ABCDEFGHIJKLMNÑOPQRSTUVWXYZÜ«ÏÙÃÀ][%3_ @@@"

		n = 0
		pos_inicial = -1               # Variable para guardar las posiciones de Ñ y J
		espacios = []                  # cadena donde se guarda todas las posiciones
		lista = ""		       # Variable para guardar la lista de todas las posiciones de Ñ y J separadas por un cero

		pos_inicial1 = -1               # Variable para guardar las posiciones de Ñ y J
		espacios1 = []                  # cadena donde se guarda todas las posiciones
		lista1 = ""		       # Variable para guardar la lista de todas las posiciones de Ñ y J separadas por un cero


		tabla = [[0]*6 for filas in range(7)]  # Defino el tamaño de la tabla y la relleno con ceros



		for f in range(7):					 # Bucle para cambiar las filas de la tabla de cifrado 
			for c in range(6):			     # Bucle para cambiar las columnas de la tabla de cifrado
				tabla[f][c] = alfabetot[n]	 # Relleno la tabla de cifrado con cada una de las letras del alfabeto
				n += 1


		
		Mcodificado = mensaje	  


		# Cifro el mensaje

		for palabra in Mcodificado:						# Ciclo para recorrer las palabras del mensaje modificado
			for filas in range(0,7):				# Ciclo para recorrer las filas de la tabla de cifrado 
				if palabra in tabla[filas]:			# Condicional para ubicar la fila de la letra a cifrar
					fila = str(filas + 1)			# 1 variable de cifrado
					columna = str((tabla[filas].index(palabra) + 1))	# 2 variable de cifrado
					cifrar += fila + columna


		# Calculo del hash

		filename = '/root/Criptografia/' + args.texto
		hasher = hashlib.md5()
		with open(filename,"rb") as open_file:
			content = open_file.read()
			hasher.update(content)
		print ("Hash = ", hasher.hexdigest())


# Cifrado con tabla 1 (numeros)

	if args.alpha1:

		salida = args.texto
		punto = salida.index(".")
		salida = salida[0:punto] + ".cif"
		cripto = open(salida, "w",encoding="ISO-8859-1")
		cripto.write(cifrar)

		tiempo_final = time()			# funcion de calculo de tiempo final
		tiempo_total = tiempo_final - tiempo_inicial   #Calculo el tiempo total de ejecucion
		print ("tiempo_total: ", tiempo_total)

# Cifrado con tabla 2 (letras)
	else:

		cifrar = cifrar.replace("1","A")			# Reemplazamos cada valor del numero con su
		cifrar = cifrar.replace("2","B")			# letra correspondiente.
		cifrar = cifrar.replace("3","C")
		cifrar = cifrar.replace("4","D")
		cifrar = cifrar.replace("5","E")
		cifrar = cifrar.replace("6","F")
		cifrar = cifrar.replace("7","G")
		cifrar = cifrar.replace("8","H")
		cifrar = cifrar.replace("5","I")


		#print(len(cifrar))
		#print(len(mensaje))

		salida = args.texto
		punto = salida.index(".")
		salida = salida[0:punto] + ".cif"
		cripto = open(salida, "w", encoding="ISO-8859-1")
		cripto.write(cifrar)

		tiempo_final = time()			       # funcion de calculo de tiempo final
		tiempo_total = tiempo_final - tiempo_inicial   #Calculo el tiempo total de ejecucion
		print ("tiempo_total: ", tiempo_total)

# Descifrado polybios

if args.spol == True and args.d == True:

	tiempo_inicial = time()         # Funciòn de tiempo original.

	cripto=open(args.texto,'r',encoding="ISO-8859-1") # leer archivo que contiene el criptograma
	cripto=cripto.read()

	cont = 0
	grupo = ""
	desci = ""
	desci_final = ""	       # Vector de string con el mensaje completo 


	# Descifro el mensaje

	if args.b64 == True:

		alfabetot = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=@@@@@@@"
		n = 0
		tabla = [[0]*8 for filas in range(9)]  # Defino el tamaño de la tabla y la relleno con ceros

		for f in range(9):					 # Bucle para cambiar las filas de la tabla de cifrado 
			for c in range(8):			     # Bucle para cambiar las columnas de la tabla de cifrado
				tabla[f][c] = alfabetot[n]	 # Relleno la tabla de cifrado con cada una de las letras del alfabeto
				n += 1

	if args.b64 == False:

		alfabetot = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZÜ«ÏÙÃÀ][%3_ @@@"
		n = 0
		tabla = [[0]*6 for filas in range(7)]  # Defino el tamaño de la tabla y la relleno con ceros

		for f in range(7):					 # Bucle para cambiar las filas de la tabla de cifrado 
			for c in range(6):			     # Bucle para cambiar las columnas de la tabla de cifrado
				tabla[f][c] = alfabetot[n]	 # Relleno la tabla de cifrado con cada una de las letras del alfabeto
				n += 1


	cripto = cripto.replace("A","1")
	cripto = cripto.replace("B","2")
	cripto = cripto.replace("C","3")
	cripto = cripto.replace("D","4")
	cripto = cripto.replace("E","5")
	cripto = cripto.replace("F","6")
	cripto = cripto.replace("G","7")
	cripto = cripto.replace("H","8")
	cripto = cripto.replace("I","9")

	for letras in cripto:
		filas = int(cripto[cont-1])
		columnas = int(cripto[cont])
		cont = cont + 1
		if cont%2 == 0:
			filas = filas - 1
			columnas = columnas -1
			desci = desci + tabla[filas][columnas]

	# Decodifico el mensaje

	if args.b64 == True:

		conversion = base64.b64decode(desci)

		decoded = conversion.decode("utf-8")	
	
	# Mensaje normal	

	if args.b64 == False:

		decoded = desci

	# Guardo el mensaje en un archivo de texto

	salida = args.texto
	punto = salida.index(".")
	salida = salida[0:punto] + ".dec"
	cripto = open(salida, "w", encoding="ISO-8859-1")
	cripto.write(decoded)
	#print(len(desci_final))

	# Calculo del hash

	filename = '/root/Criptografia/' + salida
	hasher = hashlib.md5()
	with open(filename,"rb") as open_file:
		content = open_file.read()
		hasher.update(content)
	print ("Hash = ", hasher.hexdigest())

	
	tiempo_final = time()			       # Funcion de calculo de tiempo final
	tiempo_total = tiempo_final - tiempo_inicial   # Calculo el tiempo total de ejecucion
	print ("tiempo_total: ", tiempo_total)


# Cifrado matrices de hill

if args.hill == True and args.c == True:

	tiempo_inicial = time()


	mensaje=open(args.texto,'r',encoding="ISO-8859-1")
	mensaje=mensaje.read()

	matrix = np.int64(np.loadtxt(args.txtclave))	#Se crea una variable que lee la clave en forma matricial
	key= np.array(matrix,dtype=np.int64)		#Se crea una nueva variable donde se le asigna  la matrix clave.

	# bandera para activar la codificaciòn base 64

	if args.b64 == True:

		alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

		# Codifico el mensaje a base 64 de acuerdo al estandar utf-8

		conversion = mensaje.encode("utf-8")
	
		encoded = base64.b64encode(conversion)
	
		Mcodificado = encoded.decode("utf-8")

	if args.b64 == False:

		alfabeto = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZÜ«ÏÙÃÀ][%3_ "

		Mcodificado = mensaje
	

	def cuatrigramas(Mcodificado,alfabeto):


		j = 0

		vector=[]				# Variable para guardar el mensaje dividido en cuatrigramas

		vector=list(Mcodificado)


		if len(vector)%4==1:			#El Algoritmo de hill realiza la cifra mediante cuatrigramas, atravez del 
			vector.append("X")		#modulo se determina la cantidad de x a agregar para completar los cuatrigramas.
			vector.append("X")
			vector.append("X")

		if len(vector)%4==2:
			vector.append("X")
			vector.append("X")

		if len(vector)%4==3:
			vector.append("X")


		# Ciclo para convertir las letras a decimal de acuerdo a la posiciòn en el alfabeto

		for i in range(len(vector)):
			vector[i] = alfabeto.index(vector[i])

		newvector=[]
		for x in range(0,len(vector)//4):
			newvector.append(vector[j:j+4])		#Se divide el mensaje en grupos de 4 (cuatrigramas) y cada grupo se añade a un nuevo vector, que
			j=j+4						#contiene cuatrigramas

		return newvector

	#Codigo para cifrar el mensaje

	newvector=(cuatrigramas(Mcodificado,alfabeto))              #Atravez de la funcion cuatrigramas obtengo la representacion numerica del mensaje dividido

	# Calculo en nùmero de x para quitarlas en RX			
	
	numx = (len(newvector)*4-len(Mcodificado))

								     #en grupos de 4
	cipher=[]

	cipher_cod=""

	for i in range(0 ,len(newvector)):			     #El ciclo for permite realizar la multiplicacion entre cada uno de los cuatrigramas del
		c=np.dot(key, newvector[i])			     #del mensaje y la matriz clave key.
		resto=c % len (alfabeto)			     #Se obtiene el modulo de cada uno  los elementos resultantes  de la multiplicacion matricial
		cipher.append(resto)				     # y se añaden  un nuevo vector.


	for i in range(len(cipher)):				     #Los ciclos for permiten recuperar el mensaje original, asignado a cada elemnto 
		for j in cipher[i]:				     #la resptiva representacion dentro del alfabeto.
			cipher_cod+=alfabeto[j]


	cipher_cod += str(numx)

	salida = args.texto
	punto = salida.index(".")
	salida = salida[0:punto] + ".cif"
	cripto = open(salida, "w",encoding="ISO-8859-1")
	cripto.write(cipher_cod)

	#print(len(cipher_cod))


	# Calculo del hash

	filename = '/root/Criptografia/' + args.texto
	hasher = hashlib.md5()
	with open(filename,"rb") as open_file:
		content = open_file.read()
		hasher.update(content)
	print ("Hash = ", hasher.hexdigest())
	
	tiempo_final = time()			# funcion de calculo de tiempo final
	tiempo_total = tiempo_final - tiempo_inicial   #Calculo el tiempo total de ejecucion
	print ("tiempo_total: ", tiempo_total)

# Descifrado matrices de hill

if args.hill == True and args.d == True:


	tiempo_inicial = time()

	cipher_cod=open(args.texto,'r',encoding="ISO-8859-1")
	cipher_cod=cipher_cod.read()

	matrix = np.int64(np.loadtxt(args.txtclave))
	key= np.array(matrix,dtype=np.int64)

	#clave=open(args.txtclave,'r')	# leer archivo que contiene la clave
	#clave=clave.read()
	#print(len(clave))

	if args.b64 == True:
		
		alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

	if args.b64 == False:

		alfabeto = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZÜ«ÏÙÃÀ][%3_ "

	# Calculo el nùmero de X necesarios para eliminar el relleno

	numx = cipher_cod[len(cipher_cod)-1:len(cipher_cod)]

	cipher_cod = cipher_cod[0:len(cipher_cod)-1]

	decipher_cod = list(cipher_cod)						# Convierto el criptograma a una lista 

	# Ciclo para relacionar el mensaje con su represetacion numerica dentro del criptograma

	for i in range(len(decipher_cod)):
		decipher_cod[i] = alfabeto.index(decipher_cod[i])


	i=0
	decipher=[]
	for x in range(1,len(decipher_cod)//4+1):				#se divide el criptograma en grupos de 4 (cuatrigramas)
	    decipher.append(decipher_cod[i:i+4])
	    i=i+4

	inverse=np.linalg.inv(key)						#Se obtiene la inversa de la matrix clave
	inverse=np.around(inverse).astype(int)					#se realiza un redondeo de la inversa y se especifica que el tipo de dato sea entero
	inver_mod=inverse % len (alfabeto)					#se obtiene la inversa de la matrix_clave en modulo 65

	i=0
	cipher=[]
	for i in range(0,len(decipher)):					#El ciclo for permite realizar la multiplicacion entre cada cuatrigrama y la matrix inversa
		c=np.dot(inverse, decipher[i])
		resto=c % len (alfabeto)					#se obtiene el modulo de cada vector resultante y se añaden a un nuevo vector
		cipher.append(resto)


	vector=np.around(np.array(cipher))
	plain_text=""								#El ciclo for permite recuperar el texto en claro,asignando a cada elemento del vector
	for i in range(len(vector)):						#la respectiva representacion del alfabeto.
		for j in vector[i]:
			plain_text+=alfabeto[j]


	# Decodifico el mensaje descifrado de base64 a codigo ascci

	if args.b64 == True:

		conversion = base64.b64decode(plain_text)

		decoded = conversion.decode("utf-8")		# Variable para eliminar caracteres extras de la decodificaciòn

	if args.b64 == False:

		plain_text = plain_text[0:len(plain_text)-int(numx)]

		decoded = plain_text	

	# Guardo el mensaje

	salida = args.texto 
	punto = salida.index(".")
	salida = salida[0:punto] + ".dec"
	cripto = open(salida, "w",encoding="ISO-8859-1")
	cripto.write(decoded)


	# Calculo del hash

	filename = '/root/Criptografia/' + salida
	hasher = hashlib.md5()
	with open(filename,"rb") as open_file:
		content = open_file.read()
		hasher.update(content)
	print ("Hash = ", hasher.hexdigest())

	
	tiempo_final = time()			# funcion de calculo de tiempo final
	tiempo_total = tiempo_final - tiempo_inicial   #Calculo el tiempo total de ejecucion
	print("tiempo_total: ", tiempo_total)


# Cifrado playfair

if args.splay == True and args.c == True:

	tiempo_inicial = time()

	mensaje=open(args.texto,'r', encoding="ISO-8859-1")
	mensaje=mensaje.read()

	clave=open(args.txtclave,'r')
	clave=clave.read()

	pos_inicial = -1               # Variable para guardar las posiciones de Ñ y J
	espacios = []                  # cadena donde se guarda todas las posiciones
	lista = ""

	# Codifico el mensaje a base 64 de acuerdo al estandar utf-8

	if args.b64 == True:
	
	#Se define el alfabeto

		alfabeto="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=@?¿!.;["	

		conversion = mensaje.encode("utf-8")

		encoded = base64.b64encode(conversion)

		Mcodificado = encoded.decode("utf-8")


		#Mcodificado = "ERSAERTYHIIPI"

		#print(Mcodificado)

		#try:
		#	while True:
		#		pos_inicial=Mcodificado.index("=",pos_inicial+1)
		#		espacios.append(pos_inicial)
		#except ValueError:

		#	print(espacios)	

		#Mcodificado = Mcodificado[0:espacios[0]]

		#Funciones necesarias para cifrar el mensaje

		tamaño=range(len(mensaje))
		vector=[]

		for i in Mcodificado:
			vector.append(i)

		#Permite agregar un caracter(letra de menor frecuencia en el alfabeto) en caso de que 
		#M1 M2 tengan la misma letra.
		
		x=0	

		for i in range(len(vector)//2):
			if vector[x]==vector[x+1]:
				espacios.insert(x,str(x+1))
				vector.insert(x+1,'X')			
			x=x+2

		#Playfair se caracteriza porque realiza el cifrado en digramas, en caso de que el
		#mensaje tenga un numero impar de letras se añade una "X" al final del mensaje.

		if len(vector)%2==1:
			vector.append("X")
			espacios.insert(len(espacios)+1, str(len(vector)-1))

		#print(vector)	
		#print(espacios)
		#print(vector[int(espacios[1])])


		# Finalmente se debe agrupar el mensaje en grupos de 2 M1 M2

		i=0
		newvector=[]
		for x in range(1,len(vector)//2+1):
			newvector.append(vector[i:i+2])
			i=i+2

		#Esta funcion permite obtener la matriz clave para realizar el cifrado.

		matriz_clave=[]

		#Se añade cada letra de la clave a la matriz
		for e in clave:
			if e not in matriz_clave:
				matriz_clave.append(e)
		matriz_clave.remove("\n")


		#Se complementa la matriz clave,teniendo en cuenta el alfabeto

		for e in alfabeto:
			if e not in matriz_clave:
				matriz_clave.append(e)

		#Se crea un muevo vector que permite separar la matriz en grupos de 5, con
		#el fin de obtener la matriz 8x8

		matriz_grupo=[]
		for e in range(9):
			matriz_grupo.append('')

		matriz_grupo[0]=matriz_clave[0:8]
		matriz_grupo[1]=matriz_clave[8:16]
		matriz_grupo[2]=matriz_clave[16:24]
		matriz_grupo[3]=matriz_clave[24:32]
		matriz_grupo[4]=matriz_clave[32:40]
		matriz_grupo[5]=matriz_clave[40:48]
		matriz_grupo[6]=matriz_clave[48:56]
		matriz_grupo[7]=matriz_clave[56:64]
		matriz_grupo[8]=matriz_clave[64:72]

		
	#Esta funcion nos permite encontrar la posicion de un elemento en la matriz


		def position(m,elemento):
			x=y=0
			for i in range(9):
				for j in range(8):
					if m[i][j]==elemento:
						x=i
						y=j
			return x,y


	#Esta funcion permite cifrar el mensaje

		a = newvector
		m = matriz_grupo

		vector_playfair=[]
		for e in a:
			fila1,columna1=position(m,e[0])
			fila2,columna2=position(m,e[1])
		

			if fila1==fila2:
				if columna1==7:
					columna1=-1
				if columna2==7:
					columna2=-1
				vector_playfair.append(m[fila1][columna1+1])
				vector_playfair.append(m[fila1][columna2+1])


			elif columna1==columna2:
				if fila1==8:
					fila1=-1
				if fila2==8:
					fila2=-1
				vector_playfair.append(m[fila1+1][columna1])
				vector_playfair.append(m[fila2+1][columna1])

			else:
				vector_playfair.append(m[fila1][columna2])
				vector_playfair.append(m[fila2][columna1])

	# Mensaje sin codificar

	if args.b64 == False:

		alfabeto="ABCDEFGHIJKLMNÑOPQRSTUVWXYZÜ«ÏÙÃÀ][%3_ @ab"	

		Mcodificado = mensaje

		#Mcodificado = "ERSAERTYHIIPI"

		#print(Mcodificado)

		#try:
		#	while True:
		#		pos_inicial=Mcodificado.index("=",pos_inicial+1)
		#		espacios.append(pos_inicial)
		#except ValueError:

		#	print(espacios)	

		#Mcodificado = Mcodificado[0:espacios[0]]

		#Funciones necesarias para cifrar el mensaje

		tamaño=range(len(mensaje))
		vector=[]

		for i in Mcodificado:
			vector.append(i)

		#Permite agregar un caracter(letra de menor frecuencia en el alfabeto) en caso de que 
		#M1 M2 tengan la misma letra.
		
		x=0	

		for i in range(len(vector)//2):
			if vector[x]==vector[x+1]:
				espacios.insert(x,str(x+1))
				vector.insert(x+1,'X')			
			x=x+2

		#Playfair se caracteriza porque realiza el cifrado en digramas, en caso de que el
		#mensaje tenga un numero impar de letras se añade una "X" al final del mensaje.

		if len(vector)%2==1:
			vector.append("X")
			espacios.insert(len(espacios)+1, str(len(vector)-1))

		#print(vector)	
		#print(espacios)
		#print(vector[int(espacios[1])])


		# Finalmente se debe agrupar el mensaje en grupos de 2 M1 M2

		i=0
		newvector=[]
		for x in range(1,len(vector)//2+1):
			newvector.append(vector[i:i+2])
			i=i+2

		#Esta funcion permite obtener la matriz clave para realizar el cifrado.

		matriz_clave=[]

		#Se añade cada letra de la clave a la matriz
		for e in clave:
			if e not in matriz_clave:
				matriz_clave.append(e)
		matriz_clave.remove("\n")


		#Se complementa la matriz clave,teniendo en cuenta el alfabeto

		for e in alfabeto:
			if e not in matriz_clave:
				matriz_clave.append(e)

		#Se crea un muevo vector que permite separar la matriz en grupos de 5, con
		#el fin de obtener la matriz 8x8

		matriz_grupo=[]
		for e in range(7):
			matriz_grupo.append('')

		matriz_grupo[0]=matriz_clave[0:6]
		matriz_grupo[1]=matriz_clave[6:12]
		matriz_grupo[2]=matriz_clave[12:18]
		matriz_grupo[3]=matriz_clave[18:24]
		matriz_grupo[4]=matriz_clave[24:30]
		matriz_grupo[5]=matriz_clave[30:36]
		matriz_grupo[6]=matriz_clave[36:42]

	
	#Esta funcion nos permite encontrar la posicion de un elemento en la matriz


		def position(m,elemento):
			x=y=0
			for i in range(7):
				for j in range(6):
					if m[i][j]==elemento:
						x=i
						y=j
			return x,y


	#Esta funcion permite cifrar el mensaje

		a = newvector
		m = matriz_grupo

		vector_playfair=[]
		for e in a:
			fila1,columna1=position(m,e[0])
			fila2,columna2=position(m,e[1])
		

			if fila1==fila2:
				if columna1==5:
					columna1=-1
				if columna2==5:
					columna2=-1
				vector_playfair.append(m[fila1][columna1+1])
				vector_playfair.append(m[fila1][columna2+1])


			elif columna1==columna2:
				if fila1==6:
					fila1=-1
				if fila2==6:
					fila2=-1
				vector_playfair.append(m[fila1+1][columna1])
				vector_playfair.append(m[fila2+1][columna1])

			else:
				vector_playfair.append(m[fila1][columna2])
				vector_playfair.append(m[fila2][columna1])


	cifrado = ""

	for i in vector_playfair:
		cifrado += i
	
	#if len(espacios) == 1:

	#	cifrado = cifrado + "="
	#else:
	#	cifrado = cifrado + "=="


	for i in espacios:
		cifrado = cifrado + "*" + i

	cifrado += "*"
	

	salida = args.texto
	punto = salida.index(".")
	salida = salida[0:punto] + ".cif"
	cripto = open(salida, "w", encoding="ISO-8859-1")
	cripto.write(cifrado)
	#print(len(cifrado))

	# Calculo del hash

	filename = '/root/Criptografia/' + args.texto
	hasher = hashlib.md5()
	with open(filename,"rb") as open_file:
		content = open_file.read()
		hasher.update(content)
	print ("Hash = ", hasher.hexdigest())

	tiempo_final = time()			# funcion de calculo de tiempo final
	tiempo_total = tiempo_final - tiempo_inicial   #Calculo el tiempo total de ejecucion
	print("tiempo_total: ", tiempo_total)

# Descifrador Playfair

if args.splay == True and args.d == True:

	tiempo_inicial = time()

	criptograma=open(args.texto,'r', encoding="ISO-8859-1")
	criptograma=criptograma.read()

	clave=open(args.txtclave,'r')
	clave=clave.read()

	pos_inicial = -1               # Variable para guardar las posiciones de =
	espacios = []                  # cadena donde se guarda todas las posiciones
	posicionx = []
	separacion = []
	lista = ""

	try:
		while True:
			pos_inicial=criptograma.index("*",pos_inicial+1)
			espacios.append(pos_inicial)
	except ValueError:
		for i in range(len(espacios)-1):
			separacion.append(espacios[i+1]-espacios[i])
	#print(separacion)

	for j in range(len(separacion)):
		posicionx.append(criptograma[int(espacios[j])+1:int(espacios[j])+int(separacion[j])])

	#print(posicionx)

	criptograma = criptograma[0:espacios[0]]

	#print(criptograma)
	

#Esta funcion permite obtener la matriz clave para realizar el cifrado

	matriz_clave=[]
	#Se añade cada letra de la clave a la metriz
	for e in clave:
		if e not in matriz_clave:
			matriz_clave.append(e)
	matriz_clave.remove("\n")
		
	#Se define el alfabeto
	
	# Decodifico con base 64

	if args.b64 == True:

		alfabeto="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=@?¿!.;["

		#Se complementa la mariz_clave,teniendo en cuenta el alfabeto
		for e in alfabeto:
			if e not in matriz_clave:
				matriz_clave.append(e)
		
		#Se crea un muevo vector que permite separar la matriz en grupos de 5, con 
		#el fin de obtener la matriz 5x5

		matriz_grupo=[]

		for e in range(9):
			matriz_grupo.append('')

		matriz_grupo[0]=matriz_clave[0:8]
		matriz_grupo[1]=matriz_clave[8:16]
		matriz_grupo[2]=matriz_clave[16:24]
		matriz_grupo[3]=matriz_clave[24:32]
		matriz_grupo[4]=matriz_clave[32:40]
		matriz_grupo[5]=matriz_clave[40:48]
		matriz_grupo[6]=matriz_clave[48:56]
		matriz_grupo[7]=matriz_clave[56:64]
		matriz_grupo[8]=matriz_clave[64:72]

		# Esta funcionpermite dividir  el criptograma en Digramas

		i=0
		nuevocripto=[]
		for x in range(len(criptograma)//2):
			nuevocripto.append(criptograma[i:i+2])
			i=i+2

	#Esta funcion nos permite encontrar la posicion de un elemento en la matriz

		def position(m,elemento):
			x=y=0
			for i in range(9):
				for j in range(8):
					if m[i][j]==elemento:
						x=i
						y=j

			return x,y


	#Funcion de descifrado

		decifrado=[]

		c = nuevocripto
		m = matriz_grupo


		for e in c:
			fila1,columna1=position(m,e[0])
			fila2,columna2=position(m,e[1])
			if fila1==fila2:
				if columna1==7:
					columna1=-1
				if columna2==7:
					columna2=-1
				decifrado.append(m[fila1][columna1-1])
				decifrado.append(m[fila1][columna2-1])

			elif columna1==columna2:
				if fila1==8:
					fila1=-1
				if fila2==8:
					fila2=-1
				decifrado.append(m[fila1-1][columna1])
				decifrado.append(m[fila2-1][columna1])

			else:
				decifrado.append(m[fila1][columna2])
				decifrado.append(m[fila2][columna1])

	if args.b64 == False:

		alfabeto="ABCDEFGHIJKLMNÑOPQRSTUVWXYZÜ«ÏÙÃÀ][%3_ @ab"

		#Se complementa la mariz_clave,teniendo en cuenta el alfabeto
		for e in alfabeto:
			if e not in matriz_clave:
				matriz_clave.append(e)
		
		#Se crea un muevo vector que permite separar la matriz en grupos de 5, con 
		#el fin de obtener la matriz 5x5

		matriz_grupo=[]

		for e in range(7):
			matriz_grupo.append('')

		matriz_grupo[0]=matriz_clave[0:6]
		matriz_grupo[1]=matriz_clave[6:12]
		matriz_grupo[2]=matriz_clave[12:18]
		matriz_grupo[3]=matriz_clave[18:24]
		matriz_grupo[4]=matriz_clave[24:30]
		matriz_grupo[5]=matriz_clave[30:36]
		matriz_grupo[6]=matriz_clave[36:42]

		# Esta funcionpermite dividir  el criptograma en Digramas

		i=0
		nuevocripto=[]
		for x in range(len(criptograma)//2):
			nuevocripto.append(criptograma[i:i+2])
			i=i+2

	#Esta funcion nos permite encontrar la posicion de un elemento en la matriz

		def position(m,elemento):
			x=y=0
			for i in range(7):
				for j in range(6):
					if m[i][j]==elemento:
						x=i
						y=j

			return x,y


	#Funcion de descifrado

		decifrado=[]

		c = nuevocripto
		m = matriz_grupo


		for e in c:
			fila1,columna1=position(m,e[0])
			fila2,columna2=position(m,e[1])
			if fila1==fila2:
				if columna1==5:
					columna1=-1
				if columna2==5:
					columna2=-1
				decifrado.append(m[fila1][columna1-1])
				decifrado.append(m[fila1][columna2-1])

			elif columna1==columna2:
				if fila1==6:
					fila1=-1
				if fila2==6:
					fila2=-1
				decifrado.append(m[fila1-1][columna1])
				decifrado.append(m[fila2-1][columna1])

			else:
				decifrado.append(m[fila1][columna2])
				decifrado.append(m[fila2][columna1])



	ajuste = 0


	for i in posicionx:
		decifrado.pop(int(i)-ajuste)
		ajuste += 1

	#print(cifrado)

	descifrado = ""

	for i in decifrado:
		descifrado += i
		

	# Decodifico el mensaje descifrado de base64 a codigo ascci

	if args.b64 == True:

		conversion = base64.b64decode(descifrado)

		decoded = conversion.decode("utf-8")		# elimina caracteres extra de la codificacion

	if args.b64 == False:
	
		decoded = descifrado		

	salida = args.texto
	punto = salida.index(".")
	salida = salida[0:punto] + ".dec"
	cripto = open(salida, "w", encoding="ISO-8859-1")
	cripto.write(decoded)

	# Calculo del hash

	filename = '/root/Criptografia/' + salida
	hasher = hashlib.md5()
	with open(filename,"rb") as open_file:
		content = open_file.read()
		hasher.update(content)
	print ("Hash = ", hasher.hexdigest())

	tiempo_final = time()			# funcion de calculo de tiempo final
	tiempo_total = tiempo_final - tiempo_inicial   #Calculo el tiempo total de ejecucion
	print("tiempo_total: ", tiempo_total)


# cifrador vigenere rozier

if args.vroz == True and args.c == True:

	#Cargo el tiempo inicial del algoritmo
	tiempo_inicial = time()
	#Cargo el mensaje a cifrar
	mensaje = open (args.texto, 'r', encoding="ISO-8859-1")
	mensaje = mensaje.read()

	#Cargo la clave para cifrar el mensaje
	clave=open(args.txtclave,'r')
	clave = clave.read()
	clave = clave + clave[0]

	if args.b64 == True:

		# Codifico el mensaje a base 64 de acuerdo al estandar utf-8

		conversion = mensaje.encode("utf-8")

		encoded = base64.b64encode(conversion)

		Mcodificado = encoded.decode("utf-8")

		alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

	if args.b64 == False:

		Mcodificado = mensaje

		alphabet="ABCDEFGHIJKLMNÑOPQRSTUVWXYZÜ«ÏÙÃÀ][%3_ "

	#Variables para crear la nueva clave y la clave total de cifrado
	clave_lista = []
	new_clave = ""
	residuo = ""


	#Convierto el string de la clave a una lista, para eliminar errores "\n"

	for letras in clave:
		clave_lista.append(letras)
	clave_lista.remove("\n")


	posicion = []  # Variable para operar la letras y conformar la nueva clave

	comp = ""
	cifrado = ""
	msg_cifrado = ""

	# Encuentro la posicion de cada una de las letras de la clave en el alfabeto

	for letras in clave_lista:
		posicion.append(alphabet.index(letras))

	# Conformo la nueva clave utilizada para cifrar con el algoritmo de vigenere clasico.

	for x in range (1, (len(clave)-1)):
		operacion = (posicion[x] - posicion[x-1] ) % len (alphabet)
		new_clave = new_clave + alphabet[operacion]

	long_key = len(new_clave)
	long_msg = len(Mcodificado)
	# Completo la clave para cifrar el mensaje

	numero_key=long_msg//long_key

	# Conformo la clave total de cifrado

	clave_cifra = (new_clave*numero_key)
	residuo = long_msg%long_key

	clave_cifra = clave_cifra + new_clave[:residuo]

	#print(len(clave_cifra))
	#print(len(mensaje))

	# Cifro el mensaje de acuerdo a la ecuacion correspondiente de vigenere

	for x in range(0,long_msg):
		cifrado = (alphabet.index(Mcodificado[x]) + alphabet.index(clave_cifra[x])) % len (alphabet)
		msg_cifrado = msg_cifrado + alphabet[cifrado]

	#Guardo el criptograma en un texto cifrado
	salida = args.texto
	punto = salida.index(".")
	salida = salida[0:punto] + ".cif"
	cripto = open(salida, "w",encoding="ISO-8859-1")
	cripto.write(msg_cifrado)

	# Calculo del hash

	filename = '/root/Criptografia/' + args.texto
	hasher = hashlib.md5()
	with open(filename,"rb") as open_file:
		content = open_file.read()
		hasher.update(content)
	print ("Hash = ", hasher.hexdigest())

	#Calculo el tiempo total de ejecuciòn del cifrado
	tiempo_final = time()
	tiempo_total = tiempo_final-tiempo_inicial
	print(tiempo_total)


# Descifrado vigenere rozier


if args.vroz == True and args.d == True:

	#Cargo el tiempo inicial del algoritmo
	tiempo_inicial = time()
	#Cargo el criptograma a descifrar
	criptograma = open (args.texto, 'r',encoding="ISO-8859-1")
	criptograma = criptograma.read()

	#Cargo la clave para descifrar el criptograma
	clave=open(args.txtclave,'r')
	clave = clave.read()
	clave = clave + clave[0]

	clave_lista = []
	new_clave = ""
	residuo = ""
	#Convierto el string de la clave a una lista, para eliminar errores "\n"

	for letras in clave:
		clave_lista.append(letras)
	clave_lista.remove("\n")

	if args.b64 == True:

		alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

	if args.b64 == False:

		alphabet="ABCDEFGHIJKLMNÑOPQRSTUVWXYZÜ«ÏÙÃÀ][%3_ "

	posicion = []  # Variable para operar la letras y conformar la nueva clave

	comp = ""
	descifrado = ""
	msg_descifrado = ""

	# Encuentro la posicion de cada una de las letras de la clave en el alfabeto

	for letras in clave_lista:
		posicion.append(alphabet.index(letras))

	# Conformo la nueva clave utilizada para cifrar con el algoritmo de vigenere clasico.

	for x in range (1, (len(clave)-1)):
		operacion = (posicion [x] - posicion[x-1] ) % len (alphabet)
		new_clave = new_clave + alphabet[operacion]

	long_key = len(new_clave)
	long_msg = len(criptograma)

	numero_key=long_msg//long_key

	# Conformo la clave total de descifrado

	clave_cifra = (new_clave*numero_key)

	residuo = long_msg%long_key

	clave_cifra = clave_cifra + new_clave[:residuo]

	#print(clave_cifra)
	#print(len(criptograma))

	# Descifro el criptograma de acuerdo a la ecuacion correspondiente de vigenere

	for x in range(0,long_msg):
		descifrado = (alphabet.index(criptograma[x]) - alphabet.index(clave_cifra[x])) % len (alphabet)
		msg_descifrado = msg_descifrado + alphabet[descifrado]


	# Decodifico el mensaje descifrado de base64 a codigo ascci

	if args.b64 == True:

		conversion = base64.b64decode(msg_descifrado)

		decoded = conversion.decode("utf-8")		# elimina caracteres extra de la codificacion

	if args.b64 == False:

		decoded = msg_descifrado

	#Guardo el mensaje descifrado en un texto correspondiente
	salida = args.texto
	punto = salida.index(".")
	salida = salida[0:punto] + ".dec"
	cripto = open(salida, "w",encoding="ISO-8859-1")
	cripto.write(decoded)

	# Calculo del hash

	filename = '/root/Criptografia/' + salida
	hasher = hashlib.md5()
	with open(filename,"rb") as open_file:
		content = open_file.read()
		hasher.update(content)
	print ("Hash = ", hasher.hexdigest())

	#Calculo el tiempo total de ejecuciòn del cifrado
	tiempo_final = time()
	tiempo_total = tiempo_final-tiempo_inicial
	print(tiempo_total)

if args.tg == False and args.spol == False and args.splay == False and args.vroz == False and args.hill == False and args.c == False and args.d == False:
	print("""
        ---------------------------UNIVERSIDAD DEL CAUCA---------------------------
        ------------------------Algoritmos Criptograficos--------------------------
        |                                                                         |
	|                							  |
        |     Sintaxis: ./menu <algoritmo>                                        |
        |                                                                         |
        |     -tg      :Algoritmo de Trasposicion por grupos                      |
        |     -spol    :Algoritmo de sustitucion monoalfabetica Polybios          |
        |     -splay   :Algoritmo de sustitucion monoalfabetica Playfair          |
        |     -vro>    :Cifrado polialfabetico de vigenère rozie                  |
	|     -hill    :Cifrado de sustitucion poligrafica (matrices de hill)     |
	|                     						          |
	|       consultar ayuda de un algoritmo determinado:                      |
	|       sintaxis: ./menu.py < algoritmo > 				  |
	|									  |
	|   Introducciòn a la criptografia.					  |
	|   Profesor: Siler Amador Donado.					  |
	|   Semestre 2018-2.							  |
	|   Elaborado por: Esteban Arteaga     estebanben@unicauca.edu.co	  |
	|		   German Moran        germanmoran@unicauca.edu.co	  |
	|-------------------------------------------------------------------------|
        """)


