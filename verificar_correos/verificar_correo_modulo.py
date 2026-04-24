import getpass
import os
import logging
import requests
import csv

brechas = None

def leer_archivo():
	if not os.path.exists("apikey.txt"):
		print("No se encontró el archivo apikey.txt")
		clave = getpass.getpass("Ingresa tu API key: ")
		with open("apikey.txt", "w") as archivo:
			archivo.write(clave.strip())
			logging.info("Exito con guardar la llave")
	else:
		print("Ya existe el archivo apikey.txt")

def consultar_brechas():
	global brechas

	try:
		with open("apikey.txt", "r") as f:
			apikey = f.read().strip()
	except FileNotFoundError:
		print("Aun no existe la apikey")
		return None

	correo = input("Ingrese el correo a analizar brechas: ")
	urlhibp = f"https://haveibeenpwned.com/api/v3/breachedAccount/{correo}"
	headers = {
		"hibp-api-key": apikey,
		"user-agent": "verificar_correo/1.0"
	}
	try:
		response = requests.get(urlhibp, headers=headers)
		if response.status_code == 200:
			brechas = response.json()
			logging.info(f"Consulta exitosa a {correo}, ¡Encontraron {len(brechas)}brechas!")
			for i, brecha in enumerate(brechas, start=1):
				print(f"Brecha {i}")

				titulo = brecha.get('Title') or brecha.get('Name') or 'No disponible'
				dominio = brecha.get('Domain') or 'No disponible'
				fecha = brecha.get('BreachDate') or 'No disponible'
				datos_comprometidos = brecha.get('DataClasses')

				if datos_comprometidos and isinstance(datos_comprometidos, list):
					datos_brecha = ", ".join(datos_comprometidos)
				else:
					datos_brecha = "No especificado"

				verificado = "Si" if brecha.get('IsVerified') else 'No'
				sensible = "Si" if brecha.get('IsSensitive') else 'No'
	
				print(f"Titulo: {titulo}\nDominio: {dominio}")
				print(f"Dia: {fecha}\nDatos Comprometidos: {datos_brecha}")
				print(f"Verificado: {verificado}\nSensible: {sensible}")

				pwn_cuentas = brecha.get('PwnCount')
				if pwn_cuentas:
					print(f'Cuentas afectadas: {pwn_cuentas:,}')

			return brechas

		elif response.status_code == 404:
			logging.info(f"Cnosulta exitosa a {correo}, ¡No se encontraron brechas!")
			print(f"Consulta exitosa a {correo}, ¡No te encontraron brechas!")
			brechas = []
			return []

		elif response.status_code == 401:
			logging.error("Error 401: Error con la ApiKey")
			print("Error con la ApiKey")
			return None

		else:
			logging.error("Error inesperado")
			print("Error inesperado")
			return None

	except Exception as e:
			logging.error(f"Error {e}")
			print(f"Error {e}")
			return None

def detalles_brecha():
	global brechas
	
	if brechas is None:
		logging.info("No hay correo analizado")
		print("Primero debes consultar brechas")
		return

	if not brechas:
		logging.info("No hay brechas en el correo")
		print("No hay brechas para mostrar")
		return

	for i, brecha in enumerate(brechas, start=1):
		print(f"{i}.Nombre: {brecha.get("Name", "No disponible")}\nFecha:{brecha.get("BreachDate", "No disponible")}")

		ver_detalles = input("¿Ver detalles de brecha? (s/n)?: ").lower()
		if ver_detalles == "s":
			num_detalles = int(input("Elige numero de brecha a mostrar: "))
			if num_detalles >= 1 and num_detalles <= len(brechas):
				brecha_detalles = brechas[num_detalles - 1]
				print(f"Nombre: {brecha_detalles.get("Name", "No disponible")}")
				print(f"Descripcion: {brecha_detalles.get("Description", "No disponible")}")
				print(f"Datos: {", ".join(brecha_detalles.get("DataClasses", []))}")
			else:
				print("Opcion invalida")
		else:
			print("Saliendo")

def generar_csv():
	global brechas

	if brechas is None:
		logging.info("No hay correo analizado")
		print("Primero debes consultar brechas")
		return

	if not brechas:
		print("No hay brechas que guardar, el correo esta seguro")
		logging.info("El correo esta seguro")
	try:	
		with open("registro.csv", "w", newline="", encoding="utf-8") as archivo_csv:
			writer = csv.writer(archivo_csv)
			writer.writerow(["Titulo", "Dominio", "Fecha de Brecha", "Datos Comprometidos",  "Verificada", "Sensible"])
			for brecha in brechas:
				writer.writerow([
					brecha.get("Title", "No disponible"),
					brecha.get("Domain", "No disponible"),
					brecha.get("BreachDate", "No disponible"),
					", ".join(brecha.get("DataClasses", [])),
					brecha.get("IsVerified", False),
					brecha.get("IsSensitive", False)
				])
			logging.info("Reporte csv generado con exito")
			print("Archivo registro.csv guardado")
	except Exception as e:
		logging.error(f"Error al guardar CSV: {e}")
		print(f"Error al guardar CSV: {e}")

def iniciar_logging():
	logging.basicConfig(
	filename="registro.log",
	level=logging.INFO,
	format="%(asctime)s - %(levelname)s - %(message)s"
	)
	print("Logging creado con exito")

def mostrar_menu():
	while True:
		print("===Brecha en correos con HIBP===")
		print("1) Crear archivo apikey.txt\n2) Consultar brechas en un correo")
		print("3) Analizar detalles de una brecha\n4) Generar reporte_csv")
		print("5) Iniciar logging\n6) Salir")	
		try:
			opcion = int(input("Selecciona una opcion: "))
			os.system("cls" if os.name == "nt" else "clear")
			if opcion == 1:
				leer_archivo()
				print()
			elif opcion == 2:
				consultar_brechas()
				print()
			elif opcion == 3:
				detalles_brecha()
				print()
			elif opcion == 4:
				generar_csv()
				print()
			elif opcion == 5:
				iniciar_logging()
				print()
			elif opcion == 6:
				break
			else:
				print("Opcion invalida")
		except ValueError:
			print("Opcion invalida")
			os.system("cls" if os.name == "nt" else "clear")