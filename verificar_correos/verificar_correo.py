import getpass
import os
import logging
import requests as re
import csv

if not os.path.exists("apikey.txt"):
	print("No se encontró el archivo apikey.txt")
	clave = getpass.getpass("Ingresa tu API key: ")
	with open("apikey.txt", "w") as archivo:
		archivo.write(clave.strip())

with open("apikey.txt", "r") as f:
	apikey = f.read().strip()

logging.basicConfig(
	filename="registro.log",
	level=logging.INFO,
	format="%(asctime)s - %(levelname)s - %(message)s"
)

correo = input("Ingrese el correo a analizar brechas: ")

urlhibp = f"https://haveibeenpwned.com/api/v3/breachedAccount/{correo}"
headers = {
	"hibp-api-key": apikey,
	"user-agent": "verificar_correo/1.0"
}

try:
	response = re.get(urlhibp, headers=headers)

	if response.status_code == 200:
		brechas = response.json()
		logging.info(f"Consulta exitosa para {correo}. Brechas encontradas: {len(brechas)}")	
		with open("reporte.csv", "w", newline='', encoding="utf-8") as archivo_csv:
			writer = csv.writer(archivo_csv)
			writer.writerow(["Título", "Dominio", "Fecha de Brecha", "Datos Comprometidos",  "Verificada", "Sensible"])
			for brecha in brechas:
				writer.writerow([
					brecha.get("Title", ""),
					brecha.get("Domain", ""),
					brecha.get("BreachDate", ""),
					", ".join(brecha.get("DataClasses", [])),
					brecha.get("IsVerified", False),
					brecha.get("IsSensitive", False)
				])
		print("Archivo csv guardado")

	elif response.status_code == 404:
		logging.info(f"Consulta exitosa para {correo}. No se encontraron brechas.")
		print("No se hallaron brechas en el correo")
		with open("reporte.csv", "w", newline= "", encoding="utf-8") as archivo_csv:
			writer = csv.writer(archivo_csv)
			writer.writerow(["Título", "Dominio", "Fecha de Brecha", "Datos Comprometidos",  "Verificada", "Sensible"])
			writer.writerow(["No se encontraron brechas", correo])
			print("Archivo csv guardado")
	elif response.status_code == 401:
		logging.error("Error 401: API key inválida.")
		print(f"Llave invalida")

	else:
		logging.error(f"Error inesperado. Código de estado: {response.status_code}")
		print(f"Error {response.status_code}")

except Exception as e:
	logging.error(f"Error al escribir reporte.csv: {e}")
	print(f"Error {e}")