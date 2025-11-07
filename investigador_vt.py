
import requests
import json
import time

# --- CONFIGURACIÓN ---
API_KEY = "8954bd730114e5fd9adf5a8a245793d32c3d09450c11f43721b913d154621aca" # ¡Reemplaza con tu propia API Key!
BASE_URL = "https://www.virustotal.com/api/v3/"

# --- FUNCIÓN PARA CONSULTAR HASH ---
def consultar_hash_archivo(hash_sha256):
    print(f"\n--- Consultando HASH: {hash_sha256} ---")
    endpoint = f"files/{hash_sha256}"
    headers = {
        "x-apikey": API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(BASE_URL + endpoint, headers=headers)
        response.raise_for_status() # Lanza un error para códigos de estado HTTP 4xx/5xx
        response.raise_for_status
        data = response.json()

        if response.status_code == 200:
            # Extraer información relevante
            atributos = data['data']['attributes']
            print(f"Nombre del archivo (si está disponible): {atributos.get('meaningful_name', 'N/A')}")
            print(f"Tamaño: {atributos.get('size', 'N/A')} bytes")

            # Obtener análisis de reputación
            malicious_votes = atributos['last_analysis_stats']['malicious']
            suspicious_votes = atributos['last_analysis_stats']['suspicious']
            undetected_votes = atributos['last_analysis_stats']['undetected']
            timeout_votes = atributos['last_analysis_stats']['timeout']
            harmless_votes = atributos['last_analysis_stats']['harmless']

            total_votes = malicious_votes + suspicious_votes + undetected_votes + timeout_votes + harmless_votes

            print(f"\nResultados del análisis (de {total_votes} motores):")
            print(f"  Maliciosos: {malicious_votes}")
            print(f"  Sospechosos: {suspicious_votes}")
            print(f"  Inofensivos: {harmless_votes}")
            print(f"  No detectados: {undetected_votes}")

            if malicious_votes > 0 or suspicious_votes > 0:
                print("\n¡ADVERTENCIA! Este archivo parece ser MALICIOSO o SOSPECHOSO.")
            else:
                print("\nEste archivo parece ser LIMPIO.")

        else:
            print(f"Error al consultar el HASH. Código de estado: {response.status_code}")
            print(f"Mensaje: {data.get('error', {}).get('message', 'No hay mensaje de error adicional.')}")

    except requests.exceptions.HTTPError as err:
        print(f"Error HTTP: {err}")
        if response.status_code == 401:
            print("Error: API Key no válida o no autorizada. Revisa tu clave.")
        elif response.status_code == 404:
            print("Error: El hash del archivo no fue encontrado en VirusTotal.")
        elif response.status_code == 429:
            print("Error: Límite de solicitudes excedido. Espera un momento y vuelve a intentarlo.")
    except requests.exceptions.ConnectionError as err:
        print(f"Error de conexión: {err}")
    except requests.exceptions.Timeout as err:
        print(f"Tiempo de espera agotado: {err}")
    except requests.exceptions.RequestException as err:
        print(f"Ocurrió un error inesperado: {err}")
    except json.JSONDecodeError:
        print("Error al decodificar la respuesta JSON. La respuesta no es un JSON válido.")
    except Exception as e:
        print(f"Un error inesperado ocurrió: {e}")
# ... (código anterior) ...

# --- FUNCIÓN PARA CONSULTAR URL/DOMINIO ---
def consultar_url_dominio(url_o_dominio):
    print(f"\n--- Consultando URL/Dominio: {url_o_dominio} ---")
    # Primero, se debe "enviar" la URL para análisis si no ha sido analizada recientemente.
    # Esto requiere una solicitud POST, luego una GET para el informe.

    # Paso 1: Enviar la URL para análisis (POST request)
    print("Enviando URL para análisis...")
    submit_endpoint = "urls"
    headers = {
        "x-apikey": API_KEY,
        "Accept": "application/json"
    }
    data = {'url': url_o_dominio}

    try:
        submit_response = requests.post(BASE_URL + submit_endpoint, headers=headers, data=data)
        submit_response.raise_for_status()
        submit_data = submit_response.json()

        if submit_response.status_code == 200:
            analysis_id = submit_data['data']['id']
            print(f"URL enviada. ID del análisis: {analysis_id}")
            print("Esperando unos segundos para que se procese el análisis...")
            import time
            time.sleep(10) # Esperar un momento para que VirusTotal procese la URL

            # Paso 2: Obtener el informe del análisis (GET request)
            report_endpoint = f"analyses/{analysis_id}"
            report_response = requests.get(BASE_URL + report_endpoint, headers=headers)
            report_response.raise_for_status()
            report_data = report_response.json()

            if report_response.status_code == 200:
                status = report_data['data']['attributes']['status']
                print(f"Estado del análisis: {status}")

                if status == "completed":
                    # Obtener resultados finales del análisis de la URL
                    url_id= analysis_id.split("-")[1]
                    url_info_endpoint = f"urls/{url_id}" # El ID de la URL es diferente al ID del análisis
                    final_url_response = requests.get(BASE_URL + url_info_endpoint, headers=headers)
                    final_url_response.raise_for_status()
                    final_url_data = final_url_response.json()

                    url_attributes = final_url_data['data']['attributes']
                    malicious_votes = url_attributes['last_analysis_stats']['malicious']
                    suspicious_votes = url_attributes['last_analysis_stats']['suspicious']
                    undetected_votes = url_attributes['last_analysis_stats']['undetected']
                    harmless_votes = url_attributes['last_analysis_stats']['harmless']

                    total_votes = malicious_votes + suspicious_votes + undetected_votes + harmless_votes

                    print(f"\nResultados del análisis de URL (de {total_votes} motores):")
                    print(f"  Maliciosos: {malicious_votes}")
                    print(f"  Sospechosos: {suspicious_votes}")
                    print(f"  Inofensivos: {harmless_votes}")
                    print(f"  No detectados: {undetected_votes}")

                    if malicious_votes > 0 or suspicious_votes > 0:
                        print("\n¡ADVERTENCIA! Esta URL/Dominio parece ser MALICIOSO o SOSPECHOSO.")
                    else:
                        print("\nEsta URL/Dominio parece ser LIMPIO.")
                else:
                    print("El análisis de la URL aún no ha finalizado. Intenta de nuevo más tarde.")
            else:
                print(f"Error al obtener el informe de la URL. Código de estado: {report_response.status_code}")
                print(f"Mensaje: {report_data.get('error', {}).get('message', 'No hay mensaje de error adicional.')}")
        else:
            print(f"Error al enviar la URL para análisis. Código de estado: {submit_response.status_code}")
            print(f"Mensaje: {submit_data.get('error', {}).get('message', 'No hay mensaje de error adicional.')}")

    except requests.exceptions.HTTPError as err:
        print(f"Error HTTP: {err}")
        if submit_response.status_code == 401:
            print("Error: API Key no válida o no autorizada. Revisa tu clave.")
        elif submit_response.status_code == 400:
            print("Error: La URL enviada no es válida o está en un formato incorrecto.")
        elif submit_response.status_code == 429:
            print("Error: Límite de solicitudes excedido. Espera un momento y vuelve a intentarlo.")
    except requests.exceptions.ConnectionError as err:
        print(f"Error de conexión: {err}")
    except requests.exceptions.Timeout as err:
        print(f"Tiempo de espera agotado: {err}")
    except requests.exceptions.RequestException as err:
        print(f"Ocurrió un error inesperado: {err}")
    except json.JSONDecodeError:
        print("Error al decodificar la respuesta JSON. La respuesta no es un JSON válido.")
    except Exception as e:
        print(f"Un error inesperado ocurrió: {e}")

# Modificar la función `main()` para incluir la opción de URL/Dominio
def main():
    print("Bienvenido al Investigador de Ciberseguridad con VirusTotal.")
    while True:
        print("\n¿Qué deseas investigar?")
        print("1. HASH de archivo (SHA256)")
        print("2. URL/Dominio")
        print("3. Salir")

        opcion = input("Elige una opción: ")

        if opcion == '1':
            hash_input = input("Introduce el HASH SHA256 del archivo (ej. db82b260f913d09a061414441b8ac5ed53e344e66c757a3e792f33c0429f4b52): ")
            longitud=len(hash_input)
            print(f"El texto ingresado tiene {longitud}caracteres.")
            if longitud == 64:
               consultar_hash_archivo(hash_input.lower())
            else:
                print("Advertencia: el texto no tiene 64 caracteres, puede no ser un SHA256 valido.")
        elif opcion == '2':
            url_input = input("Introduce la URL o Dominio a investigar (ej. https://ejemplo.com/malware.exe o www.phishing-sitio.net): ")
            consultar_url_dominio(url_input)
        elif opcion == "3":
            print("Saliendo del programa...")
            break
if __name__ == "__main__":
    main()
