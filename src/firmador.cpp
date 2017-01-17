/* Firmador is a program that communicates web browsers with smartcards.

Copyright (C) 2017 Francisco de la Peña Fernández.

This file is part of Firmador.

Firmador is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Firmador is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Firmador.  If not, see <http://www.gnu.org/licenses/>.  */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <gnutls/pkcs11.h>
#include <gnutls/abstract.h>
/* FIXME: Es de POSIX, reemplazar luego con wxPasswordEntryDialog */
#include <unistd.h>
#include "firmador.h"

wxIMPLEMENT_APP(Firmador);

static int pin_callback(void *user, int attempt, const char *token_url,
	const char *token_label, unsigned int flags, char *pin,
	size_t pin_max) {

	const char *password;
	int len;

	/* No se usan esta variables, silenciar al compilador */
	(void)user;
	(void)attempt;
	(void)token_url;

	if (flags & GNUTLS_PIN_FINAL_TRY)
		printf("*** ADVERTENCIA: este es el ultimo intento antes de bloquear la tarjeta!\n");
	if (flags & GNUTLS_PIN_COUNT_LOW)
		printf("*** AVISO: quedan pocos intentos antes de bloquear la tarjeta!\n");
	if (flags & GNUTLS_PIN_WRONG)
		printf("*** PIN incorrecto\n");

	printf("Identificador: '%s'.\n", token_label);
	password = getpass("Introduce el PIN: ");
	if (password == NULL || password[0] == 0) {
		fprintf(stderr, "No se ha introducido ningun valor.\n");
		exit(1);
	}

	len = std::min(pin_max - 1, strlen(password));
	memcpy(pin, password, len);
	pin[len] = 0;

	return 0;
}

bool Firmador::OnInit() {

	gnutls_pkcs11_set_pin_function(pin_callback, NULL);

	int ret;

	ret = gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL);

	if (ret < GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Error al inicializar: %s\n",
			gnutls_strerror(ret));
		exit(ret);
	}

	/*
	 * Ruta a la libreria PKCS #11 o al nombre del modulo en p11-kit.
	 * Si la libreria es privativa no afecta al programa GPL porque
	 * se encarga p11-kit de manejarlo.
	 */
	ret = gnutls_pkcs11_add_provider("libASEP11.so", NULL);

	if (ret < GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Error al agregar proveedor: %s\n",
			gnutls_strerror(ret));
		exit(ret);
	}

	/*
	 * Obtiene un listado de todos los token conectados
	 * (aunque normalmente haya uno) y lo guarda en token_urls.
	 */
	std::vector<std::string> token_urls;
	for (size_t i = 0; ; i++) {
		char* url;
		ret = gnutls_pkcs11_token_get_url(i,
			GNUTLS_PKCS11_URL_GENERIC, &url);

		if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			break;
		}

		if (ret < GNUTLS_E_SUCCESS) {
			fprintf(stderr,
				"Error al obtener identificadores: %s\n",
				gnutls_strerror(ret));
			exit(ret);
		}

		token_urls.push_back(url);
		gnutls_free(url);
	}

	gnutls_pkcs11_obj_t* obj_list;
	std::vector<gnutls_pkcs11_obj_t*> token_obj_lists;
	std::vector<unsigned int> token_obj_lists_sizes;
	unsigned int obj_list_size = 0;
	/*
	 * Importa todos los objetos de tipo certificado de los tokens y
	 * guarda la lista de certificados de cada token en un obj_list,
	 * guardando la cantidad en obj_list_size y guardando estos de cada
	 * token en vectores.
	 */
	for (size_t i = 0; i < token_urls.size(); i++) {
		ret = gnutls_pkcs11_obj_list_import_url2(&obj_list,
			&obj_list_size, token_urls.at(i).c_str(), 0,
			GNUTLS_PKCS11_OBJ_FLAG_CRT);

		if (ret < GNUTLS_E_SUCCESS) {
			fprintf(stderr,
				"Error al importar objetos de tipo certificado del identificador %lu: %s\n",
				i, gnutls_strerror(ret));
			exit(ret);
		}
		token_obj_lists.push_back(obj_list);
		token_obj_lists_sizes.push_back(obj_list_size);
	}

	std::multimap<std::string, std::string> candidate_certs;
	/* Muestra los certificados en pantalla. */
	for (size_t i = 0; i < token_obj_lists_sizes.size(); i++) {
		for (size_t j = 0; j < token_obj_lists_sizes.at(i); j++) {
			gnutls_x509_crt_t cert;
			ret = gnutls_x509_crt_init(&cert);

			if (ret < GNUTLS_E_SUCCESS) {
				fprintf(stderr,
					"Error al crear estructura del certificado %lu del identificador %lu: %s\n",
					j, i, gnutls_strerror(ret));
				exit(ret);
			}

			ret = gnutls_x509_crt_import_pkcs11(cert,
				token_obj_lists.at(i)[j]);

			if (ret < GNUTLS_E_SUCCESS) {
				fprintf(stderr,
					"Error al importar el certificado %lu del identificador %lu: %s\n",
					j, i, gnutls_strerror(ret));
				exit(ret);
			}

			char givenname[32];
			size_t givenname_size = sizeof(givenname);
			gnutls_x509_crt_get_dn_by_oid(cert,
				GNUTLS_OID_X520_GIVEN_NAME, 0, 0, givenname,
				&givenname_size);

			if (ret < GNUTLS_E_SUCCESS) {
				fprintf(stderr,
					"Error al obtener el nombre del certificado %lu del identificador %lu: %s\n",
					j, i, gnutls_strerror(ret));
				exit(ret);
			}

			char surname[80];
			size_t surname_size = sizeof(surname);
			gnutls_x509_crt_get_dn_by_oid(cert,
				GNUTLS_OID_X520_SURNAME, 0, 0, surname,
				&surname_size);

			if (ret < GNUTLS_E_SUCCESS) {
				fprintf(stderr,
					"Error al obtener el apellido del certificado %lu del identificador %lu: %s\n",
					j, i, gnutls_strerror(ret));
				exit(ret);
			}

			char serialnumber[128];
			size_t serialnumber_size = sizeof(serialnumber);
			gnutls_x509_crt_get_dn_by_oid(cert, "2.5.4.5", 0, 0,
				serialnumber, &serialnumber_size);

			if (ret < GNUTLS_E_SUCCESS) {
				fprintf(stderr,
					"Error al obtener el numero de documento del certificado %lu del identificador %lu: %s\n",
					j, i, gnutls_strerror(ret));
				exit(ret);
			}

			char obj_label[384];
			size_t obj_label_size = sizeof(obj_label);
			ret = gnutls_pkcs11_obj_get_info(token_obj_lists.at(i)[j],
				GNUTLS_PKCS11_OBJ_LABEL, obj_label,
				&obj_label_size);

			if (ret < GNUTLS_E_SUCCESS) {
				fprintf(stderr, "Error al obtener la etiqueta del certificado %lu: %s\n",
					j, gnutls_strerror(ret));
				exit(ret);
			}

			char obj_id[384];
			size_t obj_id_size;
			obj_id_size = sizeof(obj_id);
			ret = gnutls_pkcs11_obj_get_info(token_obj_lists.at(i)[j],
				GNUTLS_PKCS11_OBJ_ID_HEX, obj_id,
				&obj_id_size);

			if (ret < GNUTLS_E_SUCCESS) {
				fprintf(stderr, "Error al obtener el identificador del certificado %lu del identificador %lu: %s\n",
					j, i, gnutls_strerror(ret));
				exit(ret);
			}

			printf("Identificador %lu: Certificado %lu: %s %s (Documento: %s, etiqueta: %s, ID: %s)\n",
				i, j, givenname, surname, serialnumber,
				obj_label, obj_id);

			unsigned int keyusage;
			ret = gnutls_x509_crt_get_key_usage(cert, &keyusage,
				NULL);

			if (keyusage & GNUTLS_KEY_NON_REPUDIATION) {
				printf("La clave del identificador %lu, certificado %lu es adecuada para firmar porque tiene uso 'no repudio'.\n",
					i, j);
				char *obj_url;
				ret = gnutls_pkcs11_obj_export_url(token_obj_lists.at(i)[j], GNUTLS_PKCS11_URL_GENERIC, &obj_url);
				if (ret < GNUTLS_E_SUCCESS) {
					fprintf(stderr,
						"Error al obtener la URL del certificado %lu del identificador %lu: %s\n",
						j, i,
						gnutls_strerror(ret));
					exit(ret);
				}
				candidate_certs.insert(
					std::pair<std::string, std::string>(
						token_urls.at(i), obj_url
					)
				);
				gnutls_free(obj_url);
			}
			gnutls_x509_crt_deinit(cert);
		}
	}

	gnutls_privkey_t key;
	ret = gnutls_privkey_init(&key);

	if (ret < GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Error al inicializar la clave privada: %s\n", gnutls_strerror(ret));
		exit(ret);
	}

	// TODO: iterar multimap para insertar las cadenas en la listbox

	/*
	// TODO: tras seleccionarse en el listbox, cargar el token
	//       correspondiente, esta vez con PIN para poder usar la
	//       clave privada para poder firmar
	ret = gnutls_pkcs11_obj_import_url(obj_list[i], url, GNUTLS_PKCS11_OBJ_FLAG_PRIVKEY);
	if (ret < GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Error al importar la URL de la clave privada para el certificado %lu: %s\n", i, gnutls_strerror(ret));
		exit(ret);
	}
	*/
	/*
	// TODO: firmar datos eventualmente
	gnutls_datum_t data = {(unsigned char*)"hola", 4};
	gnutls_datum_t sig;
	ret = gnutls_privkey_sign_data(key, GNUTLS_DIG_SHA256, 0, &data, &sig);

	if (ret < GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Error al firmar datos con la clave privada del certificado %lu: %s\n", i, gnutls_strerror(ret));
		exit(ret);
	}
	*/
	for (size_t i = 0; i < token_obj_lists_sizes.size(); i++) {
		for (size_t j = 0; j < token_obj_lists_sizes.at(i); j++) {
			gnutls_pkcs11_obj_deinit(token_obj_lists.at(i)[j]);
		}
	}

	if (obj_list_size > 0) {
		gnutls_free(obj_list);
	}

	gnutls_pkcs11_deinit();

	return false; // FIXME: cambiar a true cuando haya GUI
}

