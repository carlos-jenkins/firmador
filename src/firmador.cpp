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
#include <string>
#include <vector>
#include <gnutls/pkcs11.h>
/* FIXME: Es de POSIX, reemplazar luego con wxPasswordEntryDialog */
#include <unistd.h>

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

int main() {
	int ret;
	unsigned int i;
	char* url;
	std::vector<std::string> token_urls;
	gnutls_pkcs11_obj_t* obj_list;
	unsigned int obj_list_size = 0;
	gnutls_x509_crt_t cert;
	/* Segun el RFC 5280 el givenName es hasta 16, pero por aquello */
	char givenname[32];
	size_t givenname_size;
	/* Segun el RFC 5280 el surname es hasta 40, pero por aquello */
	char surname[80];
	size_t surname_size;
	unsigned int keyusage;

	gnutls_pkcs11_set_pin_function(pin_callback, NULL);

	ret = gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL);

	if (ret < GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Error al inicializar: %s\n", gnutls_strerror(ret));
		exit(ret);
	}

	/* Ruta a la libreria PKCS #11 o al nombre del modulo en p11-kit */
	ret = gnutls_pkcs11_add_provider("libASEP11.so", NULL);

	if (ret < GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Error al agregar proveedor: %s\n", gnutls_strerror(ret));
		exit(ret);
	}

	/*
	 * Obtiene un listado de todos los token conectados
	 * (aunque normalmente haya uno) y lo guarda en token_urls.
	 */
	for (i = 0; ; i++) {
		ret = gnutls_pkcs11_token_get_url(i, GNUTLS_PKCS11_URL_GENERIC, &url);

		if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			break;
		}

		if (ret < GNUTLS_E_SUCCESS) {
			fprintf(stderr, "Error al obtener identificadores: %s\n", gnutls_strerror(ret));
			exit(ret);
		}

		token_urls.push_back(url);
		gnutls_free(url);
	}

	/*
	 * Importa todos los objetos de tipo certificado de los tokens
	 * y los guarda en obj_list, guardando la cantidad en obj_list_size.
	 */
	for (i = 0; i < token_urls.size(); i++) {
		ret = gnutls_pkcs11_obj_list_import_url4(&obj_list, &obj_list_size,
			token_urls.at(i).c_str(), GNUTLS_PKCS11_OBJ_FLAG_CRT | GNUTLS_PKCS11_OBJ_FLAG_WITH_PRIVKEY | GNUTLS_PKCS11_OBJ_FLAG_LOGIN);

		if (ret < GNUTLS_E_SUCCESS) {
			fprintf(stderr, "Error al importar objetos del identificador %d: %s\n", i, gnutls_strerror(ret));
			exit(ret);
		}
	}

	/* Muestra los certificados en pantalla. */
	for (i = 0; i < obj_list_size; i++) {
		ret = gnutls_x509_crt_init(&cert);

		if (ret < GNUTLS_E_SUCCESS) {
			fprintf(stderr, "Error al crear estructura de certificado %d: %s\n", i, gnutls_strerror(ret));
			exit(ret);
		}

		ret = gnutls_x509_crt_import_pkcs11(cert, obj_list[i]);

		if (ret < GNUTLS_E_SUCCESS) {
			fprintf(stderr, "Error al importar certificado %d: %s\n", i, gnutls_strerror(ret));
			exit(ret);
		}

		givenname_size = sizeof(givenname);
		gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_GIVEN_NAME, 0, 0, givenname, &givenname_size);

		if (ret < GNUTLS_E_SUCCESS) {
			fprintf(stderr, "Error al obtener el nombre del certificado %d: %s\n", i, gnutls_strerror(ret));
			exit(ret);
		}

		surname_size = sizeof(surname);
		gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_SURNAME, 0, 0, surname, &surname_size);

		if (ret < GNUTLS_E_SUCCESS) {
			fprintf(stderr, "Error al obtener el apellido del certificado %d: %s\n", i, gnutls_strerror(ret));
			exit(ret);
		}

		printf("Certificado %d: %s %s\n", i, givenname, surname);

		ret = gnutls_x509_crt_get_key_usage(cert, &keyusage, NULL);

		if (keyusage & GNUTLS_KEY_NON_REPUDIATION) {
			printf("La clave del certificado %d es adecuada para firmar porque tiene uso 'no repudio'.\n", i);
		}

		gnutls_x509_crt_deinit(cert);
	}

	for (i = 0; i < obj_list_size; i++) {
		gnutls_pkcs11_obj_deinit(obj_list[i]);
	}

	if (obj_list_size > 0) {
		gnutls_free(obj_list);
	}

	gnutls_pkcs11_deinit();

	return 0;
}
