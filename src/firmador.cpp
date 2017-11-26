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

#include "firmador.h"

#include <iostream>
#include <string>
#include <vector>
/* FIXME: Es de POSIX, reemplazar luego con wxPasswordEntryDialog */
#include <unistd.h>

#include <gnutls/pkcs11.h>
#include <gnutls/abstract.h>

IMPLEMENT_APP(Firmador)

static int pin_callback(void *user, int attempt, const char *token_url,
	const char *token_label, unsigned int flags, char *pin,
	size_t pin_max) {

	const char *password = NULL;
	int len;

	/* No se usan esta variables, silenciar al compilador */
	(void)user;
	(void)attempt;
	(void)token_url;

	if (flags & GNUTLS_PIN_FINAL_TRY)
		std::cout << "*** ADVERTENCIA: este es el ultimo intento "
			<< "antes de bloquear la tarjeta!" << std::endl;
	if (flags & GNUTLS_PIN_COUNT_LOW)
		std::cout << "*** AVISO: quedan pocos intentos antes de "
			<< "bloquear la tarjeta!" << std::endl;
	if (flags & GNUTLS_PIN_WRONG)
		std::cout << "*** PIN incorrecto" << std::endl;

	std::cout << "Identificador: '" << token_label << "'." << std::endl;
#ifndef _WIN32
	password = getpass("Introduce el PIN: ");
#endif
	if (password == NULL || password[0] == 0) {
		std::cerr << "No se ha introducido ningun valor." << std::endl;
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
		std::cerr << "Error al inicializar: " << gnutls_strerror(ret)
			<< std::endl;
		exit(ret);
	}

	/*
	 * Ruta a la libreria PKCS #11 o al nombre del modulo en p11-kit.
	 * Si la libreria es privativa no afecta al programa GPL porque
	 * se encarga p11-kit de manejarlo.
	 */
#ifdef _WIN32
	ret = gnutls_pkcs11_add_provider((const) getenv("WINDIR") + "\\system32\\asepkcs11.dll", NULL);
#else
	ret = gnutls_pkcs11_add_provider("libASEP11.so", NULL);
#endif

	if (ret < GNUTLS_E_SUCCESS) {
		std::cerr << "Error al agregar proveedor: "
			<< gnutls_strerror(ret) << std::endl;
		exit(ret);
	}

	/*
	 * Obtiene un listado de todos los identificadores conectados
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
			std::cerr << "Error al obtener identificadores: "
				<< gnutls_strerror(ret) << std::endl;
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
	 * Importa todos los objetos de tipo certificado de los identificadores
	 * y guarda la lista de certificados de cada identificador en un
	 * obj_list, guardando la cantidad de objetos en obj_list_size y
	 * guardando los de cada identificador en vectores.
	 */
	for (size_t i = 0; i < token_urls.size(); i++) {
		ret = gnutls_pkcs11_obj_list_import_url2(&obj_list,
			&obj_list_size, token_urls.at(i).c_str(), 0,
			GNUTLS_PKCS11_OBJ_FLAG_CRT);

		if (ret < GNUTLS_E_SUCCESS) {
			std::cerr << "Error al importar objetos de tipo "
				<< "certificado del identificador " << i
				<< gnutls_strerror(ret) << std::endl;
			exit(ret);
		}
		token_obj_lists.push_back(obj_list);
		token_obj_lists_sizes.push_back(obj_list_size);
	}

	std::vector<std::string> candidate_certs;
	/* Recorre las listas de objetos y analiza los certificados. */
	for (size_t i = 0; i < token_obj_lists_sizes.size(); i++) {
		for (size_t j = 0; j < token_obj_lists_sizes.at(i); j++) {
			gnutls_x509_crt_t cert;
			ret = gnutls_x509_crt_init(&cert);

			if (ret < GNUTLS_E_SUCCESS) {
				std::cerr << "Error al crear estructura del "
					<< "certificado " << j
					<< " del identificador " << i << ": "
					<< gnutls_strerror(ret) << std::endl;
				exit(ret);
			}

			ret = gnutls_x509_crt_import_pkcs11(cert,
				token_obj_lists.at(i)[j]);

			if (ret < GNUTLS_E_SUCCESS) {
				std::cerr << "Error al importar el "
					<< "certificado " << j
					<< " del identificador " << i << ": "
					<< gnutls_strerror(ret) << std::endl;
				exit(ret);
			}

			char givenname[32];
			size_t givenname_size = sizeof(givenname);
			gnutls_x509_crt_get_dn_by_oid(cert,
				GNUTLS_OID_X520_GIVEN_NAME, 0, 0, givenname,
				&givenname_size);

			if (ret < GNUTLS_E_SUCCESS) {
				std::cerr << "Error al obtener el nombre del "
					<< "certificado " << j
					<< " del identificador " << i << ": "
					<< gnutls_strerror(ret) << std::endl;
				exit(ret);
			}

			char surname[80];
			size_t surname_size = sizeof(surname);
			gnutls_x509_crt_get_dn_by_oid(cert,
				GNUTLS_OID_X520_SURNAME, 0, 0, surname,
				&surname_size);

			if (ret < GNUTLS_E_SUCCESS) {
				std::cerr << "Error al obtener el apellido "
					<< "del certificado " << j
					<< " del identificador " << i << ": "
					<< gnutls_strerror(ret) << std::endl;
				exit(ret);
			}

			char serialnumber[128];
			size_t serialnumber_size = sizeof(serialnumber);
			gnutls_x509_crt_get_dn_by_oid(cert, "2.5.4.5", 0, 0,
				serialnumber, &serialnumber_size);

			if (ret < GNUTLS_E_SUCCESS) {
				std::cerr << "Error al obtener el numero de "
					<< "documento del certificado " << j
					<< " del identificador " << i << ": "
					<< gnutls_strerror(ret) << std::endl;
				exit(ret);
			}

			char obj_label[384];
			size_t obj_label_size = sizeof(obj_label);
			ret = gnutls_pkcs11_obj_get_info(
				token_obj_lists.at(i)[j],
				GNUTLS_PKCS11_OBJ_LABEL, obj_label,
				&obj_label_size);

			if (ret < GNUTLS_E_SUCCESS) {
				std::cerr << "Error al obtener la etiqueta "
					<< "del certificado " << j << ": "
					<< gnutls_strerror(ret) << std::endl;
				exit(ret);
			}

			std::cout << "Identificador " << i << ", certificado "
				<< j << ": " << givenname << " " << surname
				<< " (Documento: " << serialnumber
				<< ", etiqueta: " << obj_label << ")"
				<< std::endl;

			unsigned int keyusage;
			ret = gnutls_x509_crt_get_key_usage(cert, &keyusage,
				NULL);

			if (keyusage & GNUTLS_KEY_NON_REPUDIATION) {
				std::cout << "La clave del identificador "
					<< i << ", certificado " << j
					<< " es adecuada para firmar porque "
					<< "tiene uso 'no repudio'."
					<< std::endl;
				char *obj_url;
				ret = gnutls_pkcs11_obj_export_url(
					token_obj_lists.at(i)[j],
					GNUTLS_PKCS11_URL_GENERIC, &obj_url);
				if (ret < GNUTLS_E_SUCCESS) {
					std::cerr << "Error al obtener la URL "
						<< "del certificado " << j
						<< "del identificador " << i
						<< ": " << gnutls_strerror(ret)
						<< std::endl;
					exit(ret);
				}
				candidate_certs.push_back(obj_url);
				gnutls_free(obj_url);
			}
			gnutls_x509_crt_deinit(cert);
		}
	}

	wxArrayString cert_choices;
	for (size_t i = 0; i < candidate_certs.size(); i++) {
		cert_choices.Add(wxString(candidate_certs.at(i).c_str(),
			wxConvUTF8));
	}

	wxSingleChoiceDialog choiceDialog(NULL,
		wxT("Seleccionar el certificado con el que se desea firmar."),
		wxT("Selección de certificado"), cert_choices);
	//int selected_cert;
	if (choiceDialog.ShowModal() == wxID_OK) {
		std::cout << "Seleccion: " << choiceDialog.GetSelection()
			<< std::endl;
	} else {
		exit(1);
	}

	gnutls_privkey_t key;
	ret = gnutls_privkey_init(&key);

	if (ret < GNUTLS_E_SUCCESS) {
		std::cerr << "Error al inicializar la clave privada: "
			<< gnutls_strerror(ret) << std::endl;
		exit(ret);
	}

	/*
	 * Tras seleccionarse, cargar el identificador correspondiente, esta
	 * vez con PIN para poder usar la clave privada para poder firmar.
	 */
/*
	ret = gnutls_pkcs11_obj_import_url(,
		candidate_certs.at(selected_cert),
		GNUTLS_PKCS11_OBJ_FLAG_PRIVKEY);
	if (ret < GNUTLS_E_SUCCESS) {
		std::cerr << "Error al importar la URL de la clave privada "
			<< "para el certificado " << selected_cert << ": "
			<< gnutls_strerror(ret) << std::endl;
		exit(ret);
	}
*/
	/*
	// TODO: firmar datos eventualmente
	gnutls_datum_t data = {(unsigned char*)"hola", 4};
	gnutls_datum_t sig;
	ret = gnutls_privkey_sign_data(key, GNUTLS_DIG_SHA256, 0, &data, &sig);

	if (ret < GNUTLS_E_SUCCESS) {
		std::cerr << "Error al firmar datos con la clave privada del "
			<< "certificado " << i << gnutls_strerror(ret)
			<< std::endl;
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
