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
#include <sstream>
#include <vector>

#include <gnutls/pkcs11.h>
#include <gnutls/abstract.h>

IMPLEMENT_APP(Firmador)

static int pin_callback(void *userdata, int attempt, const char *token_url,
	const char *token_label, unsigned int flags, char *pin,
	size_t pin_max) {

	(void) userdata;
	(void) attempt;
	(void) token_url;
	int len;
	wxString warning = wxT("");

	if (flags & GNUTLS_PIN_FINAL_TRY) {
		warning = warning + wxT("ADVERTENCIA: ¡ESTE ES EL ÚLTIMO ")
			+ wxT("INTENTO ANTES DE BLOQUEAR LA TARJETA!\n\n");
	}

	if (flags & GNUTLS_PIN_COUNT_LOW) {
		warning = warning + wxT("AVISO: ¡quedan pocos intentos antes ")
			+ wxT("de BLOQUEAR la tarjeta!\n\n");
	}

	if (flags & GNUTLS_PIN_WRONG) {
		warning = warning + wxT("PIN INCORRECTO\n\n");
	}

	wxPasswordEntryDialog pinDialog(NULL, warning
		+ wxT("Introducir el PIN de la tarjeta ")
		+ wxString(token_label, wxConvUTF8) + wxT(":"),
		wxT("Introducción del PIN"), wxEmptyString,
		wxTextEntryDialogStyle | wxSTAY_ON_TOP);

	if (pinDialog.ShowModal() == wxID_OK) {
		if (pinDialog.GetValue().mb_str(wxConvUTF8).data() == NULL
			|| pinDialog.GetValue().mb_str(wxConvUTF8)
				.data()[0] == 0) {
			std::cerr << "No se ha introducido ningun valor."
				<< std::endl;
			exit(1);
		}

		len = std::min(pin_max - 1,
			std::char_traits<char>::length(
				pinDialog.GetValue().mb_str(wxConvUTF8)));
		memcpy(pin, pinDialog.GetValue().mb_str(wxConvUTF8), len);
		pin[len] = 0;

		return 0;
	} else {
		exit(1);
	}

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
	std::ostringstream path;
	path << getenv("WINDIR") << "\\System32\\asepkcs.dll";
	ret = gnutls_pkcs11_add_provider(path.str().c_str(), NULL);
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

	for (size_t i = 0; i < token_urls.size(); i++) {
		ret = gnutls_pkcs11_obj_list_import_url2(&obj_list,
			&obj_list_size, token_urls.at(i).c_str(), 0,
			GNUTLS_PKCS11_OBJ_FLAG_CRT
			| GNUTLS_PKCS11_OBJ_FLAG_LOGIN);
		token_obj_lists.push_back(obj_list);
		token_obj_lists_sizes.push_back(obj_list_size);
	}

	std::vector<std::string> candidate_certs;

	for (size_t i = 0; i < token_obj_lists_sizes.size(); i++) {

		for (size_t j = 0; j < token_obj_lists_sizes.at(i); j++) {

			gnutls_x509_crt_t cert;
			gnutls_x509_crt_init(&cert);

			gnutls_x509_crt_import_pkcs11(cert,
				token_obj_lists.at(i)[j]);

			unsigned int keyusage;
			gnutls_x509_crt_get_key_usage(cert, &keyusage,
				NULL);

			if (keyusage & GNUTLS_KEY_NON_REPUDIATION) {

				char nombre[32];
				size_t nombre_size = sizeof(nombre);
				gnutls_x509_crt_get_dn_by_oid(cert,
					GNUTLS_OID_X520_GIVEN_NAME, 0, 0,
					 nombre, &nombre_size);

				char apellido[80];
				size_t apellido_size = sizeof(apellido);
				gnutls_x509_crt_get_dn_by_oid(cert,
					GNUTLS_OID_X520_SURNAME, 0, 0,
					apellido, &apellido_size);

				char cedula[128];
				size_t cedula_size = sizeof(cedula);
				gnutls_x509_crt_get_dn_by_oid(cert, "2.5.4.5",
					0, 0, cedula, &cedula_size);

				char obj_label[384];
				size_t obj_label_size = sizeof(obj_label);
				gnutls_pkcs11_obj_get_info(
					token_obj_lists.at(i)[j],
					GNUTLS_PKCS11_OBJ_LABEL, obj_label,
					&obj_label_size);

				std::cout << "Identificador " << i
					<< ", certificado " << j << ": "
					<< nombre << " " << apellido
					<< " (Documento: " << cedula
					<< ", etiqueta: " << obj_label << ")"
					<< std::endl;

				char *obj_url;
				gnutls_pkcs11_obj_export_url(
					token_obj_lists.at(i)[j],
					GNUTLS_PKCS11_URL_GENERIC, &obj_url);

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
