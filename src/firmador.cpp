/* Firmador is a program that communicates web browsers with smartcards.

Copyright (C) 2018 Francisco de la Peña Fernández.

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

#include <microhttpd.h>

IMPLEMENT_APP(Firmador)

//TODO: usar TLS con el certificado generado por el instalador
static int request_callback(void *cls, struct MHD_Connection *connection,
	const char *url, const char *method, const char *version,
	const char *upload_data, size_t *upload_data_size, void **con_cls) {

	struct MHD_Response *response;
	int ret;
	int ret_code = MHD_HTTP_INTERNAL_SERVER_ERROR;

	(void)cls;
	(void)version;
	(void)url;
	(void)upload_data;
	(void)upload_data_size;
	(void)con_cls;

	if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
		const char *headervalue;
		headervalue = MHD_lookup_connection_value(connection,
			MHD_HEADER_KIND, MHD_HTTP_HEADER_CONTENT_TYPE);
		if (headervalue != NULL &&
			strcmp(headervalue, "application/json") == 0) {
			ret_code = MHD_HTTP_OK;
			const char *page = "{\"Hola\": \"Mundo!\"}";
			response = MHD_create_response_from_buffer(strlen(page),
				(void *)page, MHD_RESPMEM_PERSISTENT);
			MHD_add_response_header(response,
				MHD_HTTP_HEADER_CONTENT_TYPE,
				"application/json");
		} else {
			ret_code = MHD_HTTP_BAD_REQUEST;
			const char *page = "";
			response = MHD_create_response_from_buffer(strlen(page),
				(void *)page, MHD_RESPMEM_PERSISTENT);
		}

	} else {
		ret_code = MHD_HTTP_METHOD_NOT_ALLOWED;
		const char *page = "";
		response = MHD_create_response_from_buffer(strlen(page), (void *)page,
			MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, MHD_HTTP_HEADER_ALLOW,
			MHD_HTTP_METHOD_POST);
	}

	ret = MHD_queue_response(connection, ret_code, response);
	MHD_destroy_response(response);
	return ret;
}

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
	struct MHD_Daemon *daemon;

	daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, 50600, NULL, NULL,
		&request_callback, NULL, MHD_OPTION_END);
	if (daemon == NULL) {
		return 1;
	}

	//(void)getchar();

	MHD_stop_daemon(daemon);

	gnutls_pkcs11_set_pin_function(pin_callback, NULL);

	int ret;

	ret = gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL);

	if (ret < GNUTLS_E_SUCCESS) {
		std::cerr << "Error al inicializar: " << gnutls_strerror(ret)
			<< std::endl;
		exit(ret);
	}

#ifdef __WXOSX_MAC__
	std::ostringstream path;
	path << getenv("WINDIR") << "\\System32\\asepkcs.dll";
	ret = gnutls_pkcs11_add_provider(path.str().c_str(), NULL);
#elif __WIN32__
	ret = gnutls_pkcs11_add_provider(
		"/Library/Application Support/Athena/libASEP11.dylib", NULL);
#elif __LINUX__
	ret = gnutls_pkcs11_add_provider("/usr/lib/x64-athena/libASEP11.so",
		NULL);
#else
	wxMessageBox(wxString("Sistema no soportado por el ", wxConvUTF8)
		+ wxString("firmador.\n", wxConvUTF8)
		+ wxString("El fabricante de la tarjeta ", wxConvUTF8)
		+ wxString("solamente soporta Linux, macOS y ", wxConvUTF8)
		+ wxString("Windows con procesadores x86.", wxConvUTF8),
		wxT("Sistema no soportado"), wxICON_ERROR);
	exit(1);
#endif

	if (ret < GNUTLS_E_SUCCESS) {
		std::cerr << "Error al agregar proveedor: "
			<< gnutls_strerror(ret) << std::endl;
		exit(ret);
	}

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
			&obj_list_size, token_urls.at(i).c_str(),
			GNUTLS_PKCS11_OBJ_ATTR_CRT_ALL, 0);
		token_obj_lists.push_back(obj_list);
		token_obj_lists_sizes.push_back(obj_list_size);
	}

	wxArrayString cert_choices;
	wxArrayString cert_captions;

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

				std::ostringstream caption;
				caption << nombre << " " << apellido << " ("
					<< cedula << ")";
				cert_captions.Add(wxString(
					caption.str().c_str(), wxConvUTF8));

				char *obj_url;
				gnutls_pkcs11_obj_export_url(
					token_obj_lists.at(i)[j],
					GNUTLS_PKCS11_URL_GENERIC, &obj_url);

				cert_choices.Add(wxString(obj_url,
					wxConvUTF8));
				gnutls_free(obj_url);
			}
			gnutls_x509_crt_deinit(cert);
		}
	}

	wxSingleChoiceDialog choiceDialog(NULL,
		wxT("Seleccionar el certificado con el que se desea firmar."),
		wxT("Selección de certificado"), cert_captions);

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
	gnutls_privkey_import_url(key,
		cert_choices.Item(
			choiceDialog.GetSelection()).mb_str(wxConvUTF8), 0);
	if (ret < GNUTLS_E_SUCCESS) {
		std::cerr << "Error al importar la URL de la clave privada: "
			<< gnutls_strerror(ret) << std::endl;
		exit(ret);
	}

	gnutls_datum_t data = {(unsigned char*)"hola", 4};
	gnutls_datum_t sig;
	ret = gnutls_privkey_sign_data(key, GNUTLS_DIG_SHA256, 0, &data, &sig);

	if (ret < GNUTLS_E_SUCCESS) {
		std::cerr << "Error al firmar: " << gnutls_strerror(ret)
			<< std::endl;
		exit(ret);
	}

	gnutls_datum_t sig_hex;
	gnutls_hex_encode2(&sig, &sig_hex);
	std::cout << "Firma: " << sig_hex.data << std::endl;

	gnutls_free(sig_hex.data);
	gnutls_free(sig.data);
	gnutls_privkey_deinit(key);

	for (size_t i = 0; i < token_obj_lists_sizes.size(); i++) {
		for (size_t j = 0; j < token_obj_lists_sizes.at(i); j++) {
			gnutls_pkcs11_obj_deinit(token_obj_lists.at(i)[j]);
		}
	}

	if (obj_list_size > 0) {
		gnutls_free(obj_list);
	}

	gnutls_pkcs11_deinit();

	return false;
}
