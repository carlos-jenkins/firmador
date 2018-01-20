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

#include "request.h"

#include <cstring>
#include <iostream>

//TODO: usar TLS con el certificado generado por el instalador
int request_callback(void *cls, struct MHD_Connection *connection,
	const char *url, const char *method, const char *version,
	const char *upload_data, std::size_t *upload_data_size,
	void **con_cls) {

	struct MHD_Response *response;
	int ret;
	int ret_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
	std::string page = "";

	(void)cls;
	(void)version;
	(void)upload_data;
	(void)upload_data_size;
	(void)con_cls;

	if (strcmp(url, "/") == 0 || strcmp(url, "/nexu-info") == 0) {
		ret_code = MHD_HTTP_OK;
		page = "{ \"version\": \"1.10.5\"}";
	}

	if (strcmp(url, "/rest/certificates") == 0) {
		if (strcmp(method, MHD_HTTP_METHOD_OPTIONS) == 0) {
			ret_code = MHD_HTTP_OK;
		}

		if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
			ret_code = MHD_HTTP_OK;
			std::cout << "FIXME: abrir interfaz de certificados"
				<< std::endl;
			std::cout << "FIXME: enviar UUID, ID de certificado, "
				<< "DER del certificado y DER de la cadena."
				<< std::endl;
		}
	}

	if (strcmp(url, "/rest/sign") == 0) {
		if (strcmp(method, MHD_HTTP_METHOD_OPTIONS) == 0) {
			ret_code = MHD_HTTP_OK;
		}

		if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
			ret_code = MHD_HTTP_OK;
			std::cout << "FIXME: abrir interfaz de solicitar PIN "
				<< "del token y firmar el PKCS#7 "
				<< "proporcionado con el algoritmo indicado."
				<< std::endl;
			std::cout << "FIXME: enviar firma y algoritmo usado, "
				<< "DER del certificado y DER de la cadena."
				<< std::endl;
		}
	}

	response = MHD_create_response_from_buffer(page.length(),
		(void*)page.c_str(), MHD_RESPMEM_MUST_COPY);
	if (strcmp(page.c_str(), "") != 0) {
		MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE,
			"application/json;charset=utf-8");
	}
	MHD_add_response_header(response, "Access-Control-Allow-Headers",
		MHD_HTTP_HEADER_CONTENT_TYPE);
	MHD_add_response_header(response, "Access-Control-Allow-Methods",
		"OPTIONS, GET, POST");
	MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
	MHD_add_response_header(response, MHD_HTTP_HEADER_CONNECTION,
		MHD_HTTP_HEADER_CLOSE);
	ret = MHD_queue_response(connection, ret_code, response);
	MHD_destroy_response(response);

	return ret;
}
