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

#include <sys/types.h>
#ifndef _WIN32
# include <sys/select.h>
# include <sys/socket.h>
#else
# include <winsock2.h>
#endif
#include <cstring>
#include <cstdio>
#include <microhttpd.h>

//FIXME agregar al proyecto de automake. De momento compilar con:
//g++ servidorweb.cpp `pkg-config --cflags --libs libmicrohttpd` -o servidorweb
//Ejecutar con ./servidorweb
//Abrir en el navegador http://localhost:50600
//TODO: usar TLS con el certificado generado por el instalador

static int answer_to_connection(void *cls, struct MHD_Connection *connection,
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
		ret_code = MHD_HTTP_OK;
		const char *page = "{\"Hola\": \"Mundo!\"}";
		response = MHD_create_response_from_buffer(strlen(page), (void *)page,
			 MHD_RESPMEM_PERSISTENT);
	} else {
		ret_code = MHD_HTTP_METHOD_NOT_ALLOWED;
		const char *page = "";
		response = MHD_create_response_from_buffer(strlen(page), (void *)page,
			 MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, MHD_HTTP_HEADER_ALLOW,
			MHD_HTTP_METHOD_POST);
	}

	MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE,
		"application/json");
	ret = MHD_queue_response(connection, ret_code, response);
	MHD_destroy_response(response);

	return ret;
}

int main() {
	struct MHD_Daemon *daemon;

	daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, 50600, NULL, NULL,
		 &answer_to_connection, NULL, MHD_OPTION_END);
	if (daemon == NULL) {
		return 1;
	}

	(void)getchar();

	MHD_stop_daemon(daemon);

	return 0;
}
