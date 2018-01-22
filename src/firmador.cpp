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
#include "base64.h"
#include "pin.h"
#include "request.h"
#include "uuid.h"

#include <string>
#include <sstream>
#include <vector>

#include <gnutls/abstract.h>

#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#define FIRMADOR_PORT 50600

IMPLEMENT_APP(Firmador)

bool Firmador::OnInit() {
	struct sockaddr_in daemon_ip_addr;
	memset(&daemon_ip_addr, 0, sizeof(struct sockaddr_in));
	daemon_ip_addr.sin_family = AF_INET;
	daemon_ip_addr.sin_port = htons(FIRMADOR_PORT);
	daemon_ip_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	struct MHD_Daemon *daemon;
	daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
		FIRMADOR_PORT, NULL, NULL, &request_callback, NULL,
		MHD_OPTION_SOCK_ADDR, &daemon_ip_addr, MHD_OPTION_END);
	if (daemon == NULL) {
		wxMessageBox(wxString(
			"No se ha podido iniciar el servicio firmador.\n"
			"El puerto podría estar ocupado por otro servicio.",
			wxConvUTF8),
			wxT("Error al iniciar"), wxICON_ERROR);
		exit(1);
	}

	gnutls_pkcs11_set_pin_function(pin_callback, NULL);

	int ret;

	ret = gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL);

	if (ret < GNUTLS_E_SUCCESS) {
		std::ostringstream error;
		error << "Error al inicializar el proveedor: "
			<< std::endl << gnutls_strerror(ret);
		wxMessageBox(wxString(error.str().c_str(), wxConvUTF8),
			wxT("Error al inicializar dispositivo"), wxICON_ERROR);
		return ret;
	}

#ifdef __WIN32__
	std::ostringstream path;
	path << getenv("WINDIR") << "\\System32\\asepkcs.dll";
	ret = gnutls_pkcs11_add_provider(path.str().c_str(), NULL);
#elif __WXOSX_MAC__
	ret = gnutls_pkcs11_add_provider(
		"/Library/Application Support/Athena/libASEP11.dylib", NULL);
#elif __LINUX__
	ret = gnutls_pkcs11_add_provider("/usr/lib/x64-athena/libASEP11.so",
		NULL);
#else
	wxMessageBox(wxString(
		"Sistema no soportado por el firmador.\n"
		"El fabricante de la tarjeta solamente soporta GNU/Linux, "
		"macOS y Windows con procesadores x86 y x86_64.", wxConvUTF8),
		wxT("Sistema no soportado"), wxICON_ERROR);
	exit(1);
#endif

	if (ret < GNUTLS_E_SUCCESS) {
		std::ostringstream error;
		error << "Error al agregar proveedor:" << std::endl
			<< gnutls_strerror(ret);
		wxMessageBox(wxString(error.str().c_str(), wxConvUTF8),
			wxT("Error al agregar proveedor"), wxICON_ERROR);
		return ret;
	}

	std::vector<std::string> token_urls;
	for (std::size_t i = 0; ; i++) {
		char* url;
		ret = gnutls_pkcs11_token_get_url(i,
			GNUTLS_PKCS11_URL_GENERIC, &url);

		if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			break;
		}

		if (ret < GNUTLS_E_SUCCESS) {
			std::ostringstream error;
			error << "Error al obtener identificador:"
				<< std::endl << gnutls_strerror(ret);
			wxMessageBox(wxString(error.str().c_str(), wxConvUTF8),
				wxT("Error al obtener token"), wxICON_ERROR);
		}

		token_urls.push_back(url);
		gnutls_free(url);
	}

	gnutls_pkcs11_obj_t* obj_list;
	std::vector<gnutls_pkcs11_obj_t*> token_obj_lists;
	std::vector<unsigned int> token_obj_lists_sizes;
	unsigned int obj_list_size = 0;

	for (std::size_t i = 0; i < token_urls.size(); i++) {
		ret = gnutls_pkcs11_obj_list_import_url2(&obj_list,
			&obj_list_size, token_urls.at(i).c_str(),
			GNUTLS_PKCS11_OBJ_ATTR_CRT_ALL, 0);
		if (ret < GNUTLS_E_SUCCESS) {
			std::ostringstream error;
			error << "Error al importar objeto:"
				<< std::endl << gnutls_strerror(ret);
			wxMessageBox(wxString(error.str().c_str(), wxConvUTF8),
				wxT("Error al importar objeto"), wxICON_ERROR);
		}
		token_obj_lists.push_back(obj_list);
		token_obj_lists_sizes.push_back(obj_list_size);
	}

	wxArrayString cert_choices;
	wxArrayString cert_captions;

	for (std::size_t i = 0; i < token_obj_lists_sizes.size(); i++) {

		for (std::size_t j = 0; j < token_obj_lists_sizes.at(i); j++) {

			gnutls_x509_crt_t cert;
			gnutls_x509_crt_init(&cert);

			gnutls_x509_crt_import_pkcs11(cert,
				token_obj_lists.at(i)[j]);

			unsigned int keyusage;
			gnutls_x509_crt_get_key_usage(cert, &keyusage,
				NULL);

			if (keyusage & GNUTLS_KEY_NON_REPUDIATION) {

				char nombre[32];
				std::size_t nombre_size = sizeof(nombre);
				gnutls_x509_crt_get_dn_by_oid(cert,
					GNUTLS_OID_X520_GIVEN_NAME, 0, 0,
					nombre, &nombre_size);

				char apellido[80];
				std::size_t apellido_size = sizeof(apellido);
				gnutls_x509_crt_get_dn_by_oid(cert,
					GNUTLS_OID_X520_SURNAME, 0, 0,
					apellido, &apellido_size);

				char cedula[128];
				std::size_t cedula_size = sizeof(cedula);
				gnutls_x509_crt_get_dn_by_oid(cert, "2.5.4.5",
					0, 0, cedula, &cedula_size);

				unsigned int bits;
				int algo = gnutls_x509_crt_get_pk_algorithm(
					cert, &bits);
				std::string encryptionAlgorithm =
					gnutls_pk_algorithm_get_name(
						(gnutls_pk_algorithm_t)algo);
				//std::cout << "encryptionAlgoritm: "
				//	<< encryptionAlgorithm << std::endl;
				char cert_id[32];
				std::size_t cert_id_size = sizeof(cert_id);
				gnutls_x509_crt_get_fingerprint(cert,
					GNUTLS_DIG_SHA256, cert_id,
					&cert_id_size);
				gnutls_datum_t certId_bin = {
					(unsigned char*)cert_id,
					(unsigned)cert_id_size};
				gnutls_datum_t certId;
				gnutls_hex_encode2(&certId_bin, &certId);
				//std::cout << "certId: " << certId.data
				//	<< std::endl;
				gnutls_datum_t cert_der;
				gnutls_x509_crt_export2(cert,
					GNUTLS_X509_FMT_DER, &cert_der);
				gnutls_datum_t certificate;
				gnutls_pem_base64_encode_alloc(NULL, &cert_der,
					&certificate);
				//std::cout << "certificate: "
				//	<< certificate.data
				//	<< std::endl;

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
		if (cert_captions.IsEmpty()) {
			wxMessageBox(wxString(
				"No se ha seleccionado ningún certificado.",
				wxConvUTF8),
				wxT("Certificado no seleccionado"),
				wxICON_ERROR);
			return -1;
		}
	} else {
		wxMessageBox(wxString(
			"Se ha cancelado la selección de certificado.",
			wxConvUTF8),
			wxT("Certificado no seleccionado"));
		return -1;
	}

	rapidjson::StringBuffer stringBuffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(stringBuffer);

	std::string id = uuid();

	writer.StartObject();
	writer.Key("success");
	writer.Bool(true);
	writer.Key("response");
	writer.StartObject();
	writer.Key("tokenId");
	writer.StartObject();
	writer.Key("id");
	writer.String(id.c_str());
	writer.EndObject();
	writer.Key("keyId");
	writer.String("D8363BD6BD2FE30C4191CD5BB05A97E7556EFE01F207C459D81DEC58186BF665");
	writer.Key("certificate");
	writer.String(
		"MIIFuTCCBKGgAwIBAgITFAABH/a5gZb8gqHY/AAAAAEf9jANBgkqhkiG9w0BAQsF"
		"ADCBmTEZMBcGA1UEBRMQQ1BKLTQtMDAwLTAwNDAxNzELMAkGA1UEBhMCQ1IxJDAi"
		"BgNVBAoTG0JBTkNPIENFTlRSQUwgREUgQ09TVEEgUklDQTEiMCAGA1UECxMZRElW"
		"SVNJT04gU0lTVEVNQVMgREUgUEFHTzElMCMGA1UEAxMcQ0EgU0lOUEUgLSBQRVJT"
		"T05BIEZJU0lDQSB2MjAeFw0xNzAyMTcxOTUyMTZaFw0yMTAyMTYxOTUyMTZaMIG7"
		"MRkwFwYDVQQFExBDUEYtMDgtMDExOS0wNTkyMR4wHAYDVQQEDBVERSBMQSBQRcOR"
		"QSBGRVJOQU5ERVoxEjAQBgNVBCoTCUZSQU5DSVNDTzELMAkGA1UEBhMCQ1IxFzAV"
		"BgNVBAoTDlBFUlNPTkEgRklTSUNBMRIwEAYDVQQLEwlDSVVEQURBTk8xMDAuBgNV"
		"BAMMJ0ZSQU5DSVNDTyBERSBMQSBQRcORQSBGRVJOQU5ERVogKEZJUk1BKTCCASIw"
		"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANEwGLI0tTAuRSamUFtO69dvREWZ"
		"mZ05WivpREENs1sYlRcdlVLN3V7gXgGZLGd0EorgQFh1SsIf5wRXdi+W2tlxqwel"
		"QQVqOPL6dIeY9SHjtlBqzYizLBf4nO2NtEpb9D40fUiNWM5XbScPt1MdWQjxqiTw"
		"wzzKiYMzRRudfiYp11tfRfQ0o3YhiYGMny92zaEnTKGwIyBn3+467fyhLpyuDUv5"
		"bY/0AJkxJshdcfTL6Wk04RUQLJoK1X6/f45fXqGYJr9foJlL2TTjsA3Z/BE9manO"
		"I4JNdPgmT+exDIsNmrHf8iNvvclNo7F5CHQo2ZQwFL3Cvn8A8rG5Iu7wxAECAwEA"
		"AaOCAdQwggHQMB0GA1UdDgQWBBRsEVTpU9pDREKQDn/fF08VmzWXbDAfBgNVHSME"
		"GDAWgBS0dIurntt28H+lKOOUrTHMcvCzKTBeBgNVHR8EVzBVMFOgUaBPhk1odHRw"
		"Oi8vZmRpLnNpbnBlLmZpLmNyL3JlcG9zaXRvcmlvL0NBJTIwU0lOUEUlMjAtJTIw"
		"UEVSU09OQSUyMEZJU0lDQSUyMHYyLmNybDCBlQYIKwYBBQUHAQEEgYgwgYUwWQYI"
		"KwYBBQUHMAKGTWh0dHA6Ly9mZGkuc2lucGUuZmkuY3IvcmVwb3NpdG9yaW8vQ0El"
		"MjBTSU5QRSUyMC0lMjBQRVJTT05BJTIwRklTSUNBJTIwdjIuY3J0MCgGCCsGAQUF"
		"BzABhhxodHRwOi8vb2NzcC5zaW5wZS5maS5jci9vY3NwMA4GA1UdDwEB/wQEAwIG"
		"wDA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiFxOpbgtHjNZWRG4L5lxiGpctr"
		"gX+BudJygZ6/eAIBZAIBBzATBgNVHSUEDDAKBggrBgEFBQcDBDAbBgkrBgEEAYI3"
		"FQoEDjAMMAoGCCsGAQUFBwMEMBUGA1UdIAQOMAwwCgYIYIE8AQEBAQIwDQYJKoZI"
		"hvcNAQELBQADggEBANRbQKYeFjiqnLMCiE7B+deWmGqtskuQMRMrj0OrsN+LFlHd"
		"AJ/Zia43gsvf/rzrFYJm9uPRZGGLtUV853yazekWUcbPLLLCX33F/aY6h4h4WkAR"
		"KM33WWqC6n5DEp1HnFbsqNJ597VPniO4BCpA8+qRRsfUPWJgLXOll2B4tCZ0mcUg"
		"DHZELukTdE06Xocu9X0MgxdbqIU0CIdy7h0RpkAnyut8Hcdklkd4RkN/Y15/aSIa"
		"xt35Tz7hJWWDdHON+/JLqlnTDze0EvIeiHsPN5jhAxNbLZT0rrhtcb2Q3Z11SjbP"
		"Awzv9VKU1c7OJsHer1mFZbxfp0nXmxb66fbvUsw=");

	writer.Key("certificateChain");
	writer.StartArray();

	writer.String(
		"MIIFuTCCBKGgAwIBAgITFAABH/a5gZb8gqHY/AAAAAEf9jANBgkqhkiG9w0BAQsF"
		"ADCBmTEZMBcGA1UEBRMQQ1BKLTQtMDAwLTAwNDAxNzELMAkGA1UEBhMCQ1IxJDAi"
		"BgNVBAoTG0JBTkNPIENFTlRSQUwgREUgQ09TVEEgUklDQTEiMCAGA1UECxMZRElW"
		"SVNJT04gU0lTVEVNQVMgREUgUEFHTzElMCMGA1UEAxMcQ0EgU0lOUEUgLSBQRVJT"
		"T05BIEZJU0lDQSB2MjAeFw0xNzAyMTcxOTUyMTZaFw0yMTAyMTYxOTUyMTZaMIG7"
		"MRkwFwYDVQQFExBDUEYtMDgtMDExOS0wNTkyMR4wHAYDVQQEDBVERSBMQSBQRcOR"
		"QSBGRVJOQU5ERVoxEjAQBgNVBCoTCUZSQU5DSVNDTzELMAkGA1UEBhMCQ1IxFzAV"
		"BgNVBAoTDlBFUlNPTkEgRklTSUNBMRIwEAYDVQQLEwlDSVVEQURBTk8xMDAuBgNV"
		"BAMMJ0ZSQU5DSVNDTyBERSBMQSBQRcORQSBGRVJOQU5ERVogKEZJUk1BKTCCASIw"
		"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANEwGLI0tTAuRSamUFtO69dvREWZ"
		"mZ05WivpREENs1sYlRcdlVLN3V7gXgGZLGd0EorgQFh1SsIf5wRXdi+W2tlxqwel"
		"QQVqOPL6dIeY9SHjtlBqzYizLBf4nO2NtEpb9D40fUiNWM5XbScPt1MdWQjxqiTw"
		"wzzKiYMzRRudfiYp11tfRfQ0o3YhiYGMny92zaEnTKGwIyBn3+467fyhLpyuDUv5"
		"bY/0AJkxJshdcfTL6Wk04RUQLJoK1X6/f45fXqGYJr9foJlL2TTjsA3Z/BE9manO"
		"I4JNdPgmT+exDIsNmrHf8iNvvclNo7F5CHQo2ZQwFL3Cvn8A8rG5Iu7wxAECAwEA"
		"AaOCAdQwggHQMB0GA1UdDgQWBBRsEVTpU9pDREKQDn/fF08VmzWXbDAfBgNVHSME"
		"GDAWgBS0dIurntt28H+lKOOUrTHMcvCzKTBeBgNVHR8EVzBVMFOgUaBPhk1odHRw"
		"Oi8vZmRpLnNpbnBlLmZpLmNyL3JlcG9zaXRvcmlvL0NBJTIwU0lOUEUlMjAtJTIw"
		"UEVSU09OQSUyMEZJU0lDQSUyMHYyLmNybDCBlQYIKwYBBQUHAQEEgYgwgYUwWQYI"
		"KwYBBQUHMAKGTWh0dHA6Ly9mZGkuc2lucGUuZmkuY3IvcmVwb3NpdG9yaW8vQ0El"
		"MjBTSU5QRSUyMC0lMjBQRVJTT05BJTIwRklTSUNBJTIwdjIuY3J0MCgGCCsGAQUF"
		"BzABhhxodHRwOi8vb2NzcC5zaW5wZS5maS5jci9vY3NwMA4GA1UdDwEB/wQEAwIG"
		"wDA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiFxOpbgtHjNZWRG4L5lxiGpctr"
		"gX+BudJygZ6/eAIBZAIBBzATBgNVHSUEDDAKBggrBgEFBQcDBDAbBgkrBgEEAYI3"
		"FQoEDjAMMAoGCCsGAQUFBwMEMBUGA1UdIAQOMAwwCgYIYIE8AQEBAQIwDQYJKoZI"
		"hvcNAQELBQADggEBANRbQKYeFjiqnLMCiE7B+deWmGqtskuQMRMrj0OrsN+LFlHd"
		"AJ/Zia43gsvf/rzrFYJm9uPRZGGLtUV853yazekWUcbPLLLCX33F/aY6h4h4WkAR"
		"KM33WWqC6n5DEp1HnFbsqNJ597VPniO4BCpA8+qRRsfUPWJgLXOll2B4tCZ0mcUg"
		"DHZELukTdE06Xocu9X0MgxdbqIU0CIdy7h0RpkAnyut8Hcdklkd4RkN/Y15/aSIa"
		"xt35Tz7hJWWDdHON+/JLqlnTDze0EvIeiHsPN5jhAxNbLZT0rrhtcb2Q3Z11SjbP"
		"Awzv9VKU1c7OJsHer1mFZbxfp0nXmxb66fbvUsw=");

	// CA SINPE - PERSONA FISICA v2
	writer.String(
		"MIINADCCCuigAwIBAgITSwAAAAMTyepkVGDdawAAAAAAAzANBgkqhkiG9w0BAQ0F"
		"ADB9MRkwFwYDVQQFExBDUEotMi0xMDAtMDk4MzExMQswCQYDVQQGEwJDUjEPMA0G"
		"A1UEChMGTUlDSVRUMQ0wCwYDVQQLEwREQ0ZEMTMwMQYDVQQDEypDQSBQT0xJVElD"
		"QSBQRVJTT05BIEZJU0lDQSAtIENPU1RBIFJJQ0EgdjIwHhcNMTYwMTIxMTgxNjA4"
		"WhcNMjQwMTIxMTgyNjA4WjCBmTEZMBcGA1UEBRMQQ1BKLTQtMDAwLTAwNDAxNzEL"
		"MAkGA1UEBhMCQ1IxJDAiBgNVBAoTG0JBTkNPIENFTlRSQUwgREUgQ09TVEEgUklD"
		"QTEiMCAGA1UECxMZRElWSVNJT04gU0lTVEVNQVMgREUgUEFHTzElMCMGA1UEAxMc"
		"Q0EgU0lOUEUgLSBQRVJTT05BIEZJU0lDQSB2MjCCASIwDQYJKoZIhvcNAQEBBQAD"
		"ggEPADCCAQoCggEBAOa9ooS00UHFT099PwJl/OLq8TVJD9STp1Kcqhjl234reztc"
		"/NNzMgvwcRJiLKWY5RaKWwxbEDOsgIcIp32gmNH057NqgAQcRAVfWLIVjqqTtQCk"
		"j3ZgTFUZeYwXe2qKgV/jRAfwy9ZQAO/la9ccWh7Upwf3y6Z9MAqA+er/o6FUfIBD"
		"nzSxBJvLlN5VuVXmp0bm5KT/wCYm/SIktDCIGAzIDo1ndowbhfTs6D/cMRzlMQgF"
		"Qz6cwutaOGg13ojo0OLeqbNR/c8ERom5xcaMiGkJ4EPv30v4fb6lCtX+M3Soz+uh"
		"a+tr9s0gWXPSrpyXWAWWrLl4yugXT5RxvLx7kWsCAwEAAaOCCFowgghWMBAGCSsG"
		"AQQBgjcVAQQDAgEAMB0GA1UdDgQWBBS0dIurntt28H+lKOOUrTHMcvCzKTCCBdYG"
		"A1UdIASCBc0wggXJMIIBFAYHYIE8AQEBATCCAQcwgaYGCCsGAQUFBwICMIGZHoGW"
		"AEkAbQBwAGwAZQBtAGUAbgB0AGEAIABsAGEAIABQAG8AbABpAHQAaQBjAGEAIABk"
		"AGUAIABsAGEAIABSAGEAaQB6ACAAQwBvAHMAdABhAHIAcgBpAGMAZQBuAHMAZQAg"
		"AGQAZQAgAEMAZQByAHQAaQBmAGkAYwBhAGMAaQBvAG4AIABEAGkAZwBpAHQAYQBs"
		"ACAAdgAyMCoGCCsGAQUFBwIBFh5odHRwOi8vd3d3LmZpcm1hZGlnaXRhbC5nby5j"
		"cgAwMAYIKwYBBQUHAgEWJGh0dHA6Ly93d3cubWljaXQuZ28uY3IvZmlybWFkaWdp"
		"dGFsADCCAVUGCGCBPAEBAQEBMIIBRzCB5gYIKwYBBQUHAgIwgdkegdYASQBtAHAA"
		"bABlAG0AZQBuAHQAYQAgAGwAYQAgAFAAbwBsAGkAdABpAGMAYQAgAGQAZQAgAEMA"
		"QQAgAEUAbQBpAHMAbwByAGEAIABwAGEAcgBhACAAUABlAHIAcwBvAG4AYQBzACAA"
		"RgBpAHMAaQBjAGEAcwAgAHAAZQByAHQAZQBuAGUAYwBpAGUAbgB0AGUAIABhACAA"
		"bABhACAAUABLAEkAIABOAGEAYwBpAG8AbgBhAGwAIABkAGUAIABDAG8AcwB0AGEA"
		"IABSAGkAYwBhACAAdgAyMCoGCCsGAQUFBwIBFh5odHRwOi8vd3d3LmZpcm1hZGln"
		"aXRhbC5nby5jcgAwMAYIKwYBBQUHAgEWJGh0dHA6Ly93d3cubWljaXQuZ28uY3Iv"
		"ZmlybWFkaWdpdGFsADCCAagGCGCBPAEBAQECMIIBmjCCATgGCCsGAQUFBwICMIIB"
		"Kh6CASYASQBtAHAAbABlAG0AZQBuAHQAYQAgAGwAYQAgAFAAbwBsAGkAdABpAGMA"
		"YQAgAHAAYQByAGEAIABjAGUAcgB0AGkAZgBpAGMAYQBkAG8AIABkAGUAIABmAGkA"
		"cgBtAGEAIABkAGkAZwBpAHQAYQBsACAAZABlACAAcABlAHIAcwBvAG4AYQBzACAA"
		"ZgBpAHMAaQBjAGEAcwAgACgAYwBpAHUAZABhAGQAYQBuAG8ALwByAGUAcwBpAGQA"
		"ZQBuAHQAZQApACAAcABlAHIAdABlAG4AZQBjAGkAZQBuAHQAZQAgAGEAIABsAGEA"
		"IABQAEsASQAgAE4AYQBjAGkAbwBuAGEAbAAgAGQAZQAgAEMAbwBzAHQAYQAgAFIA"
		"aQBjAGEAIAB2ADIwKgYIKwYBBQUHAgEWHmh0dHA6Ly93d3cuZmlybWFkaWdpdGFs"
		"LmdvLmNyADAwBggrBgEFBQcCARYkaHR0cDovL3d3dy5taWNpdC5nby5jci9maXJt"
		"YWRpZ2l0YWwAMIIBqAYIYIE8AQEBAQMwggGaMIIBOAYIKwYBBQUHAgIwggEqHoIB"
		"JgBJAG0AcABsAGUAbQBlAG4AdABhACAAbABhACAAUABvAGwAaQB0AGkAYwBhACAA"
		"cABhAHIAYQAgAGMAZQByAHQAaQBmAGkAYwBhAGQAbwAgAGQAZQAgAGEAdQB0AGUA"
		"bgB0AGkAYwBhAGMAaQBvAG4AIABkAGUAIABwAGUAcgBzAG8AbgBhAHMAIABmAGkA"
		"cwBpAGMAYQBzACAAKABjAGkAdQBkAGEAZABhAG4AbwAvAHIAZQBzAGkAZABlAG4A"
		"dABlACkAIABwAGUAcgB0AGUAbgBlAGMAaQBlAG4AdABlACAAYQAgAGwAYQAgAFAA"
		"SwBJACAATgBhAGMAaQBvAG4AYQBsACAAZABlACAAQwBvAHMAdABhACAAUgBpAGMA"
		"YQAgAHYAMjAqBggrBgEFBQcCARYeaHR0cDovL3d3dy5maXJtYWRpZ2l0YWwuZ28u"
		"Y3IAMDAGCCsGAQUFBwIBFiRodHRwOi8vd3d3Lm1pY2l0LmdvLmNyL2Zpcm1hZGln"
		"aXRhbAAwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMBIG"
		"A1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUaJ1pNsuEbnvqk2EZ/1gwHdX/"
		"XMswgeoGA1UdHwSB4jCB3zCB3KCB2aCB1oZmaHR0cDovL3d3dy5maXJtYWRpZ2l0"
		"YWwuZ28uY3IvcmVwb3NpdG9yaW8vQ0ElMjBQT0xJVElDQSUyMFBFUlNPTkElMjBG"
		"SVNJQ0ElMjAtJTIwQ09TVEElMjBSSUNBJTIwdjIuY3JshmxodHRwOi8vd3d3Lm1p"
		"Y2l0LmdvLmNyL2Zpcm1hZGlnaXRhbC9yZXBvc2l0b3Jpby9DQSUyMFBPTElUSUNB"
		"JTIwUEVSU09OQSUyMEZJU0lDQSUyMC0lMjBDT1NUQSUyMFJJQ0ElMjB2Mi5jcmww"
		"gf4GCCsGAQUFBwEBBIHxMIHuMHIGCCsGAQUFBzAChmZodHRwOi8vd3d3LmZpcm1h"
		"ZGlnaXRhbC5nby5jci9yZXBvc2l0b3Jpby9DQSUyMFBPTElUSUNBJTIwUEVSU09O"
		"QSUyMEZJU0lDQSUyMC0lMjBDT1NUQSUyMFJJQ0ElMjB2Mi5jcnQweAYIKwYBBQUH"
		"MAKGbGh0dHA6Ly93d3cubWljaXQuZ28uY3IvZmlybWFkaWdpdGFsL3JlcG9zaXRv"
		"cmlvL0NBJTIwUE9MSVRJQ0ElMjBQRVJTT05BJTIwRklTSUNBJTIwLSUyMENPU1RB"
		"JTIwUklDQSUyMHYyLmNydDANBgkqhkiG9w0BAQ0FAAOCAgEAXMDsvznzaps0YruV"
		"9IpoXIN3enrxNHnzu9eEW9ucl3jP3yOK4SfqwTYvJ8PKKaG+p5WxhVFVh5Qn2nm0"
		"CPR8zrxMEskqg7GdScqIpoMe9ZojSEk4Xw19cHj3KN+eetp96lBpjTlva4ipz2ES"
		"09tVUA/ctU6kRbMR22B9qjeSE8agrYKaUBc4n44h1W6K7itGkIMVB/wQ1nF8sxko"
		"VOitqLXjVy7ZKTk+4+S0rWK7SYt2fkaQZA8tSSt6fatPx68+gDKSv3JXNWG+Nr8I"
		"XZdyrpICwI/318JPPjR0QJnD7kivjZK2QFZCbuJu4rZoyblvXJLmei4QXpSIgRMg"
		"Z0MJamP5dW2Xw3qq2YQS4ma8ZTCqecat5wFGsH81RR10JnpRp4A4NpftguvbnZhG"
		"9m8kdmOKaq4R7NRp/wM/XZi0jxsvzdtUomquCQc+AJ26AZPWVy4nj+kglEJE759o"
		"o/Qjpgu9PZrkEARInpjHzYBSeq6SCHud58pzZIwStlOMicLozcLAyOvgTKAjg9cQ"
		"Bg1HVi1wT2aVL76tOAI0ZlCGiSnyGq3RUEKSC3TcFfTzpPJiHKw+6nPmTAAnCN8+"
		"co+s0Prh/+Ju24hA8ShhKYy3ORQ+3u2l8EoyPUcl+EDOC2kufLbuF7AKrBDF0hXm"
		"Lfon9nZBnfr/EpL/J1qRaM7am1s="
	);

	// CA POLITICA PERSONA FISICA - COSTA RICA v2
	writer.String(
		"MIIMrDCCCpSgAwIBAgITTgAAAAJzjeZ3/o5oQAAAAAAAAjANBgkqhkiG9w0BAQ0F"
		"ADBzMRkwFwYDVQQFExBDUEotMi0xMDAtMDk4MzExMQ0wCwYDVQQLEwREQ0ZEMQ8w"
		"DQYDVQQKEwZNSUNJVFQxCzAJBgNVBAYTAkNSMSkwJwYDVQQDEyBDQSBSQUlaIE5B"
		"Q0lPTkFMIC0gQ09TVEEgUklDQSB2MjAeFw0xNTAyMjUxODA4MzhaFw0zMTAyMjUx"
		"ODE4MzhaMH0xGTAXBgNVBAUTEENQSi0yLTEwMC0wOTgzMTExCzAJBgNVBAYTAkNS"
		"MQ8wDQYDVQQKEwZNSUNJVFQxDTALBgNVBAsTBERDRkQxMzAxBgNVBAMTKkNBIFBP"
		"TElUSUNBIFBFUlNPTkEgRklTSUNBIC0gQ09TVEEgUklDQSB2MjCCAiIwDQYJKoZI"
		"hvcNAQEBBQADggIPADCCAgoCggIBANkkXhbXpjPWMmmjmKLZBpk+EsM/nBp0JgPB"
		"tQFmnmA0d4fPlKXy8/sD0buS1QRDZZAerSvprfyaiKPAEpZpOWCl2fu46MQyyTa1"
		"DjH/ellvjADlOueC3p3O9qG5JIUrhuLTcx5G+eYyoJIURNob9O4Ur52+eTOYYqvJ"
		"IYomKLc+/2pbJ0SApv+2m3p3oAp2SjTeWTMKVH6sPgqMD2izWJ3xChCefu2yec7N"
		"YaGjS1aMefYDIN2uklX7IhBTf9ErGGIPQ6Jmgoe5GvYfLB7O1BgaTcC3ZIwvGfoA"
		"owfiRYOzLfnuxuuTkUWFfafcYJTUYEkZimHeyEWh41M+kOkZE/q5jwQkfgTLGV+U"
		"QpVGMKSkzsW5EdgcI51ynZBkunnJsglTys66EEfAnoLr3uhiS67AE2Qqvvp7NOUU"
		"G1YCm7WOyEvVt1QbZUlkLZRxhlF5SKjmzhqruisBfmUz6tX6WO3EJyNT5N62YwQx"
		"SULOatx90ztuxzCHHhCcoh3xOWhWYtTwx4F2QDiRqfXfyTw9Te4CGlzmOYSQIdnO"
		"eTUTkDZ3WOxs2bAGgmGQQL+WtzIW3qj2xtspV4F7owwjlG+jhNHJzbjVxoYJoUJm"
		"yR8NCBYkdl/iNxewSUcOseZz+VVvlYJrcI1pRuJ1cnhyvWF/ymc8N1ZGtUMauSel"
		"r1tBGakNAgMBAAGjggctMIIHKTAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU"
		"aJ1pNsuEbnvqk2EZ/1gwHdX/XMswggTcBgNVHSAEggTTMIIEzzCCARQGB2CBPAEB"
		"AQEwggEHMIGmBggrBgEFBQcCAjCBmR6BlgBJAG0AcABsAGUAbQBlAG4AdABhACAA"
		"bABhACAAUABvAGwAaQB0AGkAYwBhACAAZABlACAAbABhACAAUgBhAGkAegAgAEMA"
		"bwBzAHQAYQByAHIAaQBjAGUAbgBzAGUAIABkAGUAIABDAGUAcgB0AGkAZgBpAGMA"
		"YQBjAGkAbwBuACAARABpAGcAaQB0AGEAbAAgAHYAMjAqBggrBgEFBQcCARYeaHR0"
		"cDovL3d3dy5maXJtYWRpZ2l0YWwuZ28uY3IAMDAGCCsGAQUFBwIBFiRodHRwOi8v"
		"d3d3Lm1pY2l0LmdvLmNyL2Zpcm1hZGlnaXRhbAAwggFVBghggTwBAQEBATCCAUcw"
		"geYGCCsGAQUFBwICMIHZHoHWAEkAbQBwAGwAZQBtAGUAbgB0AGEAIABsAGEAIABw"
		"AG8AbABpAHQAaQBjAGEAIABkAGUAIABDAEEAIABFAG0AaQBzAG8AcgBhACAAcABh"
		"AHIAYQAgAFAAZQByAHMAbwBuAGEAcwAgAEYAaQBzAGkAYwBhAHMAIABwAGUAcgB0"
		"AGUAbgBlAGMAaQBlAG4AdABlACAAYQAgAGwAYQAgAFAASwBJACAATgBhAGMAaQBv"
		"AG4AYQBsACAAZABlACAAQwBvAHMAdABhACAAUgBpAGMAYQAgAHYAMjAqBggrBgEF"
		"BQcCARYeaHR0cDovL3d3dy5maXJtYWRpZ2l0YWwuZ28uY3IAMDAGCCsGAQUFBwIB"
		"FiRodHRwOi8vd3d3Lm1pY2l0LmdvLmNyL2Zpcm1hZGlnaXRhbAAwggErBghggTwB"
		"AQEBAjCCAR0wgbwGCCsGAQUFBwICMIGvHoGsAEkAbQBwAGwAZQBtAGUAbgB0AGEA"
		"IABsAGEAIABwAG8AbABpAHQAaQBjAGEAIABwAGEAcgBhACAAZgBpAHIAbQBhACAA"
		"ZABpAGcAaQB0AGEAbAAgAGQAZQAgAHAAZQByAHMAbwBuAGEAcwAgAGYAaQBzAGkA"
		"YwBhAHMAIAAoAGMAaQB1AGQAYQBkAGEAbgBvAC8AcgBlAHMAaQBkAGUAbgB0AGUA"
		"KQAgAHYAMjAqBggrBgEFBQcCARYeaHR0cDovL3d3dy5maXJtYWRpZ2l0YWwuZ28u"
		"Y3IAMDAGCCsGAQUFBwIBFiRodHRwOi8vd3d3Lm1pY2l0LmdvLmNyL2Zpcm1hZGln"
		"aXRhbAAwggErBghggTwBAQEBAzCCAR0wgbwGCCsGAQUFBwICMIGvHoGsAEkAbQBw"
		"AGwAZQBtAGUAbgB0AGEAIABsAGEAIABwAG8AbABpAHQAaQBjAGEAIABwAGEAcgBh"
		"ACAAYQB1AHQAZQBuAHQAaQBjAGEAYwBpAG8AbgAgAGQAZQAgAHAAZQByAHMAbwBu"
		"AGEAcwAgAGYAaQBzAGkAYwBhAHMAIAAoAGMAaQB1AGQAYQBkAGEAbgBvAC8AcgBl"
		"AHMAaQBkAGUAbgB0AGUAKQAgAHYAMjAqBggrBgEFBQcCARYeaHR0cDovL3d3dy5m"
		"aXJtYWRpZ2l0YWwuZ28uY3IAMDAGCCsGAQUFBwIBFiRodHRwOi8vd3d3Lm1pY2l0"
		"LmdvLmNyL2Zpcm1hZGlnaXRhbAAwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEw"
		"CwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU4PL+fcRE"
		"TlDkNf0IiY9OhBlEM0AwgdIGA1UdHwSByjCBxzCBxKCBwaCBvoZaaHR0cDovL3d3"
		"dy5maXJtYWRpZ2l0YWwuZ28uY3IvcmVwb3NpdG9yaW8vQ0ElMjBSQUlaJTIwTkFD"
		"SU9OQUwlMjAtJTIwQ09TVEElMjBSSUNBJTIwdjIuY3JshmBodHRwOi8vd3d3Lm1p"
		"Y2l0LmdvLmNyL2Zpcm1hZGlnaXRhbC9yZXBvc2l0b3Jpby9DQSUyMFJBSVolMjBO"
		"QUNJT05BTCUyMC0lMjBDT1NUQSUyMFJJQ0ElMjB2Mi5jcmwwgeYGCCsGAQUFBwEB"
		"BIHZMIHWMGYGCCsGAQUFBzAChlpodHRwOi8vd3d3LmZpcm1hZGlnaXRhbC5nby5j"
		"ci9yZXBvc2l0b3Jpby9DQSUyMFJBSVolMjBOQUNJT05BTCUyMC0lMjBDT1NUQSUy"
		"MFJJQ0ElMjB2Mi5jcnQwbAYIKwYBBQUHMAKGYGh0dHA6Ly93d3cubWljaXQuZ28u"
		"Y3IvZmlybWFkaWdpdGFsL3JlcG9zaXRvcmlvL0NBJTIwUkFJWiUyME5BQ0lPTkFM"
		"JTIwLSUyMENPU1RBJTIwUklDQSUyMHYyLmNydDANBgkqhkiG9w0BAQ0FAAOCAgEA"
		"v5rU86FMttoAqCsAJGUQl7DboiQosF/FAvhX0YhsfYWRyUL5BOmuWjIMNuljuU5L"
		"c6BR5eWePSUkOe3acDzslBkUjKzyNRZNQA7IXkuVs1arFT5djjhGiCdzwH7+rFek"
		"bNxicdhWJSJ7Fge5dMTkErgDJDERAWfePgzg55hacoTCgX0RkBQDZ08UJMVNgNuo"
		"gfGGfXYgliwoFj4SnwktHjJHmAptQyLi+tCrt4VWr8+G34FFL51bAvio+RABqD7n"
		"u26cnnyNvZ5Ce4oMIcPxUkMX/LINqOFUjY75CcBhovqUJYEobbR9cvMcu3EC2su5"
		"asHDWjZxiUQrvSRHvH+7jNYuSk84THfiNcZq99o9ra/pG3ufO07ox1IHDDlX6LX6"
		"lTt6DbKw+5Z5L9I4GphhcxWxIdeNmg7xq60Cfy02sqLHeelOoweJLr97rliieeZk"
		"XXkGRN62z+1/ZcdS4gj1v+JKHiYLquTkxZFVCo/GmjC5IfUV5SrwtF7vfsJF9Hkd"
		"aEcsQ9iuKOS28OR4vR0baEsCvlMotJn3jMFbFYO/v/e9P/79T3e+cVi/Va//avW1"
		"jxgCQGvTkca6RfqTr3WkMrnwZhHBvTvu0utoIRruw4vpbboFbrm6kkRbMYlA7Yop"
		"UEBsMW+iqjp6jzifnlluqriqPuBAfmTv8ASr8JE8Ytw="
	);

	// CA RAIZ NACIONAL - COSTA RICA v2
	writer.String(
		"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"
	);

	writer.EndArray();
	writer.Key("encryptionAlgorithm");
	writer.String("RSA");
	writer.EndObject();
	writer.EndObject();

	//std::cout << stringBuffer.GetString() << std::endl;

	gnutls_privkey_t key;
	ret = gnutls_privkey_init(&key);
	if (ret < GNUTLS_E_SUCCESS) {
		std::ostringstream error;
		error << "Error al inicializar la clave privada:" << std::endl
			<< gnutls_strerror(ret);
		wxMessageBox(wxString(error.str().c_str(), wxConvUTF8),
			wxT("Error al inicializar clave"), wxICON_ERROR);
		return ret;
	}

	/*
	 * Tras seleccionarse, cargar el identificador correspondiente, esta
	 * vez con PIN para poder usar la clave privada para poder firmar.
	 */
	ret = gnutls_privkey_import_url(key,
		cert_choices.Item(
			choiceDialog.GetSelection()).mb_str(wxConvUTF8), 0);
	if (ret < GNUTLS_E_SUCCESS) {
		std::ostringstream error;
		error << "Error al importar la URL de la clave privada:"
			<< std::endl << gnutls_strerror(ret);
		wxMessageBox(wxString(error.str().c_str(), wxConvUTF8),
			wxT("Error al importar URL de clave"), wxICON_ERROR);
		return ret;
	}

	std::string datos_base64 =
		"MYIBUzAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMC8GCSqGSIb3DQEJBDEiBCDALgEEhMr4mMg9m1MJ1vQBKXm/BcZrdi7E1GJaN6Nd2DCCAQQGCyqGSIb3DQEJEAIvMYH0MIHxMIHuMIHrMA0GCWCGSAFlAwQCAQUABCDYNjvWvS/jDEGRzVuwWpfnVW7+AfIHxFnYHexYGGv2ZTCBtzCBn6SBnDCBmTEZMBcGA1UEBRMQQ1BKLTQtMDAwLTAwNDAxNzELMAkGA1UEBhMCQ1IxJDAiBgNVBAoTG0JBTkNPIENFTlRSQUwgREUgQ09TVEEgUklDQTEiMCAGA1UECxMZRElWSVNJT04gU0lTVEVNQVMgREUgUEFHTzElMCMGA1UEAxMcQ0EgU0lOUEUgLSBQRVJTT05BIEZJU0lDQSB2MgITFAABH/a5gZb8gqHY/AAAAAEf9g==";
	std::string datos = base64_decode(datos_base64);
	gnutls_datum_t data = {(unsigned char*)datos.c_str(),
		(unsigned)datos.length()};

	gnutls_datum_t sig;
	ret = gnutls_privkey_sign_data(key, GNUTLS_DIG_SHA256, 0, &data, &sig);
	if (ret < GNUTLS_E_SUCCESS) {
		std::ostringstream error;
		error << "Error al firmar:"
			<< std::endl << gnutls_strerror(ret);
		wxMessageBox(wxString(error.str().c_str(), wxConvUTF8),
			wxT("Error al firmar"), wxICON_ERROR);
		return ret;
	}

	gnutls_datum_t signatureValue;
	gnutls_pem_base64_encode_alloc(NULL, &sig, &signatureValue);

	//std::cout << "signatureValue: " << signatureValue.data << std::endl;

	gnutls_free(sig.data);
	gnutls_privkey_deinit(key);

	for (std::size_t i = 0; i < token_obj_lists_sizes.size(); i++) {
		for (std::size_t j = 0; j < token_obj_lists_sizes.at(i); j++) {
			gnutls_pkcs11_obj_deinit(token_obj_lists.at(i)[j]);
		}
	}

	if (obj_list_size > 0) {
		gnutls_free(obj_list);
	}

	gnutls_pkcs11_deinit();

	return false;
}
