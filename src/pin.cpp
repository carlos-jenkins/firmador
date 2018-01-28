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

#include "pin.h"

#include <wx/wxprec.h>
#ifndef WX_PRECOMP
# include <wx/wx.h>
#endif

#include <gnutls/pkcs11.h>

int pin_callback(void *userdata, int attempt, const char *token_url,
	const char *token_label, unsigned int flags, char *pin,
	std::size_t pin_max) {

	(void) userdata;
	(void) attempt;
	(void) token_url;
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
			wxMessageBox(
				wxString("No se ha introducido ningún valor",
					wxConvUTF8),
				wxT("PIN en blanco"));
			return -1;
		}

		int len = std::min(pin_max - 1,
			std::char_traits<char>::length(
				pinDialog.GetValue().mb_str(wxConvUTF8)));
		memcpy(pin, pinDialog.GetValue().mb_str(wxConvUTF8), len);
		pin[len] = 0;

		return 0;
	} else {
		return -1;
	}
}
