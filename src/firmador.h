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

#ifndef FIRMADOR_H
#define FIRMADOR_H

#include <sys/types.h>
#ifndef _WIN32
# include <sys/select.h>
# include <sys/socket.h>
#else
# define UNICODE
# include <winsock2.h>
#endif

#include <wx/wxprec.h>
#ifndef WX_PRECOMP
# include <wx/wx.h>
#endif

class Firmador : public wxApp
{
public:
	virtual bool OnInit();
};

#endif
