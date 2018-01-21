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

#include "uuid.h"

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iostream>

std::string uuid() {
	char uuid_cstr[37];

	srand(time(NULL));
	sprintf(uuid_cstr,
		"%02x%02x%02x%02x-%02x%02x-%02x%02x"
		"-%02x%02x-%02x%02x%02x%02x%02x%02x",
		rand() & 0xFF, rand() & 0xFF, rand() & 0xFF,
		rand() & 0xFF, rand() & 0xFF, rand() & 0xFF,
		(rand() & 0x0F) | 0x40, rand() & 0xFF,
		rand() % 0x3F + 0x80, rand() & 0xFF,
		rand() & 0xFF, rand() & 0xFF, rand() & 0xFF,
		rand() & 0xFF, rand() & 0xFF, rand() & 0xFF);
	std::string uuid(uuid_cstr);

	return uuid;
}
