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

#include "base64.h"

#include <vector>

std::string base64_decode(const std::string &in) {
	std::string out;
	std::vector<int> vec(256, -1);

	for (int i = 0; i < 64; i++) {
		vec[
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
			"ghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
	}
	int val = 0, valb = -8;
	for (unsigned c = 0; c < in.size(); ++c) {
		if (vec[in[c]] == -1) break;
		val = (val << 6) + vec[in[c]];
		valb += 6;
		if (valb >= 0) {
			out.push_back(char((val >> valb) & 0xFF));
			valb -= 8;
		}
	}

	return out;
}
