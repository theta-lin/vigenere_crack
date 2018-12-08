/*
Copyright (c) 2018 Theta Lin

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
*/

#include <cctype>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <vector>

struct Attempt
{
	size_t len;
	float ic; // index of coincidence
};

std::string g_secret;
size_t keyLen;
std::vector<Attempt> g_attempt;

std::string readFile(const std::ifstream &in)
{
	std::stringstream stream;
	stream << in.rdbuf();
	return stream.str();
}

void sanitize(std::string &str)
{
	str.erase(std::remove_if(str.begin(), str.end(), [](char c) { return !::isalpha(c); }), str.end());
	std::transform(str.begin(), str.end(), str.begin(), ::toupper);
}

void encrypt(const std::string &inFile, const std::string &keyFile, const std::string &outFile)
{
	std::ifstream in{inFile};
	if (!in.is_open())
	{
		std::cerr << "Failed to open \"" << inFile << "\"!" << std::endl;
		return;
	}

	std::ifstream keyIn{keyFile};
	if (!keyIn.is_open())
	{
		std::cerr << "Failed to open \"" << keyFile << "\"!" << std::endl;
		return;
	}

	std::ofstream out{outFile};
	if (!out.is_open())
	{
		std::cerr << "Failed to open \"" << outFile << "\"!" << std::endl;
		return;
	}

	std::string plain{readFile(in)};
	sanitize(plain);
	std::string key{readFile(keyIn)};
	sanitize(key);

	size_t j{0};
	for (size_t i{0}; i < plain.size(); ++i)
	{
		out << static_cast<char>(((plain[i] - 'A') + (key[j] - 'A')) % 26 + 'A');
		++j;
		if (j == key.size())
			j = 0;
	}
}

void load(const std::string &inFile)
{
	std::ifstream in{inFile};
	if (!in.is_open())
	{
		std::cerr << "Failed to open \"" << inFile << "\"!" << std::endl;
		return;
	}

	g_secret = readFile(in);
	sanitize(g_secret);
	keyLen = 0;
	g_attempt.clear();
}

void guess(size_t maxLen)
{
	if (g_secret.empty())
	{
		std::cerr << "Secret not loaded!" << std::endl;
		return;
	}

	g_attempt.clear();
	g_attempt.reserve(g_secret.size());
	for (size_t len{1}; len <= std::min(maxLen, g_secret.size()); ++len)
	{
		float total{0};
		for (size_t col{0}; col < len; ++col)
		{
			std::vector<int> count(256);
			int colLen{0};
			for (size_t i{col}; i < g_secret.size(); i += len)
			{
				++count[g_secret[i]];
				++colLen;
			}

			float current{0};
			for (char i{'A'}; i <= 'Z'; ++i)
				current += count[i] * (count[i] - 1);
			current *= 26;
			current /= colLen * (colLen - 1);
			total += current;
		}

		g_attempt.push_back({len, total / len});
	}

	std::sort(g_attempt.begin(), g_attempt.end(), [](const Attempt &a, const Attempt &b) { return a.ic > b.ic; });
}

int main()
{
	std::cout << "Vigenere Cracker\n"
		      << "e <in_file> <key_file> <out_file>: encrypt\n"
		      << "l <in_file>: load for decryption\n"
		      << "g <max_len>: guess key length\n"
			  << "p <max_len>: List possible length and IC\n"
		      << "d <out_file>: decrypt\n"
		      << "q : quit\n";

	bool quit{false};
	while (!quit)
	{
		std::string input;
		std::getline(std::cin, input);
		std::istringstream stream{input};
		char cmd;
		stream >> cmd;

		switch (cmd)
		{
		case 'e':
		{
			std::string inFile, keyFile, outFile;
			stream >> inFile >> keyFile >> outFile;
			encrypt(inFile, keyFile, outFile);
			break;
		}

		case 'l':
		{
			std::string inFile;
			stream >> inFile;
			load(inFile);
			break;
		}

		case 'g':
		{
			size_t maxLen{0};
			stream >> maxLen;
			guess(maxLen);
			break;
		}

		case 'p':
		{
			size_t maxLen{0};
			stream >> maxLen;
			std::cout << "Length\tIC" << std::endl;
			for (size_t i(0); i < std::min(maxLen, g_attempt.size()); ++i)
				std::cout << g_attempt[i].len << '\t' << g_attempt[i].ic << std::endl;
			break;
		}

		case 'q':
			quit = true;
			break;

		default:
			std::cerr << "Unknown command!" << std::endl;
		}

	}

	return 0;
}
