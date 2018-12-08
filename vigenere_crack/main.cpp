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
#include <array>

struct Attempt
{
	size_t len;
	double ic; // index of coincidence
};

struct Frequency
{
	char letter;
	double dev;
};

std::string g_secret;
size_t g_keyLen{0};
std::string g_key;
std::vector<Attempt> g_attempt;
std::vector<std::array<Frequency, 26> > g_frequency;
std::array<double, 26> g_stdfreq =
                                {
      								0.08167,0.01492,0.02782,0.04253,0.12702,0.02228,0.02015,0.06094,
									0.06966,0.00153,0.03872,0.04025,0.02406,0.06749,0.07507,0.01929,
									0.00095,0.05987,0.06327,0.09256,0.02758,0.00978,0.05370,0.00150,
									0.03978,0.00074
	                            };

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
		out << static_cast<char>((static_cast<int>(plain[i] - 'A') + (key[j] - 'A')) % 26 + 'A');
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
	g_keyLen = 0;
	g_key.clear();
	g_attempt.clear();
	g_frequency.clear();
}

void guess(size_t maxLen)
{
	if (g_secret.empty())
	{
		std::cerr << "Secret not loaded!" << std::endl;
		return;
	}

	g_attempt.clear();
	g_attempt.resize(std::min(maxLen, g_secret.size()));
	for (size_t len{1}; len <= std::min(maxLen, g_secret.size()); ++len)
	{
		double total{0};
		for (size_t col{0}; col < len; ++col)
		{
			std::array<int, 256> count{};
			int colLen{0};
			for (size_t i{col}; i < g_secret.size(); i += len)
			{
				++count[g_secret[i]];
				++colLen;
			}

			double current{0};
			for (size_t i{'A'}; i <= 'Z'; ++i)
				current += count[i] * (count[i] - 1);
			current *= 26;
			current /= colLen * (colLen - 1);
			total += current;
		}

		g_attempt[len - 1] = {len, total / len};
	}

	std::sort(g_attempt.begin(), g_attempt.end(), [](const Attempt &a, const Attempt &b) { return a.ic > b.ic; });
}

void analyze()
{
	if (g_secret.empty())
	{
		std::cerr << "Secret not loaded!" << std::endl;
		return;
	}

	if (!g_keyLen)
	{
		std::cerr << "Key length not set" << std::endl;
		return;
	}

	g_frequency.clear();
	g_frequency.resize(g_keyLen);
	
	for (size_t col{0}; col < g_keyLen; ++col)
	{
		std::array<double, 256> count{};
		int colLen{0};
		for (size_t i{col}; i < g_secret.size(); i += g_keyLen)
		{
			++count[g_secret[i]];
			++colLen;
		}

		for (size_t i{'A'}; i <= 'Z'; ++i)
			count[i] /= colLen;

		for (size_t offset{0}; offset < 26; ++offset)
		{
			g_frequency[col][offset].letter = static_cast<char>('A' + offset);
			for (size_t i{0}; i < 26; ++i)
			{
				size_t result{(i + offset) % 26};
				g_frequency[col][offset].dev += std::abs(count['A' + result] - g_stdfreq[i]) * g_stdfreq[i];
			}
		}

		std::sort(g_frequency[col].begin(), g_frequency[col].end(), [](const Frequency &a, const Frequency &b) { return a.dev < b.dev; });
	}
}

void decrypt(std::string &outFile)
{
	if (g_secret.empty())
	{
		std::cerr << "Secret not loaded!" << std::endl;
		return;
	}

	if (!g_keyLen)
	{
		std::cerr << "Key length not set" << std::endl;
		return;
	}

	bool validKey{true};
	for (char letter : g_key)
	{
		if (letter < 'A' || letter > 'Z')
		{
			validKey = false;
			break;
		}
	}

	if (!validKey)
	{
		std::cerr << "Invalid key" << std::endl;
		return;
	}

	std::ofstream out{outFile};
	if (!out.is_open())
	{
		std::cerr << "Failed to open \"" << outFile << "\"!" << std::endl;
		return;
	}

	size_t j{0};
	for (size_t i{0}; i < g_secret.size(); ++i)
	{
		out << static_cast<char>(((g_secret[i] - 'A') - (g_key[j] - 'A') + 26) % 26 + 'A');
		++j;
		if (j == g_keyLen)
			j = 0;
	}
}


int main()
{
	std::cout << "Vigenere Cracker\n"
		      << "e <in_file> <key_file> <out_file>: encrypt\n"
		      << "l <in_file>: load for decryption\n"
		      << "g <max_len>: guess key length\n"
			  << "p <max_len>: list possible length and IC\n"
		      << "s <length>: set key length, <length> = -1 for auto choice\n"
		      << "a: run frequency analysis\n"
		      << "w <pos>: show frequency analysis for pos\n"
		      << "m <pos> <value>: set key value fo pos, <pos> = -1 for auto choice\n"
		      << "c: view configuration\n"
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

		case 's':
		{
			int length{-2};
			stream >> length;
			
			if (length == -1)
			{
				if (g_attempt.empty())
				{
					std::cerr << "Key Length guess was not ran" << std::endl;
				}
				else
				{
					g_keyLen = g_attempt[0].len;
					g_key.clear();
					g_key.resize(g_keyLen);
				}
			}
			else if (length > 0)
			{
				g_keyLen = static_cast<size_t>(length);
				g_key.clear();
				g_key.resize(g_keyLen);
			}
			else
			{
				std::cerr << "Invalid key length" << std::endl;
				break;
			}

			break;
		}

		case 'a':
			analyze();
			break;

		case 'w':
		{
			size_t position{0};
			stream >> position;
			if (position < g_keyLen)
			{
				std::cout << "Letter\tDeviation" << std::endl;
				for (const Frequency &freq : g_frequency[position])
					std::cout << freq.letter << '\t' << freq.dev << std::endl;
			}
			else
			{
				std::cerr << "Invalid position" << std::endl;
			}

			break;
		}

		case 'm':
		{
			int position{-2};
			stream >> position;

			if (position == -1)
			{
				if (g_frequency.empty())
				{
					std::cerr << "Frequency analysis not ran" << std::endl;
				}
				else
				{
					for (size_t i{0}; i < g_keyLen; ++i)
						g_key[i] = g_frequency[i][0].letter;
				}
			}
			else if (0 <= position && position < static_cast<int>(g_keyLen))
			{
				char value{0};
				stream >> value;
				if ('A' <= value && value <= 'Z')
					g_key[position] = value;
				else
					std::cerr << "Invalid value" << std::endl;
			}
			else
			{
				std::cerr << "Invalid position" << std::endl;
			}

			break;
		}

		case 'c':
			std::cout << "Key length: " << g_keyLen << std::endl;
			std::cout << "Key: ";
			for (char letter : g_key)
			{
				if ('A' <= letter && letter <= 'Z')
					std::cout << letter;
				else
					std::cout << '!';
			}
			std::cout << std::endl;

			break;

		case 'd':
		{
			std::string outFile;
			stream >> outFile;
			decrypt(outFile);
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
