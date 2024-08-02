#define CRYPTOPP_DISABLE_ASM 1
#define CRYPTOPP_DISABLE_AESNI 1
#define CRYPTOPP_DISABLE_SHANI 1

#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iterator>
#include <fstream>
#include <chrono>
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include <cstdlib>

// Declaraci�n de los namespace usados en el proyecto

using namespace CryptoPP;

// Declaraci�n de las constantes usadas en el proyecto

const size_t CHUNK_SIZE = 1000 * 1024 * 1024;

// Declaraci�n de las funciones usadas en el proyecto

void encrypt(const std::string &input_path, const std::string &output_path);
void decrypt(const std::string &input_path, const std::string &output_path);
void generateSeed();
std::string generateRandomString(std::mt19937 &generator, size_t length);
std::string buildKey();
std::string buildIV();

// Funcion principal

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        std::cerr << "Uso: " << argv[0] << " <operation> <input_path> <output_path>" << std::endl;
        return 1;
    }

    std::string operation = argv[1];
    std::string input_path = argv[2];
    std::string output_path = argv[3];

    if (operation == "encrypt")
    {
        encrypt(input_path, output_path);
    }
    else if (operation == "decrypt")
    {
        decrypt(input_path, output_path);
    }
    else
    {
        std::cerr << "Operaci�n no v�lida: " << operation << std::endl;
        return 1;
    }

    return 0;
}

// Funcion para encriptar

void encrypt(const std::string &input_path, const std::string &output_path)
{

    generateSeed();
    std::string key = buildKey();
    // std::string key = "U))3bv(b&ae(u$p3rSMj(5x%iavgtE&y"; // 32 bytes key for AES-256
    // std::string iv = "0123456789abcdef";  // 16 bytes IV
    std::string iv = buildIV();

    std::cout << "input_path=" << input_path << std::endl;
    std::cout << "output_path=" << output_path << std::endl;

    try
    {
        CTR_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV((const byte *)key.data(), 32, (const byte *)iv.data());

        std::ifstream inFile(input_path, std::ios::binary);
        std::ofstream outFile(output_path, std::ios::binary);

        if (!inFile.is_open() || !outFile.is_open())
        {
            std::cerr << "Error opening file." << std::endl;
            return;
        }

        std::vector<byte> buffer(CHUNK_SIZE);

        while (inFile)
        {
            inFile.read(reinterpret_cast<char *>(buffer.data()), CHUNK_SIZE);
            std::streamsize bytesRead = inFile.gcount();

            if (bytesRead > 0)
            {
                std::vector<byte> encrypted(bytesRead);
                encryptor.ProcessData(encrypted.data(), buffer.data(), bytesRead);
                outFile.write(reinterpret_cast<char *>(encrypted.data()), bytesRead);
            }
        }

        inFile.close();
        outFile.close();
    }
    catch (const Exception &e)
    {
        std::cerr << e.what() << std::endl;
    }

    std::cout << "Encrypted image" << std::endl;
}

// Funcion para desencriptar

void decrypt(const std::string &input_path, const std::string &output_path)
{

    std::string key = buildKey();
    std::string iv = buildIV();

    std::cout << "input_path=" << input_path << std::endl;
    std::cout << "output_path=" << output_path << std::endl;

    try
    {
        CTR_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV((const byte *)key.data(), 32, (const byte *)iv.data());

        std::ifstream inFile(input_path, std::ios::binary);
        std::ofstream outFile(output_path, std::ios::binary);

        if (!inFile.is_open() || !outFile.is_open())
        {
            std::cerr << "Error opening file." << std::endl;
            return;
        }

        std::vector<byte> buffer(CHUNK_SIZE);

        while (inFile)
        {
            inFile.read(reinterpret_cast<char *>(buffer.data()), CHUNK_SIZE);
            std::streamsize bytesRead = inFile.gcount();

            if (bytesRead > 0)
            {
                std::vector<byte> decrypted(bytesRead);
                decryptor.ProcessData(decrypted.data(), buffer.data(), bytesRead);
                outFile.write(reinterpret_cast<char *>(decrypted.data()), bytesRead);
            }
        }

        inFile.close();
        outFile.close();
    }
    catch (const Exception &e)
    {
        std::cerr << e.what() << std::endl;
    }

    std::cout << "Decrypted image" << std::endl;
}

// Funcion para generar una semilla

void generateSeed()
{

    SHA256 hash;
    std::string digest;

    unsigned int seed = static_cast<unsigned int>(std::time(0));
    std::mt19937 generator(seed);
    std::uniform_int_distribution<int> distribution(0, 9999);

    StringSource ss(std::to_string(distribution(generator)), true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest), false)));

    std::ofstream outFile("ncp.bin", std::ios::binary);
    if (!outFile)
    {
        std::cerr << "Could not write seed information" << std::endl;
    }

    size_t length = digest.size();
    outFile.write(reinterpret_cast<const char *>(&length), sizeof(length));
    outFile.write(digest.c_str(), length);
    outFile.close();

    // std::cout << "Semilla Generada: " << digest << " Size: " << sizeof(digest) << std::endl;
}

std::string generateRandomString(std::mt19937 &generator, size_t length)
{

    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%&/()=?�*-+";
    const size_t maxIndex = (sizeof(charset) - 1);

    std::string randomString(length, 0);
    std::uniform_int_distribution<> distribution(0, maxIndex);

    for (size_t i = 0; i < 64; ++i)
    {
        randomString[i] = charset[distribution(generator)];
    }

    return randomString;
}

std::string buildKey()
{

    std::ifstream inFile("ncp.bin", std::ios::binary);
    size_t length = 64;

    if (!inFile)
    {
        std::cerr << "Seed information could not be obtained" << std::endl;
    }

    inFile.read(reinterpret_cast<char *>(&length), sizeof(length));
    std::string seed(length, '\0');
    inFile.read(&seed[0], length); // Leer la cadena
    inFile.close();

    // std::cout << "Semilla Leida: " << seed << " Size: " << sizeof(seed) << std::endl;

    std::hash<std::string> hasher;
    std::mt19937 generator(hasher(seed));

    std::string seedKey = generateRandomString(generator, length);

    // std::cout << "String:" << seedKey << " Size: " << sizeof(seedKey) << std::endl;

    for (int i = 0; i < 4; ++i)
    {
        std::string tempKey = generateRandomString(generator, length);
        // std::cout << "String: " << tempKey << " Size: " << sizeof(tempKey) << std::endl;
        for (int j = 0; j < 64; ++j)
        {
            seedKey += seedKey[j] ^ tempKey[j];
        }
    }

    // std::cout << "Seed Key:" << seedKey << " Size: " << sizeof(seedKey) << std::endl;

    SHA256 hash;
    std::string digest;

    StringSource ss(seedKey, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest), false)));

    // std::cout << "Key:" << digest << " Size: " << digest.length() << std::endl;

    return digest;
}

std::string buildIV()
{

    std::ifstream inFile("ncp.bin", std::ios::binary);
    size_t length = 64;

    if (!inFile)
    {
        std::cerr << "Seed information could not be obtained" << std::endl;
    }

    inFile.read(reinterpret_cast<char *>(&length), sizeof(length));
    std::string seed(length, '\0');
    inFile.read(&seed[0], length); // Leer la cadena
    inFile.close();

    // std::cout << "Semilla Leida: " << seed << " Size: " << sizeof(seed) << std::endl;

    std::hash<std::string> hasher;
    std::mt19937 generator(hasher(seed));

    std::string iv = generateRandomString(generator, 32);

    // std::cout << "iv: " << iv << "Size: " << iv.length() << std::endl;

    return iv;
}
