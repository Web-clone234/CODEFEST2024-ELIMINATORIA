


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



using namespace CryptoPP;



const size_t chunkSize = 1000 * 1024 * 1024;



void updateHash(SHA256& hash, std::vector<byte>& buffer, std::vector<byte>& processedData, size_t bytesRead, bool isEncrypt);
void processFile(const std::string& input_path, const std::string& output_path, bool isEncrypt);
void encrypt(const std::string& input_path, const std::string& output_path);
void decrypt(const std::string& input_path, const std::string& output_path);
void generateSeed();

std::string generateRandomString(std::mt19937& generator, size_t length);
std::string buildKey();
std::string buildIV();



int main(int argc, char* argv[]) {

    if (argc != 4) {
        std::cerr << "Uso: " << argv[0] << " <operation> <input_path> <output_path>" << std::endl;
        return 1;
    }

    std::string operation = argv[1];
    std::string input_path = argv[2];
    std::string output_path = argv[3];

    if (operation == "encrypt") {
        encrypt(input_path, output_path);
    }
    else if (operation == "decrypt") {
        decrypt(input_path, output_path);
    }
    else {
        std::cerr << "Operaci�n no v�lida: " << operation << std::endl;
        return 1;
    }
    return 0;
}



void updateHash(SHA256& hash, std::vector<byte>& buffer, std::vector<byte>& processedData, size_t bytesRead, bool isEncrypt) {
    if (isEncrypt) {
        hash.Update(buffer.data(), bytesRead);
    }
    else {
        hash.Update(processedData.data(), bytesRead);
    }
}



void processFile(const std::string& input_path, const std::string& output_path, bool isEncrypt) {
    try {
        std::string key = buildKey();
        std::string iv = buildIV();
        std::ifstream inFile(input_path, std::ios::binary);
        std::ofstream outFile(output_path, std::ios::binary);

        if (!inFile.is_open() || !outFile.is_open()) {
            std::cerr << "Error abriendo los archivos" << std::endl;
            return;
        }

        CTR_Mode<AES>::Encryption encryptor;
        CTR_Mode<AES>::Decryption decryptor;
        if (isEncrypt) {
            encryptor.SetKeyWithIV((const byte*)key.data(), 32, (const byte*)iv.data());
        }
        else {
            decryptor.SetKeyWithIV((const byte*)key.data(), 32, (const byte*)iv.data());
        }

        std::vector<byte> buffer(chunkSize);
        SHA256 hash;

        while (inFile) {
            inFile.read(reinterpret_cast<char*>(buffer.data()), chunkSize);
            std::streamsize bytesRead = inFile.gcount();

            if (bytesRead > 0) {
                std::vector<byte> processedData(bytesRead);
                if (isEncrypt) {
                    updateHash(hash, buffer, processedData, bytesRead, true);
                    encryptor.ProcessData(processedData.data(), buffer.data(), bytesRead);
                }
                else {
                    decryptor.ProcessData(processedData.data(), buffer.data(), bytesRead);
                    updateHash(hash, buffer, processedData, bytesRead, false);
                }
                outFile.write(reinterpret_cast<char*>(processedData.data()), bytesRead);
            }
        }

        inFile.close();
        outFile.close();

        byte digest[CryptoPP::SHA256::DIGESTSIZE];
        hash.Final(digest);
        std::string hashResult;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashResult));
        encoder.Put(digest, sizeof(digest));
        encoder.MessageEnd();

        if (isEncrypt) {
            std::ofstream outHashFile("hash.bin", std::ios::binary);
            if (!outHashFile) {
                std::cerr << "No se pudo crear el archivo de integridad" << std::endl;
                return;
            }
            size_t length = hashResult.size();
            outHashFile.write(reinterpret_cast<const char*>(&length), sizeof(length));
            outHashFile.write(hashResult.c_str(), length);
            outHashFile.close();
        }
        else {
            std::ifstream inHashFile("hash.bin", std::ios::binary);
            size_t length = 64;
            if (!inHashFile) {
                std::cerr << "No se pudo acceder al archivo de integridad" << std::endl;
                return;
            }
            inHashFile.read(reinterpret_cast<char*>(&length), sizeof(length));
            std::string calculatedHash(length, '\0');
            inHashFile.read(&calculatedHash[0], length);
            inHashFile.close();

            if (hashResult != calculatedHash) {
                std::cerr << "La imagen ha sido alterada durante su envio!!" << std::endl;
                return;
            }
        }
    }
    catch (const Exception& e) {
        std::cerr << e.what() << std::endl;
    }
}



void encrypt(const std::string& input_path, const std::string& output_path) {
    generateSeed();
    std::cout << "input_path=" << input_path << std::endl;
    std::cout << "output_path=" << output_path << std::endl;
    processFile(input_path, output_path, true);
    std::cout << "Encrypted image" << std::endl;
}

void decrypt(const std::string& input_path, const std::string& output_path) {
    std::cout << "input_path=" << input_path << std::endl;
    std::cout << "output_path=" << output_path << std::endl;
    processFile(input_path, output_path, false);
    std::cout << "Decrypted image" << std::endl;
}



void generateSeed() {
    
    SHA256 hash;
    std::string digest;
    
    unsigned int seed = static_cast<unsigned int>(std::time(0));
    
    std::mt19937 generator(seed);
    std::uniform_int_distribution<int> distribution(0, 9999);
    
    StringSource ss(std::to_string(distribution(generator)), true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest), false)));
    
    std::ofstream outFile("seed.bin", std::ios::binary);
    
    if (!outFile) {
        std::cerr << "No se pudo crear el archivo semilla" << std::endl;
        return;
    }
    
    size_t length = digest.size();
    outFile.write(reinterpret_cast<const char*>(&length), sizeof(length)); 
    outFile.write(digest.c_str(), length); 
    outFile.close();
}



std::string generateRandomString(std::mt19937& generator, size_t length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%&/()=?�*-+";
    const size_t maxIndex = (sizeof(charset) - 1);
    std::string randomString(length, 0);
    std::uniform_int_distribution<> distribution(0, maxIndex);
    for (size_t i = 0; i < length; ++i) {
        randomString[i] = charset[distribution(generator)];
    }
    return randomString;
}



std::string buildKey() {
    std::ifstream inFile("seed.bin", std::ios::binary);
    size_t length = 64;
    if (!inFile) {
        std::cerr << "No se pudo acceder al archivo semilla" << std::endl;
        return "";
    }
    inFile.read(reinterpret_cast<char*>(&length), sizeof(length)); 
    std::string seed(length, '\0'); 
    inFile.read(&seed[0], length); 
    inFile.close();
    std::hash<std::string> hasher;
    std::mt19937 generator(hasher(seed));
    std::string seedKey = generateRandomString(generator, length);
    for (int i = 0; i < 4; ++i) {
        std::string tempKey = generateRandomString(generator, length);
        for (int j = 0; j < 64; ++j) {
            seedKey += seedKey[j] ^ tempKey[j]; 
        }
    }
    SHA256 hash;
    std::string digest;
    StringSource ss(seedKey, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest), false)));
    return digest;
}



std::string buildIV() {
    std::ifstream inFile("seed.bin", std::ios::binary);
    size_t length = 64;
    if (!inFile) {
        std::cerr << "No se pudo acceder al archivo semilla" << std::endl;
        return "";
    }
    inFile.read(reinterpret_cast<char*>(&length), sizeof(length));
    std::string seed(length, '\0');
    inFile.read(&seed[0], length); 
    inFile.close();
    std::hash<std::string> hasher;
    std::mt19937 generator(hasher(seed));
    std::string iv = generateRandomString(generator, 32);
    return iv;
}
