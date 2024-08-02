//
//** Declaracion de las librerias usadas en el codigo **//

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

//** Declaracion de los namespace de las librerias usadas **//

using namespace CryptoPP;

//** Declaracion del tama�o del chunk de lectura (1 Gb) **//

const size_t chunkSize = 1000 * 1024 * 1024;

//** Declaracion de las funciones construidas y usada en el codigo **//

void encrypt(const std::string& input_path, const std::string& output_path);
void decrypt(const std::string& input_path, const std::string& output_path);
void generateSeed();
std::string generateRandomString(std::mt19937& generator, size_t length);
std::string buildKey();
std::string buildIV();

//** Funcion principal del programa **//
//** Permite el ingreso de parametros y la seleccion del modo de uso **//

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

//** Funcion que se encarga de encriptar el archivo ubicado en input_path y guardar el resultado en output_path **//
//** La funcion se encarga de generar la semilla de encriptacion y el hash necesario para verificar la integridad de la imagen **//

void encrypt(const std::string& input_path, const std::string& output_path) {

    //Se genera la semilla que se usara como base para el proceso de generacion de llaves
    generateSeed();
    //Se asigna la llave criptografica y el vector de inicializacion para usar AES CTR
    std::string key = buildKey();
    std::string iv = buildIV();
    //Se informan las rutas de entrada y salida de los archivos
    std::cout << "input_path=" << input_path << std::endl;
    std::cout << "output_path=" << output_path << std::endl;
    try {
        //Se inicializa la libreria en modo AES CTR y se asignan tanto la llave como el vector de inicializacion
        CTR_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV((const byte*)key.data(), 32, (const byte*)iv.data());
        //Se abre el archivo de entrada y se crea el archivo de salida
        std::ifstream inFile(input_path, std::ios::binary);
        std::ofstream outFile(output_path, std::ios::binary);
        //Se manejan posibles errores asociados a la apertura de los archivos
        if (!inFile.is_open() || !outFile.is_open()) {
            std::cerr << "Error abriendo los archivos" << std::endl;
            return;
        }
        //Se inicializa el buffer en el cual se usara para almacenar la informacion de la imagen en chuks (partes)
        std::vector<byte> buffer(chunkSize);
        //Se inicializa la utilidad de la libreria para calcular hashes en modo SHA-256
        SHA256 hash;
        //Se itera hasta que toda la informacion de entrada se haya leido completamente
        while (inFile) {
            //Se lee una porcion de la imagen del tama�o especificado en el chunk
            inFile.read(reinterpret_cast<char*>(buffer.data()), chunkSize);
            std::streamsize bytesRead = inFile.gcount();
            //Desde que exista infromacion para procesar
            if (bytesRead > 0) {
                //Se calcula de forma constante el hash de la imagen para temas de integridad
                hash.Update(buffer.data(), bytesRead);
                std::vector<byte> encrypted(bytesRead);
                //Se encripta la informacion leida en el chunk y se escribe en el archivo de salida
                encryptor.ProcessData(encrypted.data(), buffer.data(), bytesRead);
                outFile.write(reinterpret_cast<char*>(encrypted.data()), bytesRead);
            }
        }
        //Se cierran los archivos usados para evitar fugas de memoria
        inFile.close();
        outFile.close();
        //Se calcula el hash final de la imagen teniendo en cuenta los hashes de todos los chunks leidos
        byte digest[CryptoPP::SHA256::DIGESTSIZE];
        hash.Final(digest);
        std::string hashResult;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashResult));
        encoder.Put(digest, sizeof(digest));
        encoder.MessageEnd();
        //Se almacena el hash en un archivo binario para su posterior uso en la funcion de desencriptar
        std::ofstream outHashFile("hash.bin", std::ios::binary);
        //Se manejan posibles errores asociados a la apertura del archivo
        if (!outHashFile) {
            std::cerr << "No se pudo crear el archivo de integridad" << std::endl;
            return;
        }
        //Finalmente, se escribe el hash de la imagen en el archivo binario
        size_t length = hashResult.size();
        outHashFile.write(reinterpret_cast<const char*>(&length), sizeof(length));
        outHashFile.write(hashResult.c_str(), length);
        outHashFile.close();  
    }
    catch (const Exception& e) {
        std::cerr << e.what() << std::endl;
    }
    //Se informa la finalizacion del proceso de encriptado
    std::cout << "Encrypted image" << std::endl;
}

//** Funcion que se encarga de desencriptar el archivo ubicado en input_path y guardar el resultado en output_path **//
//** La funcion se encarga de verificar la integridad del archivo desencriptado e informar si fue corrompido o alterado **//

void decrypt(const std::string& input_path, const std::string& output_path) {
    //Se recupera la llave criptografica y el vector de inicializacion para usar AES CTR
    std::string key = buildKey();
    std::string iv = buildIV();
    //Se informan las rutas de entrada y salida de los archivos
    std::cout << "input_path=" << input_path << std::endl;
    std::cout << "output_path=" << output_path << std::endl;
    try {
        //Se inicializa la libreria en modo AES CTR y se asignan tanto la llave como el vector de inicializac�on
        CTR_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV((const byte*)key.data(), 32, (const byte*)iv.data());
        //Se abre el archivo de entrada y se crea el archivo de salida
        std::ifstream inFile(input_path, std::ios::binary);
        std::ofstream outFile(output_path, std::ios::binary);
        //Se manejan posibles errores asociados a la apertura de los archivos
        if (!inFile.is_open() || !outFile.is_open()) {
            std::cerr << "Error abriendo los archivos" << std::endl;
            return;
        }
        //Se inicializa el buffer en el cual se usara para almacenar la infromacion de la imagen en chuks (partes)
        std::vector<byte> buffer(chunkSize);
        //Se inicializa la utilidad de la libreria para calcular hashes en modo SHA-256
        SHA256 hash;
        //Se itera hasta que toda la informacion de entrada se haya leido completamente
        while (inFile) {
            //Se lee una porcion de la imagen del tama�o especificado en el chunk
            inFile.read(reinterpret_cast<char*>(buffer.data()), chunkSize);
            std::streamsize bytesRead = inFile.gcount();
            //Desde que exista infromacion para procesar
            if (bytesRead > 0) {
                //Se desencripta la informacion leida en el chunk
                std::vector<byte> decrypted(bytesRead);
                decryptor.ProcessData(decrypted.data(), buffer.data(), bytesRead);
                //Se calcula de forma constante el hash de la imagen para temas de integridad
                hash.Update(decrypted.data(), bytesRead);
                //Se escribe la infromacion desencriptada en el archivo de salida
                outFile.write(reinterpret_cast<char*>(decrypted.data()), bytesRead);
            }
        }
        //Se cierran los archivos usados para evitar fugas de memoria
        inFile.close();
        outFile.close();
        //Se calcula el hash final de la imagen teniendo en cuenta los hashes de todos los chunks leidos
        byte digest[CryptoPP::SHA256::DIGESTSIZE];
        hash.Final(digest);
        std::string hashResult;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashResult));
        encoder.Put(digest, sizeof(digest));
        encoder.MessageEnd();
        //Se recupera el hash calculado de la imagen original
        std::ifstream inHashFile("hash.bin", std::ios::binary);
        size_t length = 64;
        //Se manejan posibles errores asociados a la apertura del archivo
        if (!inHashFile) {
            std::cerr << "No se pudo acceder al archivo de integridad" << std::endl;
            return;
        }
        //Se transfiere la infromacion del archivo a una variable
        inHashFile.read(reinterpret_cast<char*>(&length), sizeof(length));
        std::string calculatedHash(length, '\0');
        inHashFile.read(&calculatedHash[0], length); 
        inHashFile.close();
        //Se verifica la integridad de la imagen desencriptada y se informa en caso de que existan alteraciones
        if (hashResult != calculatedHash) {
            std::cerr << "La imagen ha sido alterada durante su envio!!" << std::endl;
            return;
        }
    }
    catch (const Exception& e) {
        std::cerr << e.what() << std::endl;
    }
    //Se informa la finalizacion del proceso de encriptado
    std::cout << "Decrypted image" << std::endl;
}

//** Funcion que se encarga de generar una semilla (en forma de un string de 64 caracteres) a partir del tiempo actual del sistema **//
//** La semilla generada se usara posteriormente para la creaci�n desacoplada de la llave criptografia **//

void generateSeed() {
    //Se inicializa la utilidad de la libreria para calcular hashes en modo SHA-256
    SHA256 hash;
    std::string digest;
    //Se genera una semilla para generar numeros aleatorios usando el tiempo actual del sistema
    unsigned int seed = static_cast<unsigned int>(std::time(0));
    //Se configura un generador de numeros aleatorios usando una distribucion uniforme y la semilla generada anteriormente
    std::mt19937 generator(seed);
    std::uniform_int_distribution<int> distribution(0, 9999);
    //Se configura el flujo para la generacion de un hash SHA 256 a partir de un string
    StringSource ss(std::to_string(distribution(generator)), true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest), false)));
    //Se crea o accede al archivo binario en el cual se guardara la semilla generadora para su comunicacion
    std::ofstream outFile("seed.bin", std::ios::binary);
    //Se manejan posibles errores asociados a la apertura del archivo
    if (!outFile) {
        std::cerr << "No se pudo crear el archivo semilla" << std::endl;
        return;
    }
    //Se escribe la semilla en el archivo binario y posteriormente se cierra para evitar fugas de memoria
    size_t length = digest.size();
    outFile.write(reinterpret_cast<const char*>(&length), sizeof(length)); 
    outFile.write(digest.c_str(), length); 
    outFile.close();
}

//** Funcion que se encarga de generar un string de 64 carcateres a partir de una semilla de la misma longitud **//
//** La generaci�in es replicable siempre y cuando se use la misma semilla generadora **//

std::string generateRandomString(std::mt19937& generator, size_t length) {
    //Se definen los caracteres que pueden ser usados para generar los string aleatorios
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%&/()=?�*-+";
    const size_t maxIndex = (sizeof(charset) - 1);
    //Se configura un generador de numeros usando una distribucion uniforme y la semilla creada anteriormente
    std::string randomString(length, 0);
    std::uniform_int_distribution<> distribution(0, maxIndex);
    //Se generan string aleatorios de la longitud ingresada como parametro
    for (size_t i = 0; i < length; ++i) {
        randomString[i] = charset[distribution(generator)];
    }
    //Se retorna el string generado
    return randomString;
}

//** Funcion que se encarga de construir la llave criptografica a partir de 5 llaves temporales y una llave semilla **//
//** Esta funcion es la encargada de permitir que se generen las llaves de forma desacoplada y segura **//

std::string buildKey() {
    //Se abre el archivo en el que se encuentra la semilla necesaria para reconstuir la llave
    std::ifstream inFile("seed.bin", std::ios::binary);
    size_t length = 64;
    //Se manejan posibles errores asociados a la apertura del archivo
    if (!inFile) {
        std::cerr << "No se pudo acceder al archivo semilla" << std::endl;
        return "";
    }
    //Se obtiene la infromacion de la semilla almacenada
    inFile.read(reinterpret_cast<char*>(&length), sizeof(length)); 
    std::string seed(length, '\0'); 
    inFile.read(&seed[0], length); 
    inFile.close();
    //Se convierte la semilla de alfanumerica a numerica (int) usando una funcion de hash nativa
    std::hash<std::string> hasher;
    //Se configura el generador de numeros aleatorios usando la semilla
    std::mt19937 generator(hasher(seed));
    //Se asigna un string aleatorio (64 caracteres) a la llave semilla
    std::string seedKey = generateRandomString(generator, length);
    //A lo largo del for se generan cuatro llaves temporales las cuales se integran a la llave semilla haciendo uso del operador xor
    for (int i = 0; i < 4; ++i) {
        std::string tempKey = generateRandomString(generator, length);
        for (int j = 0; j < 64; ++j) {
            seedKey += seedKey[j] ^ tempKey[j]; 
        }
    }
    //Se inicializa la utilidad de la libreria para calcular hashes en modo SHA-256
    SHA256 hash;
    std::string digest;
    //Se calcula el SHA-256 de la llave semilla resultante 
    StringSource ss(seedKey, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest), false)));
    //Se retorna la llave criptografica
    return digest;
}

//** Funcion que se encraga de construir el vector de inicializaci�n a partir de una semilla generada anteriormente **//

std::string buildIV() {
    //Se abre el archivo en el que se encuentra la semilla necesaria para reconstuir el vector de inicializacion
    std::ifstream inFile("seed.bin", std::ios::binary);
    size_t length = 64;
    //Se manejan posibles errores asociados a la apertura del archivo
    if (!inFile) {
        std::cerr << "No se pudo acceder al archivo semilla" << std::endl;
        return "";
    }
    //Se obtiene la informacion de la semilla a partir del archivo y se almacena
    inFile.read(reinterpret_cast<char*>(&length), sizeof(length));
    std::string seed(length, '\0');
    inFile.read(&seed[0], length); 
    inFile.close();
    //Se convierte la semilla alfanumerica a numerica (int) para ser usada dentro del generador de numero aleatorios
    std::hash<std::string> hasher;
    std::mt19937 generator(hasher(seed));
    //Se genera el vector de inicializacion
    std::string iv = generateRandomString(generator, 32);
    //Se retorna el vector de inicializacion
    return iv;
}
