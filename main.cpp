// Se importan las librerías
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
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cstdlib>
#include <stdint.h>
#include <bitset>
#include <filesystem>

using namespace CryptoPP;
using namespace std;

// Se declara el tamaño de los batches
const size_t BATCH_SIZE = 1000 * 1024 * 1024;


void encrypt(const string& input_path, const string& output_path);
void decrypt(const string& input_path, const string& output_path);


int main(int argc, char* argv[]) {

    if (argc != 4) {
        cerr << "Uso: " << argv[0] << " <operation> <input_path> <output_path>" << endl;
        return 1;
    }

    string operation = argv[1];
    string input_path = argv[2];
    string output_path = argv[3];

    if (operation == "encrypt") {
        encrypt(input_path, output_path);
    }
    else if (operation == "decrypt") {
        decrypt(input_path, output_path);
    }
    else {
        cerr << "Operacion no valida: " << operation << endl;
        return 1;
    }
    return 0;
}

// Funcion que genera una semilla aleatoria que sirve para generar las llaves y los vectores de inicialización 
void generateRandomSeed() {

    // Se inicializa un generador de números aleatorios que toma como semilla el tiempo actual 
    srand(static_cast<unsigned int>(std::time(0)));

    // Se obtiene un número aleatorio de 16 bits
    uint16_t random_number = static_cast<uint16_t>(rand() % 65536);

    filesystem::create_directory("extra");

    // Se crea un archivo para guardar la semilla
    ofstream outFile("extra\\semilla.bin", ios::binary);
    if (!outFile) {
        cerr << "No se puede guardar la semilla" << endl;
    }

    // Se guarda la semilla en el archivo
    outFile.write(reinterpret_cast<const char*>(&random_number), sizeof(random_number));

    // Se cierra el archivo
    outFile.close();
}

// Función para generar una secuencia LFSR de longitud dada
// uint16_t se utiliza para trabajar con el campo finito GF(2^16). Cada operación en el LFSR se realiza dentro de los límites de 16 bits
vector<uint16_t> generateLFSRSequence(uint16_t start_state, int length) {
    vector<uint16_t> sequence(length);  // Vector para almacenar la secuencia
    uint16_t lfsr = start_state;             // Estado inicial del LFSR
    uint16_t period = 0;

    for (int i = 0; i < length; ++i) {
        // Almacenar el estado actual del LFSR en la secuencia
        sequence[i] = lfsr;

        // Obtener el bit menos significativo (LSB)
        unsigned lsb = lfsr & 1u;
        // Desplazar el registro hacia la derecha
        lfsr >>= 1;
        // Aplicar la máscara de retroalimentación si el LSB es 1
        if (lsb) {
            // ^= es un XOR. 0xB400u es: 1011 0100 0000 0000 el cual es un polinomio primitivo. Es decir garantiza un período máximo de 2^16 -1 estados
            lfsr ^= 0xB400u;
        }
        ++period;
    }

    return sequence;
}

// Función para generar las llaves de 32 Bytes cifrado de forma dinámica a partir de una semilla.
string generateDynamicKey() {

    // Se abre el archivo con la semilla
    ifstream inFile("extra\\semilla.bin", ios::binary);
    int length = 64;

    if (!inFile) {
        cerr << "Error al abrir el archivo" << endl;
    }

     // Variable para almacenar la semilla
    uint16_t seed = 0;

    // Se lee la semilla
    inFile.read(reinterpret_cast<char*>(&seed), sizeof(seed));

    // Se cierra el archivo
    inFile.close();

    // A partir de la semilla se genera una secuencia LFSR
    vector<uint16_t> seedKey = generateLFSRSequence(seed, length);

    // Se almacena esta secuencia como un string
    string string_key;
    for (const auto& elem : seedKey) {
        string_key.append(reinterpret_cast<const char*>(&elem), sizeof(uint16_t));
    }

    // Para aumentar la seguridad y entropía de la llave se obtiene el hash de esta llave
    SHA256 hash;
    string key;

    // Se calcula el hash SHA256 de la secuencia el cual funcionará como la llave
    StringSource ss(string_key, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(key), false)));
    
    // Se retorna la llave
    return key;
}

// Función para generar los vectores de inicialización de 16 Bytes de forma dinámica a partir de una semilla.
string generateDynamicIV() {
    
    // Se abre el archivo con la semilla
    ifstream inFile("extra\\semilla.bin", ios::binary);
    int length = 64;

    if (!inFile) {
        cerr << "Error al abrir el archivo" << endl;
    }

     // Variable para almacenar la semilla
    uint16_t seed = 0;

    // Se lee la semilla
    inFile.read(reinterpret_cast<char*>(&seed), sizeof(seed));

    // Se cierra el archivo
    inFile.close();

    // A partir de la semilla se genera una secuencia LFSR
    vector<uint16_t> seedIV = generateLFSRSequence(seed, length);

    // Se almacena esta secuencia como string
    string iv;
    for (const auto& elem : seedIV) {
        iv.append(reinterpret_cast<const char*>(&elem), sizeof(uint16_t));
    }

    // Se retorna esta secuencia como vector de inicialización
    return iv;
}

//Función que se encarga de encriptar una imagen utilizando AES y el cifrado por bloques CTR
void encrypt(const string& input_path, const string& output_path) {

    //Se genera una semilla
    generateRandomSeed();
    //A partir de esta semilla se genera la llave y el vector de inicialización para cifrar
    string key = generateDynamicKey();
    string iv = generateDynamicIV();

    // Se obtienen las rutas de la imagen a leer y la imagen a almacenar
    cout << "input_path=" << input_path << endl;
    cout << "output_path=" << output_path << endl;


    try {
        // Se declara el método de cifrado como AES con el cifrado por bloques CTR
        CTR_Mode<AES>::Encryption enc;

        // Se le asigna al encriptador la llave y el vector inicial
        enc.SetKeyWithIV((const CryptoPP::byte*)key.data(), 32, (const CryptoPP::byte*)iv.data());

        // Se abren las imagenes
        ifstream inImage(input_path, ios::binary);
        ofstream outImage(output_path, ios::binary);

        if (!inImage.is_open() || !outImage.is_open()) {
            cerr << "Error al abrir las imagenes" << endl;
            return;
        }

        // Se declara el tamaño del buffer para leer las imagenes en batches
        vector<CryptoPP::byte> buffer(BATCH_SIZE);

        // Se declara el hash que permitirá verificar la integridad de la imagen
        SHA256 sha;

        // Ciclo donde se leerá la imagen por batches
        while (inImage) {
            // Se lee un batch
            inImage.read(reinterpret_cast<char*>(buffer.data()), BATCH_SIZE);
            streamsize bytesProcesados = inImage.gcount();

            if (bytesProcesados > 0) {
                // Se calcula el hash
                sha.Update(buffer.data(), bytesProcesados);
                vector<CryptoPP::byte> encrypted(bytesProcesados);
                // Se cifra el batch con la llave y el vector de inicialización generados
                enc.ProcessData(encrypted.data(), buffer.data(), bytesProcesados);
                // Se guarda el batch cifrado en la imagen de salida
                outImage.write(reinterpret_cast<char*>(encrypted.data()), bytesProcesados);
            }
        }

        // Se cierran las imagenes
        inImage.close();
        outImage.close();

        // Se calcula el hash de toda la imagen
        CryptoPP::byte hash[CryptoPP::SHA256::DIGESTSIZE];
        sha.Final(hash);

        // Se codifica el hash resultante para visualizarlo como hexadecimal
        string hashResult;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashResult));
        encoder.Put(hash, sizeof(hash));
        encoder.MessageEnd();

        // Se crea un archivo donde guardar el hash en un archivo que permitirá verificar la integridad
        ofstream hashFile("extra\\integridad.bin", ios::binary);
        if (!hashFile) {
            cerr << "No se pudo almacenar la infromacion del Hash" << endl;
        }

        // Se almacena este resultado
        size_t length = hashResult.size();
        hashFile.write(reinterpret_cast<const char*>(&length), sizeof(length));
        hashFile.write(hashResult.c_str(), length);
        hashFile.close();  
    }
    catch (const Exception& e) {
        cerr << e.what() << endl;
    }
    cout << "Encrypted image" << endl;
}


void decrypt(const string& input_path, const string& output_path) {

    // Se genera la llave y el vector de inicialzación para desencriptar a partir de la semilla almacenada
    string key = generateDynamicKey();
    string iv = generateDynamicIV();

    // Se solicitan las rutas de la imagen encriptada y la imagen desencriptada
    cout << "input_path=" << input_path << endl;
    cout << "output_path=" << output_path << endl;
    
    try {
        // Se declara el método de descifrado como AES con el cifrado por bloques CTR
        CTR_Mode<AES>::Decryption dec;
        // Se le asignan las llaves y el vector de inicialización generados
        dec.SetKeyWithIV((const CryptoPP::byte*)key.data(), 32, (const CryptoPP::byte*)iv.data());

        // Se abren las imagenes 
        ifstream inImage(input_path, ios::binary);
        ofstream outImage(output_path, ios::binary);

        if (!inImage.is_open() || !outImage.is_open()) {
            cerr << "Error al abrir las imagenes." << endl;
            return;
        }

        // Se declara el tamaño del buffer para leer las imagenes en batches
        vector<CryptoPP::byte> buffer(BATCH_SIZE);

        // Se declara el hash que permitirá verificar la integridad de la imagen
        SHA256 sha;

        // Ciclo donde se leerá la imagen encriptada por batches
        while (inImage) {
            // Se lee un batch de la imagen encriptada
            inImage.read(reinterpret_cast<char*>(buffer.data()), BATCH_SIZE);
            streamsize bytesProcesados = inImage.gcount();

            if (bytesProcesados > 0) {
                vector<CryptoPP::byte> decrypted(bytesProcesados);
                // Se descifra el batch encriptado
                dec.ProcessData(decrypted.data(), buffer.data(), bytesProcesados);
                // Se calcula el hash del batch para verificar la integridad
                sha.Update(decrypted.data(), bytesProcesados);
                // Se guarda el batch desencriptado en la imagen de salida
                outImage.write(reinterpret_cast<char*>(decrypted.data()), bytesProcesados);
            }
        }

        // Se cierran las imagenes
        inImage.close();
        outImage.close();

        // Se calcula el hash de toda la imagen desencriptada
        CryptoPP::byte hash[CryptoPP::SHA256::DIGESTSIZE];
        sha.Final(hash);

        // Se guarda el hash en hexadecimal para compararlo con el hash original
        string hashResult;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashResult));
        encoder.Put(hash, sizeof(hash));
        encoder.MessageEnd();

        // Se abre el archivo donde esta el hash original
        ifstream hashFile("extra\\integridad.bin", ios::binary);
        size_t length = 64;

        if (!hashFile) {
            cerr << "No se pudo leer la información del hash" << endl;
        }

        // Se lee el hash de la información original
        hashFile.read(reinterpret_cast<char*>(&length), sizeof(length));
        string calculatedHash(length, '\0');
        hashFile.read(&calculatedHash[0], length); // Leer la cadena
        hashFile.close();

        // Se compara el hash de la imagen original con el hash de la imagen desencriptada
        if (hashResult != calculatedHash) {
            cerr << "La imagen fue alterada" << endl;
        }
    }
    catch (const Exception& e) {
        cerr << e.what() << endl;
    }
    cout << "Decrypted image" << endl;
}


