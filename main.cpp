#define CRYPTOPP_DISABLE_ASM 1
#define CRYPTOPP_DISABLE_AESNI 1
#define CRYPTOPP_DISABLE_SHANI 1

#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <sstream>
#include "cryptopp/aes.h"
#include "cryptopp/rsa.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/osrng.h"
#include "cryptopp/files.h"
#include "cryptopp/pssr.h"

using namespace CryptoPP;
using namespace std;

//Generador de numeros aleatorias para la construcción de llaves asimétricas RSA

AutoSeededRandomPool rng;

//Tamaño del bloque de lectura de la imagen, por defecto 500 Mb
//Se puede configurar dependiendo de las características del dispositivo para evitar 
//problemas de memoria

const size_t size_chunk = 500 * 1024 * 1024;

//Funciones principales encargadas de la labor de encriptar y desencriptar las 
//imagenes

void encrypt(const string& input_path, const string& output_path);
void decrypt(const string& input_path, const string& output_path);

//Función encargada de generar el par de llaves asimétricas (público y privada) con
//las cuales se protegerá la semilla usada para generar la llaves y el hash para
//verificar la integridad de la imagen enviada

void generateAssymetricPair(){

    //Se generan llaves de 2048 bits, osea 32 bytes, para equilibrar seguridad y
    //rendimiento

    InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize(rng, 2048);

    //Se generan las llaves haciendo uso del generador de números aleatorios y
    //el tamaño de llave definido

    RSA::PrivateKey privateKey(parameters);
    RSA::PublicKey publicKey(parameters);

    //Se alamcenan las llaves con el fin de simular un entorno de ejecución real.
    //Se utiliza la extensión .key para facilitar el uso de la librería y mejorar la 
    //integridad de la llave

    privateKey.Save(FileSink("private.key", true).Ref());
    publicKey.Save(FileSink("public.key", true).Ref());
}

//Función encargada de generar la semilla aleatoria la cual se usará para generar 
//la llave simétrica y el vector de inicialización. La estrategia de generación de la
//semilla se especifica en el documento.

string generateRandomSeed(){
    
    //Se inicializa la variable en la cual se guardará el resultado de aplicar SHA256
    //A su vez, se inicializa el objeto necesario para aplicar la función de hash

    SHA256 hash;
    string digest;

    //Se inicia la semilla obteniendo el tiempo actual del reloj del sistema

    unsigned int seed = static_cast<unsigned int>(time(0));

    //Con la semilla, se inicia un generador de números pseudoaleatorios

    mt19937 generator(seed);

    //Haciendo uso del generador, se crea una distribución uniforme entre 0 y 9999

    uniform_int_distribution<int> distribution(0,9999);

    //Finalmente, se genera un número pseudoaleatorio haciendo uso de la distribución 
    //creada y se le aplica la función de Hash. Esto devuelve como resultado una cadena
    //alfanumérica de 32 bytes

    StringSource ss(to_string(distribution(generator)), true, new HashFilter(hash, new HexEncoder(new StringSink(digest), false)));

    return digest;
}

//Función encargada de generar un string alfanumérico aleatorio de 32 bytes partiendo
//de un generador de números pseudoaleatorios

string generateRandomString(mt19937 &generator, size_t length){

    //Se inicia el arreglo de caracteres que se pueden usar para la construcción de los
    //strings

    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%&/()=?*-+";
    const size_t maxIndex = (sizeof(charset) - 1);
    string randomString(length, 0);
    uniform_int_distribution<> distribution(0, maxIndex);
    
    //Se genera el string de 32 bytes haciendo uso de una distribución uniforme basada en
    //el generador recibido por parametro

    for (size_t i = 0; i < length; ++i){
        randomString[i] = charset[distribution(generator)];
    }

    return randomString;
}

//Función encargada de genenrar una llave simétrica dinámica de 32 bytes a partir de
//una semila representada por una cadena alfanumérica

string generateDynamicKey(const string &seed){

    //Se inicia convirtiendo la semilla alfanumérica a una semilla netamente numérica haciendo
    //uso de una funcion de hash estandar. A partir del generador creado con la semilla, se genera
    //la semilla alfanumerica inicial

    hash<string> hasher;
    mt19937 generator(hasher(seed));
    string seedKey = generateRandomString(generator, 64);

    //Posteriormente, se generan 4 strings aleatorios los cuales funcionan como llaves temporales.
    //Para llegar a la llave final, se aplica la operación XOR sobre las llaves generadas

    for(int i = 0; i < 4; ++i){
        string temporalKey = generateRandomString(generator, 64);
        for(int j = 0; j < 64; ++j){
            seedKey += seedKey[j] ^ temporalKey[j];
        }
    }

    //Finalmente, se aplica la función de hash SHA256 sobre la llave resultante del proceso anterior,
    //se verifica que esté en formato string y se retorna

    SHA256 hash;
    string digest;
    StringSource ss(seedKey, true, new HashFilter(hash, new HexEncoder(new StringSink(digest), false)));

    return digest;
}

//Función encargada de generar un vector de inicialización dinámico de 16 bytes a partir 
//de una semilla representada por una cadena alfanumérica

string generateDynamicIV(const string &seed){

    //Se inicia convirtiendo la semilla alfanumérica a una semilla netamente numérica haciendo
    //uso de una funcion de hash estandar. A partir del generador creado con la semilla, se genera
    //la semilla alfanumérica inicial

    hash<string> hasher;
    mt19937 generator(hasher(seed));

    //Para generar el vector de inicialización, se genera un string aleatorio de 16 bytes
    //y se retorna tal cual se genera

    string IV = generateRandomString(generator, 32);

    return IV;
}

//Función que se encarga de encriptar una imagen y de almacenar como resultado la
//imagen encriptada

void encrypt(const string& input_path, const string& output_path){

    //Se genera una semilla haciendo uso de la función definida anteriormente y, a 
    //partir de esta se genera la llave simétrica y el vector de inicialización

    string seed = generateRandomSeed();

    string key = generateDynamicKey(seed);
    string IV = generateDynamicIV(seed);

    //Se genera el par de llaves asimétricas para asegurar la confidencialidad al 
    //momento de compartir la semilla y el hash de verificación

    generateAssymetricPair();

    //Se procesa la imagen a encriptar en bloques de 500 Mb por defecto. Este proceso
    //se realiza para evitar sobrecargar la memoria del sistema embebido y garantizar
    //que la totalidad de la imagen se encripte correctamente

    auto processBatch = [](ifstream& inImage, ofstream& outImage, SHA256& sha, CTR_Mode<AES>::Encryption& enc){
        vector<CryptoPP::byte> buffer(size_chunk);
        while(inImage){
            inImage.read(reinterpret_cast<char*>(buffer.data()), size_chunk);
            streamsize processedBytes = inImage.gcount();
            if(processedBytes > 0){
                sha.Update(buffer.data(), processedBytes);
                vector<CryptoPP::byte> encrypted(processedBytes);
                enc.ProcessData(encrypted.data(), buffer.data(), processedBytes);
                outImage.write(reinterpret_cast<char*>(encrypted.data()), processedBytes);
            }
        }
    };

    //Luego de encriptar correctamente la imagen, se inicia el proceso de encriptar la 
    //semilla y el valor de hash haciendo uso de la llave pública asimétrica. Se usa la llave 
    //pública para que solo la pueda desencriptar la estación terrena

    try{
        CTR_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV((const CryptoPP::byte*)key.data(), 32, (const CryptoPP::byte*)IV.data());

        ifstream inImage(input_path, ios::binary);
        ofstream outImage(output_path, ios::binary);

        if (!inImage.is_open() || !outImage.is_open()) {
            cout << "Error opening the files" << endl;
            return;
        }

        SHA256 sha;
        processBatch(inImage, outImage, sha, enc);

        //Se calcula el hash de la totalidad de la imagen para que, en un futuro cuando sea
        //desencriptada, se pueda verificar su integridad

        CryptoPP::byte hash[CryptoPP::SHA256::DIGESTSIZE];
        sha.Final(hash);

        string hashResult;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashResult));
        encoder.Put(hash, sizeof(hash));
        encoder.MessageEnd();

        //Se juntan tanto la semilla como el valor de hash calculado para su posterior encriptación
        //haciendo uso del algoritmo asimétrico AES

        string messageToEncrypt;
        messageToEncrypt.append(seed);
        messageToEncrypt.append(hashResult);

        //Se encripta el conjunto de semilla y valor de hash y, finalmente, se concatena al final de 
        //la imagen encriptada. De esta forma se garantiza que se envíe de forma segura la información
        //necesaria para desencriptar la imagen

        RSA::PublicKey publicKey;
        publicKey.Load(FileSource("public.key", true).Ref());

        string encryptedInfo;
        RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
        StringSource ss(messageToEncrypt, true,
            new PK_EncryptorFilter(rng, encryptor,
                new StringSink(encryptedInfo)
            )
        );

        outImage.write(encryptedInfo.data(), encryptedInfo.size());
        inImage.close();
        outImage.close();
    }
    catch (const Exception& e) {
        cerr << e.what() << endl;
    }
}

//Función que se encarga de desencriptar una imagen y de almacenar como resultado la
//imagen recuperada

void decrypt(const string& input_path, const string& output_path){

    ifstream inImage(input_path, ios::binary);
    ofstream outImage(output_path, ios::binary);

    if (!inImage.is_open() || !outImage.is_open()) {
        cout << "Error opening the images" << endl;;
        return;
    }

    //Se definen los rangos del vector en los cuales se encuentran los datos encriptados de
    //la imagen. A su vez, se define en que rango se encuentra la información asociada al valor
    //de la semilla y el hash

    inImage.seekg(0, ios::end);
    streampos fileSize = inImage.tellg();
    size_t encryptedRSASize = 256;

    inImage.seekg(static_cast<streamsize>(fileSize) - static_cast<streamsize>(encryptedRSASize), ios::beg);
    string encryptedRSA(encryptedRSASize, '\0');
    inImage.read(&encryptedRSA[0], encryptedRSASize);

    streamsize encryptedDataSize = static_cast<streamsize>(fileSize) - static_cast<streamsize>(encryptedRSASize);
    inImage.seekg(0, ios::beg);
    
    //Se recupera la llave privada con el objetivo de poder desencriptar la información asociada
    //a la semilla para la generación de la llave y el hash de verificación

    RSA::PrivateKey privateKey;
    privateKey.Load(FileSource("private.key", true).Ref());

    //Se desencripta la infromacion y se recupera tanto la cadena que representa la semilla 
    //como el valor de hash calculado al momento de encriptar la imagen

    string decryptedMessage;
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    StringSource ss(encryptedRSA, true,
        new PK_DecryptorFilter(rng, decryptor,
            new StringSink(decryptedMessage)
        )
    );

    //Se almacenan los valores recuperados para su uso posterior

    string seed(64, '\0'); 
    string originalHash;

    size_t length = 64; 
    memcpy(&seed[0], decryptedMessage.data(), length);

    originalHash = decryptedMessage.substr(length);

    //Una vez recuperada la semilla, se recuperan tanto la llave simétrica como el 
    //vector de inicialización

    string key = generateDynamicKey(seed);
    string iv = generateDynamicIV(seed);

    //Una vez recuperados tanto la llave como el vector, se lleva a cabo el proceso de
    //desencriptar la imagen. Se utiliza la misma estrategia que en el proceso de encriptado
    //con el fin de preservar la memoria

    auto processBatch = [](ifstream& inImage, ofstream& outImage, SHA256& sha, CTR_Mode<AES>::Decryption& dec, streamsize encryptedDataSize) {
        vector<CryptoPP::byte> buffer(size_chunk);

        streamsize totalProcessed = 0;
        while (totalProcessed < encryptedDataSize) {
            streamsize bytesToProcess = min(static_cast<streamsize>(size_chunk), encryptedDataSize - totalProcessed);
            inImage.read(reinterpret_cast<char*>(buffer.data()), bytesToProcess);
            streamsize bytesProcesados = inImage.gcount();
            if (bytesProcesados > 0) {
                vector<CryptoPP::byte> decrypted(bytesProcesados);
                dec.ProcessData(decrypted.data(), buffer.data(), bytesProcesados);
                sha.Update(decrypted.data(), bytesProcesados);
                outImage.write(reinterpret_cast<char*>(decrypted.data()), bytesProcesados);
                totalProcessed += bytesProcesados;
            }
        }
    };

    try {

        //Finalmente, se calcula el hash asociado a la totalidad de la imagen desencriptada
        //Para esto, se repite el mismo proceso que se uso para calcular el hash de la imagen original

        CTR_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV((const CryptoPP::byte*)key.data(), 32, (const CryptoPP::byte*)iv.data());

        SHA256 sha;
        processBatch(inImage, outImage, sha, dec, encryptedDataSize);

        inImage.close();
        outImage.close();

        CryptoPP::byte hash[CryptoPP::SHA256::DIGESTSIZE];
        sha.Final(hash);
        
        string hashResult;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashResult));
        encoder.Put(hash, sizeof(hash));
        encoder.MessageEnd();

        //Finalmente, se comparan los valores de hash para identificar posibles problemas de 
        //integridad de la información

        if (originalHash != hashResult) {
            cerr << "The image was modified" << endl;
        }
    }
    catch (const Exception& e) {
        cerr << e.what() << endl;
    }
}

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


