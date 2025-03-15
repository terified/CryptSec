#include <iostream>
#include <fstream>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>

const int SALT_SIZE = 16;
const int HASH_SIZE = 32;
const int ITERATIONS = 10000;

void generate_salt(unsigned char* salt, int size) {
    RAND_bytes(salt, size);
}

void hash_password(const std::string& password, unsigned char* salt, unsigned char* hash) {
    PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(), salt, SALT_SIZE, ITERATIONS, HASH_SIZE, hash);
}

void store_password(const std::string& username, const std::string& password) {
    unsigned char salt[SALT_SIZE];
    unsigned char hash[HASH_SIZE];

    generate_salt(salt, SALT_SIZE);
    hash_password(password, salt, hash);

    std::ofstream file(username + ".pwd", std::ios::binary);
    file.write(reinterpret_cast<char*>(salt), SALT_SIZE);
    file.write(reinterpret_cast<char*>(hash), HASH_SIZE);
    file.close();
}

bool verify_password(const std::string& username, const std::string& password) {
    std::ifstream file(username + ".pwd", std::ios::binary);
    if (!file) return false;

    unsigned char salt[SALT_SIZE];
    unsigned char stored_hash[HASH_SIZE];
    unsigned char computed_hash[HASH_SIZE];

    file.read(reinterpret_cast<char*>(salt), SALT_SIZE);
    file.read(reinterpret_cast<char*>(stored_hash), HASH_SIZE);
    file.close();

    hash_password(password, salt, computed_hash);
    return memcmp(stored_hash, computed_hash, HASH_SIZE) == 0;
}

int main() {
    std::string username = "example_user";
    std::string password = "example_password";

    store_password(username, password);

    if (verify_password(username, password)) {
        std::cout << "Password verified successfully." << std::endl;
    } else {
        std::cout << "Password verification failed." << std::endl;
    }

    return 0;
}