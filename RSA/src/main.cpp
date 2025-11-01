#include "rsa.h"

#include <iostream>

void test_case(int data, int No, bool displayEncodedData){
    std::cout << "_________________________TEST CASE No " << No << "_____________________________________________" << std::endl;
    std::cout << "____________________________________________________________________________________" << std::endl;
    RSA rsa_test;
    std::array<RSAKey, 2> public_private_keys = rsa_test.generatePublicANDPrivateKey();

    mpz_class encoded_data = rsa_test.encode(data, public_private_keys[0]);

    std::cout << "TEST VALUE FOR ENCODING = " << data << std::endl;

    if(displayEncodedData){
        std::cout << "ENCODED DATA: " << encoded_data;
        std::cout << std::endl << std::endl;
    }
    std::cout << "DECODED DATA: " << rsa_test.decode(encoded_data, public_private_keys[1]) << std::endl;

    std::cout << "____________________________________________________________________________________" << std::endl << std::endl << std::endl;
}

int main(void){
    int values[] = { 10000, 25000, 2020008769, 0x101};
    int counter = 1;

    for(auto item : values){
        test_case(item, counter, false);
        counter += 1;
    }

    std::cout << std::endl << std::endl;
    std::cout << "OLD TEST CASES, WHICH DISPLAYING ENCODED DATA" << std::endl;
    std::cout << std::endl << std::endl;
    
    for(auto item : values){
        test_case(item, counter, true);
        counter += 1;
    }

    return 0;
}