#include "rsa.h"
#include <gmpxx.h>

RSA::RSA() : rng(gmp_randinit_default){
    rng.seed(time(nullptr) + clock());
}

RSA::~RSA(){ }

mpz_class RSA::GeneratePrime(int prime_number_length_in_bits){
    mpz_class random_num;

    do
    {
        random_num = rng.get_z_bits(prime_number_length_in_bits);
    }
    while(mpz_probab_prime_p(random_num.get_mpz_t(), 25) == 0);

    return random_num;
}

mpz_class RSA::CalculateMultiply(mpz_class left_operand, mpz_class right_operand){
    return left_operand * right_operand;
}

GCDResult RSA::CalculateGCD(mpz_class left_operand, mpz_class right_operand){
    GCDResult gcd_result;
    mpz_class g, s, t;
    
    mpz_gcdext(g.get_mpz_t(), s.get_mpz_t(), t.get_mpz_t(), left_operand.get_mpz_t(), right_operand.get_mpz_t());

    gcd_result.g = g;
    gcd_result.x = s;
    gcd_result.y = t;

    return gcd_result;
}

std::array<RSAKey, 2> RSA::generatePublicANDPrivateKey(){
    mpz_class p = GeneratePrime(4096);
    mpz_class q = GeneratePrime(4096);
    
    mpz_class n = CalculateMultiply(p, q);
    mpz_class phi = CalculateMultiply(p - mpz_class(1), q - mpz_class(1));

    mpz_class e = mpz_class(0x010001);
    
    while(CalculateGCD(e, phi).g != 1){
        e = GeneratePrime(32);
    }

    GCDResult proto_d = CalculateGCD(e, phi);

    mpz_class d_intermediate = proto_d.x % phi;
    mpz_class d = (d_intermediate + phi) % phi;

    std::array<RSAKey, 2> result = { RSAKey(e, n), RSAKey(d, n) };

    return result;
}

mpz_class RSA::encode(int data, RSAKey publicKey){
    mpz_class converted = data;

    mpz_class encoded_data;

    mpz_powm(encoded_data.get_mpz_t(), converted.get_mpz_t(), publicKey.e.get_mpz_t(), publicKey.n.get_mpz_t());

    return encoded_data;
}

mpz_class RSA::decode(mpz_class data, RSAKey privateKey){
    mpz_class converted = data;
    mpz_class decoded_data;

    mpz_powm(decoded_data.get_mpz_t(), converted.get_mpz_t(), privateKey.e.get_mpz_t(), privateKey.n.get_mpz_t());

    return decoded_data;
}