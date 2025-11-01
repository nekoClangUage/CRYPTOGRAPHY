#ifndef RSA_HEADER
#define RSA_HEADER

#include <ctime>

#include <gmp.h>
#include <gmpxx.h>

#include <array>

struct GCDResult{
    mpz_class g;
    mpz_class x;
    mpz_class y;
};

struct RSAKey{
    mpz_class e;
    mpz_class n;

    RSAKey(mpz_class e, mpz_class n) 
        : e(e), n(n)
    {}
};

class RSA{
private:
    gmp_randclass rng;

    mpz_class GeneratePrime(int prime_number_length_in_bits = 4096);
    mpz_class CalculateMultiply(mpz_class left_operand, mpz_class right_operand);
    GCDResult CalculateGCD(mpz_class first_operand, mpz_class second_operand);
public:
    RSA();
    ~RSA();

    std::array<RSAKey, 2> generatePublicANDPrivateKey();
    mpz_class decode(mpz_class data, RSAKey privateKey);
    mpz_class encode(int       data, RSAKey publicKey);
};

#endif
