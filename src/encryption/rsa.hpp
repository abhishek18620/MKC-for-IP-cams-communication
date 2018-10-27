/**
 * @file rsa.hpp
 *
 * @brief Header for Encryption module
 *
 * @author Abhishek Rawat (abhishek18620@gmail.com)
 */

#ifndef MKC_FOR_IP_CAMS_COMMUNICATION_SRC_ENCRYPTION_RSA_HPP_
#define MKC_FOR_IP_CAMS_COMMUNICATION_SRC_ENCRYPTION_RSA_HPP_

/*
 * sys includes
 * */
#include <memory>
#include <string>
#include <thread>
#include <vector>

/*
 * our includes
 * */
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_bin_float.hpp>

using namespace boost::multiprecision;

typedef struct _Key Key;

struct _Key {
  cpp_int modulus;
  cpp_int exponent;

  _Key(cpp_int x, cpp_int y) : modulus(x), exponent(y) {}
};

class RsaEncrytion {
public:
  /**
   * @brief Generates public and private keys
   *
   * @param pub
   * @param priv
   * @param PRIME_SOURCE_FILE
   */
  void RsaKeyGenerate();

  /**
   * @brief
   *
   * @param message
   *
   * @return
   */
  ::std::string Encrypt(::std::string &message);

  /**
   * @brief
   *
   * @param message
   *
   * @return
   */
  ::std::string Decrypt(::std::string &message);

private:

void MontgomeryReductionInit();

cpp_int MontgomeryReductionMultiply(cpp_int x, cpp_int y);


  /**
   * @brief Number of cores = Number of threads it can run concurrently
   *
   * @return number of cores in the system
   */
  cpp_int GetNumberOfCores() const {
    return ::std::thread::hardware_concurrency();
  }

  /**
   * @brief
   *
   * @param message
   * @param start
   * @param end
   * @param index
   * @param encrypted
   */
  void ParallelEncrypt(::std::string &message, cpp_int start, cpp_int end,
                       cpp_int index, ::std::vector<::std::string> &encrypted);

  /**
   * @brief
   *
   * @param message
   * @param start
   * @param end
   * @param index
   * @param a*b
   * @param b
   */
  void ParallelDecrypt(::std::string &message, cpp_int start, cpp_int end,
                                   cpp_int index, ::std::vector<::std::string> &decrypted);


  void convert_in(cpp_int &x) const { (x << m_reducer_bits.convert_to<unsigned> ()) % m_mod; }

  void convert_out(cpp_int &x) const { (x * m_mod_mul_inverse) % m_mod; }

  cpp_int ModularExponentiation(cpp_int x, cpp_int y);

  /**
   * @brief Counts number of bits in a decimal
   */
  static cpp_int GetNumberOfBits(cpp_int x) {
    return cpp_int(log2(cpp_bin_float_100(x))) + 1;
  }

  /**
   * @brief calculates modular multiplicative inverse (y such that  x*y=1(mod)m)
   *
   * @returns cpp_int modular multiplicative inverse of x with mod
   */
  static cpp_int InverseMod(cpp_int a, cpp_int mod);

  cpp_int m_mod; // modulus : should be a large number

  cpp_int m_prime1;

  cpp_int m_prime2;

  cpp_int m_reducer;

  cpp_int m_factor;

  cpp_int m_reducer_bits;

  cpp_int m_mask;

  cpp_int m_mod_mul_inverse;

  cpp_int m_converted_reducer;

  cpp_int m_max_num_of_digits;

  ::std::shared_ptr<_Key> m_public_key;

  ::std::shared_ptr<_Key> m_private_key;

  static ::std::string m_primes_file;
};

#endif
