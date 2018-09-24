/**
 * @file rsa.hpp
 *
 * @copyright Tarana Wireless, Inc.  All Rights Reserved.
 *
 * @brief Header for Encryption module
 *
 * @author Abhishek Rawat (abhishek.rawat@taranawireless.com)
 */

#ifndef MKC_FOR_IP_CAMS_COMMUNICATION_SRC_ENCRYPTION_RSA_HPP_
#define MKC_FOR_IP_CAMS_COMMUNICATION_SRC_ENCRYPTION_RSA_HPP_

/*
 * sys includes
 * */
#include <string>
#include <vector>

/*
 * our includes
 * */

struct key {
  uint64_t mod;
  uint64_t exp;
}

class RsaEncrytion {
public:
  /**
   * @brief Generates public and private keys
   *
   * @param pub
   * @param priv
   * @param PRIME_SOURCE_FILE
   */
  void rsa_gen_keys(struct public_key_class *pub,
                    struct private_key_class *priv,
                    const char *PRIME_SOURCE_FILE);

  /**
   * @brief Encrypts the message text.
   *
   * @param message
   * @param message_size
   * @param pub
   *
   * @return
   */
  uint64_t *rsa_encrypt(const char *message, const unsigned long message_size,
                        const struct public_key_class *pub);

  /**
   * @brief Decrypts the message
   *
   * @param message
   * @param message_size
   * @param pub
   *
   * @return
   */
  char *rsa_decrypt(const long long *message, const unsigned long message_size,
                    const struct private_key_class *pub);

private:
  ::std::string primes_file;
}

#endif
