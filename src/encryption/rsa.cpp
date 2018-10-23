/**
 * @file rsa.cpp
 *
 * @brief Implementation for RSA
 *
 * @author Abhishek Rawat (abhishek18620@gmail.com)
 */

/*
 * sys includes
 * */
#include <algorithm>
#include <cstring>
#include <cassert>
#include <cmath>
#include <cerrno>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <utility>
#include <thread>
/*
 * our includes
 * */
#include "rsa.hpp"
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/math/common_factor_rt.hpp>

using ::std::cout;
using ::std::cerr;
using ::std::endl;
using ::std::invalid_argument;
using ::std::string;
using ::std::vector;
using ::std::log2;
using ::std::min;
using ::std::move;
using ::std::exchange;
using ::std::fstream;
using ::std::random_device;
using ::std::mt19937;
using ::std::uniform_int_distribution;
using ::std::strerror;
using ::std::thread;
using ::std::ref;
using namespace boost::multiprecision;
using boost::math::gcd;

#define trace2(x, y)          cerr <<"Function : "<<__func__<<" | "<<#x<<": "<<x<<" | "<<#y<<": "<<y<< endl;
#define trace3(x, y, z)       cerr <<"Function : "<<__func__<<" | "<<#x<<": "<<x<<" | "<<#y<<": "<<y<<" | "<<#z<<": "<<z<<endl;
#define trace4(a, b, c, d)    cerr <<"Function : "<<__func__<<" | "<<#a<<": "<<a<<" | "<<#b<<": "<<b<<" | "<<#c<<": "<<c<<" | "<<#d<<": "<<d<<endl;
#define trace5(a, b, c, d, e) cerr <<"Function : "<<__func__<<" | "<<#a<<": "<<a<<" | "<<#b<<": "<<b<<" | "<<#c<<": "<<c<<" | "<<#d<<": "<<d<<" | "<<#e<<": "<<e<<endl;
/**
 * RSA Algorithm
 -----------------
  Step 1: Generate randomly two large prime's p and q of
					approximately the same size, but not too close
					together. Which are kept secret.

  Step 2: Calculate the modulus n = p*q. and Calculate:
					φ(n) = (p-1) (q-1); Where φ (n) represents the Euler
					Totient function.

  Step 3: Choose a random encryption exponent e less than
					n such that the GCD (φ (n), e) =1, 1<e< φ (n).

  Step 4: Calculate the decryption exponent d using The
	        Extended Euclidean algorithm: d. e = 1 mod φ (n).
	        Which d is the multiplicative inverse of e modulo φ(n).

  Step 5: The encryption function is: E (M) = M^e mod n.

  Step 6: The decryption function is: D (C) = C^d mod n.

  Step 7: The RSA keys are: The public key is (n, e), and
	        the private key is (p, q, d).
 **/

/** static data members */
string RsaEncrytion::m_primes_file = "primes16.txt";

static inline void RemoveLeadingZeroes(string &str) {
  str.erase(0, min(str.find_first_not_of('0'), str.size() - 1));
}

cpp_int RsaEncrytion::ModularExponentiation(cpp_int x, cpp_int y)
{
    //trace3(x, y, m_mod);
    cpp_int res = 1;      // Initialize result

    x = x % m_mod;  // Update x if it is more than or
                // equal to p

    while (y > 0)
    {
        // If y is odd, multiply x with result
        if (y & 1)
            res = (res*x) % m_mod;

        // y must be even now
        y = y>>1; // y = y/2
        x = (x*x) % m_mod;
    }
    return res;
}

static inline string ConcatenateVectorOfstring(vector<string> &vec_str) {
  string concatenated_ret;
  for (auto &s : vec_str) {
    concatenated_ret += s;
  }
  return concatenated_ret;
}

cpp_int RsaEncrytion::InverseMod(cpp_int a, cpp_int mod) {
  //trace2(a, mod);
  if (mod == 1)
    return 0;

  cpp_int temp_mod = mod;
  cpp_int y = 0;
  cpp_int x = 1;

  while (a > 1) {
    cpp_int q = a / mod;
    cpp_int t = mod;
    mod = a % mod, a = t;
    t = y;
    y = x - q * y;
    x = t;
  }
  if (x < 0)
    x += temp_mod;
  return x;
}

/*[>* Montgomery reduction for calculating (a*b)mod(n)<]*/
//void RsaEncrytion::MontgomeryReductionInit() {
  ////trace2(__func__, m_mod);
  //if(m_mod < 3 or !(m_mod&1)) {
    //throw invalid_argument("mod should be odd and greater than 3");
  //}
  //cpp_int reducer_bits = (GetNumberOfBits(m_mod) / 8 + 1) * 8;
  //cpp_int m_reducer = cpp_int(1) << reducer_bits.convert_to<unsigned> (); // 2^reducer_bits
  //cpp_int m_mask = m_reducer - 1;
  //[>* m_reducer(r) should be greater than and coprime with it <]
  //assert(m_reducer > m_mod and gcd(m_reducer, m_mod) == 1);
  //m_mod_mul_inverse = InverseMod(m_reducer % m_mod, m_mod);
  //m_factor = (m_reducer * m_mod_mul_inverse - 1) / m_mod;
  //m_converted_reducer = m_reducer % m_mod;
//}

//cpp_int RsaEncrytion::MontgomeryReductionMultiply(cpp_int x, cpp_int y) {
  ////trace2(x, y);
  ////assert(x >= 0 and x < m_mod and y >= 0 and y < m_mod);
  //cpp_int product = x * y;
  //cpp_int temp = ((product & m_mask) * m_factor) & m_mask;
  //cpp_int reduced = (product + temp * m_mod) >> m_reducer_bits;
  //cpp_int result = (reduced < m_mod) ? reduced : reduced - m_mod;
  ////trace2(result, m_mod);
  ////assert(result >= 0 and result < m_mod);
  //return result;
//}

//cpp_int RsaEncrytion::ModularExponentiation(cpp_int x, cpp_int y) {
  ////trace3(__func__, x, y);
  //assert(x >= 0 and x < m_mod);
  //if (y < 0) {
    //throw invalid_argument("Exponent should be greater than 0");
  //}
  //cpp_int z = m_converted_reducer;
  //while (y != 0) {
    //if (y & 1)
      //z = MontgomeryReductionMultiply(z, x);
    //x = MontgomeryReductionMultiply(x, x);
    //y >>= 1;
  //}
  //return z;
/*}*/

void RsaEncrytion::RsaKeyGenerate() {
  fstream primes_list_handler(m_primes_file, primes_list_handler.in);
  if (!primes_list_handler.is_open()) {
    cout<<"Failed to open, Reason : "<<strerror(errno)<<endl;
  }

  // count number of primes in the list
  cpp_int prime_count = 10000;
  // p, q : random prime numbers
  cpp_int p = 0;
  cpp_int q = 0;
  cpp_int e = (1<<8) + 1;
  cpp_int d = 0;
  cpp_int n = 0;
  cpp_int phi_of_n = 0;
  random_device rd;
	mt19937 mt(rd());
  uniform_int_distribution <> dist(1, 10000);

  do {
    // a and b are the positions of p and q in the list
    cpp_int pos_p = dist(mt);
    cpp_int pos_q = dist(mt);
    p = 0;
    q = 0;
    cpp_int curr_ind = 0;
    string prime_num_str;
    while ( p==0 or q==0 ) {
      getline(primes_list_handler, prime_num_str);
      curr_ind++;
      if ( curr_ind == pos_p) p = cpp_int(prime_num_str);
      if ( curr_ind == pos_q) q = cpp_int(prime_num_str);
    }
    phi_of_n = cpp_int(p - 1) * cpp_int(q - 1);
    //n = cpp_int(p) * cpp_int(q);
  } while (!(p && q) or (p == q) or (gcd(phi_of_n, e) != 1)); // p!=q and phi_of_n should be coprime with e.

  // Next, we need to choose a,b, so that a*max+b*e = gcd(max,e). We actually
  // only need b here, and in keeping with the usual notation of RSA we'll call
  // it d. We'd also like to make sure we get a representation of d as positive,
  // hence the while loop.
  m_mod = n = p * q;
  d = InverseMod(e, phi_of_n);
  m_max_num_of_digits = n.convert_to <string> ().length();
  //trace2(n, m_max_num_of_digits);
  while (d < 0) {
    d = d + phi_of_n;
  }

  //MontgomeryReductionInit();
  //trace2(p, q);
  //trace4(n, phi_of_n, e, d);
  //cout <<"primes are p = " << p<<" : q = "<< q<<endl;
  //printf("primes are %lld and %lld\n", (cpp_int)p, (cpp_int)q);
  // We now store the public / private keys in the appropriate structs
  m_public_key = ::std::make_shared <_Key> (n, e);
  m_private_key = ::std::make_shared <_Key> (n, d);
  //trace4(m_public_key->modulus, m_public_key->exponent, m_private_key->modulus, m_private_key->exponent);
}

/** Parallel Rsa */
void RsaEncrytion::ParallelEncrypt(string &message, cpp_int start,
                                      cpp_int end, cpp_int index,
                                      vector<string> &encrypted) {
  //trace4(message, start, end, index);
  string encrypted_str;
  for (auto i = start; i <= end; i++) {
    auto ind = i.convert_to<int> ();
    //trace2(i, index);
    cpp_int ret = ModularExponentiation(cpp_int(message[ind]), m_public_key->exponent);
    encrypted_str = ret.convert_to<string> ();
    if (encrypted_str.length() < m_max_num_of_digits) {
      // Pad it some zeroes to make the number of digits equal
      encrypted_str= string(m_max_num_of_digits.convert_to <int> () - encrypted_str.length(), '0') + encrypted_str;
    }
    encrypted[index.convert_to<int> ()].append(encrypted_str);
    //trace4(i, message[ind],encrypted_str ,encrypted[index.convert_to<int> ()]);
  }
}

void RsaEncrytion::ParallelDecrypt(string &message, cpp_int start, cpp_int end,
                                   cpp_int index, vector<string> &decrypted) {
  //trace4(message, start, end, index);
  // number of blocks of encrypted text that a core would handle
  cpp_int num_of_blocks = end - start + 1;
  string decrypted_str;
  string encrypted_str;
  cpp_int substr_beg = start * m_max_num_of_digits;
  cpp_int substr_end = substr_beg + m_max_num_of_digits - 1;
  //trace2(substr_beg, substr_end);
  for (auto block_i = 0; block_i < num_of_blocks; block_i++) {
    //cout<< "I'm inside loop....\n";
    //auto ind = block_i.convert_to<int> ();
    encrypted_str = message.substr(substr_beg.convert_to<int> (), m_max_num_of_digits.convert_to<int> ());
    // Remove leading zeroes to avoid cpp_int exception
    RemoveLeadingZeroes(encrypted_str);
    //trace4(block_i, substr_beg, substr_end, encrypted_str);
    auto temp = ModularExponentiation(cpp_int(encrypted_str), m_private_key->exponent);
    auto decrypted_ch = temp.convert_to<char> ();
    decrypted_str.push_back(decrypted_ch);
    //trace3(block_i, temp, decrypted_str);
    substr_beg = substr_end + 1;
    substr_end = substr_beg + m_max_num_of_digits - 1;
    //trace5(block_i, encrypted_str, decrypted_ch, substr_beg, substr_end);
  }
  ////trace5(message, start, end, encrypted_str, decrypted_str);
  decrypted[index.convert_to<int> ()] = decrypted_str;
}

string RsaEncrytion::Encrypt(string &message) {
  cpp_int thread_index = 0;
  cpp_int num_of_cores = GetNumberOfCores();
  vector<thread> threadpool(num_of_cores.convert_to<int> ());
  cpp_int txt_for_each_core =
      message.length() / num_of_cores; // this is essentially an integer
  cpp_int start = 0;
  cpp_int end = txt_for_each_core - 1;
  vector<string> encrypted(num_of_cores.convert_to<int> ());
  for (auto &thread_i : threadpool) {
    //trace4(thread_index, start, end, encrypted[thread_index.convert_to<int> ()]);
    thread_i = move(thread(&RsaEncrytion::ParallelEncrypt, this, ref(message), start, end,
                           thread_index, ref(encrypted)));
    thread_index ++;
    start = end + 1;
    // last thread should take extra left characters
    end = (thread_index == num_of_cores - 1) ? cpp_int(message.length() - 1) : cpp_int(start + txt_for_each_core - 1);
  }
  for (auto &thread_i : threadpool) thread_i.join();
  string encrypted_message = ConcatenateVectorOfstring(encrypted);
  return encrypted_message;
}

string RsaEncrytion::Decrypt(string &message) {
  cpp_int thread_index = 0;
  cpp_int num_of_cores = GetNumberOfCores();
  cpp_int num_of_blocks = message.length() / m_max_num_of_digits;
  cpp_int num_of_blocks_for_each_core = num_of_blocks / num_of_cores;
  vector<thread> threadpool(num_of_cores.convert_to<int> ());
  vector<string> decrypted(num_of_cores.convert_to<int> ());
  cpp_int start = 0;
  cpp_int end = num_of_blocks_for_each_core - 1;
  //trace2(message.length(), num_of_blocks);
  for (auto &thread_i : threadpool) {
    thread_i = move(thread(&RsaEncrytion::ParallelDecrypt, this, ref(message), start, end,
                                           thread_index, ref(decrypted)));
    //trace4(thread_index, start, end, decrypted[thread_index.convert_to<int> ()]);
    thread_index ++;
    start = end + 1;
    end = (thread_index == num_of_cores -1) ? cpp_int(num_of_blocks - 1) : cpp_int(start + num_of_blocks_for_each_core - 1);
  }
  for (auto &thread_i : threadpool) thread_i.join();
  string decrypted_message = ConcatenateVectorOfstring(decrypted);
  //trace2(num_of_blocks, decrypted_message);
  return decrypted_message;
}
