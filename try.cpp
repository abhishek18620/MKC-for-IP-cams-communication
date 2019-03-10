#include <iostream>
#include <fstream>
#include <random>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_bin_float.hpp>
#include <string>
#include <algorithm>
#include <boost/math/common_factor_rt.hpp>
#include <cstdlib>

using boost::math::gcd;
using ::std::string;
using namespace boost::multiprecision;
using ::std::cerr;
using ::std::endl;
using ::std::exchange;

#define trace2(x, y)          cerr <<#x<<": "<<x<<" | "<<#y<<": "<<y<< endl;
#define trace3(x, y, z)       cerr <<#x<<": "<<x<<" | "<<#y<<": "<<y<<" | "<<#z<<": "<<z<<endl;
#define trace4(a, b, c, d)    cerr <<#a<<": "<<a<<" | "<<#b<<": "<<b<<" | "<<#c<<": "<<c<<" | "<<#d<<": "<<d<<endl;
#define trace5(a, b, c, d, e) cerr <<#a<<": "<<a<<" | "<<#b<<": "<<b<<" | "<<#c<<": "<<c<<" | "<<#d<<": "<<d<<" | "<<#e<<": "<<e<<endl;
//using namespace std;

cpp_int InverseMod(cpp_int x, cpp_int mod) {
  /** Based on a simplification of the extended Euclidean algorithm */
  //assert(mod > 0 and x >= 0 and x < mod);
  cpp_int y = exchange(x, mod);
  cpp_int a = 0;
  cpp_int b = 1;
  while (y != 0) {
    // exchange updates b with the expresion and returns old value of b
    a = exchange(b, a - (x / y) * b);
    x = exchange(y, x % y);
  }
  //if (x == 1)
    return a % mod;
  //else
  //throw invalid_argument("Inverse doesn't exist");
}


int modInverse(int a, int m)
{
    int m0 = m;
    int y = 0, x = 1;

    if (m == 1)
      return 0;

    while (a > 1)
    {
        // q is quotient
        int q = a / m;
        int t = m;

        // m is remainder now, process same as
        // Euclid's algo
        m = a % m, a = t;
        t = y;

        // Update y and x
        y = x - q * y;
        x = t;
    }

    // Make x positive
    if (x < 0)
       x += m0;

    return x;
}

int main() {
	std::random_device rd;
	std::mt19937 mt(rd());
  std::uniform_int_distribution <> dist(1, 10000);
  std::string str("15368439633134523967");
  cpp_int pro = cpp_int(str) * cpp_int("11462955731759877077");
  std::cout<< "pro = "<< pro << std::endl;
  std::fstream fh("primes64.txt", fh.in);
  //for (int i=0; i<2; ++i)
  int posp = dist(mt);
  int posq = dist(mt);
  std::cout<<" posp = "<<posp<<" posq = "<<posq<<std::endl;
  cpp_int p = 0;
  cpp_int q = 0;
  uint16_t i = 0;
  while (p==0 or q==0) {
    i++;
    getline(fh, str);
    char* endptr;
    if(posp == i) p = strtoull(str.c_str(), &endptr, 10);
    if(posq == i) q = strtoull(str.c_str(), &endptr, 10);
  }
  cpp_int pro_new = p * q;
  std::cout << "log2(" << pro_new << ") = " << cpp_int(log2(cpp_bin_float_100(pro_new))) << "\n";
  std::cout << "pstr = " << p.convert_to <string> () << " qstr = "<< q.convert_to<string> () << std::endl;
  std::cout << "ascii for a = "<< cpp_int(49).convert_to<char> () <<std::endl;
  std::cout << " print 0 5 times : " << cpp_int("7194")<<std::endl;
  std::cout<<gcd(p, q)<<std::endl;
  trace3(p,q,gcd(p,q));
  std::cout<<" p = "<<p<<" q = "<<q<<" pro = "<<pro_new<<std::endl;
  cpp_int a =3, m=11;
  if (p&1) std::cout << " P is fucking oddddd..."<< std::endl;
  str = "00000078484";
  str.erase(0, ::std::min(str.find_first_not_of('0'), str.size()-1));
  trace2(str.size(), str);
  trace3(a,m,InverseMod(a,m));
  return 0;
}
