#include <bits/stdc++.h>
#include <memory>
#include <chrono>
#include "rsa.hpp"

using namespace std;
using ::std::chrono::steady_clock;
using ::std::chrono::duration_cast;
using ::std::chrono::milliseconds;

int main() {
  fstream file_handler("sample_text2.txt", file_handler.in);
  vector<string> buffer;
  string text; //"Text messaging, or texting, is the act of composing and sending electronic messages, typically consisting of alphabetic and numeric characters, between two or more users of mobile devices, desktops/laptops, or other type of compatible computer.");
  while(!file_handler.eof()) {
    getline(file_handler, text);
    buffer.push_back(text);
  }
  shared_ptr<RsaEncrytion> encryption_ptr = make_shared <RsaEncrytion> ();
  auto start = steady_clock::now();
  encryption_ptr->RsaKeyGenerate();
  //encryption_ptr->m_mod = 13;
  //encryption_ptr->MontgomeryReductionInit();
  //cout << encryption_ptr->power(2,5, encryption_ptr->m_mod) << endl;
  int index = 1;
	for (auto text_i : buffer) {
		if(text_i.empty()) continue;
		cout<<"index : "<<index++ <<" text_i = " << text_i <<endl;
		string encrypted = encryption_ptr->Encrypt(text_i);
    //std::this_thread::sleep_for(std::chrono::seconds(10));
    cout << "Encrypted = " << encrypted <<"\n";
    string decrypted = encryption_ptr->Decrypt(encrypted);
    cout << "Decrypted = " << decrypted <<"\n";
  }
  auto end = steady_clock::now();
  cout<<"Time elapsed: "<<duration_cast<milliseconds> (end-start).count()<<" ms.\n";

  return 0;
}
