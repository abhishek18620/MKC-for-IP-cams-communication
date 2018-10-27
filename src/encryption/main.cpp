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
  vector<string> message_vec;
  vector<string> encrypted_vec;
  vector<string> decrypted_vec;
  string text; //"Text messaging, or texting, is the act of composing and sending electronic messages, typically consisting of alphabetic and numeric characters, between two or more users of mobile devices, desktops/laptops, or other type of compatible computer.");
  int total_chars = 0;
  while(!file_handler.eof()) {
    getline(file_handler, text);
    total_chars += text.length();
    message_vec.push_back(text);
  }
  cout << "total chars = " << total_chars << endl;
  shared_ptr<RsaEncrytion> encryption_ptr = make_shared <RsaEncrytion> ();
  encryption_ptr->RsaKeyGenerate();
  //encryption_ptr->m_mod = 13;
  //encryption_ptr->MontgomeryReductionInit();
  //cout << encryption_ptr->power(2,5, encryption_ptr->m_mod) << endl;
  auto start = steady_clock::now();
  int index = 0;
  for (auto text_i : message_vec) {
		if(text_i.empty()) continue;
		//cout<<"index : "<<index++ <<" text_i = " << text_i <<endl;
    index++;
		string encrypted = encryption_ptr->Encrypt(text_i);
    encrypted_vec.push_back(encrypted);
  }
  auto end = steady_clock::now();
  cout<<"Time elapsed for encryption: "<<duration_cast<milliseconds> (end-start).count()<<" ms.\n";
  start = steady_clock::now();
  index = 0;
  for (auto encrypted_i : encrypted_vec) {
    //std::this_thread::sleep_for(std::chrono::seconds(10));
    if(encrypted_i.empty()) continue;
		//cout<<"index : "<<index++ <<" encrypted_i = " << encrypted_i <<endl;
    index++;
    string decrypted = encryption_ptr->Decrypt(encrypted_i);
    //cout << "Decrypted = " << decrypted <<"\n";
    assert(message_vec[index - 1] == decrypted);
  }
  cout << "Passed................................................................................\n";
  end = steady_clock::now();
  cout<<"Time elapsed for decryption: "<<duration_cast<milliseconds> (end-start).count()<<" ms.\n";

  return 0;
}
