#include "rsa.hpp"
#include <bits/stdc++.h>
#include <chrono>
#include <memory>

using namespace std;
using ::std::chrono::duration_cast;
using ::std::chrono::milliseconds;
using ::std::chrono::steady_clock;

constexpr int MESSAGES = 10;

int main() {
  fstream file_handler("sample_text.txt", file_handler.in);
  vector<string> message_vec;
  vector<string> encrypted_vec;
  vector<string> decrypted_vec;
  string text;
  int total_chars = 0;
  getline(file_handler, text);
  for (int msg_i = 0; msg_i < MESSAGES; msg_i++) {
    message_vec.push_back(text);
    total_chars += text.length();
  }

  cout << "total chars = " << total_chars << endl;
  shared_ptr<RsaEncrytion> encryption_ptr = make_shared<RsaEncrytion>();
  encryption_ptr->RsaKeyGenerate();
  auto start = steady_clock::now();
  int index = 0;
  for (auto text_i : message_vec) {
    if (text_i.empty())
      continue;
    index++;
    string encrypted = encryption_ptr->Encrypt(text_i);
    encrypted_vec.push_back(encrypted);
  }
  auto end = steady_clock::now();
  cout << "Time elapsed for encryption: "
       << duration_cast<milliseconds>(end - start).count() << " ms.\n";

  start = steady_clock::now();
  index = 0;
  for (auto encrypted_i : encrypted_vec) {
    if (encrypted_i.empty())
      continue;
    index++;
    string decrypted = encryption_ptr->Decrypt(encrypted_i);
  }
  cout << "Passed.............................................................."
          "..................\n";
  end = steady_clock::now();
  cout << "Time elapsed for decryption: "
       << duration_cast<milliseconds>(end - start).count() << " ms.\n";
  file_handler.close();
  return 0;
}
