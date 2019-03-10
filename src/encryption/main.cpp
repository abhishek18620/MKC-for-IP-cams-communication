#include "rsa.hpp"
#include <bits/stdc++.h>
#include <chrono>
#include <cstdio>
#include <memory>

using namespace std;
using ::std::chrono::duration_cast;
using ::std::chrono::milliseconds;
using ::std::chrono::steady_clock;

constexpr int MESSAGES = 10;

inline int GetNumberOfCores() { return ::std::thread::hardware_concurrency(); }

struct Benchmarkers {
  int sequential_time;
  int parallel_time;
  int num_of_cores;
  float speedup_factor;

  void PrintParams() {
    speedup_factor = static_cast<float> (sequential_time) / static_cast<float> (parallel_time);
    num_of_cores = GetNumberOfCores();
    printf("Sequential Time : %dms\nParallel Time : %dms\nCores Used: %d\nMessages "
           ": %d\nSpeed Up factor : %.3f\n\n\n",
           sequential_time, parallel_time, num_of_cores, MESSAGES,
           speedup_factor);
  }
};

int main() {
  fstream file_handler("sample_text.txt", file_handler.in);
  vector<string> message_vec;
  vector<string> encrypted_vec;
  vector<string> decrypted_vec;
  string text;
  int total_msg_len = 0;
  getline(file_handler, text);
  for (int msg_i = 0; msg_i < MESSAGES; msg_i++) {
    message_vec.push_back(text);
    total_msg_len += text.length();
  }

  cout << "Total Message Length = " << total_msg_len << endl;
  shared_ptr<Benchmarkers> encryption_BM = make_shared<Benchmarkers>();
  shared_ptr<Benchmarkers> decryption_BM = make_shared<Benchmarkers>();
  shared_ptr<RsaEncrytion> encryption_ptr = make_shared<RsaEncrytion>();
  encryption_ptr->RsaKeyGenerate();
  auto start = steady_clock::now();
  int index = 0;

  /* Encryption */
  // Sequential
  int num_of_cores = 1;
  for (auto text_i : message_vec) {
    if (text_i.empty())
      continue;
    index++;
    string encrypted = encryption_ptr->Encrypt(text_i, num_of_cores);
    encrypted_vec.push_back(encrypted);
  }
  auto end = steady_clock::now();
  encryption_BM->sequential_time =
      duration_cast<milliseconds>(end - start).count();
  cout << "Sequential Encryption Done................................\n";
  // Parallel Encrytion
  start = steady_clock::now();
  index = 0;
  num_of_cores = GetNumberOfCores();
  for (auto text_i : message_vec) {
    if (text_i.empty())
      continue;
    index++;
    string encrypted = encryption_ptr->Encrypt(text_i, num_of_cores);
    // encrypted_vec.push_back(encrypted);
  }
  end = steady_clock::now();
  encryption_BM->parallel_time =
      duration_cast<milliseconds>(end - start).count();
  cout << "Parallel Encryption Done...................................\n";

  std::this_thread::sleep_for (std::chrono::seconds(2));
  cout << "\nLets's sleep for a couple of seconds......................\n" << endl;
  /* Decrytion */
  // Sequential
  num_of_cores = 1;
  index = 0;
  start = steady_clock::now();
  for (auto encrypted_i : encrypted_vec) {
    if (encrypted_i.empty())
      continue;
    index++;
    string decrypted = encryption_ptr->Decrypt(encrypted_i, num_of_cores);
  }
  end = steady_clock::now();
  decryption_BM->sequential_time =
      duration_cast<milliseconds>(end - start).count();
  cout << "Sequential Decryption Done................................\n";
  /*cout << "Time elapsed for decryption: "*/
  /*<< duration_cast<milliseconds>(end - start).count() << " ms.\n";*/
  // Parallel
  num_of_cores = GetNumberOfCores();
  index = 0;
  start = steady_clock::now();
  for (auto encrypted_i : encrypted_vec) {
    if (encrypted_i.empty())
      continue;
    index++;
    string decrypted = encryption_ptr->Decrypt(encrypted_i, num_of_cores);
  }
  end = steady_clock::now();
  decryption_BM->parallel_time =
      duration_cast<milliseconds>(end - start).count();
  cout << "Parallel Decryption Done...................................\n\n";
  cout << "Encryption" << endl;
  cout << "-----------" << endl;
  encryption_BM->PrintParams();
  cout << "Decryption" << endl;
  cout << "-----------" << endl;
  decryption_BM->PrintParams();
  file_handler.close();
  return 0;
}
