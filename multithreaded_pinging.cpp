#include <curl/curl.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <chrono>
#include <thread>
/*#include <boost/asio/io_service.hpp>*/
//#include <boost/bind.hpp>
/*#include <boost/thread/thread.hpp>*/
using ::std::string;
using ::std::vector;
using ::std::fstream;
using ::std::chrono::steady_clock;
using ::std::chrono::duration_cast;
using ::std::chrono::milliseconds;
using ::std::chrono::seconds;
using ::std::cerr;
using ::std::endl;

#define trace2(x, y)          cerr <<#x<<": "<<x<<" | "<<#y<<": "<<y<< endl;
#define trace3(x, y, z)       cerr <<#x<<": "<<x<<" | "<<#y<<": "<<y<<" | "<<#z<<": "<<z<<endl;
#define trace4(a, b, c, d)    cerr <<#a<<": "<<a<<" | "<<#b<<": "<<b<<" | "<<#c<<": "<<c<<" | "<<#d<<": "<<d<<endl;
#define trace5(a, b, c, d, e) cerr <<#a<<": "<<a<<" | "<<#b<<": "<<b<<" | "<<#c<<": "<<c<<" | "<<#d<<": "<<d<<" | "<<#e<<": "<<e<<endl;
//using namespace boost::asio;
/**
 * @fn int testConnection(void)
 * @brief Pings "https://www.google.com/" to test if there is an internet
 * connection.  Timeout is set to three seconds.
 * @return Success value if connected to the internet.
 */
void testConnection(vector <string>& url_list, int start, int end) {
  trace3(__func__, start, end);
  CURL *curl;
  int res = 0;
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3);
  curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
  string url;
  for (int i = start; i<=end; i++) {
    url = url_list[i];
    if (url.length() == 0) return;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    res = curl_easy_perform(curl);
    if (!res)
      std::cout<< " URL : "<< url << " is working" << std::endl;
    else std::cout<< " URL : "<< url << " is not working" << std::endl;
  }
  curl_easy_cleanup(curl);
  curl_global_cleanup();
}

int main() {
  fstream fh("output.txt", fh.in);
  string str;
  vector <string> url_list;
  while(!fh.eof()) {
    getline(fh,str);
    url_list.push_back(str);
  }
  url_list.pop_back();
  std::cout<<"File done .... size = "<< url_list.size()<<std::endl;
  auto start = steady_clock::now();
  //testConnection(url_list);
  vector <::std::thread> threadpool;
  int partition = url_list.size() / 8;
  int ind1 = 0;
  int ind2= partition - 1;
  for (int i = 0; i < 8; i++) {
    std::cout<< "Initialising thread"<< i<< "  ";
    trace2(ind1, ind2);
    //::std::thread th(testConnection, ::std::ref(url_list), ind1, ind2);
    threadpool.push_back(move(::std::thread (testConnection, ::std::ref(url_list), ind1, ind2)));
    ind1 = ind2+1;
    ind2 = (i == 6)? url_list.size() - 1 : ind1 + partition - 1;
  }
  /*boost::asio::io_service ioService;*/
  //boost::thread_group threadpool;

  //boost::asio::io_service::work work(ioService);

  //for(int i = 0; i < 8; i++) {
    //threadpool.create_thread(boost::bind(&boost::asio::io_service::run, &ioService));
  //}
  //ioService.post(boost::bind(testConnection, url_list));
  //ioService.stop();
  /*threadpool.join_all();*/
  /*std::cout<< "From main : It'd done" << std::endl;*/
  //for (int i = 0; i<8; i++) {
    //std::cout << "Joining thread " << i << endl;
    //threadpool[i].join();
  /*}*/
  for (auto& th : threadpool) th.join();
  auto end = steady_clock::now();
  std::cout<<"Time elapsed: "<<duration_cast<milliseconds> (end-start).count()<<" ms.\n";
  return 0;
}
