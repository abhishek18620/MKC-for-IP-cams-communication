/**
 * @file worker.hpp
 *
 * @brief
 *
 * @author Abhishek Rawat (abhishek18620@gmail.com)
 */

#ifndef MKC_FOR_IP_CAMS_COMMUNICATION_SRC_SERVER_WORKER_HPP_
#define MKC_FOR_IP_CAMS_COMMUNICATION_SRC_SERVER_WORKER_HPP_

/*
 * sys includes
 * */
#include <vector>
#include <string>
#include <thread>

/*
 * our includes
 * */

typedef struct worker {
	pthread_t thread;
	int terminate;
	struct workqueue *workqueue;
	struct worker *prev;
	struct worker *next;
} worker_t;


namespace server {

  class Worker {
   public:
    Worker() : {}

    /** Initialisation function */
    void Init();

    uint32_t GetThreadPriority() { return m_thread_priority; }

   private:

    /** Thread's job function */
    void ThreadRun();

    /** worker thread*/
    ::std::thread m_thread;

    uint32_t m_thread_real_time_prioirty;

    int32_t m_terminate_signal;
  }

}

#endif //MKC_FOR_IP_CAMS_COMMUNICATION_SRC_SERVER_WORKER_HPP_

