/**
 * @file server_main.hpp
 *
 * @brief Header for main_server
 *
 * @author Abhishek Rawat (abhishek18620@gmail.com)
 */

#ifndef IP_CAMS_COMMUNICATION_SRC_SERVER_MAIN_SERVER_HPP_
#define IP_CAMS_COMMUNICATION_SRC_SERVER_MAIN_SERVER_HPP_

/*
 * sys includes
 * */
#include <queue>
#include <string>
#include <thread>
#include <vector>
#include <memory>

/*
 * our includes
 * */
#include <event.h>

namespace server {

  /** For testing purposes only, port will only be 5555 */
  constexpr int32_t port = 5555;

  /** structure for worker entity */
  typedef struct Worker {
    ::std::thread s_thread;
    uint32_t s_terminate_signal;
    ::std::queue <WorkQueue> s_work_queue;
  };

  /** structure for a worker's each job entity */
  typedef struct Job {
    // Job's function will be implmented later
    void* job_function() { return NULL; }
    void* user_data;
  };

  typedef struct WorkQueue {
    struct worker *workers;
    struct job *waiting_jobs;
    pthread_mutex_t jobs_mutex;
    pthread_cond_t jobs_cond;
  };

  class Worker {
  public:
    WorkQueue() : {}

  private:
    int workqueue_init(workqueue_t *workqueue, int numWorkers);

    void workqueue_shutdown(workqueue_t *workqueue);

    void workqueue_add_job(workqueue_t *workqueue, job_t *job);

    ::std::thread m_thread;

    uint32_t m_terminate_signal;

    ::std::queue <WorkQueue> m_work_queue;
  }

} // namespace server

#endif
