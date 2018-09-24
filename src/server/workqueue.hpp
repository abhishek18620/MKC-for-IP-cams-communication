/**
 * @file server_main.hpp
 *
 * @brief Header for main_server
 *
 * @author Abhishek Rawat (abhishek18620@gmail.com)
 */

#ifndef MKC_FOR_IP_CAMS_COMMUNICATION_SRC_SERVER_WORKQUEUE_HPP_
#define MKC_FOR_IP_CAMS_COMMUNICATION_SRC_SERVER_WORKQUEUE_HPP_

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
#include <event2/event.h>

namespace server {

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

  class WorkeQueue {
  public:
    WorkQueue() : {}

  private:
    int workqueue_init(workqueue_t *workqueue, int numWorkers);

    void workqueue_shutdown(workqueue_t *workqueue);

    void workqueue_add_job(workqueue_t *workqueue, job_t *job);

    ::std::vector <Worker> m_workers;

    ::std::queue <WorkQueue> m_work_queue;
  }

} // namespace server

#endif
