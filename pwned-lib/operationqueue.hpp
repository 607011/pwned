/*
 Copyright © 2019 Oliver Lau <ola@ct.de>, Heise Medien GmbH & Co. KG - Redaktion c't

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef __operationqueue_hpp__
#define __operationqueue_hpp__

#include <thread>
#include <pthread.h>
#include <mutex>
#include <list>
#include <queue>

#include "semaphore.hpp"
#include "operation.hpp"

namespace pwned
{

template <typename F, typename... Ts>
inline std::thread runAsync(F &&f, int prio, Ts &&... params)
{
  std::thread th(std::forward<F>(f), std::forward<Ts>(params)...);
  sched_param sch_params;
  sch_params.sched_priority = prio;
  if (pthread_setschedparam(th.native_handle(), SCHED_RR, &sch_params))
  {
    std::cerr << "Failed to set thread scheduling: " << std::strerror(errno) << std::endl;
  }
  return th;
}

static const auto opGreaterPriority = [](Operation *lhs, Operation *rhs) {
  return lhs->priority < rhs->priority;
};

template <class T>
class OperationQueue
{
  std::priority_queue<T *, std::vector<T *>, decltype(opGreaterPriority)> unscheduledOps;
  std::list<T *> runningOps;
  std::list<std::thread> opThreads;
  std::thread exeThread;
  mutable std::mutex mtx;
  std::mutex pauseMtx;
  Semaphore guard;
  int threadPriority;
  bool _isRunning;
  bool _isCancelled;
  std::condition_variable pauseCondition;

public:
  explicit OperationQueue(int threadPriority = 0)
      : unscheduledOps(opGreaterPriority), guard(Semaphore(std::thread::hardware_concurrency())), threadPriority(threadPriority), _isRunning(false), _isCancelled(false)
  { /* ... */
  }

  size_t size() const
  {
    std::lock_guard<std::mutex> lock(mtx);
    return unscheduledOps.size() + runningOps.size();
  }

  void reset()
  {
    cancel();
    opThreads.clear();
    _isRunning = false;
    _isCancelled = false;
  }

  inline bool isRunning() const
  {
    return _isRunning;
  }

  inline bool isCancelled() const
  {
    return _isCancelled;
  }

  void operationWait()
  {
    std::cout << "operationWait()" << std::endl;
    std::unique_lock<std::mutex> lock(pauseMtx);
    pauseCondition.wait(lock);
    std::cout << "operationWait() resuming ... " << std::endl;
  }

  void pause()
  {
    if (_isCancelled)
      return;
    if (_isRunning)
    {
      for (Operation *op : runningOps)
      {
        op->pause();
      }
      std::lock_guard<std::mutex> lock(mtx);
      _isRunning = false;
    }
  }

  void resume()
  {
    if (_isCancelled)
      return;
    if (!_isRunning)
    {
      std::cout << "OperationQueue::resume() notifying all ..." << std::endl;
      pauseCondition.notify_all();
      _isRunning = true;
    }
  }

  void cancel()
  {
    std::lock_guard<std::mutex> lock(mtx);
    _isCancelled = true;
    for (Operation *op : runningOps)
    {
      op->cancel();
    }
    while (!unscheduledOps.empty())
    {
      Operation *op = unscheduledOps.top();
      op->cancel();
      delete op;
      unscheduledOps.pop();
    }
  }

  void add(T *const op)
  {
    std::lock_guard<std::mutex> lock(mtx);
    op->setQueue(reinterpret_cast<OperationQueue<Operation> *>(this));
    unscheduledOps.push(op);
  }

  void finished(T *const op)
  {
    std::lock_guard<std::mutex> lock(mtx);
    runningOps.remove(op);
    delete op;
  }

  void execute(bool _waitForScheduled = false)
  {
    sched_param param;
    int policy;
    int rc = pthread_getschedparam(pthread_self(), &policy, &param);
    int parentPriority = (rc == 0) ? param.sched_priority : 0;
    exeThread = runAsync([this] {
      while (!unscheduledOps.empty())
      {
        if (_isCancelled)
          break;
        guard.wait();
        mtx.lock();
        T *const op = unscheduledOps.top();
        unscheduledOps.pop();
        runningOps.push_back(op);
        opThreads.push_back(runAsync([op, this]() {
          op->start();
          finished(op);
          guard.notify();
        },
                                     threadPriority));
        mtx.unlock();
      }
    },
                         parentPriority);
    _isRunning = true;
    if (_waitForScheduled)
    {
      waitForScheduled();
    }
  }

  void waitForScheduled()
  {
    exeThread.join();
  }

  void waitForFinished()
  {
    for (auto &thread : opThreads)
    {
      thread.join();
    }
    reset();
  }
};
} // namespace pwned

#endif // __operationqueue_hpp__
