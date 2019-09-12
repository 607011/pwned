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

#ifndef __operation_hpp__
#define __operation_hpp__

#include <atomic>
#include <mutex>
#include <condition_variable>
#include <sys/resource.h>
#include <exception>

#include "operation.hpp"
#include "uuid.hpp"

namespace pwned
{

class OperationException : public std::exception
{
protected:
  std::string msg;
  int _code;

public:
  enum
  {
    OK = 0,
    QueueNotSet
  };

  explicit OperationException(const char *message, int code);
  explicit OperationException(const std::string &message, int code);
  const std::string &what() noexcept;
  const char *what() const noexcept;
  int code() const noexcept;
  virtual ~OperationException() throw();
};

template <class T>
class OperationQueue;

class Operation
{
protected:
  std::atomic<bool> isRunning;
  std::atomic<bool> isFinished;
  std::atomic<bool> isCancelled;
  std::atomic<bool> isPaused;
  std::mutex mtx;
  std::condition_variable finishedCondition;
  OperationQueue<Operation> *queue;
  void wait() noexcept(false);
  void waitForFinished();

public:
  UUID uuid;
  long long priority;

  Operation();
  virtual ~Operation();

  void setQueue(OperationQueue<Operation> *queue) noexcept;

  /**
         * Description: Signals the operation to pause by setting `isPaused` to `true`. It's up to the implementation of the Operation to take the necessary measures to pause execution.
         * Parameters: none
         */
  void pause() noexcept;

  /**
         * Description: Starts the operation by calling the abstract method `execute()`.
         * Parameters: none
         */
  virtual void start() noexcept;

  /**
         * Description: Signals the operation by setting `isCancelled` to `true`, then waits for all operations (pending and scheduled) to finish by calling `waitForFinished()`.
         * Parameters: none
         */
  void cancel();

  virtual void execute() noexcept(false) = 0;
};

} // namespace pwned

#endif // __operation_hpp__
