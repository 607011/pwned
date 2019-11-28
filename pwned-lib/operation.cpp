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

#include "operation.hpp"
#include "operationqueue.hpp"

namespace pwned
{

OperationException::OperationException(const char *message, int code)
    : msg(message)
    , _code(code)
{
}

OperationException::OperationException(const std::string &message, int code)
    : msg(message)
    , _code(code)
{
}

const std::string &OperationException::what() noexcept
{
  return msg;
}

const char *OperationException::what() const noexcept
{
  return msg.c_str();
}

int OperationException::code() const noexcept
{
  return _code;
}

Operation::~Operation()
{
  if (isRunning)
  {
    cancel();
  }
}

void Operation::setQueue(OperationQueue<Operation> *queue) noexcept
{
  this->queue = queue;
}

/**
     * Method name: pause()
     * Description: Signals the operation to pause. It's up to the implementation of the Operation to take the necessary measures to pause execution.
     * Parameters: none
     */
void Operation::pause() noexcept
{
  std::cout << "Operation::pause() " << uuid << std::endl;
  isPaused = true;
}

void Operation::wait() noexcept(false)
{
  if (queue != nullptr)
  {
    queue->operationWait();
  }
  else
  {
    throw OperationException("Queue not set", OperationException::QueueNotSet);
  }
}

void Operation::start() noexcept
{
  if (isCancelled)
    return;
  isRunning = true;
  isPaused = false;
  try
  {
    execute();
  }
  catch (OperationException &e)
  {
    std::cerr << "Exception in Operation::execute(): " << e.what() << std::endl;
  }
  isRunning = false;
  isFinished = true;
  finishedCondition.notify_one();
}

void Operation::waitForFinished()
{
  std::unique_lock<std::mutex> lock(mtx);
  finishedCondition.wait(lock);
}

void Operation::cancel()
{
  std::cout << "Operation::cancel()" << std::endl;
  isCancelled = true;
  waitForFinished();
}

} // namespace pwned
