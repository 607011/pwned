//
//  lazy.hpp
//  pwned-lib
//
//  Created by Oliver Lau on 25.04.19.
//  Copyright © 2019 Oliver Lau. All rights reserved.
//

#ifndef __lazy_hpp__
#define __lazy_hpp__

#include <memory>
#include <mutex>

namespace pwned
{

template <typename T>
class Lazy
{
  struct State
  {
    std::function<T()> createValue;
    std::once_flag initialized;
    std::unique_ptr<T> value;
  };

public:
  using value_type = T;

  Lazy() = default;

  explicit Lazy(std::function<T()> createValue)
  {
    state->createValue = createValue;
  }

  explicit operator bool() const
  {
    return static_cast<bool>(state->value);
  }

  T &value()
  {
    init();
    return *state->value;
  }

  const T &value() const
  {
    init();
    return *state->value;
  }

  T *operator->()
  {
    return &value();
  }

  const T *operator->() const
  {
    return &value();
  }

  T &operator*()
  {
    return value();
  }

  const T &operator*() const
  {
    return value();
  }

private:
  void init() const
  {
    std::call_once(state->initialized, [&] { state->value = std::make_unique<T>(state->createValue()); });
  }
  std::shared_ptr<State> state = std::make_shared<State>();
};

} // namespace pwned

#endif // __lazy_hpp__
