/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SPIN_LOCK_CONTEXT_H_
#define SPIN_LOCK_CONTEXT_H_

#include <ndis.h>

// Lock for the entire life time of the object. Caller can just create the
// object and it will grab the lock on constructor and release it on
// destructor.
//
// spin_lock needs to call NdisAllocateSpinLock before pass it to this class.
//
// i.e.,
// .... (code not protected by lock)
// {
//    SpinLockContext lock(lock_object, is_dpc_level);
//    ...(code protected by lock)
// }
// ....(code not protected by lock)
class SpinLockContext {
 public:
  // is_dpc_level: whether the caller is running at DISPATCH_LEVEL.
  SpinLockContext(NDIS_SPIN_LOCK* spin_lock, bool is_dpc_level)
      : spin_lock_(spin_lock), is_dpc_level_(is_dpc_level) {
    Lock();
  }

  ~SpinLockContext() { Unlock(); }

  SpinLockContext(const SpinLockContext&) = delete;
  SpinLockContext& operator=(const SpinLockContext&) = delete;

 private:
  void Lock() {
    if (is_dpc_level_) {
      NdisDprAcquireSpinLock(spin_lock_);
    } else {
      NdisAcquireSpinLock(spin_lock_);
    }
  }

  void Unlock() {
    if (is_dpc_level_) {
      NdisDprReleaseSpinLock(spin_lock_);
    } else {
      NdisReleaseSpinLock(spin_lock_);
    }
  }

  NDIS_SPIN_LOCK* spin_lock_;
  bool is_dpc_level_;
};

#endif  // SPIN_LOCK_CONTEXT_H_
