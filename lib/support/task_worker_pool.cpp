/*
 *
 * Copyright 2021-2023 Software Radio Systems Limited
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the distribution.
 *
 */

#include "srsran/support/executors/task_worker_pool.h"
#include <future>

using namespace srsran;

template <bool UseLockfreeMPMC>
void task_worker_pool<UseLockfreeMPMC>::start_impl(os_thread_realtime_priority           prio_,
                                                   span<const os_sched_affinity_bitmask> cpu_masks)
{
  if (cpu_masks.size() > 1) {
    // An array with a single mask is allowed, otherwise the number of masks must be equal to the number of workers.
    srsran_assert(cpu_masks.size() == workers.size(), "Wrong array of CPU masks provided");
  }
  for (unsigned i = 0; i != workers.size(); ++i) {
    auto task_func = [this, i]() {
      while (true) {
        optional<unique_task> task = pending_tasks.pop_blocking();
        if (not task.has_value()) {
          break;
        }
        (*task)();
      }
      logger.info("Task worker \"{}\" finished.", workers[i].t_handle.get_name());
    };
    if (cpu_masks.empty()) {
      workers[i].t_handle = unique_thread{fmt::format("{}#{}", pool_name, i), prio_, task_func};
    } else {
      // Check whether a single mask for all workers should be used.
      os_sched_affinity_bitmask cpu_mask = (cpu_masks.size() == 1) ? cpu_masks[0] : cpu_masks[i];
      workers[i].t_handle = unique_thread{fmt::format("{}#{}", pool_name, i), prio_, cpu_mask, task_func};
    }
  }
}

template <bool UseLockfreeMPMC>
task_worker_pool<UseLockfreeMPMC>::~task_worker_pool()
{
  stop();
}

template <bool UseLockfreeMPMC>
void task_worker_pool<UseLockfreeMPMC>::stop()
{
  for (worker& w : workers) {
    if (w.t_handle.running()) {
      pending_tasks.request_stop();
      w.t_handle.join();
    }
  }
}

/// \brief Wait for all the currently enqueued tasks to complete.
template <bool UseLockfreeMPMC>
void task_worker_pool<UseLockfreeMPMC>::wait_pending_tasks()
{
  std::packaged_task<void()> pkg_task([]() { /* do nothing */ });
  std::future<void>          fut = pkg_task.get_future();
  push_task(std::move(pkg_task));
  // blocks for enqueued task to complete.
  fut.get();
}

template class srsran::task_worker_pool<false>;
template class srsran::task_worker_pool<true>;
