#include <boost/fiber/scheduler.hpp>

#include <boost/assert.hpp>

#include <boost/fiber/context.hpp>

#if defined(BOOST_FIBERS_NO_ATOMICS)
    #error invalid boost config
#endif

#include <category/core/fiber/priority_algorithm.hpp>

#include <quill/Quill.h>

namespace boost
{
    namespace fibers
    {
        void scheduler::schedule(context *ctx) noexcept
        {
            // LOG_INFO("JAMES1");

            BOOST_ASSERT(nullptr != ctx);
            BOOST_ASSERT(!ctx->ready_is_linked());
            BOOST_ASSERT(!ctx->remote_ready_is_linked());
            BOOST_ASSERT(!ctx->terminated_is_linked());
            // remove context ctx from sleep-queue
            // (might happen if blocked in timed_mutex::try_lock_until())
            if (ctx->sleep_is_linked()) {
                // unlink it from sleep-queue
                ctx->sleep_unlink();
            }
            // push new context to ready-queue
            algo_->awakened(ctx);
        }

        void scheduler::schedule_from_remote(context *ctx) noexcept
        {
            // LOG_INFO("JAMES2");

            MONAD_ASSERT(nullptr != ctx);
            // another thread might signal the main-context of this thread
            MONAD_ASSERT(!ctx->is_context(type::dispatcher_context));
            MONAD_ASSERT(this == ctx->get_scheduler());
            MONAD_ASSERT(!ctx->ready_is_linked());
            MONAD_ASSERT(!ctx->remote_ready_is_linked());
            MONAD_ASSERT(!ctx->terminated_is_linked());
            // boost::fibers::algo::algorithm* const algo = algo_.get();
            if (auto *const algo2 =
                    dynamic_cast<monad::fiber::PriorityAlgorithm *>(
                        algo_.get());
                algo2) {
                algo2->awakened(ctx);
            }
            else {
                // protect for concurrent access
                detail::spinlock_lock lk{remote_ready_splk_};
                MONAD_ASSERT(!shutdown_);
                MONAD_ASSERT(nullptr != main_ctx_);
                MONAD_ASSERT(nullptr != dispatcher_ctx_.get());
                // push new context to remote ready-queue
                ctx->remote_ready_link(remote_ready_queue_);
                lk.unlock();
            }
            // notify scheduler
            algo_->notify();
        }
    }
}
