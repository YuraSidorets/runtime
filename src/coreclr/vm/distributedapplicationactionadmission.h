#pragma once
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <limits>
#include <mutex>

namespace dcg01_terminal_admission
{
// Model of one process/member's one-run application admission gate.
// Run/member/incarnation identity is carried separately by the caller.
class Gate
{
public:
    enum class TicketState : unsigned char { Empty, Claimed, Reserved, Active, Released };

    struct ClosedSnapshot
    {
        std::uint64_t generation;
    };

    struct Ticket
    {
        Gate* gate = nullptr;
        std::uint64_t generation = 0;
        std::atomic<TicketState> state{TicketState::Empty};

        Ticket() = default;
        Ticket(const Ticket&) = delete;
        Ticket& operator=(const Ticket&) = delete;
    };

    explicit Gate(std::uint64_t openGeneration) : openGeneration_(openGeneration) {}

    // Used for a new application action. Linearizes against Close().
    bool TryEnter(Ticket& ticket)
    {
        return TryAdd(ticket, TicketState::Active);
    }

    // Thread.Start is a new action even when nested in Main. A parent ticket
    // authorizes the attempt, but cannot bypass a closed gate.
    bool TryReserveChild(const Ticket& parent, Ticket& child)
    {
        return IsAuthorized(parent) && TryAdd(child, TicketState::Reserved);
    }

    // A callback or other synchronously reserved action may enter after Close
    // only when its ticket was reserved before Close. Reservation contributes
    // to the drain count before the close transition.
    bool TryReserve(Ticket& ticket)
    {
        return TryAdd(ticket, TicketState::Reserved);
    }

    bool ActivateReserved(Ticket& ticket)
    {
        if (ticket.state.load(std::memory_order_acquire) != TicketState::Reserved ||
            ticket.gate != this || ticket.generation != openGeneration_)
            return false;
        TicketState expected = TicketState::Reserved;
        return ticket.state.compare_exchange_strong(
            expected, TicketState::Active, std::memory_order_acq_rel);
    }

    bool EnterReservedCallback(Ticket& ticket)
    {
        return ActivateReserved(ticket);
    }

    // Nested access/publication/completion for an admitted action uses its
    // ticket. It does not reopen admission or add an unrelated counter.
    bool IsAuthorized(const Ticket& ticket) const
    {
        if (ticket.state.load(std::memory_order_acquire) != TicketState::Active)
            return false;
        return ticket.gate == this && ticket.generation == openGeneration_;
    }

    // One-way close. The packed word orders successful admissions against the
    // close transition; the close generation stays fixed for this run.
    std::uint64_t Close()
    {
        if (openGeneration_ == std::numeric_limits<std::uint64_t>::max())
        {
            // Generation exhaustion must fail closed even though no successor
            // generation can be represented or reported as terminal evidence.
            std::uint64_t word = state_.load(std::memory_order_acquire);
            while ((word & kClosed) == 0 && !state_.compare_exchange_weak(
                       word, word | kClosed, std::memory_order_acq_rel, std::memory_order_acquire))
            {
            }
            return 0;
        }
        closeGeneration_.store(openGeneration_ + 1, std::memory_order_relaxed);
        std::uint64_t word = state_.load(std::memory_order_acquire);
        while ((word & kClosed) == 0)
        {
            if (state_.compare_exchange_weak(
                    word, word | kClosed, std::memory_order_acq_rel, std::memory_order_acquire))
                return openGeneration_ + 1;
        }
        return closeGeneration_.load(std::memory_order_acquire);
    }

    std::uint64_t CloseGeneration() const
    {
        return (state_.load(std::memory_order_acquire) & kClosed) == 0
            ? 0 : closeGeneration_.load(std::memory_order_acquire);
    }

    // A nonblocking production view of the irreversible closed-and-drained
    // state. One acquire observes closure and zero live tickets together.
    // This is an admission fact, not proof of successful application completion.
    // On refusal, leave the caller's output unchanged.
    bool CaptureClosed(ClosedSnapshot* output) const
    {
        if (output == nullptr || state_.load(std::memory_order_acquire) != kClosed)
            return false;
        const std::uint64_t generation = closeGeneration_.load(std::memory_order_acquire);
        if (generation == 0)
            return false; // Closed after generation exhaustion is not a valid cut.
        *output = ClosedSnapshot{generation};
        return true;
    }

    bool IsOpen() const
    {
        return (state_.load(std::memory_order_acquire) & kClosed) == 0;
    }

    // A failed physical thread creation may cancel only a still-reserved ticket.
    bool CancelReservation(Ticket& ticket)
    {
        return Retire(ticket, TicketState::Reserved);
    }

    // An entered application action may complete only its active ticket.
    bool CompleteActive(Ticket& ticket)
    {
        return Retire(ticket, TicketState::Active);
    }

    // Returns false if closure has not linearized. Caller must invoke this
    // outside runtime, access, GC, and protocol locks.
    bool WaitForDrain()
    {
        if (IsOpen())
            return false;
        std::unique_lock<std::mutex> lock(waitMutex_);
        drained_.wait(lock, [this] {
            return (state_.load(std::memory_order_acquire) & kCountMask) == 0;
        });
        return true;
    }

    std::uint64_t InFlightForModelOnly() const
    {
        return state_.load(std::memory_order_acquire) & kCountMask;
    }

private:
    static constexpr std::uint64_t kClosed = std::uint64_t(1) << 63;
    static constexpr std::uint64_t kCountMask = ~kClosed;

    bool Retire(Ticket& ticket, TicketState expectedState)
    {
        if (ticket.gate != this || ticket.generation != openGeneration_)
            return false;
        TicketState expected = expectedState;
        if (!ticket.state.compare_exchange_strong(
                expected, TicketState::Released, std::memory_order_acq_rel))
            return false;
        const std::uint64_t old = state_.fetch_sub(1, std::memory_order_acq_rel);
        if ((old & kCountMask) == 1)
        {
            std::lock_guard<std::mutex> lock(waitMutex_);
            drained_.notify_all();
        }
        return true;
    }

    bool TryAdd(Ticket& ticket, TicketState initialState)
    {
        TicketState empty = TicketState::Empty;
        if (!ticket.state.compare_exchange_strong(
                empty, TicketState::Claimed, std::memory_order_acq_rel))
            return false;
        std::uint64_t word = state_.load(std::memory_order_acquire);
        for (;;)
        {
            if ((word & kClosed) != 0 || (word & kCountMask) == kCountMask)
            {
                ticket.state.store(TicketState::Empty, std::memory_order_release);
                return false;
            }
            if (state_.compare_exchange_weak(
                    word, word + 1, std::memory_order_acq_rel, std::memory_order_acquire))
                break;
        }
        ticket.gate = this;
        ticket.generation = openGeneration_;
        ticket.state.store(initialState, std::memory_order_release);
        return true;
    }

    const std::uint64_t openGeneration_;
    std::atomic<std::uint64_t> state_{0};
    std::atomic<std::uint64_t> closeGeneration_{0};
    std::mutex waitMutex_;
    std::condition_variable drained_;
};
} // namespace dcg01_terminal_admission
