// Bounded obligation reducer for the frozen DC-013 two-member profile.
// Called under the coordinator event serializer; no allocation, I/O or locks.
#ifndef DCG01_ROOT_OBLIGATIONS_H
#define DCG01_ROOT_OBLIGATIONS_H
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace DCG01Roots
{
enum Reason : unsigned { Application = 1, InFlight = 2 };
struct Changes
{
    unsigned count = 0;
    unsigned char ids[64][44]{};
};

class Obligations
{
    struct Entry { unsigned char id[44]{}; unsigned reasons[2]{}; } entries[64];
    unsigned used = 0;
    unsigned char run[16]{}, incarnations[2][16]{};
    bool configured = false, failed = false, closed[2]{};

    static bool Nonzero(const unsigned char* p, unsigned count)
    { unsigned value = 0; for (unsigned i = 0; i < count; ++i) value |= p[i]; return value != 0; }
    bool Reject() { failed = true; return false; }
    bool Logical(const unsigned char* id) const
    {
        const unsigned creator = id[16];
        if (creator < 1 || creator > 2 || id[17] || id[18] || id[19] ||
            std::memcmp(id, run, 16) || std::memcmp(id + 20, incarnations[creator - 1], 16) ||
            id[36] < 1 || id[36] > 64) return false;
        for (unsigned i = 37; i < 44; ++i) if (id[i]) return false;
        return true;
    }
    int Find(const unsigned char* id) const
    {
        for (unsigned i = 0; i < used; ++i) if (!std::memcmp(entries[i].id, id, 44)) return static_cast<int>(i);
        return -1;
    }
    bool Change(unsigned member, const unsigned char* ids, unsigned count,
                unsigned reasons, bool acquire, Changes* output)
    {
        if (!configured || failed || member < 1 || member > 2 || !ids || !output ||
            count == 0 || count > 64 || reasons == 0 || (reasons & ~3u) || closed[member - 1]) return Reject();
        const unsigned actor = member - 1;
        unsigned additions = 0;
        int indexes[64]{};
        // Validate the complete batch before changing any ownership or output.
        for (unsigned i = 0; i < count; ++i)
        {
            const unsigned char* id = ids + i * 44;
            if (!Logical(id)) return Reject();
            for (unsigned j = 0; j < i; ++j) if (!std::memcmp(id, ids + j * 44, 44)) return Reject();
            indexes[i] = Find(id);
            const unsigned prior = indexes[i] < 0 ? 0 : entries[indexes[i]].reasons[actor];
            if (acquire ? (prior & reasons) != 0 : (prior & reasons) != reasons) return Reject();
            if (indexes[i] < 0) ++additions;
        }
        if (additions > 64 - used) return Reject();
        Changes changes{};
        for (unsigned i = 0; i < count; ++i)
        {
            const unsigned char* id = ids + i * 44;
            unsigned index;
            if (indexes[i] < 0)
            {
                index = used++;
                std::memcpy(entries[index].id, id, 44);
            }
            else index = static_cast<unsigned>(indexes[i]);
            unsigned& prior = entries[index].reasons[actor];
            const unsigned next = acquire ? prior | reasons : prior & ~reasons;
            if ((prior == 0) != (next == 0)) std::memcpy(changes.ids[changes.count++], id, 44);
            prior = next;
        }
        *output = changes;
        return true;
    }
public:
    Obligations() = default;
    Obligations(const Obligations&) = delete;
    Obligations& operator=(const Obligations&) = delete;

    bool Configure(const unsigned char* runId, const unsigned char* memberIncarnations)
    {
        if (configured || failed || !runId || !memberIncarnations || !Nonzero(runId,16) ||
            !Nonzero(memberIncarnations,16) || !Nonzero(memberIncarnations + 16,16) ||
            !std::memcmp(memberIncarnations, memberIncarnations + 16,16)) return Reject();
        std::memcpy(run,runId,16); std::memcpy(incarnations,memberIncarnations,32);
        configured = true;
        return true;
    }
    bool Acquire(unsigned member, const unsigned char* ids, unsigned count, unsigned reasons, Changes* output)
    { return Change(member,ids,count,reasons,true,output); }
    bool Release(unsigned member, const unsigned char* ids, unsigned count, unsigned reasons, Changes* output)
    { return Change(member,ids,count,reasons,false,output); }

    // The caller must first prove actual application close/Join and source-owned
    // quiescence. This reducer does not establish runtime placement or that proof.
    bool CloseApplication(unsigned member, Changes* output)
    {
        if (!configured || failed || member < 1 || member > 2 || !output) return Reject();
        const unsigned actor = member - 1;
        if (closed[actor]) { *output = Changes{}; return true; }
        for (unsigned i = 0; i < used; ++i)
            if (entries[i].reasons[actor] & InFlight) return Reject();
        Changes changes{};
        for (unsigned i = 0; i < used; ++i)
        {
            if (entries[i].reasons[actor]) std::memcpy(changes.ids[changes.count++],entries[i].id,44);
            entries[i].reasons[actor] = 0;
        }
        closed[actor] = true;
        *output = changes;
        return true;
    }
    // Inspection is allowed after failure to preserve the pre-failure evidence.
    unsigned Reasons(unsigned member, const unsigned char* id) const
    {
        if (member < 1 || member > 2 || !id) return 0;
        const int index = Find(id);
        return index < 0 ? 0 : entries[index].reasons[member - 1];
    }
    bool Healthy() const { return configured && !failed; }
    bool Closed(unsigned member) const { return member >= 1 && member <= 2 && closed[member - 1]; }
    unsigned HistoricalObjects() const { return used; }
};
}
#endif
