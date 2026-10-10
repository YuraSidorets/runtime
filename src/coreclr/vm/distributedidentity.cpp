// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#include "common.h"
#include "assembly.hpp"
#include "ceeload.h"
#include "class.h"
#include "clsload.hpp"
#include "field.h"
#include "gchelpers.h"
#include "gcheaputilities.h"
#include "gchandleutilities.h"
#include "methodtable.h"
#include "threads.h"
#include "distributedidentity.h"
#include "distributedidentity_snapshot.h"
#include "distributedaccess.h"
#include "distributedadmission.h"
#include "distributedthread.h"

#include <atomic>
#include <cstdio>
#include <cstring>

namespace
{
constexpr int MaxObjects = 16;
constexpr unsigned MaxRetainedObjects = 64;
constexpr unsigned MaxRetainedBytes = 64 * 1024;
constexpr int IdSize = 44;
constexpr int TypeSize = 52;
constexpr int RecordSize = 190;
constexpr int HeaderSize = 8;
constexpr int MaxFrameSize = HeaderSize + MaxObjects * RecordSize;

enum RetentionRole : BYTE { SourceRetention = 1, InFlightRetention = 2, ReceiverRetention = 4 };

using ObjectId = DistributedObjectId;
struct Entry
{
    ObjectId id;
    OBJECTHANDLE weak;
    OBJECTHANDLE strong;
    UINT owner;
    UINT version;
    unsigned bytes;
    RetentionRole retention;
};
struct Directory
{
    Assembly* assembly;
    Module* module;
    std::atomic<Thread*> ownerThread{nullptr};
    DistributedIdentityContext context;
    MethodTable* nodeType;
    FieldDesc* fields[3];
    Entry entries[MaxRetainedObjects];
    unsigned count;
    unsigned retainedBytes;
    UINT64 nextCounter;
    bool initialized;
    bool failed;
};
Directory s_directory{};
std::atomic<bool> s_frozen{false};
std::atomic<bool> s_ownerHandedOff{false};
enum class WorkerSnapshotState : unsigned char { Empty, Capturing, Published, Consumed, Failed };
std::atomic<WorkerSnapshotState> s_workerSnapshotState{WorkerSnapshotState::Empty};
std::atomic<Thread*> s_workerStagingThread{nullptr};
dcg01_identity_snapshot::Snapshot s_workerSnapshot{};

bool Equal(const BYTE* a, const BYTE* b, int length) { return std::memcmp(a, b, length) == 0; }
bool IsZero(const BYTE* p, int length)
{
    for (int i = 0; i < length; i++) if (p[i] != 0) return false;
    return true;
}
void Put32(BYTE* p, UINT32 value) { for (int i = 0; i < 4; i++) p[i] = static_cast<BYTE>(value >> (8 * i)); }
UINT32 Get32(const BYTE* p) { return static_cast<UINT32>(p[0]) | (static_cast<UINT32>(p[1]) << 8) | (static_cast<UINT32>(p[2]) << 16) | (static_cast<UINT32>(p[3]) << 24); }
void Put64(BYTE* p, UINT64 value) { for (int i = 0; i < 8; i++) p[i] = static_cast<BYTE>(value >> (8 * i)); }
UINT64 Get64(const BYTE* p) { UINT64 value = 0; for (int i = 0; i < 8; i++) value |= static_cast<UINT64>(p[i]) << (8 * i); return value; }

bool OnOwnerThread()
{
    return s_directory.initialized && GetThread() == s_directory.ownerThread.load(std::memory_order_acquire);
}
int FindId(const ObjectId& id)
{
    for (unsigned i = 0; i < s_directory.count; i++)
        if (Equal(id.bytes, s_directory.entries[i].id.bytes, IdSize)) return static_cast<int>(i);
    return -1;
}
int FindObject(OBJECTREF object)
{
    for (unsigned i = 0; i < s_directory.count; i++)
    {
        Entry& entry = s_directory.entries[i];
        if (ObjectFromHandle(entry.weak) == object && ObjectFromHandle(entry.strong) == object)
            return static_cast<int>(i);
    }
    return -1;
}

bool ValidateType(MethodTable* mt)
{
    if (mt == nullptr || mt->GetModule() != s_directory.module || mt->IsArray() || mt->IsInterface() ||
        mt->IsValueType() || mt->HasInstantiation() || mt->ContainsGenericVariables() ||
        mt->HasFinalizer() || mt->HasLayout() || mt->GetNumInterfaces() != 0 ||
        !mt->IsSealed() || mt->HasClassConstructor() || mt->GetNumStaticFields() != 0 ||
        mt->GetNumInstanceFields() != 3)
        return false;
    MethodTable* parent = mt->GetParentMethodTable();
    if (parent == nullptr || !parent->IsObjectClass()) return false;
    // Literal fields are omitted from MethodTable layout counts and FieldDesc iteration.
    // The closed profile admits exactly these three declared fields, including metadata.
    IMDInternalImport* metadata = s_directory.module->GetMDImport();
    HENUMInternalHolder declaredFields(metadata);
    declaredFields.EnumInit(mdtFieldDef, mt->GetCl());
    if (metadata->EnumGetCount(&declaredFields) != 3) return false;

    FieldDesc* fields[3]{};
    ApproxFieldDescIterator iterator(mt, ApproxFieldDescIterator::INSTANCE_FIELDS);
    unsigned count = 0;
    while (FieldDesc* field = iterator.Next())
    {
        if (count == 3 || field->IsStatic()) return false;
        unsigned position = count;
        while (position > 0 && fields[position - 1]->GetMemberDef() > field->GetMemberDef())
        {
            fields[position] = fields[position - 1];
            position--;
        }
        fields[position] = field;
        count++;
    }
    if (count != 3) return false;
    for (int i = 0; i < 3; i++)
        if (IsFdInitOnly(fields[i]->GetAttributes()) || IsFdLiteral(fields[i]->GetAttributes()))
            return false;
    if (fields[0]->GetFieldType() != ELEMENT_TYPE_I4 ||
        fields[1]->GetFieldType() != ELEMENT_TYPE_CLASS || fields[2]->GetFieldType() != ELEMENT_TYPE_CLASS)
        return false;
    TypeHandle ref1 = fields[1]->GetFieldTypeHandleThrowing();
    TypeHandle ref2 = fields[2]->GetFieldTypeHandleThrowing();
    if (ref1.IsNull() || ref2.IsNull() || ref1.AsMethodTable() != mt || ref2.AsMethodTable() != mt)
        return false;
    if (s_directory.nodeType != nullptr && s_directory.nodeType != mt) return false;
    s_directory.nodeType = mt;
    for (int i = 0; i < 3; i++) s_directory.fields[i] = fields[i];
    return true;
}

bool EnsureNodeType(const BYTE* record)
{
    // Reject the external code identity before resolving its supplied metadata token.
    if (!Equal(record + IdSize, s_directory.context.assemblyHash, 32) ||
        !Equal(record + IdSize + 32, s_directory.context.mvid, 16)) return false;
    mdTypeDef token = Get32(record + IdSize + 48);
    if (TypeFromToken(token) != mdtTypeDef) return false;
    if (s_directory.nodeType == nullptr)
    {
        TypeHandle type = ClassLoader::LoadTypeDefThrowing(
            s_directory.module, token, ClassLoader::ThrowIfNotFound, ClassLoader::FailIfUninstDefOrRef);
        if (type.IsNull() || !ValidateType(type.AsMethodTable())) return false;
    }
    return s_directory.nodeType->GetCl() == token;
}

bool TypeMatches(const BYTE* typeKey, mdTypeDef token)
{
    return Equal(typeKey, s_directory.context.assemblyHash, 32) &&
        Equal(typeKey + 32, s_directory.context.mvid, 16) && Get32(typeKey + 48) == token;
}

void WriteType(BYTE* destination, mdTypeDef token)
{
    std::memcpy(destination, s_directory.context.assemblyHash, 32);
    std::memcpy(destination + 32, s_directory.context.mvid, 16);
    Put32(destination + 48, token);
}

bool ReadFrame(const BYTE* wire, int length, unsigned& count, unsigned& root)
{
    if (wire == nullptr || length < HeaderSize || length > MaxFrameSize ||
        std::memcmp(wire, "DID1", 4) != 0 || wire[4] != 1 || wire[5] == 0 || wire[5] > MaxObjects)
        return false;
    count = wire[5];
    root = static_cast<unsigned>(wire[6]) | (static_cast<unsigned>(wire[7]) << 8);
    return root < count && length == HeaderSize + static_cast<int>(count) * RecordSize;
}

bool ValidWireIdentity(const ObjectId& id)
{
    UINT64 counter = Get64(id.bytes + 36);
    if (counter == 0 || counter > MaxRetainedObjects || !Equal(id.bytes, s_directory.context.run, 16))
        return false;
    UINT32 node = Get32(id.bytes + 16);
    if (node == s_directory.context.localNode)
        return Equal(id.bytes + 20, s_directory.context.localInc, 16) && FindId(id) >= 0;
    return node == s_directory.context.peerNode && Equal(id.bytes + 20, s_directory.context.peerInc, 16);
}

int ExportGraph(OBJECTREF rootObject, BYTE* output, int capacity)
{
    if (!OnOwnerThread())
    {
        std::fprintf(stderr, "DC_IDENTITY phase=thread-rejected api=export\n");
        return -1;
    }
    if (s_directory.failed || s_frozen.load(std::memory_order_acquire) || rootObject == NULL || output == nullptr) return -1;

    OBJECTREF roots[MaxObjects];
    // Checked OBJECTREF default construction poisons slots; GCFrame requires null/live roots.
    for (unsigned i = 0; i < MaxObjects; i++) roots[i] = NULL;
    Wrapper<OBJECTHANDLE, DoNothing<OBJECTHANDLE>, DestroyStrongHandle> temporary[MaxObjects];
    ObjectId ids[MaxObjects]{};
    int count = 0;
    int written = -1;
    GCPROTECT_BEGIN(roots);
    do
    {
        // Protect the input before type validation can load field types and trigger GC.
        roots[count++] = rootObject;
        if (!ValidateType(roots[0]->GetMethodTable())) break;
        s_directory.nodeType->EnsureInstanceActive();
        temporary[0] = GetAppDomain()->CreateStrongHandle(roots[0]);

        for (int cursor = 0; cursor < count; cursor++)
        {
            OBJECTREF current = ObjectFromHandle(temporary[cursor]);
            for (int field = 1; field <= 2; field++)
            {
                OBJECTREF child = s_directory.fields[field]->GetRefValue(current);
                if (child == NULL) continue;
                if (child->GetMethodTable() != s_directory.nodeType) goto cleanup;
                bool found = false;
                for (int i = 0; i < count; i++)
                    if (ObjectFromHandle(temporary[i]) == child) { found = true; break; }
                if (!found)
                {
                    if (count == MaxObjects) goto cleanup;
                    roots[count] = child;
                    temporary[count] = GetAppDomain()->CreateStrongHandle(roots[count]);
                    count++;
                }
            }
        }

        int newCount = 0;
        for (int i = 0; i < count; i++)
            if (FindObject(ObjectFromHandle(temporary[i])) < 0) newCount++;
        unsigned baseSize = s_directory.nodeType->GetBaseSize();
        if (capacity < HeaderSize + count * RecordSize ||
            s_directory.count + newCount > MaxRetainedObjects ||
            s_directory.retainedBytes + static_cast<UINT64>(newCount) * baseSize > MaxRetainedBytes)
            break;

        for (int i = 0; i < count; i++)
        {
            int existing = FindObject(ObjectFromHandle(temporary[i]));
            if (existing >= 0) ids[i] = s_directory.entries[existing].id;
            else
            {
                for (int j = 0; j < i; j++)
                    if (ObjectFromHandle(temporary[i]) == ObjectFromHandle(temporary[j])) goto cleanup;
                if (s_directory.nextCounter > MaxRetainedObjects) goto cleanup;
                std::memcpy(ids[i].bytes, s_directory.context.run, 16);
                Put32(ids[i].bytes + 16, s_directory.context.localNode);
                std::memcpy(ids[i].bytes + 20, s_directory.context.localInc, 16);
                Put64(ids[i].bytes + 36, s_directory.nextCounter++);
            }
        }

        std::memcpy(output, "DID1", 4);
        output[4] = 1;
        output[5] = static_cast<BYTE>(count);
        output[6] = 0;
        output[7] = 0;
        for (int i = 0; i < count; i++)
        {
            BYTE* record = output + HeaderSize + i * RecordSize;
            std::memcpy(record, ids[i].bytes, IdSize);
            WriteType(record + IdSize, s_directory.nodeType->GetCl());
            Put32(record + IdSize + TypeSize,
                s_directory.fields[0]->GetValue32(ObjectFromHandle(temporary[i])));
            for (int field = 1; field <= 2; field++)
            {
                BYTE* reference = record + IdSize + TypeSize + 4 + (field - 1) * 45;
                OBJECTREF child = s_directory.fields[field]->GetRefValue(ObjectFromHandle(temporary[i]));
                if (child == NULL)
                {
                    reference[0] = 0;
                    std::memset(reference + 1, 0, IdSize);
                    continue;
                }
                reference[0] = 1;
                bool found = false;
                for (int j = 0; j < count; j++)
                    if (ObjectFromHandle(temporary[j]) == child)
                    {
                        std::memcpy(reference + 1, ids[j].bytes, IdSize);
                        found = true;
                        break;
                    }
                if (!found) goto cleanup;
            }
        }

        // Freeze-only profile: retain source objects until process exit; this is physical safety,
        // not a logical-root census or distributed-collection rule.
        for (int i = 0; i < count; i++)
        {
            if (FindId(ids[i]) >= 0) continue;
            // Allocate the weak handle before publishing/accounting this entry.
            OBJECTHANDLE weak = GetAppDomain()->CreateLongWeakHandle(ObjectFromHandle(temporary[i]));
            Entry& entry = s_directory.entries[s_directory.count++];
            entry.id = ids[i];
            entry.owner = s_directory.context.localNode;
            entry.version = 0;
            entry.bytes = baseSize;
            entry.retention = SourceRetention;
            entry.strong = temporary[i].Extract();
            entry.weak = weak;
            s_directory.retainedBytes += baseSize;
        }
        // Conservatively protect every exported representative as an in-flight source;
        // The Thread path retires the exact set after authenticated retained-root readiness.
        // Other test-only exports conservatively hold it until process exit.
        for (int i = 0; i < count; i++)
        {
            Entry& entry = s_directory.entries[FindId(ids[i])];
            entry.retention = static_cast<RetentionRole>(entry.retention | InFlightRetention);
        }
        written = HeaderSize + count * RecordSize;
    } while (false);

cleanup:
    ; // The following GC-protection macro can close the compound statement.
    // Scope-managed temporary handles release on rejection and exception unwinding.
    GCPROTECT_END();
    return written;
}

int ImportGraph(const BYTE* wire, int length, OBJECTREF* result)
{
    if (!OnOwnerThread())
    {
        std::fprintf(stderr, "DC_IDENTITY phase=thread-rejected api=import\n");
        return -1;
    }
    if (s_directory.failed || s_frozen.load(std::memory_order_acquire) || result == nullptr) return -1;
    unsigned count, root;
    if (!ReadFrame(wire, length, count, root)) return -1;

    const BYTE* records[MaxObjects]{};
    ObjectId ids[MaxObjects]{};
    int existing[MaxObjects]{};
    for (unsigned i = 0; i < count; i++)
    {
        records[i] = wire + HeaderSize + i * RecordSize;
        std::memcpy(ids[i].bytes, records[i], IdSize);
        for (unsigned j = 0; j < i; j++)
            if (Equal(ids[i].bytes, ids[j].bytes, IdSize)) return -1;
    }
    for (unsigned i = 0; i < count; i++)
    {
        const BYTE* record = records[i];
        if (!ValidWireIdentity(ids[i]) || !EnsureNodeType(record) ||
            !TypeMatches(record + IdSize, s_directory.nodeType->GetCl())) return -1;
        for (int edge = 0; edge < 2; edge++)
        {
            const BYTE* reference = record + IdSize + TypeSize + 4 + edge * 45;
            if (reference[0] > 1 || (reference[0] == 0 && !IsZero(reference + 1, IdSize)))
                return -1;
            if (reference[0] == 1)
            {
                bool found = false;
                for (unsigned j = 0; j < count; j++)
                    if (Equal(reference + 1, ids[j].bytes, IdSize)) found = true;
                if (!found) return -1;
            }
        }
        existing[i] = FindId(ids[i]);
    }

    bool reachable[MaxObjects]{};
    reachable[root] = true;
    for (unsigned pass = 0; pass < count; pass++)
        for (unsigned i = 0; i < count; i++) if (reachable[i])
            for (int edge = 0; edge < 2; edge++)
            {
                const BYTE* reference = records[i] + IdSize + TypeSize + 4 + edge * 45;
                if (reference[0])
                    for (unsigned j = 0; j < count; j++)
                        if (Equal(reference + 1, ids[j].bytes, IdSize)) reachable[j] = true;
            }

    unsigned newCount = 0;
    for (unsigned i = 0; i < count; i++)
    {
        if (!reachable[i] || (existing[i] < 0 &&
            Get32(ids[i].bytes + 16) == s_directory.context.localNode)) return -1;
        if (existing[i] < 0) newCount++;
    }
    unsigned baseSize = s_directory.nodeType->GetBaseSize();
    if (s_directory.count + newCount > MaxRetainedObjects ||
        s_directory.retainedBytes + static_cast<UINT64>(newCount) * baseSize > MaxRetainedBytes) return -1;

    OBJECTREF objects[MaxObjects];
    for (unsigned i = 0; i < MaxObjects; i++) objects[i] = NULL;
    Wrapper<OBJECTHANDLE, DoNothing<OBJECTHANDLE>, DestroyStrongHandle> handles[MaxObjects];
    int status = -1;
    GCPROTECT_BEGIN(objects);
    EX_TRY
    {
        s_directory.nodeType->EnsureInstanceActive();
        for (unsigned i = 0; i < count; i++)
        {
            if (existing[i] >= 0) objects[i] = ObjectFromHandle(s_directory.entries[existing[i]].strong);
            else
            {
                objects[i] = AllocateObject(s_directory.nodeType);
                handles[i] = GetAppDomain()->CreateStrongHandle(objects[i]);
            }
        }
        bool matches = true;
        for (unsigned i = 0; i < count; i++)
            if (objects[i] == NULL || objects[i]->GetMethodTable() != s_directory.nodeType)
                matches = false;
        for (unsigned i = 0; i < count && matches; i++)
        {
            const BYTE* record = records[i];
            if (existing[i] >= 0 &&
                s_directory.fields[0]->GetValue32(objects[i]) != Get32(record + IdSize + TypeSize))
            {
                matches = false;
                break;
            }
            if (existing[i] < 0)
                s_directory.fields[0]->SetValue32(objects[i], Get32(record + IdSize + TypeSize));
            for (int edge = 0; edge < 2; edge++)
            {
                const BYTE* reference = record + IdSize + TypeSize + 4 + edge * 45;
                OBJECTREF target = NULL;
                if (reference[0])
                    for (unsigned j = 0; j < count; j++)
                        if (Equal(reference + 1, ids[j].bytes, IdSize)) { target = objects[j]; break; }
                if (existing[i] >= 0)
                {
                    if (s_directory.fields[edge + 1]->GetRefValue(objects[i]) != target)
                    {
                        matches = false;
                        break;
                    }
                }
                else
                    s_directory.fields[edge + 1]->SetRefValue(objects[i], target);
            }
        }
        if (matches)
        {
            for (unsigned i = 0; i < count; i++) if (existing[i] < 0)
            {
                OBJECTHANDLE weak = GetAppDomain()->CreateLongWeakHandle(objects[i]);
                Entry& entry = s_directory.entries[s_directory.count++];
                entry.id = ids[i];
                entry.owner = Get32(ids[i].bytes + 16);
                entry.version = 0;
                entry.bytes = baseSize;
                entry.retention = ReceiverRetention;
                entry.strong = handles[i].Extract();
                entry.weak = weak;
                s_directory.retainedBytes += baseSize;
            }
            *result = objects[root];
            status = 0;
        }
    }
    EX_CATCH
    {
        s_directory.failed = true;
        status = -1;
    }
    EX_END_CATCH
    GCPROTECT_END();
    return status;
}

} // namespace

namespace
{
bool IsInt32Array(OBJECTREF object)
{
    if (object == NULL) return false;
    MethodTable* type = object->GetMethodTable();
    return type->IsArray() && !type->IsMultiDimArray() &&
        type->GetArrayElementType() == ELEMENT_TYPE_I4;
}

bool RegisterArray(OBJECTREF object, const ObjectId& id, RetentionRole role, unsigned bytes)
{
    Wrapper<OBJECTHANDLE, DoNothing<OBJECTHANDLE>, DestroyStrongHandle> strong;
    strong = GetAppDomain()->CreateStrongHandle(object);
    OBJECTHANDLE weak = GetAppDomain()->CreateLongWeakHandle(ObjectFromHandle(strong));
    Entry& entry = s_directory.entries[s_directory.count++];
    entry.id = id;
    entry.strong = strong.Extract();
    entry.weak = weak;
    entry.owner = Get32(id.bytes + 16);
    entry.bytes = bytes;
    entry.retention = role;
    s_directory.retainedBytes += bytes;
    return true;
}
}

// DIA1: magic[4], version=1[4 LE], ID[44], length[4 LE], int32 elements[4 LE each].
// The element type is fixed by this profile, never a sender-supplied MethodTable.
int DistributedIdentityExportArray(OBJECTREF array, BYTE* wire, int capacity)
{
    if (!OnOwnerThread() || s_directory.failed || s_frozen.load(std::memory_order_acquire) ||
        !IsInt32Array(array) || wire == nullptr) return -1;
    BASEARRAYREF elements = (BASEARRAYREF)array;
    unsigned length = elements->GetNumComponents();
    if (length > 32 || capacity < static_cast<int>(56 + length * 4)) return -1;
    unsigned bytes = static_cast<unsigned>(elements->GetMethodTable()->GetBaseSize() + length * sizeof(INT32));
    int index = FindObject(array);
    if (index < 0 && (s_directory.count == MaxRetainedObjects ||
        s_directory.nextCounter > MaxRetainedObjects ||
        static_cast<UINT64>(s_directory.retainedBytes) + bytes > MaxRetainedBytes)) return -1;
    ObjectId id{};
    if (index >= 0) id = s_directory.entries[index].id;
    else
    {
        std::memcpy(id.bytes, s_directory.context.run, 16);
        Put32(id.bytes + 16, s_directory.context.localNode);
        std::memcpy(id.bytes + 20, s_directory.context.localInc, 16);
        Put64(id.bytes + 36, s_directory.nextCounter++);
    }
    std::memcpy(wire, "DIA1", 4);
    Put32(wire + 4, 1);
    std::memcpy(wire + 8, id.bytes, IdSize);
    Put32(wire + 52, length);
    const INT32* data = reinterpret_cast<const INT32*>(elements->GetDataPtr());
    for (unsigned i = 0; i < length; i++) Put32(wire + 56 + i * 4, data[i]);
    if (index < 0)
        RegisterArray(array, id, static_cast<RetentionRole>(SourceRetention | InFlightRetention), bytes);
    return 56 + length * 4;
}

bool DistributedIdentityImportArray(const BYTE* wire, int length, OBJECTREF* result)
{
    if (!OnOwnerThread() || s_directory.failed || s_frozen.load(std::memory_order_acquire) ||
        wire == nullptr || result == nullptr || length < 56 || length > 184 ||
        std::memcmp(wire, "DIA1", 4) != 0 || Get32(wire + 4) != 1) return false;
    unsigned count = Get32(wire + 52);
    if (count > 32 || length != static_cast<int>(56 + 4 * count)) return false;
    ObjectId id{};
    std::memcpy(id.bytes, wire + 8, IdSize);
    if (!ValidWireIdentity(id)) return false;
    int existing = FindId(id);
    OBJECTREF object = NULL;
    bool accepted = false;
    GCPROTECT_BEGIN(object);
    if (existing >= 0)
    {
        object = ObjectFromHandle(s_directory.entries[existing].strong);
        if (IsInt32Array(object) && ((BASEARRAYREF)object)->GetNumComponents() == count)
        {
            accepted = true;
            const INT32* data = reinterpret_cast<const INT32*>(((BASEARRAYREF)object)->GetDataPtr());
            for (unsigned i = 0; i < count; i++)
                if (static_cast<UINT32>(data[i]) != Get32(wire + 56 + i * 4)) accepted = false;
        }
    }
    else if (Get32(id.bytes + 16) != s_directory.context.localNode &&
        s_directory.count < MaxRetainedObjects)
    {
        object = AllocatePrimitiveArray(ELEMENT_TYPE_I4, count);
        unsigned bytes = static_cast<unsigned>(object->GetMethodTable()->GetBaseSize() + count * sizeof(INT32));
        if (static_cast<UINT64>(s_directory.retainedBytes) + bytes <= MaxRetainedBytes)
        {
            INT32* data = reinterpret_cast<INT32*>(((BASEARRAYREF)object)->GetDataPtr());
            for (unsigned i = 0; i < count; i++) data[i] = static_cast<INT32>(Get32(wire + 56 + i * 4));
            accepted = RegisterArray(object, id, ReceiverRetention, bytes);
        }
    }
    if (accepted) *result = object;
    GCPROTECT_END();
    return accepted;
}

bool DistributedIdentityImportAccessGraph(const BYTE* wire, int length, OBJECTREF* result)
{
    return ImportGraph(wire, length, result) == 0;
}

bool DistributedIdentityFreeze(DistributedAccessSeed* seeds, unsigned* count)
{
    if (!OnOwnerThread() || s_directory.failed || seeds == nullptr || count == nullptr ||
        s_frozen.load(std::memory_order_acquire) || s_directory.count == 0) return false;
    for (unsigned i = 0; i < s_directory.count; i++)
    {
        DistributedAccessSeed& seed = seeds[i];
        seed = {};
        seed.id = s_directory.entries[i].id;
        OBJECTREF object = ObjectFromHandle(s_directory.entries[i].strong);
        if (object == NULL || ObjectFromHandle(s_directory.entries[i].weak) != object) return false;
        if (IsInt32Array(object))
        {
            seed.kind = 1;
            seed.length = ((BASEARRAYREF)object)->GetNumComponents();
            if (seed.length > 32) return false;
            const INT32* data = reinterpret_cast<const INT32*>(((BASEARRAYREF)object)->GetDataPtr());
            for (unsigned j = 0; j < seed.length; j++) seed.values[j] = data[j];
        }
        else
        {
            if (object->GetMethodTable() != s_directory.nodeType) return false;
            seed.values[0] = s_directory.fields[0]->GetValue32(object);
            for (unsigned j = 0; j < 2; j++)
            {
                OBJECTREF value = s_directory.fields[j + 1]->GetRefValue(object);
                if (value == NULL) continue;
                int target = FindObject(value);
                if (target < 0 || value->GetMethodTable() != s_directory.nodeType) return false;
                seed.references[j] = s_directory.entries[target].id;
            }
        }
    }
    *count = s_directory.count;
    s_frozen.store(true, std::memory_order_release);
    return true;
}

bool DistributedIdentityHandoffThreadOwner(Thread* next)
{
    // The prepared CLR Thread exists, but its OS thread has not been created. No GC,
    // allocation, managed callback, lock or transport wait is permitted in this handoff.
    Thread* current = GetThread();
    if (!DistributedAdmissionIsThreadProbe() || !OnOwnerThread() || s_directory.failed ||
        !s_frozen.load(std::memory_order_acquire) || s_directory.context.localNode != 2 ||
        s_directory.context.peerNode != 1 || next == nullptr || next == current ||
        !next->HasThreadState(Thread::TS_Unstarted))
        return false;
    bool notHandedOff = false;
    if (!s_ownerHandedOff.compare_exchange_strong(notHandedOff, true, std::memory_order_acq_rel))
        return false;
    // Failure is terminal for this handoff. Never reset the claim or restore ownership.
    s_workerStagingThread.store(current, std::memory_order_release);
    return s_directory.ownerThread.compare_exchange_strong(current, next, std::memory_order_acq_rel);
}

bool DistributedIdentityAccessCaller() { return OnOwnerThread() && !s_directory.failed; }
bool DistributedIdentityPublicationFinishCaller()
{
    // Permit only the publication coordinator to serialize an aborted diagnostic history.
    // This is intentionally not an access capability and never clears the failure latch.
    return OnOwnerThread() && s_frozen.load(std::memory_order_acquire) &&
        s_directory.context.localNode == 1 && DistributedAdmissionIsPublicationProbe();
}
unsigned DistributedIdentityLocalNode() { return s_directory.context.localNode; }
bool DistributedIdentityIsFrozen() { return s_frozen.load(std::memory_order_acquire); }

// -3 array bounds, -2 invalid capability/type, -1 unregistered local object, otherwise shared entry.
// Owner-only bootstrap may access unregistered objects before promotion. After freeze, DC-012
// may append a fully staged publication batch on the same owner thread; earlier entries remain
// immutable. No other caller thread or graph/network API is admitted by this lookup.
int DistributedIdentityAccessTarget(OBJECTREF target, UINT_PTR location, bool array,
    DistributedObjectId* id, unsigned* slot)
{
    if (!DistributedIdentityAccessCaller() || target == NULL || id == nullptr || slot == nullptr) return -2;
    int result = -2;
    GCPROTECT_BEGIN(target);
    bool valid = false;
    if (array)
    {
        valid = IsInt32Array(target);
        if (valid && location >= ((BASEARRAYREF)target)->GetNumComponents())
        {
            result = -3;
            valid = false;
        }
        if (valid) *slot = static_cast<unsigned>(location);
    }
    else
    {
        valid = s_directory.nodeType != nullptr
            ? target->GetMethodTable() == s_directory.nodeType : ValidateType(target->GetMethodTable());
        if (valid)
        {
            valid = false;
            for (unsigned i = 0; i < 3; i++)
                if (reinterpret_cast<UINT_PTR>(s_directory.fields[i]) == location)
                {
                    *slot = i;
                    valid = true;
                }
        }
    }
    if (valid)
    {
        // Owner-thread publication may append a complete batch after freeze; existing entries
        // remain immutable and no other caller thread can observe the table concurrently.
        bool frozen = s_frozen.load(std::memory_order_acquire);
        result = FindObject(target);
        if (result >= 0)
        {
            if (!frozen) result = -2;
            else *id = s_directory.entries[result].id;
        }
    }
    GCPROTECT_END();
    return result;
}

bool DistributedIdentityAccessReference(OBJECTREF value, DistributedObjectId* id)
{
    if (!DistributedIdentityAccessCaller() || id == nullptr) return false;
    *id = {};
    if (value == NULL) return true;
    if (!s_frozen.load(std::memory_order_acquire) || value->GetMethodTable() != s_directory.nodeType) return false;
    int index = FindObject(value);
    if (index < 0) return false;
    *id = s_directory.entries[index].id;
    return true;
}

bool DistributedIdentityResolveReference(const DistributedObjectId& id, OBJECTREF* result)
{
    if (!DistributedIdentityAccessCaller() || !s_frozen.load(std::memory_order_acquire) || result == nullptr)
        return false;
    *result = NULL;
    if (IsZero(id.bytes, IdSize)) return true;
    int index = FindId(id);
    if (index < 0) return false;
    OBJECTREF object = ObjectFromHandle(s_directory.entries[index].strong);
    if (object == NULL || object->GetMethodTable() != s_directory.nodeType ||
        ObjectFromHandle(s_directory.entries[index].weak) != object) return false;
    *result = object;
    return true;
}

bool DistributedIdentityInitialize(Assembly* assembly, const DistributedIdentityContext& context)
{
    GCX_COOP();
    if (s_directory.initialized || assembly == nullptr || assembly->IsDynamic() || assembly->IsCollectible() ||
        context.localNode == context.peerNode || assembly->GetModule() == nullptr ||
        IsZero(context.run, 16) || IsZero(context.localInc, 16) || IsZero(context.peerInc, 16) ||
        IsZero(context.assemblyHash, 32) || IsZero(context.mvid, 16)) return false;

    bool initialized = false;
    EX_TRY
    {
        Module* module = assembly->GetModule();
        bool multiModule = module->GetMDImport()->GetCountWithTokenKind(mdtFile) != 0;
        MethodTable* global = module->GetGlobalMethodTable();
        if (multiModule)
            std::fprintf(stderr, "DC_IDENTITY phase=init-rejected reason=multimodule\n");
        else if (global != nullptr && global->HasClassConstructor())
            std::fprintf(stderr, "DC_IDENTITY phase=init-rejected reason=module-initializer\n");
        else
        {
            GUID mvid{};
            if (SUCCEEDED(module->GetMDImport()->GetScopeProps(nullptr, &mvid)) &&
                Equal(reinterpret_cast<const BYTE*>(&mvid), context.mvid, 16))
            {
                s_directory.assembly = assembly;
                s_directory.module = module;
                s_directory.ownerThread = GetThread();
                s_directory.context = context;
                s_directory.nextCounter = 1;
                s_directory.initialized = true;
                initialized = true;
            }
        }
    }
    EX_CATCH
    {
        initialized = false;
    }
    EX_END_CATCH
    if (!initialized)
        std::fprintf(stderr, "DC_IDENTITY phase=init-rejected reason=profile-or-metadata\n");
    return initialized;
}

extern "C" int DistributedIdentityExportForTest(OBJECTREF root, BYTE* buffer, int capacity)
{
    int status = -1;
    EX_TRY { status = ExportGraph(root, buffer, capacity); }
    EX_CATCH { s_directory.failed = true; status = -1; }
    EX_END_CATCH
    return status;
}

extern "C" int DistributedIdentityImportForTest(const BYTE* wire, int length, QCall::ObjectHandleOnStack result)
{
    OBJECTREF imported = NULL;
    int status = -1;
    GCPROTECT_BEGIN(imported);
    EX_TRY
    {
        status = ImportGraph(wire, length, &imported);
        if (status == 0) result.Set(imported);
    }
    EX_CATCH
    {
        s_directory.failed = true;
        status = -1;
    }
    EX_END_CATCH
    GCPROTECT_END();
    return status;
}

int DistributedIdentityProcessGraph(const unsigned char* wire, int length, unsigned char* reply, int capacity)
{
    int written = -1;
    unsigned count = 0;
    bool moved = false;
    unsigned retained = 0;
    unsigned bytes = 0;
    {
        GCX_COOP();
        if (!OnOwnerThread())
        {
            std::fprintf(stderr, "DC_IDENTITY phase=thread-rejected api=process\n");
            return -1;
        }
        if (wire == nullptr || reply == nullptr || length <= 0) return -1;
        EX_TRY
        {
            OBJECTREF first = NULL, second = NULL;
            GCPROTECT_BEGIN(first);
            GCPROTECT_BEGIN(second);
            if (ImportGraph(wire, length, &first) != 0 ||
                ImportGraph(wire, length, &second) != 0 || first != second)
                s_directory.failed = true;
            else
            {
                UINT_PTR before = reinterpret_cast<UINT_PTR>(OBJECTREFToObject(first));
                GCHeapUtilities::GetGCHeap()->GarbageCollect(
                    2, false, collection_compacting | collection_blocking);
                moved = before != reinterpret_cast<UINT_PTR>(OBJECTREFToObject(first));
                // Transfer roots remain process-lifetime retained because DC-010 has no terminal cut.
                written = ExportGraph(first, reply, capacity);
                if (written >= 0)
                {
                    count = static_cast<unsigned>((written - HeaderSize) / RecordSize);
                    for (unsigned i = 0; i < count; i++)
                    {
                        ObjectId id{};
                        std::memcpy(id.bytes, reply + HeaderSize + i * RecordSize, IdSize);
                        int index = FindId(id);
                        if (index >= 0) s_directory.entries[index].retention = static_cast<RetentionRole>(s_directory.entries[index].retention | InFlightRetention);
                    }
                    retained = s_directory.count;
                    bytes = s_directory.retainedBytes;
                }
                else s_directory.failed = true;
            }
            GCPROTECT_END();
            GCPROTECT_END();
        }
        EX_CATCH
        {
            s_directory.failed = true;
            written = -1;
        }
        EX_END_CATCH
    }
    if (written >= 0)
        std::fprintf(stderr, "DC_IDENTITY phase=resolved count=%u gc_moved=%u retained=%u bytes=%u\n",
            count, moved ? 1u : 0u, retained, bytes);
    return written;
}


namespace
{
constexpr unsigned PublicationHeaderSize = 76;
constexpr unsigned PublicationMaxFrameSize = PublicationHeaderSize +
    DistributedPublicationMaxObjects * RecordSize;
enum class PublicationPhase : BYTE { Idle, Prepared, Activated };
struct PendingPublicationNode
{
    ObjectId id{};
    OBJECTHANDLE strong{};
    OBJECTHANDLE weak{};
    unsigned bytes{};
};
struct PendingPublication
{
    PublicationPhase phase{PublicationPhase::Idle};
    UINT64 transaction{};
    UINT64 sourceFrontier{};
    unsigned count{};
    unsigned bytes{};
    ObjectId root{};
    PendingPublicationNode nodes[DistributedPublicationMaxObjects]{};
};
PendingPublication s_publication{};
UINT64 s_lastSourcePublicationTransaction{};
UINT64 s_lastImportedPublicationTransaction{};
std::atomic<unsigned> s_pendingPublicationRootCount{0};
bool s_initialThreadTransferCompleted = false; // Source-owner-only, one-way readiness cut.

bool PublicationCaller(unsigned localNode)
{
    return OnOwnerThread() && !s_directory.failed && s_frozen.load(std::memory_order_acquire) &&
        DistributedAdmissionIsPublicationProbe() && s_directory.context.localNode == localNode &&
        s_directory.context.peerNode == (localNode == 1 ? 2u : 1u);
}

bool CanonicalNode(const ObjectId& id, OBJECTREF* result)
{
    int index = FindId(id);
    if (index < 0) return false;
    Entry& entry = s_directory.entries[index];
    OBJECTREF object = ObjectFromHandle(entry.strong);
    if (object == NULL || object->GetMethodTable() != s_directory.nodeType ||
        ObjectFromHandle(entry.weak) != object) return false;
    if (result != nullptr) *result = object;
    return true;
}

int FindPublicationRecord(const ObjectId& id, const ObjectId* ids, unsigned count)
{
    for (unsigned i = 0; i < count; i++)
        if (Equal(id.bytes, ids[i].bytes, IdSize)) return static_cast<int>(i);
    return -1;
}

void ForceCompactingCollection()
{
    GCHeapUtilities::GetGCHeap()->GarbageCollect(
        2, false, collection_compacting | collection_blocking);
}

unsigned CollectionDelta(unsigned before, unsigned after)
{
    return after >= before ? after - before : 0;
}

bool ReadPublicationHeader(const BYTE* wire, unsigned length, UINT64& transaction,
    UINT64& sourceFrontier, unsigned& count, ObjectId& root)
{
    if (wire == nullptr || length < PublicationHeaderSize || length > PublicationMaxFrameSize ||
        std::memcmp(wire, "DGP1", 4) != 0 || Get32(wire + 4) != 1 || Get32(wire + 28) != 0)
        return false;
    transaction = Get64(wire + 8);
    sourceFrontier = Get64(wire + 16);
    count = Get32(wire + 24);
    if (transaction == 0 || transaction > MaxRetainedObjects || sourceFrontier > 2048 ||
        count == 0 || count > DistributedPublicationMaxObjects ||
        length != PublicationHeaderSize + count * RecordSize)
        return false;
    std::memcpy(root.bytes, wire + 32, IdSize);
    return true;
}

void FillPublicationSeed(DistributedAccessSeed& seed, const BYTE* record)
{
    seed = {};
    std::memcpy(seed.id.bytes, record, IdSize);
    seed.kind = 0;
    seed.length = 0;
    seed.values[0] = Get32(record + IdSize + TypeSize);
    for (unsigned edge = 0; edge < 2; edge++)
    {
        const BYTE* encoded = record + IdSize + TypeSize + 4 + edge * 45;
        if (encoded[0] == 1)
            std::memcpy(seed.references[edge].bytes, encoded + 1, IdSize);
    }
}

void CollectStagedPublicationRoots(OBJECTREF* objects,
    Wrapper<OBJECTHANDLE, DoNothing<OBJECTHANDLE>, DestroyStrongHandle>* strong,
    unsigned count, unsigned& collections, bool& moved)
{
    UINT_PTR before[DistributedPublicationMaxObjects]{};
    for (unsigned i = 0; i < count; i++)
    {
        before[i] = reinterpret_cast<UINT_PTR>(OBJECTREFToObject(objects[i]));
        // Transfer handles independently root each staged node; source graph references can
        // also retain them, while receiver slots are intentionally cleared before fixup.
        objects[i] = NULL;
    }
    unsigned gcBefore = GCHeapUtilities::GetGCHeap()->GetGcCount();
    ForceCompactingCollection();
    unsigned gcAfter = GCHeapUtilities::GetGCHeap()->GetGcCount();
    collections += CollectionDelta(gcBefore, gcAfter);
    for (unsigned i = 0; i < count; i++)
    {
        objects[i] = ObjectFromHandle(strong[i]);
        if (before[i] != reinterpret_cast<UINT_PTR>(OBJECTREFToObject(objects[i]))) moved = true;
    }
}
}

namespace
{

ObjectId MakePublicationId(UINT node, const BYTE* incarnation, UINT64 counter)
{
    ObjectId id{};
    std::memcpy(id.bytes, s_directory.context.run, 16);
    Put32(id.bytes + 16, node);
    std::memcpy(id.bytes + 20, incarnation, 16);
    Put64(id.bytes + 36, counter);
    return id;
}

bool IsNullPublicationReference(const BYTE* ref)
{
    return ref[0] == 0 && IsZero(ref + 1, IdSize);
}

bool PublicationRole(unsigned node)
{
    return PublicationCaller(node);
}
}

bool DistributedIdentityPreparePublication(OBJECTREF root, UINT64 transaction, UINT64 sourceFrontier,
    BYTE* wire, unsigned capacity, unsigned* length, DistributedPublicationBatch* batch)
{
    GCX_COOP();
    if (!OnOwnerThread())
    {
        std::fprintf(stderr, "DC_PUBLICATION phase=thread-rejected api=prepare\n");
        return false;
    }
    if (!PublicationRole(1) || root == NULL || transaction == 0 || wire == nullptr ||
        length == nullptr || batch == nullptr || s_publication.phase != PublicationPhase::Idle ||
        transaction > MaxRetainedObjects || transaction <= s_lastSourcePublicationTransaction)
        return false;

    OBJECTREF roots[DistributedPublicationMaxObjects];
    for (unsigned i = 0; i < DistributedPublicationMaxObjects; i++) roots[i] = NULL;
    Wrapper<OBJECTHANDLE, DoNothing<OBJECTHANDLE>, DestroyStrongHandle> strong[DistributedPublicationMaxObjects];
    Wrapper<OBJECTHANDLE, DoNothing<OBJECTHANDLE>, DestroyLongWeakHandle> weak[DistributedPublicationMaxObjects];
    ObjectId ids[DistributedPublicationMaxObjects]{};
    DistributedPublicationBatch prepared{};
    unsigned count = 0;
    unsigned gcCollections = 0;
    bool moved = false;
    bool success = false;
    GCPROTECT_BEGIN(roots);
    EX_TRY
    {
        UINT_PTR initialRootAddress = 0;
        unsigned before = 0;
        unsigned baseSize = 0;
        if (s_directory.failed || !s_frozen.load(std::memory_order_acquire) ||
            FindObject(root) >= 0)
            goto prepare_done;

        roots[count++] = root;
        if (!ValidateType(roots[0]->GetMethodTable()))
            goto prepare_done;
        initialRootAddress = reinterpret_cast<UINT_PTR>(OBJECTREFToObject(roots[0]));
        before = GCHeapUtilities::GetGCHeap()->GetGcCount();
        ForceCompactingCollection();
        gcCollections += CollectionDelta(before, GCHeapUtilities::GetGCHeap()->GetGcCount());
        if (roots[0] == NULL || roots[0]->GetMethodTable() != s_directory.nodeType)
            goto prepare_done;
        if (initialRootAddress != reinterpret_cast<UINT_PTR>(OBJECTREFToObject(roots[0])))
            moved = true;
        s_directory.nodeType->EnsureInstanceActive();

        for (unsigned cursor = 0; cursor < count; cursor++)
        {
            OBJECTREF current = roots[cursor];
            for (unsigned edge = 0; edge < 2; edge++)
            {
                OBJECTREF child = s_directory.fields[edge + 1]->GetRefValue(current);
                if (child == NULL) continue;
                if (child->GetMethodTable() != s_directory.nodeType)
                    goto prepare_done;
                if (FindObject(child) >= 0) continue;
                bool found = false;
                for (unsigned i = 0; i < count; i++)
                    if (roots[i] == child) { found = true; break; }
                if (!found)
                {
                    if (count == DistributedPublicationMaxObjects)
                        goto prepare_done;
                    roots[count++] = child;
                }
            }
        }

        baseSize = s_directory.nodeType->GetBaseSize();
        if (s_directory.count + count > MaxRetainedObjects ||
            static_cast<UINT64>(s_directory.retainedBytes) +
                static_cast<UINT64>(count) * baseSize > MaxRetainedBytes ||
            capacity < PublicationHeaderSize + count * RecordSize ||
            s_directory.nextCounter == 0 ||
            s_directory.nextCounter + count - 1 > MaxRetainedObjects)
            goto prepare_done;

        // Consume IDs even if later handle allocation fails. An aborted run never reuses them.
        for (unsigned i = 0; i < count; i++)
            ids[i] = MakePublicationId(s_directory.context.localNode,
                s_directory.context.localInc, s_directory.nextCounter++);
        for (unsigned i = 0; i < count; i++)
        {
            strong[i] = GetAppDomain()->CreateStrongHandle(roots[i]);
            weak[i] = GetAppDomain()->CreateLongWeakHandle(roots[i]);
        }
        CollectStagedPublicationRoots(roots, strong, count, gcCollections, moved);

        std::memcpy(wire, "DGP1", 4);
        Put32(wire + 4, 1);
        Put64(wire + 8, transaction);
        Put64(wire + 16, sourceFrontier);
        Put32(wire + 24, count);
        Put32(wire + 28, 0);
        std::memcpy(wire + 32, ids[0].bytes, IdSize);
        for (unsigned i = 0; i < count; i++)
        {
            BYTE* record = wire + PublicationHeaderSize + i * RecordSize;
            std::memset(record, 0, RecordSize);
            std::memcpy(record, ids[i].bytes, IdSize);
            WriteType(record + IdSize, s_directory.nodeType->GetCl());
            Put32(record + IdSize + TypeSize,
                s_directory.fields[0]->GetValue32(ObjectFromHandle(strong[i])));
            for (unsigned edge = 0; edge < 2; edge++)
            {
                BYTE* encoded = record + IdSize + TypeSize + 4 + edge * 45;
                OBJECTREF child = s_directory.fields[edge + 1]->GetRefValue(ObjectFromHandle(strong[i]));
                if (child == NULL) continue; // Canonical zero marker and zero ID from memset.
                encoded[0] = 1;
                int existing = FindObject(child);
                if (existing >= 0)
                {
                    std::memcpy(encoded + 1, s_directory.entries[existing].id.bytes, IdSize);
                    continue;
                }
                bool found = false;
                for (unsigned j = 0; j < count; j++)
                    if (ObjectFromHandle(strong[j]) == child)
                    {
                        std::memcpy(encoded + 1, ids[j].bytes, IdSize);
                        found = true;
                        break;
                    }
                if (!found) goto prepare_done;
            }
        }

        prepared.transaction = transaction;
        prepared.sourceFrontier = sourceFrontier;
        prepared.count = count;
        prepared.root = ids[0];
        prepared.gcCollections = gcCollections;
        prepared.moved = moved ? 1u : 0u;
        prepared.stagedTransferRoots = count;
        for (unsigned i = 0; i < count; i++)
        {
            FillPublicationSeed(prepared.seeds[i], wire + PublicationHeaderSize + i * RecordSize);
            s_publication.nodes[i].id = ids[i];
            s_publication.nodes[i].bytes = baseSize;
            s_publication.nodes[i].strong = strong[i].Extract();
            s_publication.nodes[i].weak = weak[i].Extract();
        }
        s_publication.transaction = transaction;
        s_publication.sourceFrontier = sourceFrontier;
        s_publication.count = count;
        s_publication.bytes = count * baseSize;
        s_publication.root = ids[0];
        s_publication.phase = PublicationPhase::Prepared;
        s_lastSourcePublicationTransaction = transaction;
        s_pendingPublicationRootCount.store(count, std::memory_order_release);
        *batch = prepared;
        *length = PublicationHeaderSize + count * RecordSize;
        success = true;
prepare_done:
        ;
    }
    EX_CATCH
    {
        s_directory.failed = true;
        success = false;
    }
    EX_END_CATCH
    GCPROTECT_END();
    if (!success)
    {
        s_directory.failed = true;
        return false;
    }
    std::fprintf(stderr, "DC_PUBLICATION phase=source-prepared tx=%llu count=%u gc=%u moved=%u roots=%u bytes=%u\n",
        static_cast<unsigned long long>(prepared.transaction), prepared.count,
        prepared.gcCollections, prepared.moved, prepared.stagedTransferRoots,
        s_publication.bytes);
    return true;
}

bool DistributedIdentityImportPublication(const BYTE* wire, unsigned length, DistributedPublicationBatch* batch)
{
    GCX_COOP();
    if (!OnOwnerThread())
    {
        std::fprintf(stderr, "DC_PUBLICATION phase=thread-rejected api=import\n");
        return false;
    }
    if (!PublicationRole(2) || wire == nullptr || batch == nullptr ||
        s_publication.phase != PublicationPhase::Idle || s_directory.failed ||
        !s_frozen.load(std::memory_order_acquire))
        return false;

    UINT64 transaction = 0, sourceFrontier = 0;
    unsigned count = 0;
    ObjectId root{};
    if (!ReadPublicationHeader(wire, length, transaction, sourceFrontier, count, root))
    {
        s_directory.failed = true;
        return false;
    }
    if (transaction <= s_lastImportedPublicationTransaction)
    {
        s_directory.failed = true;
        return false;
    }

    const BYTE* records[DistributedPublicationMaxObjects]{};
    ObjectId ids[DistributedPublicationMaxObjects]{};
    unsigned baseSize = 0;
    for (unsigned i = 0; i < count; i++)
    {
        records[i] = wire + PublicationHeaderSize + i * RecordSize;
        std::memcpy(ids[i].bytes, records[i], IdSize);
        if (FindId(ids[i]) >= 0 || Get32(ids[i].bytes + 16) != s_directory.context.peerNode ||
            !ValidWireIdentity(ids[i]) || !EnsureNodeType(records[i]) ||
            !TypeMatches(records[i] + IdSize, s_directory.nodeType->GetCl()))
        {
            s_directory.failed = true;
            return false;
        }
        for (unsigned j = 0; j < i; j++)
            if (Equal(ids[i].bytes, ids[j].bytes, IdSize))
            {
                s_directory.failed = true;
                return false;
            }
    }
    if (FindPublicationRecord(root, ids, count) < 0)
    {
        s_directory.failed = true;
        return false;
    }

    bool reachable[DistributedPublicationMaxObjects]{};
    unsigned rootIndex = static_cast<unsigned>(FindPublicationRecord(root, ids, count));
    reachable[rootIndex] = true;
    for (unsigned pass = 0; pass < count; pass++)
    {
        for (unsigned i = 0; i < count; i++)
        {
            if (!reachable[i]) continue;
            for (unsigned edge = 0; edge < 2; edge++)
            {
                const BYTE* encoded = records[i] + IdSize + TypeSize + 4 + edge * 45;
                if (encoded[0] > 1 || (encoded[0] == 0 && !IsNullPublicationReference(encoded)))
                {
                    s_directory.failed = true;
                    return false;
                }
                if (encoded[0] == 0) continue;
                ObjectId ref{};
                std::memcpy(ref.bytes, encoded + 1, IdSize);
                int internal = FindPublicationRecord(ref, ids, count);
                if (internal >= 0) reachable[internal] = true;
                else if (!CanonicalNode(ref, nullptr))
                {
                    s_directory.failed = true;
                    return false;
                }
            }
        }
    }
    for (unsigned i = 0; i < count; i++)
        if (!reachable[i])
        {
            s_directory.failed = true;
            return false;
        }

    baseSize = s_directory.nodeType->GetBaseSize();
    if (s_directory.count + count > MaxRetainedObjects ||
        static_cast<UINT64>(s_directory.retainedBytes) +
            static_cast<UINT64>(count) * baseSize > MaxRetainedBytes)
    {
        s_directory.failed = true;
        return false;
    }

    OBJECTREF objects[DistributedPublicationMaxObjects];
    for (unsigned i = 0; i < DistributedPublicationMaxObjects; i++) objects[i] = NULL;
    Wrapper<OBJECTHANDLE, DoNothing<OBJECTHANDLE>, DestroyStrongHandle> strong[DistributedPublicationMaxObjects];
    Wrapper<OBJECTHANDLE, DoNothing<OBJECTHANDLE>, DestroyLongWeakHandle> weak[DistributedPublicationMaxObjects];
    DistributedPublicationBatch imported{};
    unsigned gcCollections = 0;
    bool moved = false;
    bool success = false;
    GCPROTECT_BEGIN(objects);
    EX_TRY
    {
        unsigned start = 0;
        unsigned gcBefore = 0;
        UINT_PTR before[DistributedPublicationMaxObjects]{};
        s_directory.nodeType->EnsureInstanceActive();
        for (unsigned i = 0; i < count; i++)
        {
            objects[i] = AllocateObject(s_directory.nodeType);
            strong[i] = GetAppDomain()->CreateStrongHandle(objects[i]);
            weak[i] = GetAppDomain()->CreateLongWeakHandle(objects[i]);
        }
        CollectStagedPublicationRoots(objects, strong, count, gcCollections, moved);

        // Preallocated transfer handles alone retain these not-yet-wired representatives;
        // the directory table is not published until fixup and verification complete.
        for (unsigned i = 0; i < count; i++)
            if (objects[i] == NULL || objects[i]->GetMethodTable() != s_directory.nodeType)
                goto import_done;

        for (unsigned i = 0; i < count; i++)
        {
            const BYTE* record = records[i];
            s_directory.fields[0]->SetValue32(objects[i], Get32(record + IdSize + TypeSize));
            for (unsigned edge = 0; edge < 2; edge++)
            {
                const BYTE* encoded = record + IdSize + TypeSize + 4 + edge * 45;
                OBJECTREF target = NULL;
                if (encoded[0] == 1)
                {
                    ObjectId ref{};
                    std::memcpy(ref.bytes, encoded + 1, IdSize);
                    int internal = FindPublicationRecord(ref, ids, count);
                    if (internal >= 0) target = objects[internal];
                    else if (!CanonicalNode(ref, &target))
                        goto import_done;
                }
                s_directory.fields[edge + 1]->SetRefValue(objects[i], target);
            }
        }

        for (unsigned i = 0; i < count; i++)
        {
            if (objects[i] == NULL || objects[i]->GetMethodTable() != s_directory.nodeType)
                goto import_done;
            for (unsigned edge = 0; edge < 2; edge++)
            {
                const BYTE* encoded = records[i] + IdSize + TypeSize + 4 + edge * 45;
                OBJECTREF expected = NULL;
                if (encoded[0] == 1)
                {
                    ObjectId ref{};
                    std::memcpy(ref.bytes, encoded + 1, IdSize);
                    int internal = FindPublicationRecord(ref, ids, count);
                    if (internal >= 0) expected = objects[internal];
                    else if (!CanonicalNode(ref, &expected))
                        goto import_done;
                }
                if (s_directory.fields[edge + 1]->GetRefValue(objects[i]) != expected)
                    goto import_done;
            }
        }

        // Commit the whole new set with one count publication. On failure before this point,
        // Wrapper cleanup drops temporary handles and no canonical ID can resolve.
        if (s_directory.count + count > MaxRetainedObjects)
            goto import_done;
        start = s_directory.count;
        for (unsigned i = 0; i < count; i++)
        {
            Entry& entry = s_directory.entries[start + i];
            entry.id = ids[i];
            entry.owner = s_directory.context.peerNode;
            entry.version = 0;
            entry.bytes = baseSize;
            entry.retention = ReceiverRetention;
            entry.strong = strong[i].Extract();
            entry.weak = weak[i].Extract();
        }
        s_directory.retainedBytes += count * baseSize;
        s_directory.count = start + count;

        // Verify installed canonical representatives across another real collection.
        for (unsigned i = 0; i < count; i++)
            before[i] = reinterpret_cast<UINT_PTR>(OBJECTREFToObject(ObjectFromHandle(
                s_directory.entries[start + i].strong)));
        // Drop transient slots: only the installed canonical strong handles retain these nodes.
        for (unsigned i = 0; i < count; i++) objects[i] = NULL;
        gcBefore = GCHeapUtilities::GetGCHeap()->GetGcCount();
        ForceCompactingCollection();
        gcCollections += CollectionDelta(gcBefore, GCHeapUtilities::GetGCHeap()->GetGcCount());
        for (unsigned i = 0; i < count; i++)
        {
            OBJECTREF object = ObjectFromHandle(s_directory.entries[start + i].strong);
            if (object == NULL || object->GetMethodTable() != s_directory.nodeType ||
                ObjectFromHandle(s_directory.entries[start + i].weak) != object)
                goto import_done;
            if (before[i] != reinterpret_cast<UINT_PTR>(OBJECTREFToObject(object))) moved = true;

            for (unsigned edge = 0; edge < 2; edge++)
            {
                const BYTE* encoded = records[i] + IdSize + TypeSize + 4 + edge * 45;
                OBJECTREF expected = NULL;
                if (encoded[0] == 1)
                {
                    ObjectId ref{};
                    std::memcpy(ref.bytes, encoded + 1, IdSize);
                    int target = FindId(ref);
                    if (target < 0) goto import_done;
                    expected = ObjectFromHandle(s_directory.entries[target].strong);
                }
                if (s_directory.fields[edge + 1]->GetRefValue(object) != expected)
                    goto import_done;
            }
        }

        imported.transaction = transaction;
        imported.sourceFrontier = sourceFrontier;
        imported.count = count;
        imported.root = root;
        imported.gcCollections = gcCollections;
        imported.moved = moved ? 1u : 0u;
        imported.stagedTransferRoots = count;
        for (unsigned i = 0; i < count; i++)
            FillPublicationSeed(imported.seeds[i], records[i]);
        s_lastImportedPublicationTransaction = transaction;
        *batch = imported;
        success = true;
import_done:
        ;
    }
    EX_CATCH
    {
        s_directory.failed = true;
        success = false;
    }
    EX_END_CATCH
    GCPROTECT_END();
    if (!success)
    {
        // If entries were already installed, keep their handles and permanently fail closed.
        s_directory.failed = true;
        return false;
    }
    std::fprintf(stderr, "DC_PUBLICATION phase=receiver-installed tx=%llu count=%u gc=%u moved=%u roots=%u bytes=%u\n",
        static_cast<unsigned long long>(imported.transaction), imported.count,
        imported.gcCollections, imported.moved, imported.stagedTransferRoots,
        count * baseSize);
    return true;
}

bool DistributedIdentityActivatePublication(UINT64 transaction)
{
    if (!OnOwnerThread())
    {
        std::fprintf(stderr, "DC_PUBLICATION phase=thread-rejected api=activate\n");
        return false;
    }
    if (!PublicationRole(1) || transaction == 0)
        return false;
    if (s_publication.phase == PublicationPhase::Activated &&
        s_publication.transaction == transaction) return true;
    if (s_publication.phase != PublicationPhase::Prepared ||
        s_publication.transaction != transaction || s_directory.failed ||
        s_directory.count + s_publication.count > MaxRetainedObjects ||
        static_cast<UINT64>(s_directory.retainedBytes) + s_publication.bytes > MaxRetainedBytes)
    {
        s_directory.failed = true;
        return false;
    }

    unsigned start = s_directory.count;
    for (unsigned i = 0; i < s_publication.count; i++)
    {
        PendingPublicationNode& pending = s_publication.nodes[i];
        if (pending.strong == nullptr || pending.weak == nullptr ||
            FindId(pending.id) >= 0)
        {
            s_directory.failed = true;
            return false;
        }
    }
    for (unsigned i = 0; i < s_publication.count; i++)
    {
        PendingPublicationNode& pending = s_publication.nodes[i];
        Entry& entry = s_directory.entries[start + i];
        entry.id = pending.id;
        entry.owner = s_directory.context.localNode;
        entry.version = 0;
        entry.bytes = pending.bytes;
        entry.retention = static_cast<RetentionRole>(SourceRetention | InFlightRetention);
        entry.strong = pending.strong;
        entry.weak = pending.weak;
        pending.strong = nullptr;
        pending.weak = nullptr;
    }
    s_directory.retainedBytes += s_publication.bytes;
    s_directory.count = start + s_publication.count;
    s_publication.phase = PublicationPhase::Activated;
    return true;
}

bool DistributedIdentityCompleteInitialThreadTransfer(const DistributedAccessSeed* seeds, unsigned count)
{
    if (!OnOwnerThread() || !DistributedAdmissionIsThreadProbe() || s_directory.failed ||
        !s_frozen.load(std::memory_order_acquire) || s_directory.context.localNode != 1 ||
        s_directory.context.peerNode != 2 || s_initialThreadTransferCompleted ||
        seeds == nullptr || count == 0 || count > static_cast<unsigned>(MaxObjects) ||
        count != s_directory.count || s_publication.phase != PublicationPhase::Idle ||
        s_lastSourcePublicationTransaction != 0 || s_lastImportedPublicationTransaction != 0 ||
        s_pendingPublicationRootCount.load(std::memory_order_acquire) != 0)
        return false;

    // The caller has authenticated DTR1 and checked its digest/count against these frozen
    // seeds. Validate the complete bijection before changing any obligation. No allocation,
    // GC, network wait or handle release occurs here; the owner is still in cooperative mode.
    bool seen[MaxObjects]{};
    for (unsigned i = 0; i < count; i++)
    {
        const ObjectId& id = seeds[i].id;
        if (!ValidWireIdentity(id) || Get32(id.bytes + 16) != 1) return false;
        const int index = FindId(id);
        if (index < 0 || static_cast<unsigned>(index) >= count || seen[index]) return false;
        seen[index] = true;
        const Entry& entry = s_directory.entries[index];
        if (entry.owner != 1 || entry.version != 0 || entry.bytes == 0 ||
            entry.retention != (SourceRetention | InFlightRetention) ||
            entry.strong == nullptr || entry.weak == nullptr)
            return false;
        OBJECTREF object = ObjectFromHandle(entry.strong);
        if (object == NULL || ObjectFromHandle(entry.weak) != object) return false;
    }
    for (unsigned i = 0; i < count; i++)
        s_directory.entries[i].retention = SourceRetention;
    s_initialThreadTransferCompleted = true;
    return true;
}

bool DistributedIdentityCompletePublication(UINT64 transaction)
{
    if (!OnOwnerThread())
    {
        std::fprintf(stderr, "DC_PUBLICATION phase=thread-rejected api=complete\n");
        return false;
    }
    if (!PublicationRole(1) || transaction == 0)
        return false;
    if (s_publication.phase != PublicationPhase::Activated ||
        s_publication.transaction != transaction || s_directory.failed)
    {
        s_directory.failed = true;
        return false;
    }
    int entryIndexes[DistributedPublicationMaxObjects]{};
    for (unsigned i = 0; i < s_publication.count; i++)
    {
        entryIndexes[i] = FindId(s_publication.nodes[i].id);
        if (entryIndexes[i] < 0 ||
            s_directory.entries[entryIndexes[i]].owner != s_directory.context.localNode)
        {
            s_directory.failed = true;
            return false;
        }
    }
    for (unsigned i = 0; i < s_publication.count; i++)
    {
        Entry& entry = s_directory.entries[entryIndexes[i]];
        entry.retention = static_cast<RetentionRole>(entry.retention & ~InFlightRetention);
    }
    const unsigned count = s_publication.count;
    const UINT64 completed = s_publication.transaction;
    s_publication = {};
    s_pendingPublicationRootCount.store(0, std::memory_order_release);
    std::fprintf(stderr, "DC_PUBLICATION phase=source-complete tx=%llu count=%u roots=%u\n",
        static_cast<unsigned long long>(completed), count, count);
    return true;
}

unsigned DistributedIdentityPendingPublicationRoots()
{
    return s_pendingPublicationRootCount.load(std::memory_order_acquire);
}


bool DistributedIdentityCaptureSnapshot(dcg01_identity_snapshot::Snapshot* output,
    unsigned outputEntryCapacity)
{
    using namespace dcg01_identity_snapshot;
    // Do not read mutable directory/publication state from a non-owner thread.
    if (!OnOwnerThread() || output == nullptr || s_directory.count > kMaxEntries ||
        s_publication.count > kMaxPublicationNodes || outputEntryCapacity < s_directory.count)
        return false;

    SourceState source{};
    std::memcpy(source.run, s_directory.context.run, sizeof(source.run));
    source.localNode = s_directory.context.localNode;
    source.peerNode = s_directory.context.peerNode;
    std::memcpy(source.localInc, s_directory.context.localInc, sizeof(source.localInc));
    std::memcpy(source.peerInc, s_directory.context.peerInc, sizeof(source.peerInc));
    std::memcpy(source.assemblyHash, s_directory.context.assemblyHash, sizeof(source.assemblyHash));
    std::memcpy(source.mvid, s_directory.context.mvid, sizeof(source.mvid));
    source.entryCount = s_directory.count;
    source.retainedBytes = s_directory.retainedBytes;
    source.failed = s_directory.failed ? 1u : 0u;
    source.frozen = s_frozen.load(std::memory_order_acquire) ? 1u : 0u;
    source.pendingPublicationRootCount =
        s_pendingPublicationRootCount.load(std::memory_order_acquire);
    for (unsigned i = 0; i < s_directory.count; ++i)
    {
        const auto& entry = s_directory.entries[i];
        dcg01_identity_snapshot::Entry& copied = source.entries[i];
        std::memcpy(copied.id, entry.id.bytes, sizeof(copied.id));
        copied.owner = entry.owner;
        copied.version = entry.version;
        copied.bytes = entry.bytes;
        copied.retention = static_cast<unsigned>(entry.retention);
    }

    source.publication.phase = static_cast<unsigned>(s_publication.phase);
    source.publication.transaction = s_publication.transaction;
    source.publication.sourceFrontier = s_publication.sourceFrontier;
    source.publication.count = s_publication.count;
    source.publication.bytes = s_publication.bytes;
    std::memcpy(source.publication.root, s_publication.root.bytes,
        sizeof(source.publication.root));
    for (unsigned i = 0; i < s_publication.count; ++i)
    {
        std::memcpy(source.publication.nodeIds[i], s_publication.nodes[i].id.bytes,
            sizeof(source.publication.nodeIds[i]));
        source.publication.nodeBytes[i] = s_publication.nodes[i].bytes;
    }

    // Capture validates into its own fixed temporary and commits output only on success.
    return Capture(source, true, output, outputEntryCapacity);
}

bool DistributedIdentityPublishWorkerSnapshot()
{
    using namespace dcg01_identity_snapshot;
    WorkerSnapshotState expected = WorkerSnapshotState::Empty;
    if (!OnOwnerThread() || !s_ownerHandedOff.load(std::memory_order_acquire) ||
        s_directory.failed || !s_workerSnapshotState.compare_exchange_strong(expected,
            WorkerSnapshotState::Capturing, std::memory_order_acq_rel))
    {
        s_workerSnapshotState.exchange(WorkerSnapshotState::Failed, std::memory_order_acq_rel);
        return false;
    }

    Snapshot captured{};
    if (!DistributedIdentityCaptureSnapshot(&captured, kMaxEntries) || captured.failed != 0)
    {
        s_workerSnapshotState.exchange(WorkerSnapshotState::Failed, std::memory_order_acq_rel);
        return false;
    }
    s_workerSnapshot = captured;
    expected = WorkerSnapshotState::Capturing;
    if (!s_workerSnapshotState.compare_exchange_strong(expected, WorkerSnapshotState::Published,
        std::memory_order_acq_rel, std::memory_order_acquire))
        return false; // A concurrent failure cannot be overwritten.
    return true;
}

bool DistributedIdentityTakeWorkerSnapshotAfterJoin(
    dcg01_identity_snapshot::Snapshot* output)
{
    if (output == nullptr || GetThread() != s_workerStagingThread.load(std::memory_order_acquire) ||
        !DistributedThreadWorkerJoined())
    {
        s_workerSnapshotState.exchange(WorkerSnapshotState::Failed, std::memory_order_acq_rel);
        return false;
    }

    WorkerSnapshotState expected = WorkerSnapshotState::Published;
    if (!s_workerSnapshotState.compare_exchange_strong(expected, WorkerSnapshotState::Consumed,
        std::memory_order_acq_rel))
    {
        s_workerSnapshotState.exchange(WorkerSnapshotState::Failed, std::memory_order_acq_rel);
        return false;
    }
    *output = s_workerSnapshot;
    return true;
}
