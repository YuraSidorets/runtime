// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Collections.Generic;

namespace System
{
    public partial class Object
    {
        // DC-011 dynamic JIT helpers. All accesses keep managed arguments rooted through
        // the QCall; native code resolves IDs before entering a preemptive network wait.
        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "DistributedRuntime_AccessReadInt32")]
        private static partial int AccessReadInt32Native(ObjectHandleOnStack target, nint location, int kind);

        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "DistributedRuntime_AccessWriteInt32")]
        private static partial void AccessWriteInt32Native(ObjectHandleOnStack target, nint location, int kind, int value);

        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "DistributedRuntime_AccessReadReference")]
        private static partial void AccessReadReferenceNative(ObjectHandleOnStack target, nint field, ObjectHandleOnStack result);

        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "DistributedRuntime_AccessWriteReference")]
        private static partial void AccessWriteReferenceNative(ObjectHandleOnStack target, nint field, ObjectHandleOnStack value);

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static int DistributedGetFieldInt32(object target, nint field) =>
            AccessReadInt32Native(ObjectHandleOnStack.Create(ref target), field, 0);

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void DistributedSetFieldInt32(object target, nint field, int value) =>
            AccessWriteInt32Native(ObjectHandleOnStack.Create(ref target), field, 0, value);

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static object? DistributedGetFieldReference(object target, nint field)
        {
            object? result = null;
            AccessReadReferenceNative(ObjectHandleOnStack.Create(ref target), field, ObjectHandleOnStack.Create(ref result));
            return result;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void DistributedSetFieldReference(object target, nint field, object? value) =>
            AccessWriteReferenceNative(ObjectHandleOnStack.Create(ref target), field, ObjectHandleOnStack.Create(ref value));

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static int DistributedGetArrayInt32(object target, nint index) =>
            AccessReadInt32Native(ObjectHandleOnStack.Create(ref target), index, 1);

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void DistributedSetArrayInt32(object target, nint index, int value) =>
            AccessWriteInt32Native(ObjectHandleOnStack.Create(ref target), index, 1, value);

        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "DistributedRuntime_AccessStartForTest")]
        private static partial void AccessStartNativeForTest(ObjectHandleOnStack root, ObjectHandleOnStack array, int testCase);

        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "DistributedRuntime_AccessFinishForTest")]
        private static partial void AccessFinishNativeForTest(int coordinatorResult, ObjectHandleOnStack artifact);

        // Runtime-owned exception boundary for the exact staged DC-011 body.
        // localEntry is a local managed entrypoint; it is never portable protocol state.
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static unsafe int DistributedAccessInvokeForTest(object root, object array, int roleAndCase, nint localEntry)
        {
            try
            {
                return ((delegate* managed<object, object, int, int>)localEntry)(root, array, roleAndCase);
            }
            catch (Exception)
            {
                return -1;
            }
        }

        private static void DistributedAccessStartForTest(object root, object array, int testCase) =>
            AccessStartNativeForTest(ObjectHandleOnStack.Create(ref root), ObjectHandleOnStack.Create(ref array), testCase);

        private static byte[] DistributedAccessFinishForTest(int coordinatorResult)
        {
            object? artifact = null;
            AccessFinishNativeForTest(coordinatorResult, ObjectHandleOnStack.Create(ref artifact));
            return (byte[])artifact!;
        }

        // Private M01 experiment hook; not an application-facing distributed API.
        private static class DistributedCanonicalizationState
        {
            internal static readonly object Lock = new();
            internal static readonly Dictionary<long, WeakReference<object>> Representatives = new();
        }

        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "DistributedRuntime_GetAddressForTest")]
        private static partial nint GetAddressForDistributedRuntimeTest(ObjectHandleOnStack obj);

        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "DistributedRuntime_StartGcProgressProbeForTest")]
        private static partial int StartGcProgressProbeForTest();

        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "DistributedRuntime_StopGcProgressProbeForTest")]
        private static partial ulong StopGcProgressProbeForTest();

        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "DistributedRuntime_ControlForTest")]
        private static unsafe partial long ControlNativeForTest(int command, int argument, byte* buffer, int length);

        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "DistributedRuntime_IdentityExportForTest")]
        private static unsafe partial int IdentityExportNativeForTest(byte* buffer, int capacity, ObjectHandleOnStack root);

        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "DistributedRuntime_IdentityImportForTest")]
        private static unsafe partial int IdentityImportNativeForTest(byte* wire, int length, ObjectHandleOnStack result);

        private static unsafe byte[] DistributedIdentityExportForTest(object root)
        {
            byte[] frame = new byte[3048];
            int written;
            fixed (byte* p = frame)
                written = IdentityExportNativeForTest(p, frame.Length, ObjectHandleOnStack.Create(ref root));
            if (written < 0)
                throw new InvalidOperationException("The object graph is outside the bounded distributed identity profile.");
            Array.Resize(ref frame, written);
            return frame;
        }

        private static unsafe object DistributedIdentityImportForTest(byte[] wire)
        {
            ArgumentNullException.ThrowIfNull(wire);
            object? result = null;
            fixed (byte* p = wire)
            {
                if (IdentityImportNativeForTest(p, wire.Length, ObjectHandleOnStack.Create(ref result)) != 0)
                    throw new InvalidOperationException("The distributed identity frame is invalid or conflicts with the canonical directory.");
            }
            return result!;
        }

        // DC-008 conformance hook; buffers are pinned only for the native copy.
        private static unsafe long DistributedControlForTest(int command, int argument, byte[] buffer)
        {
            ArgumentNullException.ThrowIfNull(buffer);
            fixed (byte* p = buffer)
                return ControlNativeForTest(command, argument, p, buffer.Length);
        }

        private static int DistributedStartGcProgressProbeForTest() => StartGcProgressProbeForTest();
        private static ulong DistributedStopGcProgressProbeForTest() => StopGcProgressProbeForTest();

        private static object DistributedCanonicalizeForTest(object candidate, long identity)
        {
            ArgumentNullException.ThrowIfNull(candidate);
            lock (DistributedCanonicalizationState.Lock)
            {
                // A physical object may have at most one logical identity in this fixture table.
                // The table is bounded, so the reverse-identity check is bounded as well.
                foreach (KeyValuePair<long, WeakReference<object>> entry in DistributedCanonicalizationState.Representatives)
                {
                    if (entry.Key != identity && entry.Value.TryGetTarget(out object? represented) && ReferenceEquals(represented, candidate))
                        throw new InvalidOperationException("A representative object is already associated with a different identity.");
                }

                if (DistributedCanonicalizationState.Representatives.TryGetValue(identity, out WeakReference<object>? weak) &&
                    weak.TryGetTarget(out object? existing))
                {
                    if (!HasCompatibleCanonicalShape(existing, candidate))
                        throw new InvalidOperationException("Canonical identity is already associated with an incompatible exact type or array shape.");

                    return existing;
                }

                // ponytail: scan at most 1024 entries on insert; a generation queue is only needed if experiments outgrow this bound.
                if (DistributedCanonicalizationState.Representatives.Count >= 1024)
                {
                    List<long> stale = new();
                    foreach (KeyValuePair<long, WeakReference<object>> entry in DistributedCanonicalizationState.Representatives)
                    {
                        if (!entry.Value.TryGetTarget(out _))
                            stale.Add(entry.Key);
                    }

                    foreach (long staleIdentity in stale)
                        DistributedCanonicalizationState.Representatives.Remove(staleIdentity);

                    if (DistributedCanonicalizationState.Representatives.Count >= 1024)
                        throw new InvalidOperationException("M01 canonical table capacity reached while all representatives remain live.");
                }

                DistributedCanonicalizationState.Representatives[identity] = new WeakReference<object>(candidate);
                return candidate;
            }
        }

        private static bool HasCompatibleCanonicalShape(object existing, object candidate)
        {
            if (existing.GetType() != candidate.GetType())
                return false;

            if (existing is not Array existingArray)
                return true;

            Array candidateArray = (Array)candidate;
            if (existingArray.Rank != candidateArray.Rank)
                return false;

            for (int dimension = 0; dimension < existingArray.Rank; dimension++)
            {
                if (existingArray.GetLength(dimension) != candidateArray.GetLength(dimension) ||
                    existingArray.GetLowerBound(dimension) != candidateArray.GetLowerBound(dimension))
                    return false;
            }

            return true;
        }

        private static nint GetAddressForDistributedRuntimeTest(object obj)
        {
            return GetAddressForDistributedRuntimeTest(ObjectHandleOnStack.Create(ref obj));
        }

        // Returns a Type object which represent this object instance.
        [Intrinsic]
        public unsafe Type GetType()
        {
            MethodTable* pMT = RuntimeHelpers.GetMethodTable(this);
            RuntimeType type = RuntimeTypeHandle.GetRuntimeType(pMT);
            GC.KeepAlive(this);
            return type;
        }

        // Returns a new object instance that is a memberwise copy of this
        // object.  This is always a shallow copy of the instance. The method is protected
        // so that other object may only call this method on themselves.  It is intended to
        // support the ICloneable interface.
        [Intrinsic]
        protected internal unsafe object MemberwiseClone()
        {
            object clone = this;
            RuntimeHelpers.AllocateUninitializedClone(ObjectHandleOnStack.Create(ref clone));
            Debug.Assert(clone != this);

            // copy contents of "this" to the clone

            nuint byteCount = RuntimeHelpers.GetRawObjectDataSize(clone);
            ref byte src = ref this.GetRawData();
            ref byte dst = ref clone.GetRawData();

            if (RuntimeHelpers.GetMethodTable(clone)->ContainsGCPointers)
                Buffer.BulkMoveWithWriteBarrier(ref dst, ref src, byteCount);
            else
                SpanHelpers.Memmove(ref dst, ref src, byteCount);

            return clone;
        }
    }
}
