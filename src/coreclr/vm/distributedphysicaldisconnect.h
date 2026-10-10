// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#ifndef DISTRIBUTED_PHYSICAL_DISCONNECT_H
#define DISTRIBUTED_PHYSICAL_DISCONNECT_H
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sslerr.h>
#include <errno.h>
#include "distributedcanonicalwriter.h"

namespace DCG01Disconnect
{
// Filled only at the authenticated transport's actual SSL read/write boundary.
// No native address or handle is portable evidence.
struct Notice
{
    unsigned char run[16]{}, manifest[32]{}, localIncarnation[16]{}, peerIncarnation[16]{};
    unsigned char peerCertificate[32]{}, expectedPeerCertificate[32]{};
    unsigned localMember=0, peerMember=0, tlsVersion=0;
    bool authenticated=false, sessionReused=false, write=false;
    int result=0, sslError=0, socketError=0;
    uint64_t tlsError=0, sent=0, received=0;
    unsigned partialInputBytes=0;
};

inline unsigned Kind(const Notice& n)
{
    if (n.result>0 || n.partialInputBytes) return 0;
    if (n.sslError==SSL_ERROR_ZERO_RETURN && n.tlsError==0) return 1;
    if (n.sslError==SSL_ERROR_SYSCALL && n.tlsError==0 &&
        ((!n.write && n.result==0 && n.socketError==0) ||
         (n.write && n.socketError==EPIPE) || n.socketError==ECONNRESET ||
         n.socketError==ECONNABORTED || n.socketError==ENOTCONN)) return 2;
    if (n.sslError==SSL_ERROR_SSL && n.tlsError!=0 &&
        ERR_GET_LIB(n.tlsError)==ERR_LIB_SSL && ERR_GET_REASON(n.tlsError)==SSL_R_UNEXPECTED_EOF_WHILE_READING) return 3;
    return 0;
}

inline bool Encode(const Notice& n, unsigned char* bytes, size_t capacity, size_t* length)
{
    if (!length || !Kind(n)) return false;
    DC022Canonical::Writer w(bytes,capacity);
    const bool ok=w.BeginObject() && w.Key("authenticated") && w.Boolean(n.authenticated) &&
        w.Key("direction") && (n.write?w.String("write"):w.String("read")) &&
        w.Key("expected_peer_certificate_sha256") && w.Hex(n.expectedPeerCertificate,32) &&
        w.Key("local_incarnation_id") && w.Hex(n.localIncarnation,16) &&
        w.Key("local_member_id") && w.UInt(n.localMember) &&
        w.Key("manifest_sha256") && w.Hex(n.manifest,32) &&
        w.Key("notice_class") && w.UInt(Kind(n)) &&
        w.Key("partial_input_bytes") && w.UInt(n.partialInputBytes) &&
        w.Key("peer_certificate_sha256") && w.Hex(n.peerCertificate,32) &&
        w.Key("peer_incarnation_id") && w.Hex(n.peerIncarnation,16) &&
        w.Key("peer_member_id") && w.UInt(n.peerMember) && w.Key("received_sequence") && w.UInt(n.received) &&
        w.Key("result") && w.Int(n.result) && w.Key("run_id") && w.Hex(n.run,16) &&
        w.Key("schema") && w.String("dcg01-physical-disconnect") &&
        w.Key("sent_sequence") && w.UInt(n.sent) && w.Key("session_reused") && w.Boolean(n.sessionReused) &&
        w.Key("socket_error") && w.Int(n.socketError) && w.Key("ssl_error") && w.Int(n.sslError) &&
        w.Key("tls_error") && w.UInt(n.tlsError) && w.Key("tls_version") && w.UInt(n.tlsVersion) &&
        w.Key("version") && w.UInt(1) && w.EndObject() && w.Finish();
    if (ok) *length=w.Size();
    return ok;
}
}
#endif
