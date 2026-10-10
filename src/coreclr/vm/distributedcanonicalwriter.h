// Bounded native encoder for the frozen DC-022 canonical ASCII JSON spelling.
// Candidate only: this primitive does not authenticate facts or certify completion.
#ifndef DC022_NATIVE_CANONICAL_WRITER_H
#define DC022_NATIVE_CANONICAL_WRITER_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace DC022Canonical
{
class Writer final
{
    struct Frame
    {
        bool object;
        bool pendingKey;
        size_t count;
        size_t lastKeySize;
        char lastKey[64];
    };
    unsigned char* buffer;
    size_t capacity;
    size_t used;
    Frame frames[16];
    size_t depth;
    bool failed;
    bool root;
    bool finished;

    bool Reject() { failed = true; return false; }
    bool Put(const void* bytes, size_t count)
    {
        if (failed || finished || count > capacity - used || (count != 0 && bytes == nullptr))
            return Reject();
        if (count != 0) memcpy(buffer + used, bytes, count);
        used += count;
        return true;
    }
    bool Byte(unsigned char value) { return Put(&value, 1); }
    bool BeforeValue()
    {
        if (failed || finished) return Reject();
        if (depth == 0)
        {
            if (root) return Reject();
            root = true;
            return true;
        }
        Frame& f = frames[depth - 1];
        if (f.object)
        {
            if (!f.pendingKey) return Reject();
            f.pendingKey = false;
        }
        else if (f.count != 0 && !Byte(',')) return false;
        ++f.count;
        return true;
    }
    bool Quoted(const char* text, size_t count)
    {
        if (text == nullptr && count != 0) return Reject();
        if (!Byte('"')) return false;
        static const char hex[] = "0123456789abcdef";
        for (size_t i = 0; i < count; ++i)
        {
            unsigned char c = static_cast<unsigned char>(text[i]);
            if (c >= 128) return Reject(); // Native contract fields are ASCII/hex/base64.
            const char* escape = nullptr;
            switch (c)
            {
                case '"': escape = "\\\""; break;
                case '\\': escape = "\\\\"; break;
                case 8: escape = "\\b"; break;
                case 9: escape = "\\t"; break;
                case 10: escape = "\\n"; break;
                case 12: escape = "\\f"; break;
                case 13: escape = "\\r"; break;
            }
            if (escape != nullptr)
            {
                if (!Put(escape, 2)) return false;
            }
            else if (c < 32 || c == 127)
            {
                const char escaped[] = {'\\','u','0','0',hex[c >> 4],hex[c & 15]};
                if (!Put(escaped, sizeof(escaped))) return false;
            }
            else if (!Byte(c)) return false;
        }
        return Byte('"');
    }
    bool Digits(uint64_t value)
    {
        char text[20];
        size_t start = sizeof(text);
        do { text[--start] = static_cast<char>('0' + value % 10); value /= 10; } while (value != 0);
        return Put(text + start, sizeof(text) - start);
    }
    bool Begin(bool object)
    {
        if (depth == 16) return Reject();
        if (!BeforeValue() || !Byte(object ? '{' : '[')) return false;
        Frame& f = frames[depth++];
        f.object = object; f.pendingKey = false; f.count = 0; f.lastKeySize = 0;
        return true;
    }
    bool End(bool object)
    {
        if (failed || finished || depth == 0) return Reject();
        Frame& f = frames[depth - 1];
        if (f.object != object || f.pendingKey) return Reject();
        if (!Byte(object ? '}' : ']')) return false;
        --depth;
        return true;
    }

public:
    // Prefix is domain bytes including embedded NULs, never a JSON fragment.
    Writer(unsigned char* output, size_t limit, const void* prefix = nullptr, size_t prefixSize = 0)
        : buffer(output), capacity(limit), used(0), depth(0),
          failed(output == nullptr || limit == 0), root(false), finished(false)
    {
        if (!failed) Put(prefix, prefixSize);
    }
    bool BeginObject() { return Begin(true); }
    bool EndObject() { return End(true); }
    bool BeginArray() { return Begin(false); }
    bool EndArray() { return End(false); }
    bool Key(const char* name, size_t count)
    {
        if (failed || finished || depth == 0 || name == nullptr || count >= 64) return Reject();
        Frame& f = frames[depth - 1];
        if (!f.object || f.pendingKey) return Reject();
        for (size_t i = 0; i < count; ++i)
            if (static_cast<unsigned char>(name[i]) >= 128) return Reject();
        if (f.count != 0)
        {
            const size_t common = count < f.lastKeySize ? count : f.lastKeySize;
            const int order = memcmp(name, f.lastKey, common);
            if (order < 0 || (order == 0 && count <= f.lastKeySize)) return Reject();
            if (!Byte(',')) return false;
        }
        if (!Quoted(name, count) || !Byte(':')) return false;
        memcpy(f.lastKey, name, count); f.lastKeySize = count; f.pendingKey = true;
        return true;
    }
    template<size_t N> bool Key(const char (&name)[N]) { return Key(name, N - 1); }
    bool String(const char* text, size_t count) { return BeforeValue() && Quoted(text, count); }
    template<size_t N> bool String(const char (&text)[N]) { return String(text, N - 1); }
    bool UInt(uint64_t value) { return BeforeValue() && Digits(value); }
    bool Int(int64_t value)
    {
        if (!BeforeValue()) return false;
        if (value >= 0) return Digits(static_cast<uint64_t>(value));
        return Byte('-') && Digits(static_cast<uint64_t>(-(value + 1)) + 1);
    }
    bool Boolean(bool value) { return BeforeValue() && Put(value ? "true" : "false", value ? 4 : 5); }
    bool Null() { return BeforeValue() && Put("null", 4); }
    bool Hex(const unsigned char* bytes, size_t count)
    {
        if (bytes == nullptr && count != 0) return Reject();
        if (count > capacity / 2) return Reject();
        if (!BeforeValue() || !Byte('"')) return false;
        static const char digits[] = "0123456789abcdef";
        for (size_t i = 0; i < count; ++i)
        {
            const char pair[] = {digits[bytes[i] >> 4], digits[bytes[i] & 15]};
            if (!Put(pair, 2)) return false;
        }
        return Byte('"');
    }
    bool Base64(const unsigned char* bytes, size_t count)
    {
        if (bytes == nullptr && count != 0) return Reject();
        if (count / 3 > capacity / 4 || count > 16384) return Reject();
        if (!BeforeValue() || !Byte('"')) return false;
        static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (size_t i = 0; i < count;)
        {
            const size_t left = count - i;
            const uint32_t a = bytes[i++];
            const uint32_t b = left > 1 ? bytes[i++] : 0;
            const uint32_t c = left > 2 ? bytes[i++] : 0;
            const char group[] = {alphabet[a >> 2], alphabet[((a & 3) << 4) | (b >> 4)],
                                 left > 1 ? alphabet[((b & 15) << 2) | (c >> 6)] : '=',
                                 left > 2 ? alphabet[c & 63] : '='};
            if (!Put(group, 4)) return false;
        }
        return Byte('"');
    }
    bool Finish()
    {
        if (failed || finished || !root || depth != 0) return Reject();
        if (!Byte('\n')) return false;
        finished = true; return true;
    }
    const unsigned char* Data() const { return finished && !failed ? buffer : nullptr; }
    size_t Size() const { return finished && !failed ? used : 0; }
    bool Failed() const { return failed; }
};
}
#endif
