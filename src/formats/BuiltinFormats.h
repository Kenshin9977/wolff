#pragma once

// The zone formats Wolff knows, each registered by its function (src/formats/<game>.cpp)
namespace wolff::ZoneTables
{
    void BuiltinFormatCODOL();
    void BuiltinFormatIW3();
    void BuiltinFormatIW4();
    void BuiltinFormatIW6();
    void BuiltinFormatIW7();
    void BuiltinFormatIW8();
    void BuiltinFormatS1();
    void BuiltinFormatS2();
    void BuiltinFormatT4();
    void BuiltinFormatT5();
    void BuiltinFormatT6();
    void BuiltinFormatT7();
    void BuiltinFormatT8();
    void BuiltinFormatT9();
    void BuiltinFormatIwctx();
}
