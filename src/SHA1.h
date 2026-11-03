#pragma once

#include <cstdint>
#include <iostream>
#include <string>

namespace wolff::detail
{
class SHA1
{
public:
    SHA1();
    void update(const std::string &s);
    void update(std::istream &is);
    std::string final();

private:
    uint32_t digest[5];
    std::string buffer;
    uint64_t transforms;
};
}
