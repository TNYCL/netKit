#include "netkit.h"
#include <cstring>
#include <iostream>
#include <memory>

int main() {
    if (netkit_abi_version() != 1) return 1;
    NetkitEngine *raw = nullptr;
    if (netkit_engine_new(nullptr, &raw) != 0) {
        std::cerr << netkit_last_error() << '\n';
        return 1;
    }
    std::unique_ptr<NetkitEngine, decltype(&netkit_engine_free)> engine(raw, netkit_engine_free);
    const char message[] = "\x0b" "MSH|^~\\&|DEMO|LAB|NETKIT|TEST|20260929||ORU^R01|SYNTHETIC-1|P|2.5\rPID|1||SYNTHETIC\r" "\x1c\r";
    char *json = nullptr;
    if (netkit_decode_message(engine.get(), "hl7", reinterpret_cast<const uint8_t *>(message), std::strlen(message), &json) != 0) {
        std::cerr << netkit_last_error() << '\n';
        return 1;
    }
    std::unique_ptr<char, decltype(&netkit_string_free)> result(json, netkit_string_free);
    std::cout << result.get() << '\n';
    return 0;
}
