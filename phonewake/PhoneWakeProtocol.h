#pragma once

#include <stdint.h>

static const char *PWRequestStatus = "com.mudkipsol.phonewake.request.status";
static const char *PWRequestWake = "com.mudkipsol.phonewake.request.wake";
static const char *PWRequestUnlock = "com.mudkipsol.phonewake.request.unlock";
static const char *PWStateNotification = "com.mudkipsol.phonewake.state";

enum PWStateFlag : uint32_t {
    PWAvailable = 1u << 0,
    PWCompatibleFlag = 1u << 1,
    PWDisplayOn = 1u << 2,
    PWLocked = 1u << 3,
    PWPasscodeSet = 1u << 4,
    PWPasscodeUnknown = 1u << 5,
    PWLastRequestSucceeded = 1u << 6,
    PWLastRequestRefused = 1u << 7,
    PWCharging = 1u << 8,
    PWBatteryUnknown = 1u << 19,
};

static const uint32_t PWBatteryShift = 9;
static const uint32_t PWBatteryMask = 0x7fu << PWBatteryShift;
static const uint32_t PWThermalShift = 16;
static const uint32_t PWThermalMask = 0x7u << PWThermalShift;
static const uint64_t PWFlagMask = 0xffffffffULL;
static const uint64_t PWGenerationShift = 32;

static inline uint64_t PWEncodeState(uint32_t generation, uint32_t flags) {
    return ((uint64_t)generation << PWGenerationShift) | flags;
}

static inline uint32_t PWDecodeGeneration(uint64_t value) {
    return (uint32_t)(value >> PWGenerationShift);
}

static inline uint32_t PWDecodeFlags(uint64_t value) {
    return (uint32_t)(value & PWFlagMask);
}

static inline uint32_t PWEncodeBattery(uint32_t percent) {
    uint32_t bounded = percent > 100u ? 100u : percent;
    return (bounded << PWBatteryShift) & PWBatteryMask;
}

static inline uint32_t PWEncodeThermal(uint32_t state) {
    uint32_t bounded = state > 3u ? 3u : state;
    return (bounded << PWThermalShift) & PWThermalMask;
}
