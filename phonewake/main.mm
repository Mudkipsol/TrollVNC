#import <Foundation/Foundation.h>

#include <errno.h>
#include <notify.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#import "PhoneWakeProtocol.h"

static const int64_t PWNanosecondsPerSecond = 1000000000LL;
static const int64_t PWPollNanoseconds = 50000000LL;
static const time_t PWDeadlineSeconds = 2;

static int PWFail(int code) {
    fputs("phonewakectl: request failed\n", stderr);
    return code;
}

static BOOL PWNamesForCommand(NSString *command, const char **requestName,
                              const char **responseName) {
    if (!command || !requestName || !responseName) return NO;
    if ([command isEqualToString:@"status"]) {
        *requestName = PWRequestStatus;
        *responseName = PWResponseStatus;
        return YES;
    }
    if ([command isEqualToString:@"wake"]) {
        *requestName = PWRequestWake;
        *responseName = PWResponseWake;
        return YES;
    }
    if ([command isEqualToString:@"unlock"]) {
        *requestName = PWRequestUnlock;
        *responseName = PWResponseUnlock;
        return YES;
    }
    return NO;
}

static BOOL PWRegisterToken(const char *name, int *token) {
    if (!name || !token) return NO;
    return notify_register_check(name, token) == NOTIFY_STATUS_OK
        && *token >= 0;
}

static BOOL PWCancelToken(int *token) {
    if (!token || *token < 0) return YES;
    int status = notify_cancel(*token);
    *token = -1;
    return status == NOTIFY_STATUS_OK;
}

static int64_t PWNanosecondsUntil(struct timespec deadline,
                                  struct timespec now) {
    int64_t seconds = (int64_t)deadline.tv_sec - (int64_t)now.tv_sec;
    return seconds * PWNanosecondsPerSecond
        + (int64_t)deadline.tv_nsec - (int64_t)now.tv_nsec;
}

static BOOL PWSleepUntilNextPoll(struct timespec deadline, BOOL *timedOut) {
    if (!timedOut) return NO;
    *timedOut = NO;
    while (true) {
        struct timespec now = {0, 0};
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return NO;
        int64_t remaining = PWNanosecondsUntil(deadline, now);
        if (remaining <= 0) {
            *timedOut = YES;
            return YES;
        }

        int64_t sleepNanoseconds = MIN(remaining, PWPollNanoseconds);
        struct timespec sleepTime = {
            (time_t)(sleepNanoseconds / PWNanosecondsPerSecond),
            (long)(sleepNanoseconds % PWNanosecondsPerSecond),
        };
        if (nanosleep(&sleepTime, NULL) == 0) {
            struct timespec afterSleep = {0, 0};
            if (clock_gettime(CLOCK_MONOTONIC, &afterSleep) != 0) return NO;
            if (PWNanosecondsUntil(deadline, afterSleep) <= 0) {
                *timedOut = YES;
            }
            return YES;
        }
        if (errno != EINTR) return NO;
    }
}

static BOOL PWFlagsAreValid(uint32_t flags) {
    if ((flags & ~PWKnownFlagMask) != 0u) return NO;
    BOOL succeeded = (flags & PWLastRequestSucceeded) != 0;
    BOOL refused = (flags & PWLastRequestRefused) != 0;
    BOOL rejected = (flags & PWRequestRejected) != 0;
    uint32_t outcomeCount = (succeeded ? 1u : 0u)
        + (refused ? 1u : 0u) + (rejected ? 1u : 0u);
    BOOL passcodeSet = (flags & PWPasscodeSet) != 0;
    BOOL passcodeUnknown = (flags & PWPasscodeUnknown) != 0;
    BOOL batteryUnknown = (flags & PWBatteryUnknown) != 0;
    uint32_t batteryPercent = (flags & PWBatteryMask) >> PWBatteryShift;
    uint32_t thermalState = (flags & PWThermalMask) >> PWThermalShift;

    if (outcomeCount > 1u) return NO;
    if (passcodeSet && passcodeUnknown) return NO;
    if (!batteryUnknown && batteryPercent > 100u) return NO;
    if (batteryUnknown && batteryPercent != 0u) return NO;
    if (thermalState > 3u) return NO;
    return YES;
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc != 2 || argv[1] == NULL) return PWFail(64);

        NSString *command = [[NSString alloc]
            initWithBytes:argv[1]
                   length:strlen(argv[1])
                 encoding:NSUTF8StringEncoding];
        const char *requestName = NULL;
        const char *responseName = NULL;
        if (!PWNamesForCommand(command, &requestName, &responseName)) {
            return PWFail(64);
        }

        int requestToken = -1;
        int responseToken = -1;
        int stateToken = -1;
        int exitCode = 70;
        NSData *json = nil;

        do {
            if (!PWRegisterToken(requestName, &requestToken)) break;
            if (!PWRegisterToken(responseName, &responseToken)) break;
            if (!PWRegisterToken(PWStateNotification, &stateToken)) break;

            uint64_t startingState = 0;
            if (notify_get_state(stateToken, &startingState)
                    != NOTIFY_STATUS_OK) break;
            uint32_t startingGeneration = PWDecodeGeneration(startingState);

            uint64_t startingResponse = 0;
            if (notify_get_state(responseToken, &startingResponse)
                    != NOTIFY_STATUS_OK) break;
            uint32_t previousTicket = PWDecodeResponseTicket(startingResponse);
            uint32_t ticket = 0;
            do {
                ticket = arc4random_uniform(UINT32_MAX) + 1u;
            } while (ticket == previousTicket);

            struct timespec deadline = {0, 0};
            if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) break;
            deadline.tv_sec += PWDeadlineSeconds;

            if (notify_set_state(requestToken, ticket)
                    != NOTIFY_STATUS_OK) break;
            if (notify_post(requestName) != NOTIFY_STATUS_OK) break;

            uint64_t responseState = startingResponse;
            uint64_t globalState = startingState;
            BOOL matchedResponse = NO;
            BOOL pollFailed = NO;
            BOOL timedOut = NO;
            while (!matchedResponse) {
                BOOL reachedDeadline = NO;
                if (!PWSleepUntilNextPoll(deadline, &reachedDeadline)) {
                    pollFailed = YES;
                    break;
                }
                if (reachedDeadline) {
                    timedOut = YES;
                    break;
                }
                if (notify_get_state(responseToken, &responseState)
                        != NOTIFY_STATUS_OK) {
                    pollFailed = YES;
                    break;
                }
                if (notify_get_state(stateToken, &globalState)
                        != NOTIFY_STATUS_OK) {
                    pollFailed = YES;
                    break;
                }
                struct timespec observedAt = {0, 0};
                if (clock_gettime(CLOCK_MONOTONIC, &observedAt) != 0) {
                    pollFailed = YES;
                    break;
                }
                if (PWNanosecondsUntil(deadline, observedAt) <= 0) {
                    timedOut = YES;
                    break;
                }
                if (PWDecodeResponseTicket(responseState) == ticket
                        && PWDecodeGeneration(globalState) != startingGeneration) {
                    matchedResponse = YES;
                }
            }
            if (pollFailed) break;
            if (timedOut || !matchedResponse) {
                exitCode = 69;
                break;
            }

            uint32_t flags = PWDecodeResponseFlags(responseState);
            if (!PWFlagsAreValid(flags)) break;
            uint32_t thermalIndex =
                (flags & PWThermalMask) >> PWThermalShift;
            NSDictionary *result = @{
                @"available": @((flags & PWAvailable) != 0),
                @"compatible": @((flags & PWCompatibleFlag) != 0),
                @"display_on": @((flags & PWDisplayOn) != 0),
                @"locked": @((flags & PWLocked) != 0),
                @"passcode_set": (flags & PWPasscodeUnknown)
                    ? (id)[NSNull null] : @((flags & PWPasscodeSet) != 0),
                @"battery_level": (flags & PWBatteryUnknown)
                    ? (id)[NSNull null]
                    : @(((flags & PWBatteryMask) >> PWBatteryShift) / 100.0),
                @"charging": @((flags & PWCharging) != 0),
                @"thermal_state": [@[@"nominal", @"fair", @"serious", @"critical"]
                    objectAtIndex:thermalIndex],
                @"reason": (flags & PWRequestRejected)
                    ? @"request rejected"
                    : ((flags & PWLastRequestRefused)
                        ? @"passcode present or unknown"
                        : ((flags & PWLastRequestSucceeded)
                            ? @"ok" : @"request failed")),
            };

            NSError *jsonError = nil;
            json = [NSJSONSerialization dataWithJSONObject:result
                                                   options:0
                                                     error:&jsonError];
            if (json == nil || jsonError != nil) break;
            exitCode = 0;
        } while (false);

        BOOL cleanupSucceeded = YES;
        if (!PWCancelToken(&requestToken)) cleanupSucceeded = NO;
        if (!PWCancelToken(&responseToken)) cleanupSucceeded = NO;
        if (!PWCancelToken(&stateToken)) cleanupSucceeded = NO;
        if (!cleanupSucceeded) exitCode = 70;

        if (exitCode != 0) return PWFail(exitCode);
        size_t bodyWritten = fwrite(json.bytes, 1, json.length, stdout);
        size_t newlineWritten = fwrite("\n", 1, 1, stdout);
        int flushStatus = fflush(stdout);
        if (bodyWritten != json.length || newlineWritten != 1u
                || flushStatus != 0 || ferror(stdout)) {
            return PWFail(70);
        }
        return 0;
    }
}
