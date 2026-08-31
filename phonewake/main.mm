#import <Foundation/Foundation.h>

#include <notify.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#import "PhoneWakeProtocol.h"

static int PWFail(int code) {
    fputs("phonewakectl: request failed\n", stderr);
    return code;
}

static const char *PWNotificationForCommand(NSString *command) {
    if ([command isEqualToString:@"status"]) return PWRequestStatus;
    if ([command isEqualToString:@"wake"]) return PWRequestWake;
    if ([command isEqualToString:@"unlock"]) return PWRequestUnlock;
    return NULL;
}

static BOOL PWStateIsValid(uint64_t value, uint32_t startingGeneration) {
    uint32_t generation = PWDecodeGeneration(value);
    uint32_t flags = PWDecodeFlags(value);
    BOOL succeeded = (flags & PWLastRequestSucceeded) != 0;
    BOOL refused = (flags & PWLastRequestRefused) != 0;
    BOOL passcodeSet = (flags & PWPasscodeSet) != 0;
    BOOL passcodeUnknown = (flags & PWPasscodeUnknown) != 0;
    BOOL batteryUnknown = (flags & PWBatteryUnknown) != 0;
    uint32_t batteryPercent = (flags & PWBatteryMask) >> PWBatteryShift;

    if (generation == startingGeneration) return NO;
    if (succeeded && refused) return NO;
    if (passcodeSet && passcodeUnknown) return NO;
    if (!batteryUnknown && batteryPercent > 100u) return NO;
    return YES;
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc != 2 || argv[1] == NULL) return PWFail(64);

        NSString *command = [[NSString alloc]
            initWithBytes:argv[1]
                   length:strlen(argv[1])
                 encoding:NSUTF8StringEncoding];
        const char *requestName = command == nil
            ? NULL : PWNotificationForCommand(command);
        if (requestName == NULL) return PWFail(64);

        int token = -1;
        int exitCode = 70;
        NSData *json = nil;

        do {
            if (notify_register_check(PWStateNotification, &token)
                != NOTIFY_STATUS_OK || token < 0) break;

            uint64_t startingState = 0;
            if (notify_get_state(token, &startingState) != NOTIFY_STATUS_OK) break;
            uint32_t startingGeneration = PWDecodeGeneration(startingState);

            if (notify_post(requestName) != NOTIFY_STATUS_OK) break;

            uint64_t latestState = startingState;
            BOOL stateReadFailed = NO;
            BOOL receivedFreshState = NO;
            for (NSUInteger poll = 0; poll < 40; poll += 1) {
                usleep(50000);
                if (notify_get_state(token, &latestState) != NOTIFY_STATUS_OK) {
                    stateReadFailed = YES;
                    break;
                }
                if (PWDecodeGeneration(latestState) != startingGeneration) {
                    receivedFreshState = YES;
                    break;
                }
            }
            if (stateReadFailed) break;
            if (!receivedFreshState) {
                exitCode = 69;
                break;
            }
            if (!PWStateIsValid(latestState, startingGeneration)) break;

            uint32_t flags = PWDecodeFlags(latestState);
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
                    objectAtIndex:MIN(thermalIndex, 3u)],
                @"reason": (flags & PWLastRequestRefused)
                    ? @"passcode present or unknown"
                    : ((flags & PWLastRequestSucceeded) ? @"ok" : @"request failed"),
            };

            NSError *jsonError = nil;
            json = [NSJSONSerialization dataWithJSONObject:result
                                                   options:0
                                                     error:&jsonError];
            if (json == nil || jsonError != nil) break;
            exitCode = 0;
        } while (false);

        if (token >= 0) {
            int cancelStatus = notify_cancel(token);
            token = -1;
            if (cancelStatus != NOTIFY_STATUS_OK) exitCode = 70;
        }

        if (exitCode != 0) return PWFail(exitCode);
        fwrite(json.bytes, 1, json.length, stdout);
        fwrite("\n", 1, 1, stdout);
        return 0;
    }
}
