#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <UIKit/UIKit.h>
#import <math.h>
#import <notify.h>
#import <objc/message.h>

#import "PhoneWakeProtocol.h"

typedef NS_ENUM(NSInteger, PWPasscodeState) {
    PWPasscodeStateAbsent = 0,
    PWPasscodeStatePresent = 1,
    PWPasscodeStateUnknown = 2,
};

static int gStateToken = -1;
static uint32_t gGeneration = 0;
static BOOL gLastSucceeded = NO;
static BOOL gLastRefused = NO;
static CFStringRef gStatusRequest = NULL;
static CFStringRef gWakeRequest = NULL;
static CFStringRef gUnlockRequest = NULL;
static uint8_t gObserverMarker = 0;

static id PWSharedInstance(Class cls) {
    SEL selector = NSSelectorFromString(@"sharedInstance");
    if (!cls || ![cls respondsToSelector:selector]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(cls, selector);
}

static PWPasscodeState PWReadPasscodeState(void) {
    LAContext *context = [LAContext new];
    context.interactionNotAllowed = YES;
    NSError *error = nil;
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
        return PWPasscodeStatePresent;
    }
    if ([error.domain isEqualToString:LAErrorDomain] && error.code == LAErrorPasscodeNotSet) {
        return PWPasscodeStateAbsent;
    }
    return PWPasscodeStateUnknown;
}

static BOOL PWReadDisplayOn(void) {
    id controller = PWSharedInstance(NSClassFromString(@"SBBacklightController"));
    SEL selector = NSSelectorFromString(@"screenIsOn");
    return controller && [controller respondsToSelector:selector]
        ? ((BOOL (*)(id, SEL))objc_msgSend)(controller, selector) : NO;
}

static BOOL PWReadLocked(void) {
    id manager = PWSharedInstance(NSClassFromString(@"SBLockScreenManager"));
    SEL selector = NSSelectorFromString(@"isUILocked");
    return manager && [manager respondsToSelector:selector]
        ? ((BOOL (*)(id, SEL))objc_msgSend)(manager, selector) : YES;
}

static BOOL PWIsCompatible(void) {
    id backlight = PWSharedInstance(NSClassFromString(@"SBBacklightController"));
    id lock = PWSharedInstance(NSClassFromString(@"SBLockScreenManager"));
    return backlight && lock
        && [backlight respondsToSelector:NSSelectorFromString(@"screenIsOn")]
        && [backlight respondsToSelector:NSSelectorFromString(@"turnOnScreenFullyWithBacklightSource:")]
        && [lock respondsToSelector:NSSelectorFromString(@"isUILocked")]
        && ([lock respondsToSelector:NSSelectorFromString(@"lockScreenViewControllerRequestsUnlock")]
            || [lock respondsToSelector:NSSelectorFromString(@"unlockUIFromSource:withOptions:")]);
}

static void PWPublish(void) {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            PWPublish();
        });
        return;
    }
    if (gStateToken < 0) return;
    PWPasscodeState passcode = PWReadPasscodeState();
    uint32_t flags = PWAvailable;
    if (PWIsCompatible()) flags |= PWCompatibleFlag;
    if (PWReadDisplayOn()) flags |= PWDisplayOn;
    if (PWReadLocked()) flags |= PWLocked;
    if (passcode == PWPasscodeStatePresent) flags |= PWPasscodeSet;
    if (passcode == PWPasscodeStateUnknown) flags |= PWPasscodeUnknown;
    if (gLastSucceeded) flags |= PWLastRequestSucceeded;
    if (gLastRefused) flags |= PWLastRequestRefused;
    UIDevice *device = [UIDevice currentDevice];
    device.batteryMonitoringEnabled = YES;
    if (device.batteryState == UIDeviceBatteryStateCharging
            || device.batteryState == UIDeviceBatteryStateFull) flags |= PWCharging;
    if (device.batteryLevel < 0) {
        flags |= PWBatteryUnknown;
    } else {
        flags |= PWEncodeBattery((uint32_t)lround(device.batteryLevel * 100.0f));
    }
    flags |= PWEncodeThermal((uint32_t)[NSProcessInfo processInfo].thermalState);
    uint32_t candidateGeneration = gGeneration + 1u;
    if (notify_set_state(gStateToken, PWEncodeState(candidateGeneration, flags))
            != NOTIFY_STATUS_OK) {
        NSLog(@"PhoneWake publication failed");
        return;
    }
    gGeneration = candidateGeneration;
    if (notify_post(PWStateNotification) != NOTIFY_STATUS_OK) {
        NSLog(@"PhoneWake notification failed");
    }
}

static BOOL PWWakeDisplay(void) {
    id controller = PWSharedInstance(NSClassFromString(@"SBBacklightController"));
    SEL displayOn = NSSelectorFromString(@"screenIsOn");
    SEL turnOn = NSSelectorFromString(@"turnOnScreenFullyWithBacklightSource:");
    if (!controller || ![controller respondsToSelector:displayOn]
            || ![controller respondsToSelector:turnOn]) return NO;
    if (!PWReadDisplayOn()) {
        ((void (*)(id, SEL, long long))objc_msgSend)(controller, turnOn, 2);
    }
    return YES;
}

static BOOL PWUnlockWithoutPasscode(BOOL *refused) {
    PWPasscodeState passcode = PWReadPasscodeState();
    if (passcode != PWPasscodeStateAbsent) {
        if (refused) *refused = YES;
        return NO;
    }
    if (!PWWakeDisplay()) return NO;
    id manager = PWSharedInstance(NSClassFromString(@"SBLockScreenManager"));
    if (!manager) return NO;
    SEL request = NSSelectorFromString(@"lockScreenViewControllerRequestsUnlock");
    SEL fallback = NSSelectorFromString(@"unlockUIFromSource:withOptions:");
    if ([manager respondsToSelector:request]) {
        ((void (*)(id, SEL))objc_msgSend)(manager, request);
        return YES;
    }
    if ([manager respondsToSelector:fallback]) {
        ((void (*)(id, SEL, int, id))objc_msgSend)(manager, fallback, 0, nil);
        return YES;
    }
    return NO;
}

static void PWHandle(NSString *request) {
    dispatch_async(dispatch_get_main_queue(), ^{
        gLastSucceeded = NO;
        gLastRefused = NO;
        if ([request isEqualToString:[NSString stringWithUTF8String:PWRequestStatus]]) {
            gLastSucceeded = YES;
        } else if ([request isEqualToString:[NSString stringWithUTF8String:PWRequestWake]]) {
            gLastSucceeded = PWWakeDisplay();
        } else if ([request isEqualToString:[NSString stringWithUTF8String:PWRequestUnlock]]) {
            BOOL refused = NO;
            gLastSucceeded = PWUnlockWithoutPasscode(&refused);
            if (refused) {
                gLastSucceeded = NO;
                gLastRefused = YES;
            }
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC),
                       dispatch_get_main_queue(), ^{ PWPublish(); });
    });
}

static void PWStatusCallback(CFNotificationCenterRef, void *, CFStringRef,
                             const void *, CFDictionaryRef) {
    PWHandle([NSString stringWithUTF8String:PWRequestStatus]);
}

static void PWWakeCallback(CFNotificationCenterRef, void *, CFStringRef,
                           const void *, CFDictionaryRef) {
    PWHandle([NSString stringWithUTF8String:PWRequestWake]);
}

static void PWUnlockCallback(CFNotificationCenterRef, void *, CFStringRef,
                             const void *, CFDictionaryRef) {
    PWHandle([NSString stringWithUTF8String:PWRequestUnlock]);
}

static void PWCleanup(void) {
    CFNotificationCenterRef center = CFNotificationCenterGetDarwinNotifyCenter();
    if (center) {
        CFNotificationCenterRemoveEveryObserver(center, &gObserverMarker);
    }
    if (gStatusRequest != NULL) {
        CFRelease(gStatusRequest);
        gStatusRequest = NULL;
    }
    if (gWakeRequest != NULL) {
        CFRelease(gWakeRequest);
        gWakeRequest = NULL;
    }
    if (gUnlockRequest != NULL) {
        CFRelease(gUnlockRequest);
        gUnlockRequest = NULL;
    }
    if (gStateToken >= 0) {
        notify_cancel(gStateToken);
        gStateToken = -1;
    }
    gGeneration = 0;
    gLastSucceeded = NO;
    gLastRefused = NO;
}

%ctor {
    @autoreleasepool {
        if (![[NSBundle mainBundle].bundleIdentifier isEqualToString:@"com.apple.springboard"]) return;
        if (notify_register_check(PWStateNotification, &gStateToken)
                != NOTIFY_STATUS_OK) {
            PWCleanup();
            return;
        }
        CFNotificationCenterRef center = CFNotificationCenterGetDarwinNotifyCenter();
        if (!center) {
            PWCleanup();
            return;
        }
        gStatusRequest = CFStringCreateWithCString(
            NULL, PWRequestStatus, kCFStringEncodingUTF8);
        gWakeRequest = CFStringCreateWithCString(
            NULL, PWRequestWake, kCFStringEncodingUTF8);
        gUnlockRequest = CFStringCreateWithCString(
            NULL, PWRequestUnlock, kCFStringEncodingUTF8);
        if (!center || !gStatusRequest || !gWakeRequest || !gUnlockRequest) {
            PWCleanup();
            return;
        }
        CFNotificationCenterAddObserver(center, &gObserverMarker, PWStatusCallback,
            gStatusRequest, NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);
        CFNotificationCenterAddObserver(center, &gObserverMarker, PWWakeCallback,
            gWakeRequest, NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);
        CFNotificationCenterAddObserver(center, &gObserverMarker, PWUnlockCallback,
            gUnlockRequest, NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);
        PWPublish();
    }
}

%dtor {
    @autoreleasepool {
        PWCleanup();
    }
}
