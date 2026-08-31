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

typedef NS_ENUM(uint8_t, PWRequestKind) {
    PWRequestKindStatus = 0,
    PWRequestKindWake = 1,
    PWRequestKindUnlock = 2,
    PWRequestKindInvalid = UINT8_MAX,
};

static int gStateToken = -1;
static uint32_t gGeneration = 0;
static BOOL gLastSucceeded = NO;
static BOOL gLastRefused = NO;
static CFStringRef gStatusRequest = NULL;
static CFStringRef gWakeRequest = NULL;
static CFStringRef gUnlockRequest = NULL;
static uint8_t gObserverMarker = 0;
static const uint8_t PWMaxOutstandingRequests = 8;
static PWRequestKind gPendingRequests[PWMaxOutstandingRequests];
static uint8_t gPendingHead = 0;
static uint8_t gPendingCount = 0;
static BOOL gRequestActive = NO;

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

static BOOL PWObservedRequestSucceeded(PWRequestKind request, BOOL actionStarted, BOOL displayOn, BOOL locked) {
    if (!actionStarted) return NO;
    switch (request) {
        case PWRequestKindStatus:
            return YES;
        case PWRequestKindWake:
            return displayOn;
        case PWRequestKindUnlock:
            return displayOn && !locked;
        default:
            return NO;
    }
}

static BOOL PWEnqueueRequest(PWRequestKind request) {
    uint8_t outstanding = gPendingCount + (gRequestActive ? 1u : 0u);
    if (outstanding >= PWMaxOutstandingRequests) return NO;
    uint8_t tail = (gPendingHead + gPendingCount) % PWMaxOutstandingRequests;
    gPendingRequests[tail] = request;
    gPendingCount += 1u;
    return YES;
}

static BOOL PWDequeueRequest(PWRequestKind *request) {
    if (gPendingCount == 0) return NO;
    *request = gPendingRequests[gPendingHead];
    gPendingHead = (gPendingHead + 1u) % PWMaxOutstandingRequests;
    gPendingCount -= 1u;
    return YES;
}

static void PWStartNextRequest(void) {
    if (gRequestActive) return;
    PWRequestKind request = PWRequestKindInvalid;
    if (!PWDequeueRequest(&request)) return;
    gRequestActive = YES;

    BOOL refused = NO;
    BOOL actionStarted = request == PWRequestKindStatus;
    if (request == PWRequestKindWake) {
        actionStarted = PWWakeDisplay();
    } else if (request == PWRequestKindUnlock) {
        actionStarted = PWUnlockWithoutPasscode(&refused);
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{
        BOOL displayOn = NO;
        BOOL locked = YES;
        if (!refused && request != PWRequestKindStatus) {
            displayOn = PWReadDisplayOn();
            if (request == PWRequestKindUnlock) locked = PWReadLocked();
        }
        BOOL succeeded = !refused
            && PWObservedRequestSucceeded(request, actionStarted, displayOn, locked);
        gLastSucceeded = succeeded;
        gLastRefused = refused && !succeeded;
        PWPublish();
        gRequestActive = NO;
        PWStartNextRequest();
    });
}

static PWRequestKind PWRequestKindForName(NSString *request) {
    if ([request isEqualToString:[NSString stringWithUTF8String:PWRequestStatus]]) {
        return PWRequestKindStatus;
    }
    if ([request isEqualToString:[NSString stringWithUTF8String:PWRequestWake]]) {
        return PWRequestKindWake;
    }
    if ([request isEqualToString:[NSString stringWithUTF8String:PWRequestUnlock]]) {
        return PWRequestKindUnlock;
    }
    return PWRequestKindInvalid;
}

static void PWHandle(NSString *request) {
    if (![NSThread isMainThread]) {
        dispatch_sync(dispatch_get_main_queue(), ^{
            PWHandle(request);
        });
        return;
    }
    PWRequestKind kind = PWRequestKindForName(request);
    if (kind == PWRequestKindInvalid) return;
    if (!PWEnqueueRequest(kind)) return;
    PWStartNextRequest();
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
    gPendingHead = 0;
    gPendingCount = 0;
    gRequestActive = NO;
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
