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

typedef struct {
    PWRequestKind kind;
    uint32_t ticket;
} PWQueuedRequest;

static int gStateToken = -1;
static int gStatusRequestToken = -1;
static int gWakeRequestToken = -1;
static int gUnlockRequestToken = -1;
static int gStatusResponseToken = -1;
static int gWakeResponseToken = -1;
static int gUnlockResponseToken = -1;
static uint32_t gGeneration = 0;
static BOOL gLastSucceeded = NO;
static BOOL gLastRefused = NO;
static BOOL gLastRejected = NO;
static CFStringRef gStatusRequest = NULL;
static CFStringRef gWakeRequest = NULL;
static CFStringRef gUnlockRequest = NULL;
static uint8_t gObserverMarker = 0;
static const uint8_t PWMaxOutstandingRequests = 6;
static PWQueuedRequest gPendingRequests[PWMaxOutstandingRequests];
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

static BOOL PWPublish(uint32_t *publishedFlags) {
    if (![NSThread isMainThread]) {
        __block BOOL published = NO;
        dispatch_sync(dispatch_get_main_queue(), ^{
            published = PWPublish(publishedFlags);
        });
        return published;
    }
    if (gStateToken < 0) return NO;
    PWPasscodeState passcode = PWReadPasscodeState();
    uint32_t flags = PWAvailable;
    if (PWIsCompatible()) flags |= PWCompatibleFlag;
    if (PWReadDisplayOn()) flags |= PWDisplayOn;
    if (PWReadLocked()) flags |= PWLocked;
    if (passcode == PWPasscodeStatePresent) flags |= PWPasscodeSet;
    if (passcode == PWPasscodeStateUnknown) flags |= PWPasscodeUnknown;
    if (gLastSucceeded) flags |= PWLastRequestSucceeded;
    if (gLastRefused) flags |= PWLastRequestRefused;
    if (gLastRejected) flags |= PWRequestRejected;
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
        return NO;
    }
    gGeneration = candidateGeneration;
    if (notify_post(PWStateNotification) != NOTIFY_STATUS_OK) {
        NSLog(@"PhoneWake notification failed");
        return NO;
    }
    if (publishedFlags) *publishedFlags = flags;
    return YES;
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

static BOOL PWRegisterToken(const char *name, int *token) {
    if (!name || !token) return NO;
    return notify_register_check(name, token) == NOTIFY_STATUS_OK
        && *token >= 0;
}

static BOOL PWRegisterAllTokens(void) {
    if (!PWRegisterToken(PWStateNotification, &gStateToken)) return NO;
    if (!PWRegisterToken(PWRequestStatus, &gStatusRequestToken)) return NO;
    if (!PWRegisterToken(PWRequestWake, &gWakeRequestToken)) return NO;
    if (!PWRegisterToken(PWRequestUnlock, &gUnlockRequestToken)) return NO;
    if (!PWRegisterToken(PWResponseStatus, &gStatusResponseToken)) return NO;
    if (!PWRegisterToken(PWResponseWake, &gWakeResponseToken)) return NO;
    if (!PWRegisterToken(PWResponseUnlock, &gUnlockResponseToken)) return NO;
    return YES;
}

static BOOL PWPublishResponse(PWRequestKind kind, uint32_t ticket, uint32_t flags) {
    int responseToken = -1;
    const char *responseName = NULL;
    switch (kind) {
        case PWRequestKindStatus:
            responseToken = gStatusResponseToken;
            responseName = PWResponseStatus;
            break;
        case PWRequestKindWake:
            responseToken = gWakeResponseToken;
            responseName = PWResponseWake;
            break;
        case PWRequestKindUnlock:
            responseToken = gUnlockResponseToken;
            responseName = PWResponseUnlock;
            break;
        default:
            return NO;
    }
    if (ticket == 0u || responseToken < 0 || !responseName) return NO;
    if (notify_set_state(responseToken, PWEncodeResponse(ticket, flags))
            != NOTIFY_STATUS_OK) return NO;
    if (notify_post(responseName) != NOTIFY_STATUS_OK) return NO;
    return YES;
}

static void PWCompleteRequest(PWQueuedRequest request, BOOL succeeded,
                              BOOL refused, BOOL rejected) {
    gLastSucceeded = succeeded;
    gLastRefused = refused;
    gLastRejected = rejected;
    uint32_t flags = 0;
    if (!PWPublish(&flags)) return;
    if (!PWPublishResponse(request.kind, request.ticket, flags)) {
        NSLog(@"PhoneWake response publication failed");
    }
}

static BOOL PWEnqueueRequest(PWQueuedRequest request) {
    uint8_t outstanding = gPendingCount + (gRequestActive ? 1u : 0u);
    if (outstanding >= PWMaxOutstandingRequests) return NO;
    uint8_t tail = (gPendingHead + gPendingCount) % PWMaxOutstandingRequests;
    gPendingRequests[tail] = request;
    gPendingCount += 1u;
    return YES;
}

static BOOL PWDequeueRequest(PWQueuedRequest *request) {
    if (gPendingCount == 0) return NO;
    *request = gPendingRequests[gPendingHead];
    gPendingHead = (gPendingHead + 1u) % PWMaxOutstandingRequests;
    gPendingCount -= 1u;
    return YES;
}

static void PWStartNextRequest(void) {
    if (gRequestActive) return;
    PWQueuedRequest request = {PWRequestKindInvalid, 0u};
    if (!PWDequeueRequest(&request)) return;
    gRequestActive = YES;

    BOOL refused = NO;
    BOOL actionStarted = request.kind == PWRequestKindStatus;
    if (request.kind == PWRequestKindWake) {
        actionStarted = PWWakeDisplay();
    } else if (request.kind == PWRequestKindUnlock) {
        actionStarted = PWUnlockWithoutPasscode(&refused);
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{
        BOOL displayOn = NO;
        BOOL locked = YES;
        if (!refused && request.kind != PWRequestKindStatus) {
            displayOn = PWReadDisplayOn();
            if (request.kind == PWRequestKindUnlock) locked = PWReadLocked();
        }
        BOOL succeeded = !refused
            && PWObservedRequestSucceeded(
                request.kind, actionStarted, displayOn, locked);
        PWCompleteRequest(request, succeeded, refused && !succeeded, NO);
        gRequestActive = NO;
        PWStartNextRequest();
    });
}

static void PWHandle(PWRequestKind kind, int requestToken) {
    if (![NSThread isMainThread]) {
        dispatch_sync(dispatch_get_main_queue(), ^{
            PWHandle(kind, requestToken);
        });
        return;
    }
    if (kind == PWRequestKindInvalid) return;
    uint64_t requestState = 0;
    if (requestToken < 0
            || notify_get_state(requestToken, &requestState) != NOTIFY_STATUS_OK) {
        return;
    }
    uint32_t ticket = (uint32_t)requestState;
    if (ticket == 0u || requestState != (uint64_t)ticket) return;
    PWQueuedRequest request = {kind, ticket};
    if (!PWEnqueueRequest(request)) {
        PWCompleteRequest(request, NO, NO, YES);
        return;
    }
    PWStartNextRequest();
}

static void PWStatusCallback(CFNotificationCenterRef, void *, CFStringRef,
                             const void *, CFDictionaryRef) {
    PWHandle(PWRequestKindStatus, gStatusRequestToken);
}

static void PWWakeCallback(CFNotificationCenterRef, void *, CFStringRef,
                           const void *, CFDictionaryRef) {
    PWHandle(PWRequestKindWake, gWakeRequestToken);
}

static void PWUnlockCallback(CFNotificationCenterRef, void *, CFStringRef,
                             const void *, CFDictionaryRef) {
    PWHandle(PWRequestKindUnlock, gUnlockRequestToken);
}

static BOOL PWCancelToken(int *token) {
    if (!token || *token < 0) return YES;
    int status = notify_cancel(*token);
    *token = -1;
    return status == NOTIFY_STATUS_OK;
}

static BOOL PWCleanup(void) {
    BOOL cleaned = YES;
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
    if (!PWCancelToken(&gStateToken)) cleaned = NO;
    if (!PWCancelToken(&gStatusRequestToken)) cleaned = NO;
    if (!PWCancelToken(&gWakeRequestToken)) cleaned = NO;
    if (!PWCancelToken(&gUnlockRequestToken)) cleaned = NO;
    if (!PWCancelToken(&gStatusResponseToken)) cleaned = NO;
    if (!PWCancelToken(&gWakeResponseToken)) cleaned = NO;
    if (!PWCancelToken(&gUnlockResponseToken)) cleaned = NO;
    gGeneration = 0;
    gLastSucceeded = NO;
    gLastRefused = NO;
    gLastRejected = NO;
    gPendingHead = 0;
    gPendingCount = 0;
    gRequestActive = NO;
    return cleaned;
}

%ctor {
    @autoreleasepool {
        if (![[NSBundle mainBundle].bundleIdentifier isEqualToString:@"com.apple.springboard"]) return;
        if (!PWRegisterAllTokens()) {
            (void)PWCleanup();
            return;
        }
        CFNotificationCenterRef center = CFNotificationCenterGetDarwinNotifyCenter();
        if (!center) {
            (void)PWCleanup();
            return;
        }
        gStatusRequest = CFStringCreateWithCString(
            NULL, PWRequestStatus, kCFStringEncodingUTF8);
        gWakeRequest = CFStringCreateWithCString(
            NULL, PWRequestWake, kCFStringEncodingUTF8);
        gUnlockRequest = CFStringCreateWithCString(
            NULL, PWRequestUnlock, kCFStringEncodingUTF8);
        if (!center || !gStatusRequest || !gWakeRequest || !gUnlockRequest) {
            (void)PWCleanup();
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
        uint32_t initialFlags = 0;
        if (!PWPublish(&initialFlags)) {
            (void)PWCleanup();
            return;
        }
    }
}

%dtor {
    @autoreleasepool {
        (void)PWCleanup();
    }
}
