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
    gGeneration += 1;
    notify_set_state(gStateToken, PWEncodeState(gGeneration, flags));
    notify_post(PWStateNotification);
}
