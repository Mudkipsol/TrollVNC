from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]

PW_AVAILABLE = 1 << 0
PW_COMPATIBLE = 1 << 1
PW_DISPLAY_ON = 1 << 2
PW_LOCKED = 1 << 3
PW_PASSCODE_SET = 1 << 4
PW_PASSCODE_UNKNOWN = 1 << 5
PW_LAST_REQUEST_SUCCEEDED = 1 << 6
PW_LAST_REQUEST_REFUSED = 1 << 7
PW_CHARGING = 1 << 8
PW_BATTERY_SHIFT = 9
PW_BATTERY_MASK = 0x7F << PW_BATTERY_SHIFT
PW_THERMAL_SHIFT = 16
PW_THERMAL_MASK = 0x7 << PW_THERMAL_SHIFT
PW_BATTERY_UNKNOWN = 1 << 19
PW_GENERATION_SHIFT = 32


def decode_cli_state(value: int, starting_generation: int) -> dict[str, object]:
    generation = value >> PW_GENERATION_SHIFT
    flags = value & 0xFFFFFFFF
    succeeded = bool(flags & PW_LAST_REQUEST_SUCCEEDED)
    refused = bool(flags & PW_LAST_REQUEST_REFUSED)
    passcode_set = bool(flags & PW_PASSCODE_SET)
    passcode_unknown = bool(flags & PW_PASSCODE_UNKNOWN)
    battery_unknown = bool(flags & PW_BATTERY_UNKNOWN)
    battery_percent = (flags & PW_BATTERY_MASK) >> PW_BATTERY_SHIFT

    if generation == starting_generation:
        raise ValueError("generation did not change")
    if succeeded and refused:
        raise ValueError("outcome flags conflict")
    if passcode_set and passcode_unknown:
        raise ValueError("passcode flags conflict")
    if not battery_unknown and battery_percent > 100:
        raise ValueError("battery percent is invalid")

    thermal_index = min((flags & PW_THERMAL_MASK) >> PW_THERMAL_SHIFT, 3)
    return {
        "available": bool(flags & PW_AVAILABLE),
        "compatible": bool(flags & PW_COMPATIBLE),
        "display_on": bool(flags & PW_DISPLAY_ON),
        "locked": bool(flags & PW_LOCKED),
        "passcode_set": None if passcode_unknown else passcode_set,
        "battery_level": None if battery_unknown else battery_percent / 100.0,
        "charging": bool(flags & PW_CHARGING),
        "thermal_state": ("nominal", "fair", "serious", "critical")[
            thermal_index
        ],
        "reason": (
            "passcode present or unknown"
            if refused
            else "ok" if succeeded else "request failed"
        ),
    }


class RequestLifecycleModel:
    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.active: tuple[str, bool, bool] | None = None
        self.pending: list[tuple[str, bool, bool]] = []
        self.publications: list[tuple[bool, bool]] = []

    def accept(
        self,
        request: str,
        *,
        action_started: bool = True,
        refused: bool = False,
    ) -> bool:
        if len(self.pending) + (self.active is not None) >= self.capacity:
            return False
        item = (request, action_started, refused)
        if self.active is None:
            self.active = item
        else:
            self.pending.append(item)
        return True

    def settle(self, *, display_on: bool = False, locked: bool = True) -> None:
        if self.active is None:
            return
        request, action_started, refused = self.active
        succeeded = (
            not refused
            and action_started
            and (
                request == "status"
                or (request == "wake" and display_on)
                or (request == "unlock" and display_on and not locked)
            )
        )
        self.publications.append((succeeded, refused and not succeeded))
        self.active = self.pending.pop(0) if self.pending else None


class PhoneWakePackageTests(unittest.TestCase):
    def test_package_is_rootless_and_depends_on_ellekit(self) -> None:
        control = (ROOT / "control").read_text(encoding="utf-8")
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("Architecture: iphoneos-arm64", control)
        self.assertRegex(
            control,
            r"(?m)^Depends: firmware \(>= 15\.0\), ellekit$",
        )
        self.assertIn("THEOS_PACKAGE_SCHEME = rootless", makefile)
        self.assertIn("ARCHS = arm64 arm64e", makefile)
        self.assertIn("TARGET = iphone:clang:16.5:15.0", makefile)

    def test_tweak_injects_only_into_springboard(self) -> None:
        filter_text = (ROOT / "PhoneWake.plist").read_text(encoding="utf-8")
        compact_filter = re.sub(r"\s+", "", filter_text)
        self.assertEqual(
            compact_filter,
            '{Filter={Bundles=("com.apple.springboard");};}',
        )
        self.assertIn('Bundles = ("com.apple.springboard");', filter_text)
        self.assertEqual(filter_text.count("com.apple.springboard"), 1)
        self.assertNotIn("Executables", filter_text)

    def test_cli_installs_at_the_fixed_rootless_command_path(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("INSTALL_TARGET_PROCESSES = SpringBoard", makefile)
        self.assertIn("TWEAK_NAME = PhoneWake", makefile)
        self.assertIn("PhoneWake_FILES = Tweak.xm", makefile)
        self.assertIn("PhoneWake_CFLAGS = -fobjc-arc -Wall -Wextra", makefile)
        self.assertIn(
            "PhoneWake_FRAMEWORKS = Foundation UIKit LocalAuthentication",
            makefile,
        )
        self.assertIn("TOOL_NAME = phonewakectl", makefile)
        self.assertIn("phonewakectl_FILES = main.mm", makefile)
        self.assertIn("phonewakectl_CFLAGS = -fobjc-arc -Wall -Wextra", makefile)
        self.assertIn("phonewakectl_FRAMEWORKS = Foundation", makefile)
        self.assertIn("phonewakectl_INSTALL_PATH = /usr/bin", makefile)
        skeleton = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "Makefile", ROOT / "control", ROOT / "PhoneWake.plist")
        )
        self.assertIsNone(re.search(r"\b(listener|socket|port)\b", skeleton, re.I))

    def test_cli_accepts_only_status_wake_unlock(self) -> None:
        source = (ROOT / "main.mm").read_text(encoding="utf-8")
        self.assertRegex(
            source,
            r"if \(argc != 2 \|\| argv\[1\] == NULL\) return PWFail\(64\);",
        )
        self.assertIn('isEqualToString:@"status"', source)
        self.assertIn('isEqualToString:@"wake"', source)
        self.assertIn('isEqualToString:@"unlock"', source)
        self.assertEqual(
            re.findall(
                r'if \(\[command isEqualToString:@"(\w+)"\]\)\s*'
                r"return (PWRequest\w+);",
                source,
            ),
            [
                ("status", "PWRequestStatus"),
                ("wake", "PWRequestWake"),
                ("unlock", "PWRequestUnlock"),
            ],
        )
        self.assertRegex(
            source,
            r"initWithBytes:argv\[1\]\s*length:strlen\(argv\[1\]\)\s*"
            r"encoding:NSUTF8StringEncoding",
        )
        main = source[source.index("int main(") :]
        self.assertLess(main.index("argc != 2"), main.index("notify_register_check"))
        self.assertLess(main.index("requestName == NULL"), main.index("notify_post"))

    def test_cli_posts_once_and_waits_for_a_fresh_generation(self) -> None:
        source = (ROOT / "main.mm").read_text(encoding="utf-8")
        self.assertEqual(source.count("notify_post("), 1)
        self.assertIn("PWDecodeGeneration(startingState)", source)
        self.assertIn("PWDecodeGeneration(latestState)", source)
        self.assertRegex(
            source,
            r"for \(NSUInteger poll = 0; poll < 40; poll \+= 1\)\s*\{\s*"
            r"usleep\(50000\);",
        )
        self.assertEqual(source.count("usleep(50000)"), 1)
        polling = source[
            source.index("for (NSUInteger poll") : source.index(
                "if (stateReadFailed)"
            )
        ]
        self.assertNotRegex(polling, r"while\s*\(")
        self.assertIn("PWStateIsValid(latestState, startingGeneration)", source)

    def test_cli_checks_notify_calls_and_cancels_every_registered_token(self) -> None:
        source = (ROOT / "main.mm").read_text(encoding="utf-8")
        self.assertRegex(
            source,
            r"notify_register_check\(PWStateNotification, &token\)\s*"
            r"!= NOTIFY_STATUS_OK",
        )
        self.assertEqual(source.count("notify_get_state("), 2)
        self.assertRegex(
            source,
            r"notify_get_state\(token, &startingState\)\s*!= NOTIFY_STATUS_OK",
        )
        self.assertRegex(
            source,
            r"notify_get_state\(token, &latestState\)\s*!= NOTIFY_STATUS_OK",
        )
        self.assertRegex(
            source,
            r"notify_post\(requestName\)\s*!= NOTIFY_STATUS_OK",
        )
        self.assertRegex(
            source,
            r"if \(token >= 0\)\s*\{\s*"
            r"int cancelStatus = notify_cancel\(token\);\s*"
            r"token = -1;\s*"
            r"if \(cancelStatus != NOTIFY_STATUS_OK\) exitCode = 70;\s*\}",
        )
        main = source[source.index("int main(") :]
        registration = main.index("notify_register_check")
        cleanup = main.index("notify_cancel")
        self.assertNotIn("return", main[registration:cleanup])

    def test_cli_validates_state_before_emitting_exact_json(self) -> None:
        source = (ROOT / "main.mm").read_text(encoding="utf-8")
        validation = source[
            source.index("static BOOL PWStateIsValid") : source.index("int main(")
        ]
        self.assertIn("generation == startingGeneration", validation)
        self.assertIn("succeeded && refused", validation)
        self.assertIn("passcodeSet && passcodeUnknown", validation)
        self.assertIn("!batteryUnknown && batteryPercent > 100u", validation)

        result_block = source[
            source.index("NSDictionary *result = @{") : source.index(
                "NSJSONSerialization", source.index("NSDictionary *result = @{")
            )
        ]
        self.assertEqual(
            set(re.findall(r'^\s+@"([a-z_]+)"\s*:', result_block, re.MULTILINE)),
            {
                "available",
                "compatible",
                "display_on",
                "locked",
                "passcode_set",
                "battery_level",
                "charging",
                "thermal_state",
                "reason",
            },
        )
        self.assertIn("PWBatteryUnknown", result_block)
        self.assertIn("PWPasscodeUnknown", result_block)
        self.assertIn("MIN(thermalIndex, 3u)", result_block)
        for reason in (
            "passcode present or unknown",
            "ok",
            "request failed",
        ):
            self.assertIn(f'@"{reason}"', result_block)

    def test_cli_serializes_once_and_has_bounded_generic_exit_behavior(self) -> None:
        source = (ROOT / "main.mm").read_text(encoding="utf-8")
        self.assertEqual(source.count("NSJSONSerialization dataWithJSONObject"), 1)
        self.assertRegex(
            source,
            r"dataWithJSONObject:result\s+options:0\s+error:&jsonError",
        )
        self.assertIn("if (json == nil || jsonError != nil) break;", source)
        self.assertIn('fputs("phonewakectl: request failed\\n", stderr);', source)
        self.assertEqual(source.count("stderr"), 1)
        self.assertNotIn("fprintf", source)
        self.assertNotIn("NSLog", source)
        self.assertRegex(source, r"exitCode = 70;")
        self.assertRegex(source, r"exitCode = 69;")
        self.assertRegex(source, r"exitCode = 0;")
        self.assertIn("return PWFail(64);", source)
        self.assertIn("return PWFail(exitCode);", source)
        self.assertIn("return 0;", source)
        self.assertEqual(source.count("fwrite("), 2)
        self.assertNotIn("NSJSONWritingPrettyPrinted", source)
        main = source[source.index("int main(") :]
        self.assertLess(main.index("notify_cancel"), main.index("exitCode != 0"))
        self.assertLess(main.index("exitCode != 0"), main.index("fwrite("))

    def test_cli_model_decodes_valid_flags_and_exact_reasons(self) -> None:
        flags = (
            PW_AVAILABLE
            | PW_COMPATIBLE
            | PW_DISPLAY_ON
            | PW_PASSCODE_SET
            | PW_LAST_REQUEST_SUCCEEDED
            | PW_CHARGING
            | (73 << PW_BATTERY_SHIFT)
            | (2 << PW_THERMAL_SHIFT)
        )
        decoded = decode_cli_state((8 << PW_GENERATION_SHIFT) | flags, 7)
        self.assertEqual(
            decoded,
            {
                "available": True,
                "compatible": True,
                "display_on": True,
                "locked": False,
                "passcode_set": True,
                "battery_level": 0.73,
                "charging": True,
                "thermal_state": "serious",
                "reason": "ok",
            },
        )

        refused = decode_cli_state(
            (9 << PW_GENERATION_SHIFT)
            | PW_PASSCODE_UNKNOWN
            | PW_BATTERY_UNKNOWN
            | PW_LAST_REQUEST_REFUSED
            | (7 << PW_THERMAL_SHIFT),
            8,
        )
        self.assertIsNone(refused["passcode_set"])
        self.assertIsNone(refused["battery_level"])
        self.assertEqual(refused["thermal_state"], "critical")
        self.assertEqual(refused["reason"], "passcode present or unknown")

        failed = decode_cli_state(10 << PW_GENERATION_SHIFT, 9)
        self.assertEqual(failed["reason"], "request failed")

    def test_cli_model_rejects_invalid_fresh_state(self) -> None:
        invalid_values = {
            "stale generation": 4 << PW_GENERATION_SHIFT,
            "conflicting outcome": (
                (5 << PW_GENERATION_SHIFT)
                | PW_LAST_REQUEST_SUCCEEDED
                | PW_LAST_REQUEST_REFUSED
            ),
            "conflicting passcode": (
                (5 << PW_GENERATION_SHIFT) | PW_PASSCODE_SET | PW_PASSCODE_UNKNOWN
            ),
            "battery above one hundred": (
                (5 << PW_GENERATION_SHIFT) | (101 << PW_BATTERY_SHIFT)
            ),
        }
        for name, value in invalid_values.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                decode_cli_state(value, 4)

    def test_cli_source_has_no_remote_or_arbitrary_execution_surface(self) -> None:
        source = (ROOT / "main.mm").read_text(encoding="utf-8")
        forbidden = re.compile(
            r"\b(?:NSURLSession|CFStream|socket|listener|port|bind|listen|"
            r"accept|connect|send|recv|password|credential|passcodeEntry|"
            r"system|popen|NSTask|posix_spawn|fopen|open)\b",
            re.IGNORECASE,
        )
        self.assertIsNone(forbidden.search(source))
        self.assertNotIn("stringWithFormat", source)
        self.assertNotIn("notificationWithName", source)
        self.assertNotIn("CFNotificationCenterGetDistributedCenter", source)

    def test_protocol_exposes_only_three_fixed_requests(self) -> None:
        source = (ROOT / "PhoneWakeProtocol.h").read_text(encoding="utf-8")
        requests = re.findall(
            r'^static const char \*(PWRequest\w+) = "([^"]+)";$',
            source,
            re.MULTILINE,
        )
        self.assertEqual(
            requests,
            [
                ("PWRequestStatus", "com.mudkipsol.phonewake.request.status"),
                ("PWRequestWake", "com.mudkipsol.phonewake.request.wake"),
                ("PWRequestUnlock", "com.mudkipsol.phonewake.request.unlock"),
            ],
        )
        self.assertEqual(len({name for name, _ in requests}), 3)
        self.assertEqual(len({value for _, value in requests}), 3)
        self.assertEqual(
            re.findall(
                r'^static const char \*(PWStateNotification) = "([^"]+)";$',
                source,
                re.MULTILINE,
            ),
            [("PWStateNotification", "com.mudkipsol.phonewake.state")],
        )
        self.assertIsNone(
            re.search(
                r"\b(socket|listener|port|credential|network|NSURLSession|"
                r"CFStream|bind|listen|accept|connect|send|recv|sprintf|"
                r"snprintf|strcat|stringWithFormat|passcodeEntry)\b",
                source,
                re.IGNORECASE,
            )
        )
        self.assertEqual(
            re.findall(r"^#include\s+<([^>]+)>$", source, re.MULTILINE),
            ["stdint.h"],
        )

    def test_state_has_unknown_and_refused_bits(self) -> None:
        source = (ROOT / "PhoneWakeProtocol.h").read_text(encoding="utf-8")
        flag_bits = {
            name: int(bit)
            for name, bit in re.findall(
                r"^\s+(PW\w+) = 1u << (\d+),$", source, re.MULTILINE
            )
        }
        self.assertIn("PWPasscodeUnknown", flag_bits)
        self.assertIn("PWBatteryUnknown", flag_bits)
        self.assertIn("PWLastRequestRefused", flag_bits)
        self.assertEqual(len(flag_bits), 10)

        battery_bits = set(range(9, 16))
        thermal_bits = set(range(16, 19))
        self.assertTrue(set(flag_bits.values()).isdisjoint(battery_bits))
        self.assertTrue(set(flag_bits.values()).isdisjoint(thermal_bits))
        self.assertTrue(battery_bits.isdisjoint(thermal_bits))
        self.assertIn("PWBatteryMask = 0x7fu << PWBatteryShift", source)
        self.assertIn("PWThermalMask = 0x7u << PWThermalShift", source)
        self.assertRegex(source, r"percent > 100u \? 100u : percent")
        self.assertRegex(source, r"state > 3u \? 3u : state")

        self.assertIn("PWFlagMask = 0xffffffffULL", source)
        self.assertIn("PWGenerationShift = 32", source)
        self.assertIn(
            "((uint64_t)generation << PWGenerationShift) | flags", source
        )
        self.assertIn("value >> PWGenerationShift", source)
        self.assertIn("value & PWFlagMask", source)

    def test_tweak_uses_local_authentication_as_fail_closed_passcode_gate(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        self.assertIn("LAPolicyDeviceOwnerAuthentication", source)
        self.assertIn("LAErrorPasscodeNotSet", source)
        self.assertIn("PWPasscodeUnknown", source)
        self.assertIn("context.interactionNotAllowed = YES", source)
        self.assertRegex(
            source,
            r"if \(\[context canEvaluatePolicy:"
            r"LAPolicyDeviceOwnerAuthentication error:&error\]\)\s*\{\s*"
            r"return PWPasscodeStatePresent;",
        )
        self.assertRegex(
            source,
            r"\[error\.domain isEqualToString:LAErrorDomain\]\s*&&\s*"
            r"error\.code == LAErrorPasscodeNotSet",
        )
        self.assertRegex(
            source,
            r"error\.code == LAErrorPasscodeNotSet\)\s*\{\s*"
            r"return PWPasscodeStateAbsent;\s*\}\s*"
            r"return PWPasscodeStateUnknown;",
        )

    def test_tweak_declares_fixed_probe_state_and_runtime_imports(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        imports = re.findall(r'^#import\s+(?:<([^>]+)>|"([^"]+)")$', source, re.MULTILINE)
        self.assertEqual(
            [system or local for system, local in imports],
            [
                "Foundation/Foundation.h",
                "LocalAuthentication/LocalAuthentication.h",
                "UIKit/UIKit.h",
                "math.h",
                "notify.h",
                "objc/message.h",
                "PhoneWakeProtocol.h",
            ],
        )
        self.assertRegex(
            source,
            r"typedef NS_ENUM\(NSInteger, PWPasscodeState\)\s*\{\s*"
            r"PWPasscodeStateAbsent = 0,\s*"
            r"PWPasscodeStatePresent = 1,\s*"
            r"PWPasscodeStateUnknown = 2,\s*\};",
        )
        for declaration in (
            "static int gStateToken = -1;",
            "static uint32_t gGeneration = 0;",
            "static BOOL gLastSucceeded = NO;",
            "static BOOL gLastRefused = NO;",
        ):
            self.assertIn(declaration, source)

    def test_tweak_resolves_version_sensitive_selectors_at_runtime(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        self.assertIn('NSClassFromString(@"SBBacklightController")', source)
        self.assertIn('NSClassFromString(@"SBLockScreenManager")', source)
        self.assertIn("respondsToSelector", source)
        self.assertIn('NSSelectorFromString(@"sharedInstance")', source)
        self.assertNotRegex(source, r"#import\s+[<\"](?:SpringBoard|SpringBoardHome)")
        self.assertRegex(source, r"\(\(id \(\*\)\(id, SEL\)\)objc_msgSend\)")
        self.assertRegex(source, r"\(\(BOOL \(\*\)\(id, SEL\)\)objc_msgSend\)")

    def test_tweak_probes_display_lock_and_full_operation_compatibility(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        self.assertRegex(
            source,
            r"(?s)static BOOL PWReadDisplayOn\(void\).*?"
            r"NSSelectorFromString\(@\"screenIsOn\"\).*?"
            r"\? \(\(BOOL \(\*\)\(id, SEL\)\)objc_msgSend\)"
            r"\(controller, selector\) : NO;",
        )
        self.assertRegex(
            source,
            r"(?s)static BOOL PWReadLocked\(void\).*?"
            r"NSSelectorFromString\(@\"isUILocked\"\).*?"
            r"\? \(\(BOOL \(\*\)\(id, SEL\)\)objc_msgSend\)"
            r"\(manager, selector\) : YES;",
        )
        for selector in (
            "screenIsOn",
            "turnOnScreenFullyWithBacklightSource:",
            "isUILocked",
            "lockScreenViewControllerRequestsUnlock",
            "unlockUIFromSource:withOptions:",
        ):
            receiver = "backlight" if selector.startswith(("screen", "turn")) else "lock"
            self.assertIn(
                f'[{receiver} '
                f'respondsToSelector:NSSelectorFromString(@"{selector}")]',
                source,
            )

    def test_tweak_publishes_generation_tagged_clamped_state(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        self.assertIn("uint32_t flags = PWAvailable;", source)
        for flag in (
            "PWCompatibleFlag",
            "PWDisplayOn",
            "PWLocked",
            "PWPasscodeSet",
            "PWPasscodeUnknown",
            "PWLastRequestSucceeded",
            "PWLastRequestRefused",
            "PWCharging",
            "PWBatteryUnknown",
        ):
            self.assertIn(f"flags |= {flag};", source)
        self.assertIn("flags |= PWEncodeBattery", source)
        self.assertIn("flags |= PWEncodeThermal", source)
        self.assertIn(
            "PWEncodeState(candidateGeneration, flags)",
            source,
        )
        self.assertNotRegex(source, r"notify_post\s*\(\s*@?\"")

    def test_publish_serializes_all_state_work_on_the_main_queue(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        publish = source[source.index("static void PWPublish(void)") :]
        guard = re.match(
            r"static void PWPublish\(void\)\s*\{\s*"
            r"if \(!\[NSThread isMainThread\]\)\s*\{\s*"
            r"dispatch_async\(dispatch_get_main_queue\(\),\s*\^\{\s*"
            r"PWPublish\(\);\s*\}\);\s*return;\s*\}\s*",
            publish,
        )
        self.assertIsNotNone(guard)
        guarded_publish = publish[guard.end() :]
        self.assertRegex(guarded_publish, r"^if \(gStateToken < 0\) return;")
        for state_work in (
            "gStateToken",
            "PWReadPasscodeState()",
            "PWIsCompatible()",
            "PWReadDisplayOn()",
            "PWReadLocked()",
            "gLastSucceeded",
            "gLastRefused",
            "[UIDevice currentDevice]",
            "gGeneration",
            "notify_set_state",
            "notify_post",
        ):
            self.assertIn(state_work, guarded_publish)

    def test_publish_commits_generation_only_after_notify_state_succeeds(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        publish = source[source.index("static void PWPublish(void)") :]
        self.assertNotIn("gGeneration += 1;", publish)
        self.assertRegex(
            publish,
            r"(?s)uint32_t candidateGeneration = gGeneration \+ 1u;\s*"
            r"if \(notify_set_state\(gStateToken,\s*"
            r"PWEncodeState\(candidateGeneration, flags\)\)\s*"
            r"!= NOTIFY_STATUS_OK\)\s*\{\s*"
            r"NSLog\(@\"PhoneWake publication failed\"\);\s*"
            r"return;\s*\}\s*"
            r"gGeneration = candidateGeneration;\s*"
            r"if \(notify_post\(PWStateNotification\) != NOTIFY_STATUS_OK\)\s*\{\s*"
            r"NSLog\(@\"PhoneWake notification failed\"\);\s*\}",
        )
        logs = re.findall(r'NSLog\(@"([^"]*)"\);', publish)
        self.assertEqual(
            logs,
            ["PhoneWake publication failed", "PhoneWake notification failed"],
        )
        self.assertTrue(all("%" not in message for message in logs))

    def test_wake_only_turns_on_a_supported_display_that_is_off(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        wake = re.search(
            r"(?s)static BOOL PWWakeDisplay\(void\)\s*\{(.*?)\n\}", source
        )
        self.assertIsNotNone(wake)
        body = wake.group(1)
        self.assertIn('NSSelectorFromString(@"screenIsOn")', body)
        self.assertIn(
            'NSSelectorFromString(@"turnOnScreenFullyWithBacklightSource:")', body
        )
        self.assertRegex(
            body,
            r"if \(!controller \|\| !\[controller respondsToSelector:displayOn\]\s*"
            r"\|\| !\[controller respondsToSelector:turnOn\]\) return NO;",
        )
        self.assertRegex(
            body,
            r"if \(!PWReadDisplayOn\(\)\)\s*\{\s*"
            r"\(\(void \(\*\)\(id, SEL, long long\)\)objc_msgSend\)"
            r"\(controller, turnOn, 2\);\s*\}\s*return YES;",
        )
        self.assertEqual(
            source.count(
                "((void (*)(id, SEL, long long))objc_msgSend)(controller, turnOn, 2);"
            ),
            1,
        )

    def test_unlock_refuses_every_passcode_state_except_absent(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        unlock = re.search(
            r"(?s)static BOOL PWUnlockWithoutPasscode\(BOOL \*refused\)\s*"
            r"\{(.*?)\n\}",
            source,
        )
        self.assertIsNotNone(unlock)
        body = unlock.group(1)
        self.assertRegex(
            body,
            r"PWPasscodeState passcode = PWReadPasscodeState\(\);\s*"
            r"if \(passcode != PWPasscodeStateAbsent\)\s*\{\s*"
            r"if \(refused\) \*refused = YES;\s*return NO;\s*\}",
        )
        self.assertIn("if (!PWWakeDisplay()) return NO;", body)
        self.assertIn("gLastRefused = refused && !succeeded;", source)
        self.assertNotIn("evaluatePolicy:", source)

    def test_request_handler_uses_bounded_main_queue_fifo(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        handler = re.search(
            r"(?s)static void PWHandle\(NSString \*request\)\s*\{(.*?)\n\}", source
        )
        self.assertIsNotNone(handler)
        body = handler.group(1)
        self.assertRegex(
            body,
            r"^\s*if \(!\[NSThread isMainThread\]\)\s*\{\s*"
            r"dispatch_sync\(dispatch_get_main_queue\(\),\s*\^\{\s*"
            r"PWHandle\(request\);\s*\}\);\s*return;\s*\}",
        )
        self.assertIn("PWRequestKindForName(request)", body)
        self.assertIn("if (!PWEnqueueRequest(kind)) return;", body)
        self.assertIn("PWStartNextRequest();", body)
        self.assertNotIn("gLastSucceeded", body)
        self.assertNotIn("gLastRefused", body)

        self.assertIn("static const uint8_t PWMaxOutstandingRequests = 8;", source)
        self.assertIn(
            "static PWRequestKind gPendingRequests[PWMaxOutstandingRequests];",
            source,
        )
        self.assertRegex(
            source,
            r"uint8_t outstanding = gPendingCount\s*"
            r"\+ \(gRequestActive \? 1u : 0u\);\s*"
            r"if \(outstanding >= PWMaxOutstandingRequests\) return NO;",
        )
        self.assertIn(
            "(gPendingHead + gPendingCount) % PWMaxOutstandingRequests", source
        )

    def test_settle_observes_state_then_publishes_before_next_request(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        start = re.search(
            r"(?s)static void PWStartNextRequest\(void\)\s*\{(.*?)\n\}", source
        )
        self.assertIsNotNone(start)
        body = start.group(1)
        self.assertRegex(
            body,
            r"dispatch_after\(dispatch_time\(DISPATCH_TIME_NOW,\s*"
            r"250 \* NSEC_PER_MSEC\),\s*dispatch_get_main_queue\(\),",
        )
        completion = body[body.index("dispatch_after") :]
        for state_probe in ("PWReadDisplayOn()", "PWReadLocked()"):
            self.assertIn(state_probe, completion)
        self.assertRegex(
            completion,
            r"BOOL succeeded = !refused\s*&&\s*PWObservedRequestSucceeded\(\s*"
            r"request, actionStarted, displayOn, locked\);",
        )
        sequence = [
            completion.index("gLastSucceeded = succeeded;"),
            completion.index("gLastRefused = refused && !succeeded;"),
            completion.index("PWPublish();"),
            completion.index("gRequestActive = NO;"),
            completion.index("PWStartNextRequest();"),
        ]
        self.assertEqual(sequence, sorted(sequence))

    def test_observed_result_helper_requires_settled_target_state(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        helper = re.search(
            r"(?s)static BOOL PWObservedRequestSucceeded\("
            r"PWRequestKind request, BOOL actionStarted, BOOL displayOn, BOOL locked\)"
            r"\s*\{(.*?)\n\}",
            source,
        )
        self.assertIsNotNone(helper)
        body = helper.group(1)
        self.assertIn("if (!actionStarted) return NO;", body)
        self.assertRegex(body, r"case PWRequestKindStatus:\s*return YES;")
        self.assertRegex(body, r"case PWRequestKindWake:\s*return displayOn;")
        self.assertRegex(
            body, r"case PWRequestKindUnlock:\s*return displayOn && !locked;"
        )

    def test_refused_unlock_then_status_publishes_in_order(self) -> None:
        model = RequestLifecycleModel(capacity=8)
        self.assertTrue(
            model.accept("unlock", action_started=False, refused=True)
        )
        self.assertTrue(model.accept("status"))
        self.assertEqual(model.publications, [])

        model.settle(display_on=False, locked=True)
        self.assertEqual(model.publications, [(False, True)])

        model.settle(display_on=False, locked=True)
        self.assertEqual(model.publications, [(False, True), (True, False)])

    def test_selector_no_op_and_still_locked_requests_fail(self) -> None:
        wake = RequestLifecycleModel(capacity=8)
        self.assertTrue(wake.accept("wake", action_started=True))
        wake.settle(display_on=False)
        self.assertEqual(wake.publications, [(False, False)])

        unlock = RequestLifecycleModel(capacity=8)
        self.assertTrue(unlock.accept("unlock", action_started=True))
        unlock.settle(display_on=True, locked=True)
        self.assertEqual(unlock.publications, [(False, False)])

    def test_request_queue_cap_drops_excess_without_growing(self) -> None:
        model = RequestLifecycleModel(capacity=3)
        self.assertTrue(model.accept("status"))
        self.assertTrue(model.accept("wake"))
        self.assertTrue(model.accept("unlock"))
        self.assertFalse(model.accept("status"))
        self.assertEqual(len(model.pending), 2)

        model.settle()
        model.settle(display_on=True)
        model.settle(display_on=True, locked=False)
        self.assertEqual(len(model.publications), 3)

    def test_requests_use_exact_fixed_darwin_callbacks_and_names(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        self.assertEqual(source.count("CFNotificationCenterAddObserver"), 3)
        self.assertEqual(
            re.findall(
                r"CFNotificationCenterAddObserver\(center, &gObserverMarker,\s*"
                r"(PW\w+Callback),\s*(g\w+Request), NULL,\s*"
                r"CFNotificationSuspensionBehaviorDeliverImmediately\);",
                source,
            ),
            [
                ("PWStatusCallback", "gStatusRequest"),
                ("PWWakeCallback", "gWakeRequest"),
                ("PWUnlockCallback", "gUnlockRequest"),
            ],
        )
        self.assertEqual(
            re.findall(
                r"static void (PW\w+Callback)\([^)]*\)\s*\{\s*"
                r"PWHandle\(\[NSString stringWithUTF8String:(PWRequest\w+)\]\);\s*\}",
                source,
            ),
            [
                ("PWStatusCallback", "PWRequestStatus"),
                ("PWWakeCallback", "PWRequestWake"),
                ("PWUnlockCallback", "PWRequestUnlock"),
            ],
        )
        self.assertEqual(
            re.findall(
                r"(g\w+Request) = CFStringCreateWithCString\(\s*"
                r"NULL, (PWRequest\w+), kCFStringEncodingUTF8\);",
                source,
            ),
            [
                ("gStatusRequest", "PWRequestStatus"),
                ("gWakeRequest", "PWRequestWake"),
                ("gUnlockRequest", "PWRequestUnlock"),
            ],
        )

    def test_constructor_validates_complete_setup_before_registration(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        self.assertIn("%ctor", source)
        self.assertIn("%dtor", source)
        ctor = source[source.index("%ctor") : source.index("%dtor")]
        bundle_check = ctor.index(
            '[[NSBundle mainBundle].bundleIdentifier isEqualToString:'
            '@"com.apple.springboard"]'
        )
        token_registration = ctor.index("notify_register_check")
        observer_registration = ctor.index("CFNotificationCenterAddObserver")
        initial_publish = ctor.rindex("PWPublish();")
        self.assertLess(bundle_check, token_registration)
        self.assertLess(token_registration, observer_registration)
        self.assertLess(observer_registration, initial_publish)
        self.assertRegex(
            ctor,
            r"if \(!center \|\| !gStatusRequest \|\| !gWakeRequest\s*"
            r"\|\| !gUnlockRequest\)\s*\{\s*PWCleanup\(\);\s*return;\s*\}",
        )
        self.assertEqual(ctor.count("PWPublish();"), 1)

    def test_destructor_removes_observers_releases_names_and_resets_state(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        cleanup = re.search(
            r"(?s)static void PWCleanup\(void\)\s*\{(.*?)\n\}", source
        )
        self.assertIsNotNone(cleanup)
        body = cleanup.group(1)
        self.assertEqual(body.count("CFNotificationCenterRemoveEveryObserver"), 1)
        for request in ("gStatusRequest", "gWakeRequest", "gUnlockRequest"):
            self.assertRegex(
                body,
                rf"if \({request} != NULL\)\s*\{{\s*CFRelease\({request}\);\s*"
                rf"{request} = NULL;\s*\}}",
            )
        self.assertRegex(
            body,
            r"if \(gStateToken >= 0\)\s*\{\s*notify_cancel\(gStateToken\);\s*"
            r"gStateToken = -1;\s*\}",
        )
        for reset in (
            "gGeneration = 0;",
            "gLastSucceeded = NO;",
            "gLastRefused = NO;",
            "gPendingHead = 0;",
            "gPendingCount = 0;",
            "gRequestActive = NO;",
        ):
            self.assertIn(reset, body)
        dtor = source[source.index("%dtor") :]
        self.assertRegex(dtor, r"%dtor\s*\{\s*@autoreleasepool\s*\{\s*PWCleanup\(\);\s*\}\s*\}")

    def test_tweak_source_has_no_interactive_or_remote_control_surface(self) -> None:
        source = "\n".join(
            (ROOT / path).read_text(encoding="utf-8")
            for path in ("PhoneWakeProtocol.h", "Tweak.xm")
        )
        forbidden = re.compile(
            r"\b(?:attemptUnlockWithPasscode|passcodeEntry|password|PIN|"
            r"evaluatePolicy|SecItem|Keychain|NSURLSession|CFStream|"
            r"socket|listener|port|bind|listen|accept|connect|send|recv|"
            r"stringWithFormat|CFNotificationCenterGetDistributedCenter)\b",
            re.IGNORECASE,
        )
        self.assertIsNone(forbidden.search(source))


if __name__ == "__main__":
    unittest.main(verbosity=2)
