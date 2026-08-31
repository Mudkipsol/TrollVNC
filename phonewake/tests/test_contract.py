from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


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
        self.assertRegex(
            source,
            r"static void PWPublish\(void\)\s*\{\s*"
            r"if \(gStateToken < 0\) return;",
        )
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
        self.assertIn("gGeneration += 1;", source)
        self.assertIn(
            "notify_set_state(gStateToken, PWEncodeState(gGeneration, flags));",
            source,
        )
        self.assertIn("notify_post(PWStateNotification);", source)
        self.assertNotRegex(source, r"notify_post\s*\(\s*@?\"")

    def test_tweak_source_has_no_interactive_or_remote_control_surface(self) -> None:
        source = "\n".join(
            (ROOT / path).read_text(encoding="utf-8")
            for path in ("PhoneWakeProtocol.h", "Tweak.xm")
        )
        forbidden = re.compile(
            r"\b(?:attemptUnlockWithPasscode|passcodeEntry|password|PIN|"
            r"evaluatePolicy|SecItem|Keychain|NSURLSession|CFStream|"
            r"socket|listener|port|bind|listen|accept|connect|send|recv)\b",
            re.IGNORECASE,
        )
        self.assertIsNone(forbidden.search(source))


if __name__ == "__main__":
    unittest.main(verbosity=2)
