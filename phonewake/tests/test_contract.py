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
PW_REQUEST_REJECTED = 1 << 20
PW_GENERATION_SHIFT = 32
PW_KNOWN_FLAG_MASK = (
    PW_AVAILABLE
    | PW_COMPATIBLE
    | PW_DISPLAY_ON
    | PW_LOCKED
    | PW_PASSCODE_SET
    | PW_PASSCODE_UNKNOWN
    | PW_LAST_REQUEST_SUCCEEDED
    | PW_LAST_REQUEST_REFUSED
    | PW_CHARGING
    | PW_BATTERY_MASK
    | PW_THERMAL_MASK
    | PW_BATTERY_UNKNOWN
    | PW_REQUEST_REJECTED
)
FIXED_RESPONSES = {
    "status": "com.mudkipsol.phonewake.response.status",
    "wake": "com.mudkipsol.phonewake.response.wake",
    "unlock": "com.mudkipsol.phonewake.response.unlock",
}
POLL_SECONDS = 0.05
DEADLINE_SECONDS = 2.0
SETTLE_SECONDS = 0.25
QUEUE_CAPACITY = 6


def encode_response(ticket: int, flags: int) -> int:
    return (ticket << PW_GENERATION_SHIFT) | flags


def decode_cli_response(
    response_value: int,
    expected_ticket: int,
    global_value: int,
    starting_generation: int,
) -> dict[str, object]:
    ticket = response_value >> PW_GENERATION_SHIFT
    generation = global_value >> PW_GENERATION_SHIFT
    flags = response_value & 0xFFFFFFFF
    succeeded = bool(flags & PW_LAST_REQUEST_SUCCEEDED)
    refused = bool(flags & PW_LAST_REQUEST_REFUSED)
    rejected = bool(flags & PW_REQUEST_REJECTED)
    passcode_set = bool(flags & PW_PASSCODE_SET)
    passcode_unknown = bool(flags & PW_PASSCODE_UNKNOWN)
    battery_unknown = bool(flags & PW_BATTERY_UNKNOWN)
    battery_percent = (flags & PW_BATTERY_MASK) >> PW_BATTERY_SHIFT
    thermal_index = (flags & PW_THERMAL_MASK) >> PW_THERMAL_SHIFT

    if expected_ticket == 0 or ticket != expected_ticket:
        raise TimeoutError("response ticket did not match")
    if generation == starting_generation:
        raise ValueError("generation did not change")
    if flags & (~PW_KNOWN_FLAG_MASK & 0xFFFFFFFF):
        raise ValueError("reserved flags are set")
    if sum((succeeded, refused, rejected)) > 1:
        raise ValueError("outcome flags conflict")
    if passcode_set and passcode_unknown:
        raise ValueError("passcode flags conflict")
    if not battery_unknown and battery_percent > 100:
        raise ValueError("battery percent is invalid")
    if battery_unknown and battery_percent != 0:
        raise ValueError("unknown battery has a payload")
    if thermal_index > 3:
        raise ValueError("thermal state is invalid")

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
            "request rejected"
            if rejected
            else "passcode present or unknown"
            if refused
            else "ok"
            if succeeded
            else "request failed"
        ),
    }


def client_matches_response(
    command: str,
    ticket: int,
    response_name: str,
    response_value: int,
    global_value: int,
    starting_generation: int,
) -> bool:
    if response_name != FIXED_RESPONSES[command]:
        return False
    try:
        decode_cli_response(
            response_value,
            ticket,
            global_value,
            starting_generation,
        )
    except TimeoutError:
        return False
    return True


def next_poll_delay(now: float, deadline: float) -> float | None:
    remaining = deadline - now
    if remaining <= 0:
        return None
    return min(POLL_SECONDS, remaining)


def output_exit_code(
    body_written: int,
    body_length: int,
    newline_written: int,
    flush_status: int,
    stream_error: bool,
) -> int:
    complete = (
        body_written == body_length
        and newline_written == 1
        and flush_status == 0
        and not stream_error
    )
    return 0 if complete else 70


def cancel_registered_tokens(
    tokens: list[int], cancel_results: dict[int, bool]
) -> tuple[list[int], bool]:
    cancelled: list[int] = []
    succeeded = True
    for token in tokens:
        if token < 0:
            continue
        cancelled.append(token)
        if not cancel_results[token]:
            succeeded = False
    return cancelled, succeeded


class RequestLifecycleModel:
    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.active: tuple[str, int, bool, bool] | None = None
        self.pending: list[tuple[str, int, bool, bool]] = []
        self.publications: list[tuple[str, int, bool, bool, bool]] = []

    def accept(
        self,
        request: str,
        ticket: int,
        *,
        action_started: bool = True,
        refused: bool = False,
    ) -> bool:
        if len(self.pending) + (self.active is not None) >= self.capacity:
            self.publications.append((request, ticket, False, False, True))
            return False
        item = (request, ticket, action_started, refused)
        if self.active is None:
            self.active = item
        else:
            self.pending.append(item)
        return True

    def settle(self, *, display_on: bool = False, locked: bool = True) -> None:
        if self.active is None:
            return
        request, ticket, action_started, refused = self.active
        succeeded = (
            not refused
            and action_started
            and (
                request == "status"
                or (request == "wake" and display_on)
                or (request == "unlock" and display_on and not locked)
            )
        )
        self.publications.append(
            (request, ticket, succeeded, refused and not succeeded, False)
        )
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
                r'if \(\[command isEqualToString:@"(\w+)"\]\)\s*\{\s*'
                r"\*requestName = (PWRequest\w+);\s*"
                r"\*responseName = (PWResponse\w+);\s*return YES;\s*\}",
                source,
            ),
            [
                ("status", "PWRequestStatus", "PWResponseStatus"),
                ("wake", "PWRequestWake", "PWResponseWake"),
                ("unlock", "PWRequestUnlock", "PWResponseUnlock"),
            ],
        )
        self.assertRegex(
            source,
            r"initWithBytes:argv\[1\]\s*length:strlen\(argv\[1\]\)\s*"
            r"encoding:NSUTF8StringEncoding",
        )
        main = source[source.index("int main(") :]
        self.assertLess(main.index("argc != 2"), main.index("PWRegisterToken"))
        self.assertLess(main.index("PWNamesForCommand"), main.index("notify_post"))

    def test_cli_stores_nonzero_ticket_posts_once_and_requires_correlated_state(
        self,
    ) -> None:
        source = (ROOT / "main.mm").read_text(encoding="utf-8")
        self.assertEqual(source.count("notify_post("), 1)
        self.assertIn("arc4random_uniform(UINT32_MAX) + 1u", source)
        self.assertRegex(
            source,
            r"notify_set_state\(requestToken, ticket\)\s*!= NOTIFY_STATUS_OK",
        )
        self.assertIn("PWDecodeGeneration(startingState)", source)
        self.assertIn("PWDecodeGeneration(globalState)", source)
        self.assertIn("PWDecodeResponseTicket(responseState) == ticket", source)
        self.assertIn("PWDecodeResponseFlags(responseState)", source)
        self.assertNotIn("PWDecodeFlags(globalState)", source)
        sequence = [
            source.index("notify_set_state(requestToken, ticket)"),
            source.index("notify_post(requestName)"),
            source.index("PWDecodeResponseTicket(responseState) == ticket"),
            source.index("PWDecodeResponseFlags(responseState)"),
        ]
        self.assertEqual(sequence, sorted(sequence))

    def test_cli_uses_monotonic_absolute_deadline_and_bounded_poll_sleeps(
        self,
    ) -> None:
        source = (ROOT / "main.mm").read_text(encoding="utf-8")
        self.assertIn("clock_gettime(CLOCK_MONOTONIC", source)
        self.assertIn("static const int64_t PWPollNanoseconds = 50000000LL;", source)
        self.assertIn("static const time_t PWDeadlineSeconds = 2;", source)
        self.assertIn("deadline.tv_sec += PWDeadlineSeconds;", source)
        self.assertIn("PWNanosecondsUntil(deadline, now)", source)
        self.assertIn("MIN(remaining, PWPollNanoseconds)", source)
        self.assertIn("nanosleep(&sleepTime, NULL)", source)
        self.assertIn("errno != EINTR", source)
        self.assertNotIn("usleep", source)

    def test_cli_rechecks_deadline_after_state_reads_before_ticket_match(
        self,
    ) -> None:
        source = (ROOT / "main.mm").read_text(encoding="utf-8")
        polling = source[
            source.index("while (!matchedResponse)") :
            source.index("if (pollFailed)")
        ]
        for text in (
            "notify_get_state(responseToken, &responseState)",
            "notify_get_state(stateToken, &globalState)",
            "clock_gettime(CLOCK_MONOTONIC, &observedAt)",
            "PWNanosecondsUntil(deadline, observedAt) <= 0",
            "PWDecodeResponseTicket(responseState) == ticket",
        ):
            self.assertIn(text, polling)
        sequence = [polling.index(text) for text in (
            "notify_get_state(responseToken, &responseState)",
            "notify_get_state(stateToken, &globalState)",
            "clock_gettime(CLOCK_MONOTONIC, &observedAt)",
            "PWNanosecondsUntil(deadline, observedAt) <= 0",
            "PWDecodeResponseTicket(responseState) == ticket",
        )]
        self.assertEqual(sequence, sorted(sequence))

    def test_cli_checks_all_notify_calls_and_cleans_all_three_tokens(self) -> None:
        source = (ROOT / "main.mm").read_text(encoding="utf-8")
        for registration in (
            "PWRegisterToken(requestName, &requestToken)",
            "PWRegisterToken(responseName, &responseToken)",
            "PWRegisterToken(PWStateNotification, &stateToken)",
        ):
            self.assertIn(registration, source)
        self.assertRegex(
            source,
            r"notify_register_check\(name, token\)\s*== NOTIFY_STATUS_OK",
        )
        for state_read in (
            "notify_get_state(stateToken, &startingState)",
            "notify_get_state(responseToken, &startingResponse)",
            "notify_get_state(responseToken, &responseState)",
            "notify_get_state(stateToken, &globalState)",
        ):
            self.assertIn(state_read, source)
        self.assertIn("notify_set_state(requestToken, ticket)", source)
        self.assertIn("notify_post(requestName)", source)
        self.assertRegex(
            source,
            r"int status = notify_cancel\(\*token\);\s*\*token = -1;\s*"
            r"return status == NOTIFY_STATUS_OK;",
        )
        cleanup = source[source.index("BOOL cleanupSucceeded") :]
        for token in ("requestToken", "responseToken", "stateToken"):
            self.assertIn(f"if (!PWCancelToken(&{token}))", cleanup)
        main = source[source.index("int main(") :]
        registration = main.index("PWRegisterToken")
        cleanup_start = main.index("BOOL cleanupSucceeded")
        self.assertNotIn("return", main[registration:cleanup_start])

    def test_cli_validates_correlated_flags_before_emitting_exact_json(self) -> None:
        source = (ROOT / "main.mm").read_text(encoding="utf-8")
        self.assertIn("static BOOL PWFlagsAreValid", source)
        validation = source[
            source.index("static BOOL PWFlagsAreValid") : source.index("int main(")
        ]
        self.assertIn("flags & ~PWKnownFlagMask", validation)
        self.assertIn("outcomeCount > 1u", validation)
        self.assertIn("passcodeSet && passcodeUnknown", validation)
        self.assertIn("!batteryUnknown && batteryPercent > 100u", validation)
        self.assertIn("batteryUnknown && batteryPercent != 0u", validation)
        self.assertIn("thermalState > 3u", validation)

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
        for reason in (
            "request rejected",
            "passcode present or unknown",
            "ok",
            "request failed",
        ):
            self.assertIn(f'@"{reason}"', result_block)

    def test_cli_checks_complete_one_line_json_output_before_success(self) -> None:
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
        self.assertIn("size_t bodyWritten = fwrite", source)
        self.assertIn("size_t newlineWritten = fwrite", source)
        self.assertIn("int flushStatus = fflush(stdout);", source)
        self.assertIn("ferror(stdout)", source)
        self.assertIn("bodyWritten != json.length", source)
        self.assertIn("newlineWritten != 1u", source)
        output_failure = source.index("bodyWritten != json.length")
        success = source.rindex("return 0;")
        self.assertLess(output_failure, success)
        self.assertNotIn("NSJSONWritingPrettyPrinted", source)
        main = source[source.index("int main(") :]
        self.assertLess(main.index("PWCancelToken"), main.index("exitCode != 0"))
        self.assertLess(main.index("exitCode != 0"), main.index("fwrite("))

    def test_cli_model_decodes_correlated_flags_and_exact_reasons(self) -> None:
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
        decoded = decode_cli_response(
            encode_response(41, flags),
            41,
            8 << PW_GENERATION_SHIFT,
            7,
        )
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

        refused = decode_cli_response(
            encode_response(
                42,
                PW_PASSCODE_UNKNOWN
                | PW_BATTERY_UNKNOWN
                | PW_LAST_REQUEST_REFUSED
                | (3 << PW_THERMAL_SHIFT),
            ),
            42,
            9 << PW_GENERATION_SHIFT,
            8,
        )
        self.assertIsNone(refused["passcode_set"])
        self.assertIsNone(refused["battery_level"])
        self.assertEqual(refused["thermal_state"], "critical")
        self.assertEqual(refused["reason"], "passcode present or unknown")

        rejected = decode_cli_response(
            encode_response(43, PW_REQUEST_REJECTED),
            43,
            10 << PW_GENERATION_SHIFT,
            9,
        )
        self.assertEqual(rejected["reason"], "request rejected")

        failed = decode_cli_response(
            encode_response(44, 0),
            44,
            11 << PW_GENERATION_SHIFT,
            10,
        )
        self.assertEqual(failed["reason"], "request failed")

    def test_cli_model_rejects_invalid_correlated_state(self) -> None:
        invalid_flags = {
            "reserved bit": 1 << 21,
            "conflicting outcome": (
                PW_LAST_REQUEST_SUCCEEDED | PW_LAST_REQUEST_REFUSED
            ),
            "rejected and succeeded": (
                PW_REQUEST_REJECTED | PW_LAST_REQUEST_SUCCEEDED
            ),
            "rejected and refused": PW_REQUEST_REJECTED | PW_LAST_REQUEST_REFUSED,
            "conflicting passcode": PW_PASSCODE_SET | PW_PASSCODE_UNKNOWN,
            "battery above one hundred": 101 << PW_BATTERY_SHIFT,
            "unknown battery payload": (
                PW_BATTERY_UNKNOWN | (1 << PW_BATTERY_SHIFT)
            ),
            "thermal above critical": 4 << PW_THERMAL_SHIFT,
        }
        for name, flags in invalid_flags.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                decode_cli_response(
                    encode_response(50, flags),
                    50,
                    5 << PW_GENERATION_SHIFT,
                    4,
                )
        with self.assertRaises(ValueError):
            decode_cli_response(encode_response(50, 0), 50, 4 << 32, 4)

    def test_concurrent_command_tickets_cannot_cross_match(self) -> None:
        advanced = 2 << PW_GENERATION_SHIFT
        status_response = encode_response(101, PW_LAST_REQUEST_SUCCEEDED)
        unlock_response = encode_response(202, PW_LAST_REQUEST_REFUSED)
        self.assertTrue(
            client_matches_response(
                "status",
                101,
                FIXED_RESPONSES["status"],
                status_response,
                advanced,
                1,
            )
        )
        self.assertFalse(
            client_matches_response(
                "unlock",
                202,
                FIXED_RESPONSES["status"],
                status_response,
                advanced,
                1,
            )
        )
        self.assertTrue(
            client_matches_response(
                "unlock",
                202,
                FIXED_RESPONSES["unlock"],
                unlock_response,
                advanced,
                1,
            )
        )

    def test_same_command_ticket_overwrite_only_times_out_older_client(self) -> None:
        response_slot = encode_response(302, PW_LAST_REQUEST_SUCCEEDED)
        advanced = 7 << PW_GENERATION_SHIFT
        self.assertFalse(
            client_matches_response(
                "wake",
                301,
                FIXED_RESPONSES["wake"],
                response_slot,
                advanced,
                6,
            )
        )
        self.assertTrue(
            client_matches_response(
                "wake",
                302,
                FIXED_RESPONSES["wake"],
                response_slot,
                advanced,
                6,
            )
        )

    def test_monotonic_deadline_boundary_and_queue_budget(self) -> None:
        self.assertEqual(next_poll_delay(10.0, 12.0), POLL_SECONDS)
        self.assertAlmostEqual(next_poll_delay(11.98, 12.0), 0.02)
        self.assertIsNone(next_poll_delay(12.0, 12.0))
        self.assertIsNone(next_poll_delay(12.01, 12.0))
        self.assertLess(QUEUE_CAPACITY * SETTLE_SECONDS, DEADLINE_SECONDS)
        self.assertEqual(QUEUE_CAPACITY * SETTLE_SECONDS, 1.5)

    def test_partial_output_or_flush_failure_cannot_return_success(self) -> None:
        self.assertEqual(output_exit_code(12, 12, 1, 0, False), 0)
        for case in (
            (11, 12, 1, 0, False),
            (12, 12, 0, 0, False),
            (12, 12, 1, -1, False),
            (12, 12, 1, 0, True),
        ):
            with self.subTest(case=case):
                self.assertEqual(output_exit_code(*case), 70)

    def test_cleanup_model_cancels_every_registered_token_after_each_failure(
        self,
    ) -> None:
        all_tokens = [11, 12, 13]
        for registered_count in range(4):
            tokens = all_tokens[:registered_count] + [-1] * (3 - registered_count)
            cancelled, succeeded = cancel_registered_tokens(
                tokens,
                {token: True for token in all_tokens},
            )
            self.assertEqual(cancelled, all_tokens[:registered_count])
            self.assertTrue(succeeded)
        cancelled, succeeded = cancel_registered_tokens(
            all_tokens,
            {11: False, 12: True, 13: False},
        )
        self.assertEqual(cancelled, all_tokens)
        self.assertFalse(succeeded)

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

    def test_protocol_exposes_exact_fixed_request_and_response_names(self) -> None:
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
        responses = re.findall(
            r'^static const char \*(PWResponse\w+) = "([^"]+)";$',
            source,
            re.MULTILINE,
        )
        self.assertEqual(
            responses,
            [
                ("PWResponseStatus", "com.mudkipsol.phonewake.response.status"),
                ("PWResponseWake", "com.mudkipsol.phonewake.response.wake"),
                ("PWResponseUnlock", "com.mudkipsol.phonewake.response.unlock"),
            ],
        )
        self.assertEqual(len({name for name, _ in responses}), 3)
        self.assertEqual(len({value for _, value in responses}), 3)
        self.assertTrue(
            {value for _, value in requests}.isdisjoint(
                {value for _, value in responses}
            )
        )
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
        self.assertIn("PWEncodeResponse(uint32_t ticket, uint32_t flags)", source)
        self.assertIn("PWDecodeResponseTicket(uint64_t value)", source)
        self.assertIn("PWDecodeResponseFlags(uint64_t value)", source)
        self.assertIn(
            "((uint64_t)ticket << PWResponseTicketShift) | flags", source
        )
        self.assertIn("value >> PWResponseTicketShift", source)
        self.assertIn("value & PWResponseFlagMask", source)

    def test_state_has_unknown_refused_and_rejected_bits(self) -> None:
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
        self.assertIn("PWRequestRejected", flag_bits)
        self.assertEqual(flag_bits["PWRequestRejected"], 20)
        self.assertEqual(len(flag_bits), 11)

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
        self.assertIn("PWKnownFlagMask", source)
        self.assertEqual(PW_KNOWN_FLAG_MASK & (1 << 21), 0)

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
            "static BOOL gLastRejected = NO;",
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
            "PWRequestRejected",
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
        self.assertIn("static BOOL PWPublish(uint32_t *publishedFlags)", source)
        publish = source[
            source.index("static BOOL PWPublish(uint32_t *publishedFlags)") :
            source.index("static BOOL PWWakeDisplay")
        ]
        guard = re.match(
            r"static BOOL PWPublish\(uint32_t \*publishedFlags\)\s*\{\s*"
            r"if \(!\[NSThread isMainThread\]\)\s*\{\s*"
            r"__block BOOL published = NO;\s*"
            r"dispatch_sync\(dispatch_get_main_queue\(\),\s*\^\{\s*"
            r"published = PWPublish\(publishedFlags\);\s*\}\);\s*"
            r"return published;\s*\}\s*",
            publish,
        )
        self.assertIsNotNone(guard)
        guarded_publish = publish[guard.end() :]
        self.assertRegex(guarded_publish, r"^if \(gStateToken < 0\) return NO;")
        for state_work in (
            "gStateToken",
            "PWReadPasscodeState()",
            "PWIsCompatible()",
            "PWReadDisplayOn()",
            "PWReadLocked()",
            "gLastSucceeded",
            "gLastRefused",
            "gLastRejected",
            "[UIDevice currentDevice]",
            "gGeneration",
            "notify_set_state",
            "notify_post",
        ):
            self.assertIn(state_work, guarded_publish)

    def test_publish_commits_generation_only_after_notify_state_succeeds(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        self.assertIn("static BOOL PWPublish(uint32_t *publishedFlags)", source)
        publish = source[
            source.index("static BOOL PWPublish(uint32_t *publishedFlags)") :
            source.index("static BOOL PWWakeDisplay")
        ]
        self.assertNotIn("gGeneration += 1;", publish)
        self.assertRegex(
            publish,
            r"(?s)uint32_t candidateGeneration = gGeneration \+ 1u;\s*"
            r"if \(notify_set_state\(gStateToken,\s*"
            r"PWEncodeState\(candidateGeneration, flags\)\)\s*"
            r"!= NOTIFY_STATUS_OK\)\s*\{\s*"
            r"NSLog\(@\"PhoneWake publication failed\"\);\s*"
            r"return NO;\s*\}\s*"
            r"gGeneration = candidateGeneration;\s*"
            r"if \(notify_post\(PWStateNotification\) != NOTIFY_STATUS_OK\)\s*\{\s*"
            r"NSLog\(@\"PhoneWake notification failed\"\);\s*"
            r"return NO;\s*\}\s*"
            r"if \(publishedFlags\) \*publishedFlags = flags;\s*return YES;",
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
        self.assertIn(
            "PWCompleteRequest(request, succeeded, refused && !succeeded, NO);",
            source,
        )
        self.assertNotIn("evaluatePolicy:", source)

    def test_request_handler_uses_bounded_main_queue_fifo(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        handler = re.search(
            r"(?s)static void PWHandle\(PWRequestKind kind, int requestToken\)\s*"
            r"\{(.*?)\n\}",
            source,
        )
        self.assertIsNotNone(handler)
        body = handler.group(1)
        self.assertRegex(
            body,
            r"^\s*if \(!\[NSThread isMainThread\]\)\s*\{\s*"
            r"dispatch_sync\(dispatch_get_main_queue\(\),\s*\^\{\s*"
            r"PWHandle\(kind, requestToken\);\s*\}\);\s*return;\s*\}",
        )
        self.assertIn("notify_get_state(requestToken, &requestState)", body)
        self.assertRegex(
            body,
            r"notify_get_state\(requestToken, &requestState\)\s*"
            r"!= NOTIFY_STATUS_OK",
        )
        self.assertIn("uint32_t ticket = (uint32_t)requestState;", body)
        self.assertIn("ticket == 0u || requestState != (uint64_t)ticket", body)
        self.assertIn("PWQueuedRequest request = {kind, ticket};", body)
        self.assertIn("if (!PWEnqueueRequest(request))", body)
        self.assertIn("PWCompleteRequest(request, NO, NO, YES);", body)
        self.assertIn("PWStartNextRequest();", body)

        self.assertIn("static const uint8_t PWMaxOutstandingRequests = 6;", source)
        self.assertIn(
            "static PWQueuedRequest gPendingRequests[PWMaxOutstandingRequests];",
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

    def test_tweak_publishes_matching_ticketed_response_after_global_state(
        self,
    ) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        self.assertIn("static BOOL PWPublishResponse", source)
        self.assertIn("static void PWCompleteRequest", source)
        response = source[
            source.index("static BOOL PWPublishResponse") :
            source.index("static void PWCompleteRequest")
        ]
        for response_name, response_token in (
            ("PWResponseStatus", "gStatusResponseToken"),
            ("PWResponseWake", "gWakeResponseToken"),
            ("PWResponseUnlock", "gUnlockResponseToken"),
        ):
            self.assertIn(response_name, response)
            self.assertIn(response_token, response)
        self.assertIn(
            "notify_set_state(responseToken, PWEncodeResponse(ticket, flags))",
            response,
        )
        self.assertIn("notify_post(responseName)", response)
        self.assertRegex(
            response,
            r"notify_set_state\(responseToken, PWEncodeResponse\(ticket, flags\)\)\s*"
            r"!= NOTIFY_STATUS_OK",
        )
        self.assertRegex(
            response,
            r"notify_post\(responseName\)\s*!= NOTIFY_STATUS_OK",
        )

        completion = source[
            source.index("static void PWCompleteRequest") :
            source.index("static void PWStartNextRequest")
        ]
        sequence = [
            completion.index("gLastSucceeded = succeeded;"),
            completion.index("gLastRefused = refused;"),
            completion.index("gLastRejected = rejected;"),
            completion.index("PWPublish(&flags)"),
            completion.index(
                "PWPublishResponse(request.kind, request.ticket, flags)"
            ),
        ]
        self.assertEqual(sequence, sorted(sequence))

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
            r"request\.kind, actionStarted, displayOn, locked\);",
        )
        sequence = [
            completion.index(
                "PWCompleteRequest(request, succeeded, refused && !succeeded, NO);"
            ),
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
        model = RequestLifecycleModel(capacity=6)
        self.assertTrue(
            model.accept("unlock", 501, action_started=False, refused=True)
        )
        self.assertTrue(model.accept("status", 502))
        self.assertEqual(model.publications, [])

        model.settle(display_on=False, locked=True)
        self.assertEqual(
            model.publications,
            [("unlock", 501, False, True, False)],
        )

        model.settle(display_on=False, locked=True)
        self.assertEqual(
            model.publications,
            [
                ("unlock", 501, False, True, False),
                ("status", 502, True, False, False),
            ],
        )

    def test_selector_no_op_and_still_locked_requests_fail(self) -> None:
        wake = RequestLifecycleModel(capacity=6)
        self.assertTrue(wake.accept("wake", 601, action_started=True))
        wake.settle(display_on=False)
        self.assertEqual(
            wake.publications,
            [("wake", 601, False, False, False)],
        )

        unlock = RequestLifecycleModel(capacity=6)
        self.assertTrue(unlock.accept("unlock", 602, action_started=True))
        unlock.settle(display_on=True, locked=True)
        self.assertEqual(
            unlock.publications,
            [("unlock", 602, False, False, False)],
        )

    def test_request_queue_overflow_yields_correlated_rejected_response(self) -> None:
        model = RequestLifecycleModel(capacity=3)
        self.assertTrue(model.accept("status", 701))
        self.assertTrue(model.accept("wake", 702))
        self.assertTrue(model.accept("unlock", 703))
        self.assertFalse(model.accept("status", 704))
        self.assertEqual(len(model.pending), 2)
        self.assertEqual(
            model.publications,
            [("status", 704, False, False, True)],
        )

        model.settle()
        model.settle(display_on=True)
        model.settle(display_on=True, locked=False)
        self.assertEqual(len(model.publications), 4)
        self.assertEqual(
            {publication[1] for publication in model.publications},
            {701, 702, 703, 704},
        )

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
                r"PWHandle\((PWRequestKind\w+), (g\w+RequestToken)\);\s*\}",
                source,
            ),
            [
                ("PWStatusCallback", "PWRequestKindStatus", "gStatusRequestToken"),
                ("PWWakeCallback", "PWRequestKindWake", "gWakeRequestToken"),
                ("PWUnlockCallback", "PWRequestKindUnlock", "gUnlockRequestToken"),
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
        self.assertIn("PWRegisterAllTokens()", ctor)
        self.assertIn("PWPublish(&initialFlags)", ctor)
        bundle_check = ctor.index(
            '[[NSBundle mainBundle].bundleIdentifier isEqualToString:'
            '@"com.apple.springboard"]'
        )
        token_registration = ctor.index("PWRegisterAllTokens()")
        observer_registration = ctor.index("CFNotificationCenterAddObserver")
        initial_publish = ctor.rindex("PWPublish(&initialFlags)")
        self.assertLess(bundle_check, token_registration)
        self.assertLess(token_registration, observer_registration)
        self.assertLess(observer_registration, initial_publish)
        self.assertRegex(
            ctor,
            r"if \(!center \|\| !gStatusRequest \|\| !gWakeRequest\s*"
            r"\|\| !gUnlockRequest\)\s*\{\s*\(void\)PWCleanup\(\);\s*"
            r"return;\s*\}",
        )
        self.assertEqual(ctor.count("PWPublish(&initialFlags)"), 1)

        registration = source[
            source.index("static BOOL PWRegisterAllTokens") :
            source.index("static BOOL PWPublishResponse")
        ]
        self.assertIn(
            "notify_register_check(name, token) == NOTIFY_STATUS_OK",
            source,
        )
        for name, token in (
            ("PWStateNotification", "gStateToken"),
            ("PWRequestStatus", "gStatusRequestToken"),
            ("PWRequestWake", "gWakeRequestToken"),
            ("PWRequestUnlock", "gUnlockRequestToken"),
            ("PWResponseStatus", "gStatusResponseToken"),
            ("PWResponseWake", "gWakeResponseToken"),
            ("PWResponseUnlock", "gUnlockResponseToken"),
        ):
            self.assertIn(f"PWRegisterToken({name}, &{token})", registration)

    def test_destructor_removes_observers_releases_names_and_resets_state(self) -> None:
        source = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
        self.assertIn("static BOOL PWCleanup(void)", source)
        self.assertIn("static BOOL PWCancelToken", source)
        body = source[
            source.index("static BOOL PWCleanup(void)") : source.index("%ctor")
        ]
        cancel_helper = source[
            source.index("static BOOL PWCancelToken") :
            source.index("static BOOL PWCleanup")
        ]
        self.assertIn("int status = notify_cancel(*token);", cancel_helper)
        self.assertIn("return status == NOTIFY_STATUS_OK;", cancel_helper)
        self.assertEqual(body.count("CFNotificationCenterRemoveEveryObserver"), 1)
        for request in ("gStatusRequest", "gWakeRequest", "gUnlockRequest"):
            self.assertRegex(
                body,
                rf"if \({request} != NULL\)\s*\{{\s*CFRelease\({request}\);\s*"
                rf"{request} = NULL;\s*\}}",
            )
        for token in (
            "gStateToken",
            "gStatusRequestToken",
            "gWakeRequestToken",
            "gUnlockRequestToken",
            "gStatusResponseToken",
            "gWakeResponseToken",
            "gUnlockResponseToken",
        ):
            self.assertIn(f"if (!PWCancelToken(&{token}))", body)
        for reset in (
            "gGeneration = 0;",
            "gLastSucceeded = NO;",
            "gLastRefused = NO;",
            "gLastRejected = NO;",
            "gPendingHead = 0;",
            "gPendingCount = 0;",
            "gRequestActive = NO;",
        ):
            self.assertIn(reset, body)
        dtor = source[source.index("%dtor") :]
        self.assertRegex(
            dtor,
            r"%dtor\s*\{\s*@autoreleasepool\s*\{\s*"
            r"\(void\)PWCleanup\(\);\s*\}\s*\}",
        )

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
