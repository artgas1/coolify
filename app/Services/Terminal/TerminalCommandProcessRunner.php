<?php

namespace App\Services\Terminal;

use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process;

class TerminalCommandProcessRunner
{
    public const OUTPUT_LIMIT_BYTES = 65_536;

    public const REMOTE_KILL_GRACE_SECONDS = 1;

    public const LOCAL_EMERGENCY_BUFFER_SECONDS = 2;

    private const TRUNCATION_MARKER = "\n[... Output truncated at 65536 bytes ...]";

    /**
     * @param  array<int, string>  $argv
     * @return array{exit_code: int, stdout: string, stderr: string, duration_ms: int, stdout_bytes: int, stderr_bytes: int, stdout_truncated: bool, stderr_truncated: bool, timed_out: bool}
     */
    public function run(
        array $argv,
        string $stdin,
        int $timeout,
        int $connectionTimeout = 0,
        string $timeoutMarker = '',
        string $completionMarker = '',
    ): array {
        $stdout = '';
        $stderr = '';
        $stdoutBytes = 0;
        $stderrBytes = 0;
        $stderrPending = '';
        $timeoutMarkerDetected = false;
        $completionMarkerDetected = false;
        $localWatchdogExpired = false;
        $process = new Process($argv);
        $process->setInput($stdin);
        $process->setTimeout(self::localProcessTimeoutSeconds($timeout, $connectionTimeout));
        $startedAt = hrtime(true);

        try {
            $process->run(function (string $type, string $chunk) use ($process, $timeoutMarker, $completionMarker, &$stdout, &$stderr, &$stdoutBytes, &$stderrBytes, &$stderrPending, &$timeoutMarkerDetected, &$completionMarkerDetected): void {
                if ($type === Process::OUT) {
                    $this->captureChunk($stdout, $stdoutBytes, $chunk);
                    $process->clearOutput();

                    return;
                }

                $this->captureStderrChunk(
                    buffer: $stderr,
                    totalBytes: $stderrBytes,
                    chunk: $chunk,
                    timeoutMarker: $timeoutMarker,
                    completionMarker: $completionMarker,
                    pending: $stderrPending,
                    timeoutMarkerDetected: $timeoutMarkerDetected,
                    completionMarkerDetected: $completionMarkerDetected,
                );
                $process->clearErrorOutput();
            });
            $exitCode = $process->getExitCode() ?? 1;
        } catch (ProcessTimedOutException) {
            $exitCode = 124;
            $localWatchdogExpired = true;
        }

        if ($stderrPending !== '') {
            $this->captureChunk($stderr, $stderrBytes, $stderrPending);
        }

        $remoteTimeoutDetected = $timeoutMarkerDetected && ! $completionMarkerDetected;
        $timedOut = $remoteTimeoutDetected || $localWatchdogExpired;
        if ($remoteTimeoutDetected) {
            $exitCode = 124;
        }
        if ($timedOut && $stderrBytes === 0) {
            $this->captureChunk($stderr, $stderrBytes, "Command timed out after {$timeout} seconds.\n");
        }

        $stdoutTruncated = $stdoutBytes > self::OUTPUT_LIMIT_BYTES;
        $stderrTruncated = $stderrBytes > self::OUTPUT_LIMIT_BYTES;

        return [
            'exit_code' => $exitCode,
            'stdout' => $this->formatOutput($stdout, $stdoutTruncated),
            'stderr' => $this->formatOutput($stderr, $stderrTruncated),
            'duration_ms' => max(0, (int) round((hrtime(true) - $startedAt) / 1_000_000)),
            'stdout_bytes' => $stdoutBytes,
            'stderr_bytes' => $stderrBytes,
            'stdout_truncated' => $stdoutTruncated,
            'stderr_truncated' => $stderrTruncated,
            'timed_out' => $timedOut,
        ];
    }

    public static function localProcessTimeoutSeconds(int $remoteTimeout, int $connectionTimeout): int
    {
        return $connectionTimeout
            + $remoteTimeout
            + self::REMOTE_KILL_GRACE_SECONDS
            + self::LOCAL_EMERGENCY_BUFFER_SECONDS;
    }

    public static function maximumSupervisionSeconds(int $remoteTimeout, int $connectionTimeout): int
    {
        return self::localProcessTimeoutSeconds($remoteTimeout, $connectionTimeout);
    }

    private function captureStderrChunk(
        string &$buffer,
        int &$totalBytes,
        string $chunk,
        string $timeoutMarker,
        string $completionMarker,
        string &$pending,
        bool &$timeoutMarkerDetected,
        bool &$completionMarkerDetected,
    ): void {
        if ($timeoutMarker === '' && $completionMarker === '') {
            $this->captureChunk($buffer, $totalBytes, $chunk);

            return;
        }

        $framedTimeoutMarker = $timeoutMarker === '' ? '' : "\n{$timeoutMarker}\n";
        $framedCompletionMarker = $completionMarker === '' ? '' : "\n{$completionMarker}\n";
        $pending .= $chunk;

        while (true) {
            $timeoutPosition = $framedTimeoutMarker === '' ? false : strpos($pending, $framedTimeoutMarker);
            $completionPosition = $framedCompletionMarker === '' ? false : strpos($pending, $framedCompletionMarker);

            if ($timeoutPosition === false && $completionPosition === false) {
                break;
            }

            $isTimeoutMarker = $completionPosition === false
                || ($timeoutPosition !== false && $timeoutPosition <= $completionPosition);
            $position = $isTimeoutMarker ? $timeoutPosition : $completionPosition;
            $framedMarker = $isTimeoutMarker ? $framedTimeoutMarker : $framedCompletionMarker;
            $this->captureChunk($buffer, $totalBytes, substr($pending, 0, $position));
            $pending = substr($pending, $position + strlen($framedMarker));
            if ($isTimeoutMarker) {
                $timeoutMarkerDetected = true;
            } else {
                $completionMarkerDetected = true;
            }
        }

        $retainedBytes = max(strlen($framedTimeoutMarker), strlen($framedCompletionMarker)) - 1;
        if (strlen($pending) > $retainedBytes) {
            $flushBytes = strlen($pending) - $retainedBytes;
            $this->captureChunk($buffer, $totalBytes, substr($pending, 0, $flushBytes));
            $pending = substr($pending, $flushBytes);
        }
    }

    private function captureChunk(string &$buffer, int &$totalBytes, string $chunk): void
    {
        $totalBytes += strlen($chunk);
        $remaining = self::OUTPUT_LIMIT_BYTES - strlen($buffer);
        if ($remaining > 0) {
            $buffer .= substr($chunk, 0, $remaining);
        }
    }

    private function formatOutput(string $output, bool &$truncated): string
    {
        $output = sanitize_utf8_text($output);
        $truncated = $truncated || strlen($output) > self::OUTPUT_LIMIT_BYTES;

        if (! $truncated) {
            return $output;
        }

        return mb_strcut(
            $output,
            0,
            self::OUTPUT_LIMIT_BYTES - strlen(self::TRUNCATION_MARKER),
            'UTF-8'
        ).self::TRUNCATION_MARKER;
    }
}
