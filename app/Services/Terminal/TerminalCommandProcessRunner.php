<?php

namespace App\Services\Terminal;

use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\InputStream;
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
        string $startMarker = '',
    ): array {
        $stdout = '';
        $stderr = '';
        $stdoutBytes = 0;
        $stderrBytes = 0;
        $stderrPending = '';
        $timeoutMarkerDetectedAt = [];
        $startMarkerDetectedAt = null;
        $payloadSent = false;
        $localWatchdogExpired = false;
        $process = new Process($argv);
        $inputStream = null;
        $payload = '';
        if ($startMarker !== '') {
            $frameSeparator = strpos($stdin, "\n");
            if ($frameSeparator === false) {
                throw new \InvalidArgumentException('Staged terminal input requires a correlation frame line.');
            }
            $inputStream = new InputStream;
            $inputStream->write(substr($stdin, 0, $frameSeparator + 1));
            $payload = substr($stdin, $frameSeparator + 1);
            $process->setInput($inputStream);
        } else {
            $process->setInput($stdin);
        }
        $process->setTimeout(self::localProcessTimeoutSeconds($timeout, $connectionTimeout));
        $startedAt = hrtime(true);

        try {
            $process->run(function (string $type, string $chunk) use ($process, $inputStream, $payload, $timeoutMarker, $startMarker, &$payloadSent, &$stdout, &$stderr, &$stdoutBytes, &$stderrBytes, &$stderrPending, &$timeoutMarkerDetectedAt, &$startMarkerDetectedAt): void {
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
                    startMarker: $startMarker,
                    pending: $stderrPending,
                    timeoutMarkerDetectedAt: $timeoutMarkerDetectedAt,
                    startMarkerDetectedAt: $startMarkerDetectedAt,
                );
                if ($startMarkerDetectedAt !== null && ! $payloadSent && $inputStream !== null) {
                    $inputStream->write($payload);
                    $inputStream->close();
                    $payloadSent = true;
                }
                $process->clearErrorOutput();
            });
            $exitCode = $process->getExitCode() ?? 1;
        } catch (ProcessTimedOutException) {
            $exitCode = 124;
            $localWatchdogExpired = true;
        } finally {
            if ($inputStream !== null && ! $inputStream->isClosed()) {
                $inputStream->close();
            }
        }

        if ($stderrPending !== '') {
            $this->captureChunk($stderr, $stderrBytes, $stderrPending);
        }

        $finishedAt = hrtime(true);
        $remoteTimeoutDetected = false;
        if ($startMarkerDetectedAt !== null && in_array($exitCode, [137, 143], true)) {
            $deadline = $startMarkerDetectedAt + ($timeout * 1_000_000_000);
            foreach ($timeoutMarkerDetectedAt as $detectedAt) {
                if ($detectedAt >= $deadline) {
                    $remoteTimeoutDetected = true;
                    break;
                }
            }
        }
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
            'duration_ms' => max(0, (int) round(($finishedAt - $startedAt) / 1_000_000)),
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

    /**
     * @param  array<int, int>  $timeoutMarkerDetectedAt
     */
    private function captureStderrChunk(
        string &$buffer,
        int &$totalBytes,
        string $chunk,
        string $timeoutMarker,
        string $startMarker,
        string &$pending,
        array &$timeoutMarkerDetectedAt,
        ?int &$startMarkerDetectedAt,
    ): void {
        if ($timeoutMarker === '' && $startMarker === '') {
            $this->captureChunk($buffer, $totalBytes, $chunk);

            return;
        }

        $framedTimeoutMarker = $timeoutMarker === '' ? '' : "\n{$timeoutMarker}\n";
        $framedStartMarker = $startMarker === '' ? '' : "\n{$startMarker}\n";
        $pending .= $chunk;

        while (true) {
            $timeoutPosition = $framedTimeoutMarker === '' ? false : strpos($pending, $framedTimeoutMarker);
            $startPosition = $framedStartMarker === '' ? false : strpos($pending, $framedStartMarker);

            if ($timeoutPosition === false && $startPosition === false) {
                break;
            }

            $isTimeoutMarker = $startPosition === false
                || ($timeoutPosition !== false && $timeoutPosition <= $startPosition);
            $position = $isTimeoutMarker ? $timeoutPosition : $startPosition;
            $framedMarker = $isTimeoutMarker ? $framedTimeoutMarker : $framedStartMarker;
            $this->captureChunk($buffer, $totalBytes, substr($pending, 0, $position));
            $pending = substr($pending, $position + strlen($framedMarker));
            if ($isTimeoutMarker) {
                $timeoutMarkerDetectedAt[] = hrtime(true);
            } elseif ($startMarkerDetectedAt === null) {
                $startMarkerDetectedAt = hrtime(true);
            }
        }

        $retainedBytes = max(strlen($framedTimeoutMarker), strlen($framedStartMarker)) - 1;
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
