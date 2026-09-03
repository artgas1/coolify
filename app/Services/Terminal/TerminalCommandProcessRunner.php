<?php

namespace App\Services\Terminal;

use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process;

class TerminalCommandProcessRunner
{
    public const OUTPUT_LIMIT_BYTES = 65_536;

    public const LOCAL_PROCESS_GRACE_SECONDS = 2;

    public const CLEANUP_GRACE_SECONDS = 1;

    private const TRUNCATION_MARKER = "\n[... Output truncated at 65536 bytes ...]";

    /**
     * @param  array<int, string>  $argv
     * @return array{exit_code: int, stdout: string, stderr: string, duration_ms: int, stdout_bytes: int, stderr_bytes: int, stdout_truncated: bool, stderr_truncated: bool}
     */
    public function run(array $argv, string $stdin, int $timeout): array
    {
        $stdout = '';
        $stderr = '';
        $stdoutBytes = 0;
        $stderrBytes = 0;
        $process = new Process($argv);
        $process->setInput($stdin);
        $process->setTimeout(self::localProcessTimeoutSeconds($timeout));
        $startedAt = hrtime(true);

        try {
            $process->run(function (string $type, string $chunk) use ($process, &$stdout, &$stderr, &$stdoutBytes, &$stderrBytes): void {
                if ($type === Process::OUT) {
                    $this->captureChunk($stdout, $stdoutBytes, $chunk);
                    $process->clearOutput();

                    return;
                }

                $this->captureChunk($stderr, $stderrBytes, $chunk);
                $process->clearErrorOutput();
            });
            $exitCode = $process->getExitCode() ?? 1;
            if ($exitCode === 124 && $stderrBytes === 0) {
                $this->captureChunk($stderr, $stderrBytes, "Command timed out after {$timeout} seconds.\n");
            }
        } catch (ProcessTimedOutException) {
            if ($process->isRunning()) {
                $process->stop(self::CLEANUP_GRACE_SECONDS, 9);
            }
            $exitCode = 124;
            if ($stderrBytes === 0) {
                $this->captureChunk($stderr, $stderrBytes, "Command timed out after {$timeout} seconds.\n");
            }
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
        ];
    }

    public static function localProcessTimeoutSeconds(int $remoteTimeout): int
    {
        return $remoteTimeout + self::LOCAL_PROCESS_GRACE_SECONDS;
    }

    public static function maximumSupervisionSeconds(int $remoteTimeout): int
    {
        return self::localProcessTimeoutSeconds($remoteTimeout) + self::CLEANUP_GRACE_SECONDS;
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
