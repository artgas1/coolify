<?php

namespace App\Services\Terminal;

class TerminalCommandRedactor
{
    /**
     * @param  array<int, mixed>  $knownSecrets
     */
    public function redact(string $command, array $knownSecrets = []): string
    {
        $redacted = preg_replace(
            '/-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----/is',
            '[REDACTED PRIVATE KEY]',
            $command
        ) ?? $command;

        $redacted = preg_replace('/\bBearer\s+[^\s;|]+/i', 'Bearer [REDACTED]', $redacted) ?? $redacted;
        $redacted = preg_replace(
            '~\b([a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@~i',
            '$1[REDACTED]@',
            $redacted
        ) ?? $redacted;
        $redacted = preg_replace(
            '/\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|authorization|cookie|credential|private[_-]?key)\b(\s*[:=]\s*)("[^"]*"|\'[^\']*\'|[^\s;&|]+)/i',
            '$1$2[REDACTED]',
            $redacted
        ) ?? $redacted;
        $redacted = preg_replace(
            '/(--(?:password|passwd|secret|token|api-key|access-key|authorization|credential))(?:=|\s+)("[^"]*"|\'[^\']*\'|[^\s;&|]+)/i',
            '$1=[REDACTED]',
            $redacted
        ) ?? $redacted;
        $redacted = preg_replace(
            '/\b([A-Za-z_][A-Za-z0-9_]*=)("[^"]*"|\'[^\']*\'|[^\s;&|]+)/',
            '$1[REDACTED]',
            $redacted
        ) ?? $redacted;

        $knownSecrets = collect($knownSecrets)
            ->filter(fn (mixed $secret): bool => is_string($secret) && strlen($secret) >= 4)
            ->unique()
            ->sortByDesc(fn (string $secret): int => strlen($secret));

        foreach ($knownSecrets as $secret) {
            $redacted = str_replace($secret, '[REDACTED]', $redacted);
        }

        return $redacted;
    }
}
