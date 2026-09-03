<?php

use App\Services\Terminal\TerminalCommandRedactor;

test('terminal command redactor removes assignment auth url token private key and known secret values', function () {
    $knownSecret = 'database-password-123';
    $command = <<<'COMMAND'
FOO=bar password="hunter2" curl -H "Authorization: Bearer abc.def" https://user:pass@example.com
printf database-password-123
-----BEGIN OPENSSH PRIVATE KEY-----
private-material
-----END OPENSSH PRIVATE KEY-----
COMMAND;

    $redacted = (new TerminalCommandRedactor)->redact($command, [$knownSecret]);

    expect($redacted)
        ->toContain('FOO=[REDACTED]')
        ->toContain('password=[REDACTED]')
        ->not->toContain('hunter2')
        ->not->toContain('abc.def')
        ->not->toContain('user:pass')
        ->not->toContain($knownSecret)
        ->not->toContain('private-material');
});
