<?php

it('documents the bounded audited terminal exec contract for both targets', function () {
    $openApi = json_decode(
        file_get_contents(__DIR__.'/../../openapi.json'),
        true,
        flags: JSON_THROW_ON_ERROR,
    );

    foreach (['/applications/{uuid}/exec', '/servers/{uuid}/exec'] as $path) {
        $operation = $openApi['paths'][$path]['post'];
        $request = $operation['requestBody']['content']['application/json']['schema'];
        $limitResponse = $operation['responses']['429']['content']['application/json']['schema'];

        expect($request)
            ->additionalProperties->toBeFalse()
            ->and($request['required'])->toContain('command')
            ->and($request['properties']['command'])
            ->toMatchArray(['type' => 'string', 'minLength' => 1, 'maxLength' => 20_000])
            ->and($request['properties']['timeout'])
            ->toMatchArray(['type' => 'integer', 'default' => 10, 'minimum' => 1, 'maximum' => 10])
            ->and(array_map('strval', array_keys($operation['responses'])))
            ->toContain('200', '401', '403', '404', '422', '429', '503')
            ->and($limitResponse['required'])
            ->toBe(['message', 'retry_after'])
            ->and($limitResponse['properties']['retry_after']['minimum'])
            ->toBe(1);
    }

    expect($openApi['components']['schemas']['TerminalCommandResult']['required'])
        ->toBe([
            'exit_code',
            'stdout',
            'stderr',
            'duration_ms',
            'audit_event_id',
            'stdout_truncated',
            'stderr_truncated',
        ]);
});
