<?php

namespace App\Models;

use App\Services\Terminal\TerminalTokenGuard;
use Laravel\Sanctum\PersonalAccessToken as SanctumPersonalAccessToken;

class PersonalAccessToken extends SanctumPersonalAccessToken
{
    protected $fillable = [
        'name',
        'token',
        'abilities',
        'expires_at',
        'api_token_expiration_warning_sent_at',
        'team_id',
    ];

    protected function casts(): array
    {
        return [
            'abilities' => 'json',
            'last_used_at' => 'datetime',
            'expires_at' => 'datetime',
            'api_token_expiration_warning_sent_at' => 'datetime',
        ];
    }

    protected static function booted(): void
    {
        static::saving(function (PersonalAccessToken $token): void {
            if ($token->exists && ! $token->isDirty(['abilities', 'expires_at', 'team_id', 'tokenable_id', 'tokenable_type'])) {
                return;
            }

            resolve(TerminalTokenGuard::class)->validatePersistedToken($token);
        });
    }
}
