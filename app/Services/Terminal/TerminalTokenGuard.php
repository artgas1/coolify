<?php

namespace App\Services\Terminal;

use App\Models\PersonalAccessToken;
use App\Models\User;
use Carbon\CarbonImmutable;
use DateTimeInterface;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Validation\ValidationException;

class TerminalTokenGuard
{
    public const ABILITY = 'terminal';

    public const MAX_LIFETIME_DAYS = 90;

    /**
     * @param  array<int, string>  $abilities
     */
    public function validateIssuance(
        User $user,
        int $teamId,
        array $abilities,
        DateTimeInterface|string|null $expiresAt,
        DateTimeInterface|string|null $createdAt = null,
    ): void {
        if (! in_array(self::ABILITY, $abilities, true)) {
            return;
        }

        if (! $user->isAdminOfTeam($teamId)) {
            throw new AuthorizationException('Only team admins and owners can issue terminal API tokens.');
        }

        if (! $this->hasValidLifetime($createdAt ?? now(), $expiresAt)) {
            throw ValidationException::withMessages([
                'expires_at' => 'Terminal API tokens must expire within 90 days of creation.',
            ]);
        }
    }

    public function validatePersistedToken(PersonalAccessToken $token): void
    {
        $abilities = $this->abilities($token->abilities);
        if (! in_array(self::ABILITY, $abilities, true)) {
            return;
        }

        $user = $token->tokenable;
        $teamId = $token->team_id;
        if (! $user instanceof User || is_null($teamId)) {
            throw new AuthorizationException('Terminal API tokens require an owning user and team.');
        }

        $this->validateIssuance(
            $user,
            (int) $teamId,
            $abilities,
            $token->expires_at,
            $token->created_at ?? now(),
        );
    }

    public function hasValidLifetime(DateTimeInterface|string|null $createdAt, DateTimeInterface|string|null $expiresAt): bool
    {
        if (is_null($createdAt) || is_null($expiresAt)) {
            return false;
        }

        try {
            $created = CarbonImmutable::parse($createdAt);
            $expires = CarbonImmutable::parse($expiresAt);
        } catch (\Throwable) {
            return false;
        }

        return $expires->greaterThan($created)
            && $expires->lessThanOrEqualTo($created->addDays(self::MAX_LIFETIME_DAYS));
    }

    /**
     * @return array<int, string>
     */
    public function abilities(mixed $abilities): array
    {
        if (is_string($abilities)) {
            $abilities = json_decode($abilities, true);
        }

        return is_array($abilities) ? array_values($abilities) : [];
    }
}
