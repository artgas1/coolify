<?php

namespace App\Http\Middleware;

use App\Models\Team;
use App\Services\Terminal\TerminalTokenGuard;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureTerminalApiAccess
{
    public function __construct(private readonly TerminalTokenGuard $tokenGuard) {}

    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();
        $token = $user?->currentAccessToken();
        $teamId = $token?->team_id;

        if (! $user || ! $token || is_null($teamId)) {
            return response()->json(['message' => 'Invalid token.'], 401);
        }

        if (! in_array(TerminalTokenGuard::ABILITY, $this->tokenGuard->abilities($token->abilities), true)) {
            return $this->forbidden('Missing required permissions: terminal');
        }

        if (! $user->isAdminOfTeam((int) $teamId)) {
            return $this->forbidden('Only team admins and owners can use terminal API tokens.');
        }

        $team = Team::query()->find($teamId);
        if (! $team || ! (bool) ($team->is_terminal_api_enabled ?? false)) {
            return $this->forbidden('Terminal API is disabled for this team.');
        }

        if (! $this->tokenGuard->hasValidLifetime($token->created_at, $token->expires_at)) {
            return $this->forbidden('Terminal API token lifetime is invalid.');
        }

        return $next($request);
    }

    private function forbidden(string $message): JsonResponse
    {
        return response()->json(['message' => $message], 403);
    }
}
