<?php

use App\Livewire\Security\ApiTokens;
use App\Models\InstanceSettings;
use App\Models\Team;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Once;
use Livewire\Features\SupportLockedProperties\CannotUpdateLockedPropertyException;
use Livewire\Livewire;

uses(RefreshDatabase::class);

beforeEach(function () {
    Once::flush();
    InstanceSettings::forceCreate(['id' => 0, 'is_api_enabled' => true]);
    $this->withoutVite();

    $this->team = Team::factory()->create();

    $this->owner = User::factory()->create();
    $this->owner->teams()->attach($this->team, ['role' => 'owner']);

    $this->member = User::factory()->create();
    $this->member->teams()->attach($this->team, ['role' => 'member']);
});

describe('Livewire ApiTokens — member cannot create elevated tokens', function () {
    test('member cannot create token with root permissions', function () {
        $this->actingAs($this->member);
        session(['currentTeam' => $this->team]);

        Livewire::test(ApiTokens::class)
            ->set('description', 'my-root-token')
            ->set('permissions', ['root'])
            ->call('addNewToken')
            ->assertDispatched('error');

        expect($this->member->tokens()->count())->toBe(0);
    });

    test('member cannot create token with write permissions', function () {
        $this->actingAs($this->member);
        session(['currentTeam' => $this->team]);

        Livewire::test(ApiTokens::class)
            ->set('description', 'my-write-token')
            ->set('permissions', ['write'])
            ->call('addNewToken')
            ->assertDispatched('error');

        expect($this->member->tokens()->count())->toBe(0);
    });

    test('member cannot create token with deploy permissions', function () {
        $this->actingAs($this->member);
        session(['currentTeam' => $this->team]);

        Livewire::test(ApiTokens::class)
            ->set('description', 'my-deploy-token')
            ->set('permissions', ['deploy'])
            ->call('addNewToken')
            ->assertDispatched('error');

        expect($this->member->tokens()->count())->toBe(0);
    });

    test('member cannot create token with read:sensitive permissions', function () {
        $this->actingAs($this->member);
        session(['currentTeam' => $this->team]);

        Livewire::test(ApiTokens::class)
            ->set('description', 'my-sensitive-token')
            ->set('permissions', ['read', 'read:sensitive'])
            ->call('addNewToken')
            ->assertDispatched('error');

        expect($this->member->tokens()->count())->toBe(0);
    });

    test('member cannot create token with terminal permissions', function () {
        $this->actingAs($this->member);
        session(['currentTeam' => $this->team]);

        Livewire::test(ApiTokens::class)
            ->set('description', 'my-terminal-token')
            ->set('expiresInDays', 30)
            ->set('permissions', ['terminal'])
            ->call('addNewToken')
            ->assertDispatched('error');

        expect($this->member->tokens()->count())->toBe(0);
    });

    test('member cannot bypass by setting canUseRootPermissions property', function () {
        $this->actingAs($this->member);
        session(['currentTeam' => $this->team]);

        // Simulate snapshot replay: Livewire must reject the locked policy result.
        expect(fn () => Livewire::test(ApiTokens::class)
            ->set('canUseRootPermissions', true))
            ->toThrow(CannotUpdateLockedPropertyException::class);

        expect($this->member->tokens()->count())->toBe(0);
    });

    test('member can create token with read permissions', function () {
        $this->actingAs($this->member);
        session(['currentTeam' => $this->team]);

        Livewire::test(ApiTokens::class)
            ->set('description', 'my-read-token')
            ->set('permissions', ['read'])
            ->call('addNewToken')
            ->assertNotDispatched('error');

        expect($this->member->tokens()->count())->toBe(1);
        expect($this->member->tokens()->first()->abilities)->toBe(['read']);
    });

    test('owner can create token with root permissions', function () {
        $this->actingAs($this->owner);
        session(['currentTeam' => $this->team]);

        Livewire::test(ApiTokens::class)
            ->set('description', 'my-root-token')
            ->set('permissions', ['root'])
            ->call('addNewToken')
            ->assertNotDispatched('error');

        expect($this->owner->tokens()->count())->toBe(1);
        expect($this->owner->tokens()->first()->abilities)->toBe(['root']);
    });

    test('owner can create a terminal token expiring within 90 days', function () {
        $this->actingAs($this->owner);
        session(['currentTeam' => $this->team]);

        Livewire::test(ApiTokens::class)
            ->set('description', 'my-terminal-token')
            ->set('expiresInDays', 90)
            ->set('permissions', ['terminal'])
            ->call('addNewToken')
            ->assertNotDispatched('error');

        $token = $this->owner->tokens()->first();
        expect($token->abilities)->toBe(['terminal'])
            ->and($token->expires_at)->not->toBeNull()
            ->and($token->expires_at->lessThanOrEqualTo($token->created_at->addDays(90)))->toBeTrue();
    });

    test('tampered terminal token expiry over 90 days is rejected', function () {
        $this->actingAs($this->owner);
        session(['currentTeam' => $this->team]);

        Livewire::test(ApiTokens::class)
            ->set('description', 'long-terminal-token')
            ->set('permissions', ['terminal'])
            ->set('expiresInDays', 365)
            ->call('addNewToken')
            ->assertDispatched('error');

        expect($this->owner->tokens()->count())->toBe(0);
    });
});

test('terminal api team flag defaults off and remains null safe in the team form', function () {
    $team = Team::factory()->create();

    expect($team->is_terminal_api_enabled)->toBeFalse();
});

describe('ApiAbility middleware — member with elevated token blocked', function () {
    test('member root token is blocked on team_id=0 (root team)', function () {
        // Create root team with id=0
        $rootTeam = Team::factory()->create(['id' => 0]);
        $member = User::factory()->create();
        $rootTeam->members()->attach($member->id, ['role' => 'member']);

        session(['currentTeam' => $rootTeam]);
        $token = $member->createToken('root-token', ['root']);

        $this->withToken($token->plainTextToken)
            ->getJson('/api/v1/projects')
            ->assertStatus(403);
    });

    test('admin root token passes on team_id=0 (root team)', function () {
        $rootTeam = Team::factory()->create(['id' => 0]);
        $admin = User::factory()->create();
        $rootTeam->members()->attach($admin->id, ['role' => 'admin']);

        session(['currentTeam' => $rootTeam]);
        $token = $admin->createToken('root-token', ['root']);

        $this->withToken($token->plainTextToken)
            ->getJson('/api/v1/projects')
            ->assertSuccessful();
    });

    test('member root token is blocked on non-zero team', function () {
        session(['currentTeam' => $this->team]);
        $token = $this->member->createToken('root-token', ['root']);

        $this->withToken($token->plainTextToken)
            ->getJson('/api/v1/projects')
            ->assertStatus(403);
    });

    test('member read token passes on non-zero team', function () {
        session(['currentTeam' => $this->team]);
        $token = $this->member->createToken('read-token', ['read']);

        $this->withToken($token->plainTextToken)
            ->getJson('/api/v1/projects')
            ->assertSuccessful();
    });
});
