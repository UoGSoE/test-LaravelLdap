<?php

namespace Tests\Feature;

use App\User;
use Tests\TestCase;
use Illuminate\Foundation\Testing\WithFaker;
use Illuminate\Foundation\Testing\RefreshDatabase;

class LoginTest extends TestCase
{
    use RefreshDatabase;

    /** @test */
    public function a_local_user_can_login_with_valid_credentials()
    {
        $user = factory(User::class)->create([
            'username' => 'validuser',
            'password' => bcrypt('secret'),
        ]);

        $response = $this->post('/login', [
            'username' => 'validuser',
            'password' => 'secret',
        ]);

        $response->assertRedirect('/home');
        $this->assertTrue(\Auth::user()->is($user));
    }

    /** @test */
    public function a_local_user_cannot_login_with_an_invalid_password()
    {
        $user = factory(User::class)->create([
            'username' => 'validuser',
            'password' => bcrypt('secret'),
        ]);

        $response = $this->post('/login', [
            'username' => 'validuser',
            'password' => 'wrongpassword',
        ]);

        $response->assertRedirect('/');
        $this->assertFalse(\Auth::check());
    }

    /** @test */
    public function a_local_user_cannot_login_with_an_empty_password()
    {
        $user = factory(User::class)->create([
            'username' => 'validuser',
            'password' => bcrypt('secret'),
        ]);

        $response = $this->post('/login', [
            'username' => 'validuser',
            'password' => '',
        ]);

        $response->assertRedirect('/');
        $this->assertFalse(\Auth::check());
    }

    /** @test */
    public function an_ldap_user_can_login_with_valid_credentials()
    {
        $response = $this->post('/login', [
            'username' => env("VALID_LDAP_USERNAME"),
            'password' => env("VALID_LDAP_PASSWORD"),
        ]);

        $response->assertRedirect('/home');
        $user = User::first();
        $this->assertTrue(\Auth::user()->is($user));
        $this->assertEquals(env("VALID_LDAP_USERNAME"), $user->username);
    }

    /** @test */
    public function an_ldap_user_cannot_login_with_invalid_credentials()
    {
        $response = $this->post('/login', [
            'username' => env("VALID_LDAP_USERNAME"),
            'password' => 'wrong' . env("VALID_LDAP_PASSWORD"),
        ]);

        $response->assertRedirect('/');
        $this->assertCount(1, User::all()); // we create a user record if the username was valid
        $this->assertFalse(\Auth::check()); // but they do not get logged in
    }

    /** @test */
    public function an_ldap_user_cannot_login_with_an_empty_password()
    {
        $response = $this->post('/login', [
            'username' => env("VALID_LDAP_USERNAME"),
            'password' => '',
        ]);

        $response->assertRedirect('/');
        $this->assertCount(0, User::all()); // empty password skips the account creation**
        $this->assertFalse(\Auth::check()); // but they do not get logged in

        // ** this seems to happen a lot with bots hitting our servers for whatever reason, so built in the bypass
    }
}
