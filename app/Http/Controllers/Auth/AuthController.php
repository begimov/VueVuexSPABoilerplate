<?php

namespace App\Http\Controllers\Auth;

use App\User;
use Tymon\JWTAuth\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\RegisterFormRequest;
use App\Http\Requests\Auth\LoginFormRequest;

class AuthController extends Controller
{
    protected $auth;

    public function __construct(JWTAuth $auth)
    {
        $this->auth = $auth;
    }

    public function login(LoginFormRequest $req)
    {
        $credentials = $req->only('email', 'password');

        try {
            if (! $token = $this->auth->attempt($credentials)) {
                return response()->json([
                  'errors' => [
                    'root' => 'invalid_credentials'
                  ]
                ], 401);
            }
        } catch (JWTException $e) {
            return response()->json([
              'errors' => [
                'root' => 'could_not_create_token'
              ]
            ], 500);
        }

        return response()->json([
          'data' => $req->user(),
          'meta' => [
            'token' => $token
          ]
        ], 200);
    }

    public function register(RegisterFormRequest $req)
    {
        $user = User::create([
        'name' => $req->name,
        'email' => $req->email,
        'password' => bcrypt($req->password),

      ]);

        $token = $this->auth->attempt($req->only(['email', 'password']));

        return response()->json([
        'data' => $user,
        'meta' => [
          'token' => $token
        ]
      ], 200);
    }

    public function logout()
    {
      $this->auth->invalidate($this->auth->getToken());
      return response()->json([
        'meta' => [
          'msg' => 'token_invalidated'
        ]
      ], 200);
    }

    public function getUser(Request $req)
    {
      return response()->json([
        'data' => $req->user()
      ]);
    }

}
