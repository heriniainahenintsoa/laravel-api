<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $fields = $request->validate([
            "name" => "required|max:255",
            "email" => "unique:users|email|required",
            "password" => "required|min:8|confirmed"
        ]);

        $user = User::create($fields);

        $token = $user->createToken($user->name);

        return ["user" => $user, "token" => $token->plainTextToken];
    }
    public function login(Request $request)
    {
        $fields = $request->validate([
            "email" => "email|required",
            "password" => "required|min:8"
        ]);
        $user = User::where('email', $fields['email'])->first();

        if (!$user || !Hash::check($fields['password'], $user->password)) {
            return response([
                'errors' => [
                    "email" => ["Bad credentials"],
                    "password" => ["Bad credentials"],
                ]
            ], 401);
        }

        $token = $user->createToken($user->name);

        return ["user" => $user, "token" => $token->plainTextToken];
    }
    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();
        return ['message' => "Logged out successfully"];
    }
}
