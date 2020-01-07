<?php

namespace App\Http\Controllers;

use App\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class MainController extends Controller
{
    public function __construct()
    {
    }

    public function register(Request $request)
    {
        $request->validate([
            'name'      =>  'required|string',
            'email'     =>  'required|string|email|unique:users',
            'password'  =>  'required|string|confirmed'
        ]);
        $user = new User([
            'name'      =>  $request->name,
            'email'     =>  $request->email,
            'password'  =>  bcrypt($request->password)
        ]);

        $user->save();

        return response()->json(['success' => 'The user have been registered.'], 201);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email'         =>  'required|string|email',
            'remember_me'   =>  'boolean'
        ]);

        if(!Auth::attempt(['email' => $request->email, 'password' => $request->password]))
        {
            return response()->json(['success' => 'Unauthorized'], 401);
        }

        $user = $request->user();
        $tokenResult = $user->createToken('User Personl Access Token');
        $token = $tokenResult->token;

        if($request->remember_me)
        {
            $token->expires_at = Carbon::now()->addWeeks(2);
        }

        $token->save();

        return response()->json(['access_token' => $tokenResult->accessToken, 'token_type' => 'Bearer', 'expires_at' => Carbon::parse($tokenResult->token->expires_at)->toDateString()]);
    }

    public function logout(Request $request)
    {
        $request->user()->token()->revoke();
        return response()->json(['success' => 'You have been logged out']);
    }

    public function profile()
    {
    }
}
