<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;
use App\User;

class AuthController extends Controller
{
    /*
    |-------------------------------------------------------------------------------
    | Create a user
    |-------------------------------------------------------------------------------
    | URL:            /signup
    | Method:         GET
    |
    | @param [string] email
    | @param [string] password
    | @param [string] password_confirmation
    | @param [string] message 
    */
    public function signup(Request $request)
    {
        $request->validate([
            'name'      => 'required|string',
            'email'     => 'required|string|email|unique:users',
            'password'  => 'required|string|confirmed'
        ]);

        $user = new User([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);

        $user->save();
        
        return response()->json([
            'message'   =>'Successfully create user!'
        ], 201);
    }
    /*
    |-------------------------------------------------------------------------------
    | Login user and create token
    |-------------------------------------------------------------------------------
    | URL:            /login
    | Method:         post
    |
    | @param [string] email
    | @param [string] password
    | @param [boolean] remember_me
    | @param [string] access_token
    | @param [string] token_type
    | @param [string] expires_at 
    */
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
            'remember_me' => 'boolean'
        ]);

        $credentials = request(['email','password']);

        if (!Auth::attempt($credentials)) 
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);

        $user = $request->user();
        $tokenResult = $user->createToken('token');
        $token = $tokenResult->token;

        if($request->remember_me)
            $token->expires_at = Carbon::now()->addWeeks(1);
        $token->save();
        
        return response()->json([
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => Carbon::parse($tokenResult->token->expires_at)->toDateTimeString()
        ]);
    }
    /*
    |-------------------------------------------------------------------------------
    | Logout user or revoke the token
    |-------------------------------------------------------------------------------
    | URL:            /logout
    | Method:         post
    |
    | @param [string] message
    |
    */   
    public function logout(Request $request)
    {
        $request->user()->token()->revoke();

        return response()->json([
            'message' => 'Successfully logged out'
        ]);
    } 
    /*
    |-------------------------------------------------------------------------------
    | LGet the autheticated user
    |-------------------------------------------------------------------------------
    |
    | @param [json] user object
    */
    public function user(Request $request)
    {
        return response()->json($request->user());
    }

}
